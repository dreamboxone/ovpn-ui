#!/usr/bin/env python3
"""Remote scenario runner — drives the LIVE vpn-ui panel on a remote server plus
local incus client VMs to test, over real WAN, for openvpn / l2tp-raw /
l2tp-ipsec / pptp:

  * usage quota      (counter climbs live + session terminated on limit)
  * user limit       (K distinct devices on one account, K=1 and K=2)
  * strategy reject   (device K+1 actively refused)
  * strategy accept   (device K+1 admitted, oldest device evicted)

Run from repo root:  python3 -m test_unit.harness.remote_runner [all|openvpn|l2tp|pptp|sstp|ikev2]
Config comes from RR_* env vars (RR_SERVER_IP, RR_PORT, RR_BP, RR_SCHEME, RR_PUSER,
RR_PPASS, RR_SSH_PASS) so no creds are committed. NOTE: `all` includes pptp; for a
live box your network may not reach pptp — run protocols individually there.

Client VMs: cA=deb11 cB=deb13 cC=deb12 (all apt, behind one host NAT -> share a
public IP = realistic multi-device-behind-NAT test). Server signals are read over
ssh (unit = vpn-ui; RADIUS logs at INFO show in journalctl).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from . import checks
from . import traffic
from . import protocols as P
from .clients import openvpn as ovpn
from .clients import l2tp as l2tp_mod
from .clients import pptp as pptp_mod
from .clients import sstp as sstp_mod
from .clients import ikev2 as ikev2_mod
from .clients.base import Client
from .model import SubTest, Status
from .panel import Panel
from .server_setup import Inbound, Account, _dict_client, PSK

# ---- fixed environment ------------------------------------------------------
# Fill in for your remote panel + SSH before running (do NOT commit real creds).
SERVER_IP = os.getenv("RR_SERVER_IP", "REPLACE_ME")
PORT = int(os.getenv("RR_PORT", "2083"))
BP = os.getenv("RR_BP", "/REPLACE_ME/")
SCHEME = os.getenv("RR_SCHEME", "https")
PUSER, PPASS = os.getenv("RR_PUSER", "REPLACE_ME"), os.getenv("RR_PPASS", "REPLACE_ME")
SSH_PASS = os.getenv("RR_SSH_PASS", "REPLACE_ME")

VM_A, VM_B, VM_C = "rtca", "rtcb", "rtcc"  # 3 existing apt client VMs behind one host NAT

CFG = {
    "traffic_test": {
        "usage_mb": 12, "limit_mb": 40, "over_mb": 60, "multi_user_mb": 8,
        "settle_timeout": 50,
        "urls": [
            "https://proof.ovh.net/files/1Gb.dat",
            "https://ash-speed.hetzner.com/1GB.bin",
            "http://speedtest.tele2.net/1GB.zip",
        ],
    },
    "dns_resolve": {"domain": "cloudflare.com"},
    "dns_leak": {"api_base": "https://bash.ws"},
}

# openvpn 11194/11443, l2tp label 1901 (daemon binds 1701), pptp label 1902 (1723),
# sstp 443, ikev2 label 500 (shared charon binds 500/4500 regardless)
PORTS = {"openvpn": (11194, 11443), "l2tp": (1901, 0), "pptp": (1902, 0),
         "sstp": (443, 0), "ikev2": (500, 0)}

RESULTS = []  # (proto, transport, scenario, K, status, detail)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---- incus shim (existing VMs, no prefix) -----------------------------------
class LocalIncus:
    def exec(self, vm, cmd, timeout=300, check=False, env=None):
        try:
            p = subprocess.run(["incus", "exec", vm, "--", "sh", "-c", cmd],
                               capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"

    def push_bytes(self, vm, data, remote_path, mode="0644"):
        subprocess.run(["incus", "file", "push", "-p", "--mode", mode, "-",
                        f"{vm}{remote_path}"], input=data, text=True,
                       capture_output=True, timeout=60)


def server_exec(cmd):
    env = dict(os.environ); env["SSHPASS"] = SSH_PASS
    try:
        p = subprocess.run(
            ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
             f"root@{SERVER_IP}", cmd],
            capture_output=True, text=True, timeout=90, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "ssh timeout"


def journal_since(pattern, secs=50, extra=""):
    _, out, _ = server_exec(
        f'journalctl -u vpn-ui --no-pager --since "-{secs} seconds" 2>/dev/null '
        f'| grep {extra} "{pattern}" | tail -3')
    return out.strip()


def rec(proto, transport, scenario, K, status, detail):
    RESULTS.append((proto, transport, scenario, K, status, detail))
    log(f"[RESULT] {proto}/{transport} {scenario} K={K} => {status} :: {detail}")


# ---- panel helpers ----------------------------------------------------------
def acct(proto):
    return Account(user=f"rt{proto}a", password=f"Pw-rt-{proto}-9k",
                   email=f"rt{proto}a@t", index=0)


def wipe_inbounds(panel):
    ibs = panel.list_inbounds()
    log(f"wiping {len(ibs)} existing inbound(s)")
    for ib in ibs:
        try:
            panel.del_inbound(ib["id"]); time.sleep(2)
        except Exception as e:  # noqa: BLE001
            log(f"  del {ib.get('id')} failed: {e}")
    time.sleep(4)


def make_inbound(panel, proto, K):
    a = acct(proto)
    udp, tcp = PORTS[proto]
    if proto == "openvpn":
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True, "tcpPort": tcp,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"], "cipherMode": "all",
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": K, "clients": [_dict_client(a)],
        }
        inb = panel.add_inbound("rt-openvpn", udp, "openvpn", settings)
        iid = inb["id"]
        return Inbound(protocol="openvpn", inbound_id=iid, udp_port=udp, tcp_port=tcp,
                       accounts={"A": a}, user_limit=K,
                       ovpn_udp=panel.download_ovpn(iid, "udp"),
                       ovpn_tcp=panel.download_ovpn(iid, "tcp"))
    if proto == "l2tp":
        settings = {"ipsecEnable": True, "ipsecPsk": PSK, "allowRaw": True,
                    "clientToClient": True, "crossInbound": True,
                    "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
                    "userLimit": K, "clients": [_dict_client(a)]}
        inb = panel.add_inbound("rt-l2tp", udp, "l2tp", settings)
        return Inbound(protocol="l2tp", inbound_id=inb["id"], udp_port=udp, tcp_port=0,
                       accounts={"A": a}, psk=PSK, user_limit=K)
    if proto == "pptp":
        settings = {"clientToClient": True, "crossInbound": True,
                    "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
                    "userLimit": K, "clients": [_dict_client(a)]}
        inb = panel.add_inbound("rt-pptp", udp, "pptp", settings)
        return Inbound(protocol="pptp", inbound_id=inb["id"], udp_port=udp, tcp_port=0,
                       accounts={"A": a}, user_limit=K)
    if proto == "sstp":
        cert = panel.generate_ocserv_cert()  # self-signed; sstpc uses --cert-warn
        settings = {"dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
                    "tlsUseFile": False,
                    "certificate": cert["certificate"], "key": cert["key"],
                    "clientToClient": True, "crossInbound": True,
                    "userLimit": K, "clients": [_dict_client(a)]}
        inb = panel.add_inbound("rt-sstp", udp, "sstp", settings)  # udp = 443
        return Inbound(protocol="sstp", inbound_id=inb["id"], udp_port=udp, tcp_port=0,
                       accounts={"A": a}, user_limit=K)
    if proto == "ikev2":
        cert = panel.generate_ikev2_cert()  # self-signed leaf + CA; client trusts caCert
        settings = {"dns1": "1.1.1.1", "dns2": "8.8.8.8",
                    "authMode": "eap-mschapv2", "serverAddr": "", "tlsUseFile": False,
                    "certificate": cert["certificate"], "key": cert["key"],
                    "caCert": cert["caCert"],
                    "clientToClient": True, "crossInbound": True,
                    "userLimit": K, "clients": [_dict_client(a)]}
        inb = panel.add_inbound("rt-ikev2", udp, "ikev2", settings)  # udp label = 500
        return Inbound(protocol="ikev2", inbound_id=inb["id"], udp_port=udp, tcp_port=0,
                       accounts={"A": a}, user_limit=K,
                       ca_cert=cert.get("caCert", ""), server_addr="")
    raise ValueError(proto)


def set_K(panel, ib, K):
    inb = panel.get_inbound(ib.inbound_id)
    s = json.loads(inb.get("settings") or "{}")
    s["userLimit"] = K
    panel.update_inbound(ib.inbound_id, inb.get("remark", ""), inb.get("port", 0),
                         inb.get("protocol", ""), s, inb.get("listen", "") or "")
    ib.user_limit = K


def set_strategy(panel, ib, strat):
    panel.set_user_limit_strategy(ib.inbound_id, strat)


def set_K_strategy(panel, ib, K, strat):
    """Set userLimit AND strategy in ONE inbound update -> a SINGLE daemon restart
    (two back-to-back updates left the daemon mid-restart and dropped device1)."""
    inb = panel.get_inbound(ib.inbound_id)
    s = json.loads(inb.get("settings") or "{}")
    s["userLimit"] = K
    s["userLimitStrategy"] = strat
    panel.update_inbound(ib.inbound_id, inb.get("remark", ""), inb.get("port", 0),
                         inb.get("protocol", ""), s, inb.get("listen", "") or "")
    ib.user_limit = K


def author_freedom_route(panel, ibs):
    """Author the A-account emails -> `direct` (freedom) outbound at the FRONT of the
    xray routing rules so the test accounts reach the internet even when the box has a
    default-deny backstop for the VPN range (this live box routes 10.0.0.0/13 -> blocked,
    only specific IPs allowed). Same mechanism as server_setup.py; the DB backup covers
    the xray template so the operator's routing is restored afterwards."""
    tmpl = panel.get_xray_template()
    routing = tmpl.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    a_emails = [ib.accounts["A"].email for ib in ibs.values()]
    rules.insert(0, {"type": "field", "outboundTag": "direct", "user": a_emails})
    panel.update_xray_template(tmpl)
    log(f"authored A->freedom (direct) for {a_emails}")


# ---- connect wrapper --------------------------------------------------------
def connect(client, ib, proto, transport):
    if proto == "openvpn":
        return ovpn.connect(client, ib, "A", "udp", "new", SERVER_IP)
    if proto == "l2tp":
        return l2tp_mod.connect(client, ib, "A", ipsec=(transport == "ipsec"),
                                server_ip=SERVER_IP)
    if proto == "pptp":
        return pptp_mod.connect(client, ib, "A", SERVER_IP)
    if proto == "sstp":
        return sstp_mod.connect(client, ib, "A", server_ip=SERVER_IP)
    if proto == "ikev2":
        return ikev2_mod.connect(client, ib, "A", server_ip=SERVER_IP)
    raise ValueError(proto)


def disc(client, proto):
    {"openvpn": ovpn.disconnect, "l2tp": l2tp_mod.disconnect,
     "pptp": pptp_mod.disconnect, "sstp": sstp_mod.disconnect,
     "ikev2": ikev2_mod.disconnect}[proto](client)


def all_down(clients, proto):
    for c in clients:
        try:
            disc(c, proto); c.disconnect_all()
        except Exception:  # noqa: BLE001
            pass
    time.sleep(2)


def block_of(ip1, K):
    p3, b = ip1.rsplit(".", 1)
    return {f"{p3}.{int(b) + d}" for d in range(K)}


def server_block_peers(ip1, K):
    """Count the account's LIVE server-side ppp sessions (l2tp/pptp): distinct
    `peer <deviceIP>` addresses on the server that fall in the account's K-block.
    Used as the causative reject signal — the l2tp deny path closes the L2TP tunnel
    without a reliable RADIUS reject log, so we assert the over-cap device added no
    session (count stays <= K) rather than grepping a log line."""
    if not ip1:
        return 99
    blk = block_of(ip1, K)
    _, out, _ = server_exec(
        "ip -o addr show 2>/dev/null | grep -oE 'peer 10\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
        "| awk '{print $2}'")
    peers = {x.strip() for x in out.split("\n") if x.strip()}
    return len([x for x in peers if x in blk])


# ---- scenarios --------------------------------------------------------------
def sc_quota(panel, ib, proto, transport, cA):
    all_down([cA], proto)
    cf = lambda: connect(cA, ib, proto, transport)  # noqa: E731
    try:
        u = traffic.usage(cA, panel, ib, CFG, cf, log, server_exec=server_exec)
        rec(proto, transport, "quota-usage-counted", 1, u.status.value.upper(), u.detail)
    except Exception as e:  # noqa: BLE001
        rec(proto, transport, "quota-usage-counted", 1, "ERROR", str(e)[:120])
    all_down([cA], proto)
    try:
        m = traffic.multiplier(cA, panel, ib, CFG, cf, log, server_exec=server_exec)
        rec(proto, transport, "quota-traffic-multiplier", 1, m.status.value.upper(), m.detail)
    except Exception as e:  # noqa: BLE001
        rec(proto, transport, "quota-traffic-multiplier", 1, "ERROR", str(e)[:120])
    all_down([cA], proto)
    try:
        t = traffic.termination(cA, panel, ib, CFG, cf, log)
        rec(proto, transport, "quota-terminate-on-limit", 1, t.status.value.upper(), t.detail)
    except Exception as e:  # noqa: BLE001
        rec(proto, transport, "quota-terminate-on-limit", 1, "ERROR", str(e)[:120])
    all_down([cA], proto)


def sc_user_limit(panel, ib, proto, transport, cA, cB, K):
    """K distinct devices on one account, each a distinct in-block IP + internet."""
    all_down([cA, cB], proto)
    set_K_strategy(panel, ib, K, "reject"); time.sleep(10)
    ok1, ip1, l1 = connect(cA, ib, proto, transport)
    if not ok1 or not ip1:
        rec(proto, transport, "user-limit", K, "FAIL", f"device1 no connect: {l1[-160:]}")
        all_down([cA, cB], proto); return
    n1 = checks.internet(cA)
    if K == 1:
        status = "PASS" if n1.status == Status.PASS else "FAIL"
        rec(proto, transport, "user-limit", K, status, f"1 device {ip1} net={n1.status.value}")
        all_down([cA, cB], proto); return
    time.sleep(2)
    ok2, ip2, l2 = connect(cB, ib, proto, transport)
    n2 = checks.internet(cB) if ok2 else None
    blk = block_of(ip1, K)
    if not ok2 or not ip2:
        rec(proto, transport, "user-limit", K, "FAIL", f"device2 no connect: {l2[-160:]}")
    elif ip2 == ip1:
        rec(proto, transport, "user-limit", K, "FAIL", f"both devices SAME ip {ip1}")
    elif ip2 not in blk:
        rec(proto, transport, "user-limit", K, "FAIL",
            f"device2 {ip2} not in block {sorted(blk)} (base {ip1})")
    elif not (n1.status == Status.PASS and n2 and n2.status == Status.PASS):
        rec(proto, transport, "user-limit", K, "FAIL",
            f"net d1={n1.status.value} d2={n2.status.value if n2 else 'n/a'}")
    else:
        rec(proto, transport, "user-limit", K, "PASS",
            f"2 devices {ip1}+{ip2} distinct in-block, both online")
    all_down([cA, cB], proto)


def _baseline(devs, ib, proto, transport, tries=3):
    """Connect the K baseline devices onto account A and ensure they hold TOGETHER.
    Concurrent l2tp/pptp tunnels from one NAT are fragile, so retry the whole set
    with wide per-connect spacing until all K are up. Returns the device IPs (""
    for any not up on the final try)."""
    iface = "tun0" if proto == "openvpn" else "ppp0"
    ips = []
    for attempt in range(tries):
        for c in devs:
            c.disconnect_all()
        time.sleep(3)
        for c in devs:
            connect(c, ib, proto, transport)
            checks.internet(c)   # drive traffic: keeps the tunnel/NAT mapping fresh so the
            time.sleep(2)        # NEXT concurrent dial from the same NAT sticks (what makes K=2 hold)
        ips = [c.wait_iface(iface, timeout=12) for c in devs]
        if all(ips):
            return ips
        log(f"  baseline {attempt + 1}/{tries}: {sum(1 for x in ips if x)}/{len(devs)} up — retry")
    return ips


def sc_reject(panel, ib, proto, transport, clients, K):
    cA, cB, cC = clients
    devs = [cA] if K == 1 else [cA, cB]
    over = cB if K == 1 else cC
    iface = "tun0" if proto == "openvpn" else "ppp0"
    all_down(clients, proto)
    set_K_strategy(panel, ib, K, "reject"); time.sleep(10)
    # _baseline retries until the K devices hold together (else cap never exercised).
    base_ips = _baseline(devs, ib, proto, transport)
    ok_base = all(base_ips)
    ip1 = base_ips[0] if base_ips else ""
    t0 = time.time()
    ok3, ip3, clog3 = connect(over, ib, proto, transport)
    n3 = checks.internet(over) if ok3 else None
    admitted = ok3 and n3 is not None and n3.status == Status.PASS
    base_still = all(c.wait_iface(iface, timeout=3) for c in devs)  # held through the dial
    if proto == "openvpn":
        rows = P._ovpn_status_rows(server_exec, ib.inbound_id, "udp")
        live = 0
        if ip1:
            blk = block_of(ip1, K)
            live = sum(1 for r in rows if len(r) > 3 and r[3] in blk)
        refused = 0 < live <= K
        sig = f"live_sessions={live}<=K={K}"
    else:
        # l2tp/pptp deny by closing the L2TP tunnel (no reliable RADIUS reject log),
        # so detect the cap by OUTCOME: live server ppp sessions in the block stay <=K.
        peers = server_block_peers(ip1, K)
        jr = journal_since("user-limit reached", secs=int(time.time() - t0) + 25)
        refused = (0 < peers <= K)
        sig = f"live_ppp_in_block={peers}<=K={K} reject_log={'user-limit reached' in jr}"
    if ok_base and base_still and not admitted and refused:
        rec(proto, transport, "strategy-reject", K, "PASS",
            f"{K} up (held); over-cap refused [{sig}]")
    else:
        rec(proto, transport, "strategy-reject", K, "FAIL",
            f"base_ok={ok_base} base_still={base_still} admitted={admitted} {sig} | {clog3[-140:]}")
    all_down(clients, proto)


def sc_accept(panel, ib, proto, transport, clients, K):
    cA, cB, cC = clients
    devs = [cA] if K == 1 else [cA, cB]
    over = cB if K == 1 else cC
    iface = "tun0" if proto == "openvpn" else "ppp0"
    all_down(clients, proto)
    set_K_strategy(panel, ib, K, "accept"); time.sleep(10)
    base_ips = _baseline(devs, ib, proto, transport)
    ok_base = all(base_ips)
    ip1 = base_ips[0] if base_ips else ""      # oldest device = victim
    time.sleep(3)
    if proto == "openvpn":
        rows_before = P._ovpn_status_rows(server_exec, ib.inbound_id, "udp")
        victim_cid = P._ovpn_cid_at_ip(rows_before, ip1)
        ok3, ip3, clog3 = connect(over, ib, proto, transport)
        n3 = checks.internet(over) if ok3 else None
        admitted = ok3 and n3 is not None and n3.status == Status.PASS
        time.sleep(7)
        rows_after = P._ovpn_status_rows(server_exec, ib.inbound_id, "udp")
        still = P._ovpn_cid_present(rows_after, victim_cid)
        evicted = victim_cid != "" and not still
        why = f"victim_cid={victim_cid or '?'} present_after={still}"
    else:
        t0 = time.time()
        ok3, ip3, clog3 = connect(over, ib, proto, transport)
        n3 = checks.internet(over) if ok3 else None
        admitted = ok3 and n3 is not None and n3.status == Status.PASS
        time.sleep(3)
        j = journal_since("evicted oldest device", secs=int(time.time() - t0) + 20)
        server_evicted = ("evicted oldest device" in j) and (f"proto={proto}" in j)
        link_gone = None
        if ip1:
            _, addrs, _ = server_exec(f"ip -o addr show 2>/dev/null | grep 'peer {ip1}/' || true")
            link_gone = (addrs or "").strip() == ""
        # accept reuses the victim's IP for the incoming device, so the server-side
        # 'peer <ip>/' probe sees the NEW device's live link -> link_gone is a false
        # negative. Corroborate with the victim CLIENT losing its tunnel (mirrors the
        # fix already in protocols.py _strategy_check).
        victim_dropped = not devs[0].wait_iface(iface, timeout=4)
        evicted = server_evicted and (victim_dropped or link_gone is not False)
        why = f"server_evicted={server_evicted} link_gone={link_gone}"
    if ok_base and admitted and evicted:
        rec(proto, transport, "strategy-accept", K, "PASS",
            f"over-cap admitted ({ip3}); oldest evicted [{why}]")
    else:
        rec(proto, transport, "strategy-accept", K, "FAIL",
            f"base_ok={ok_base} admitted={admitted} evicted={evicted} [{why}] | {clog3[-160:]}")
    all_down(clients, proto)


# ---- driver -----------------------------------------------------------------
def run_proto(panel, ib, proto, transport, clients):
    cA, cB, cC = clients
    log(f"===== {proto}/{transport} (inbound {ib.inbound_id}) =====")
    # Ensure account A is enabled + zeroed (a prior quota run disables it). Quota
    # runs LAST because its termination sub-test deliberately disables account A.
    try:
        panel.reset_client_traffic(ib.inbound_id, ib.accounts["A"].email)
        time.sleep(5)
    except Exception as e:  # noqa: BLE001
        log(f"reset A failed (ok if first run): {e}")
    sc_user_limit(panel, ib, proto, transport, cA, cB, 1)
    sc_user_limit(panel, ib, proto, transport, cA, cB, 2)
    sc_reject(panel, ib, proto, transport, clients, 1)
    sc_reject(panel, ib, proto, transport, clients, 2)
    sc_accept(panel, ib, proto, transport, clients, 1)
    sc_accept(panel, ib, proto, transport, clients, 2)
    sc_quota(panel, ib, proto, transport, cA)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    protos = ["openvpn", "l2tp", "pptp", "sstp", "ikev2"] if mode == "all" else [mode]

    panel = Panel(host=SERVER_IP, port=PORT, base_path=BP, scheme=SCHEME,
                  username=PUSER, password=PPASS, timeout=40)
    panel.wait_up(30); panel.login()
    log("panel login OK")

    inc = LocalIncus()
    cA = Client(inc, VM_A, "A", log)
    cB = Client(inc, VM_B, "B", log)
    cC = Client(inc, VM_C, "C", log)
    for c in (cA, cB, cC):
        ok, plog = c.prep()
        log(f"prep {c.vm}: ok={ok} :: {plog.splitlines()[-1] if plog else ''}")
    clients = (cA, cB, cC)

    wipe_inbounds(panel)
    # build one inbound per protocol in scope, K=2 initially (scenarios reset K)
    ibs = {}
    for p in protos:
        ibs[p] = make_inbound(panel, p, 2)
        log(f"created {p} inbound id={ibs[p].inbound_id}")
        time.sleep(3)
    author_freedom_route(panel, ibs)
    panel.restart_core("xray"); time.sleep(4)

    for p in protos:
        ib = ibs[p]
        if p == "l2tp":
            run_proto(panel, ib, "l2tp", "raw", clients)
            run_proto(panel, ib, "l2tp", "ipsec", clients)
        else:
            run_proto(panel, ib, p, "udp" if p == "openvpn" else "-", clients)

    # ---- summary ----
    print("\n================ SUMMARY ================", flush=True)
    npass = sum(1 for r in RESULTS if r[4] == "PASS")
    for proto, tr, sc, K, st, det in RESULTS:
        print(f"{st:5} | {proto:8} {tr:5} | {sc:26} K={K} | {det}", flush=True)
    print(f"\n{npass}/{len(RESULTS)} PASS", flush=True)


if __name__ == "__main__":
    main()
