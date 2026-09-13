#!/usr/bin/env python3
"""Per-protocol traffic-accounting audit against a LIVE panel + one local incus client VM.

For each protocol it creates an inbound, connects a real client, pulls an exact byte
count through the tunnel, and reports counted/downloaded. The point is the RATIO: a
duplicate nft accounting rule once billed WireGuard accounts 2x while the E2E suite's
0.5x-3x tolerance stayed green, so this reports the number rather than a pass/fail band.

Run from the repo root, as root (incus needs it):
    sudo -E python3 test_unit/traffic_audit.py [proto ...]

Env: TA_SERVER, TA_PANEL_HOST, TA_PORT, TA_USER, TA_PASS, TA_SSH_PASS, TA_VM, TA_MB
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_unit.harness import server_setup as SS
from test_unit.harness.clients import awg as awg_mod
from test_unit.harness.clients import ikev2 as ikev2_mod
from test_unit.harness.clients import l2tp as l2tp_mod
from test_unit.harness.clients import openconnect as oc_mod
from test_unit.harness.clients import openvpn as ovpn_mod
from test_unit.harness.clients import pptp as pptp_mod
from test_unit.harness.clients import sstp as sstp_mod
from test_unit.harness.clients import ssh as ssh_mod
from test_unit.harness.clients import wgc as wgc_mod
from test_unit.harness.clients.base import Client
from test_unit.harness.incus import Incus
from test_unit.harness.panel import Panel

SERVER = os.getenv("TA_SERVER", "65.109.217.240")
PANEL_HOST = os.getenv("TA_PANEL_HOST", "vpn-ui.mmd.sh")
PANEL_PORT = int(os.getenv("TA_PORT", "9090"))
PANEL_USER = os.getenv("TA_USER", "a")
PANEL_PASS = os.getenv("TA_PASS", "a")
SSH_PASS = os.getenv("TA_SSH_PASS", "")
VM = os.getenv("TA_VM", "vpnclient")
MB = 1024 * 1024
N_BYTES = int(os.getenv("TA_MB", "100")) * MB
# Tried in order until one delivers the full range. The first is the reference file for
# this audit; the rest are fallbacks because a speed-test mirror will start answering 429
# once several 100MiB pulls in a row leave the same VPN egress IP, and a rate-limit page
# is 162 bytes that would otherwise read as "the tunnel counted nothing".
URLS = [
    "https://hil-speed.hetzner.com/100MB.bin",
    "https://ash-speed.hetzner.com/1GB.bin",
    "https://proof.ovh.net/files/1Gb.dat",
    "http://speedtest.tele2.net/1GB.zip",
]

# Ordered cheapest-to-set-up first. wg-c and ssh are already verified but stay in the
# list so a full run reproduces every number in one place.
ALL = ["wg-c", "awg", "openvpn", "l2tp", "pptp", "openconnect", "sstp", "ikev2", "ssh"]

# Userspace relays: no client tunnel IP, so no nft per-IP counters exist for them. They
# bill through Xray's per-user stats instead.
RELAY_PROTOCOLS = {"ssh", "mtproto"}

CONNECT = {
    "wg-c":        lambda c, ib: wgc_mod.connect(c, ib, "A", server_ip=SERVER),
    "awg":         lambda c, ib: awg_mod.connect(c, ib, "A", server_ip=SERVER),
    "openvpn":     lambda c, ib: ovpn_mod.connect(c, ib, "A", "udp", "new", SERVER),
    "l2tp":        lambda c, ib: l2tp_mod.connect(c, ib, "A", ipsec=True, server_ip=SERVER),
    "pptp":        lambda c, ib: pptp_mod.connect(c, ib, "A", server_ip=SERVER),
    "openconnect": lambda c, ib: oc_mod.connect(c, ib, "A", variant="dtls", server_ip=SERVER),
    "sstp":        lambda c, ib: sstp_mod.connect(c, ib, "A", server_ip=SERVER),
    "ikev2":       lambda c, ib: ikev2_mod.connect(c, ib, "A", server_ip=SERVER),
    "ssh":         lambda c, ib: ssh_mod.connect(c, ib, "A", server_ip=SERVER),
}


def ssh_server(cmd: str, timeout: int = 60) -> str:
    """Run a command on the VPN server over ssh, return stdout."""
    argv = ["sshpass", "-p", SSH_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=20", f"root@{SERVER}", cmd]
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        return p.stdout.decode(errors="replace")
    except subprocess.SubprocessError:
        return ""


def counted(email: str) -> tuple[int, int]:
    """(up, down) bytes the panel has recorded for this account."""
    out = ssh_server(
        "python3 -c \"import sqlite3;c=sqlite3.connect('/opt/vpn-ui/vpn-ui.db');"
        "r=c.execute('select up,down from client_traffics where email=?',"
        f"('{email}',)).fetchone();print(r[0],r[1]) if r else print(0,0)\"")
    try:
        a, b = out.split()
        return int(a), int(b)
    except ValueError:
        return 0, 0


def settle(email: str, base: int, timeout: int = 90) -> int:
    """Poll until the counter stops growing. The accounting job folds every 10s, so a
    stable read needs at least two whole cycles of quiet."""
    best, last_grow = 0, time.monotonic()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        u, d = counted(email)
        delta = (u + d) - base
        if delta > best:
            best, last_grow = delta, time.monotonic()
        if best > 0 and time.monotonic() - last_grow >= 25:
            break
        time.sleep(6)
    return best


def pull(client: Client) -> tuple[int, str]:
    """Pull exactly N_BYTES through the tunnel via a range request. Returns
    (bytes, url). Falls through the mirror list on a short read (rate limit)."""
    best, best_url = 0, ""
    for url in URLS:
        rc, out = client.sh(
            "curl -s -o /dev/null -w '%{size_download} %{http_code}' "
            f"-r 0-{N_BYTES - 1} --max-time 300 '{url}'", timeout=340)
        parts = out.strip().split()
        try:
            size = int(parts[-2]) if len(parts) >= 2 else int(parts[0])
        except (ValueError, IndexError):
            size = 0
        if size > best:
            best, best_url = size, url
        if size >= N_BYTES * 0.9:
            return size, url
        time.sleep(5)
    return best, best_url


def hard_reset(client: Client) -> str:
    """Tear down every tunnel a previous protocol may have left behind, and return any
    tunnel address still present afterwards ("" when clean).

    Client.disconnect_all() deliberately tolerates a stray ppp0 ("harmless, recreated
    next connect") and never kills openconnect at all. That holds inside one protocol's
    own suite, but not when protocols run back to back: the next connect() waits for
    ppp0 to carry an address, finds the PREVIOUS protocol's interface still up, and
    reports success against an IP the server never issued for this account. Downstream
    that looks like "tunnel up, zero bytes, zero counted", which would read as a
    protocol that cannot count rather than a dirty client.
    """
    client.disconnect_all()
    client.sh(
        "pkill -9 -f '[o]penvpn --config' 2>/dev/null; pkill -9 openconnect 2>/dev/null; "
        "pkill -9 sstpc 2>/dev/null; pkill -9 pppd 2>/dev/null; pkill -9 xl2tpd 2>/dev/null; "
        "pkill -9 pptp 2>/dev/null; pkill -9 -x charon 2>/dev/null; "
        "pkill -9 -x charon-systemd 2>/dev/null; "
        "for i in ppp0 ppp1 tun0 tun1 wgc awg; do ip link del $i 2>/dev/null; done; true")
    time.sleep(4)
    _, left = client.sh(
        "ip -4 -o addr show 2>/dev/null | grep -vE '\\blo\\b|%s' | awk '{print $2\"=\"$4}'"
        % client.eth)
    # A tunnel client that grabbed the default route can take it with it on teardown,
    # which leaves the VM with no egress at all and makes the NEXT protocol look broken.
    client.sh("ip route replace default via %s dev %s 2>/dev/null; true"
              % (client.gw, client.eth))
    client.pin_server_route(SERVER)
    return " ".join(left.split())


def acct_rules(proto: str) -> list[str]:
    """Every accounting rule for this protocol, across both direction chains. One
    connected account should produce exactly two: one uplink, one downlink."""
    slug = proto.replace("-", "")
    out = ssh_server(
        f"nft list chain ip vpn {slug}_acct_in 2>/dev/null; "
        f"nft list chain ip vpn {slug}_acct_out 2>/dev/null")
    return [l.strip() for l in out.splitlines() if "counter name" in l]


def audit(panel: Panel, client: Client, proto: str) -> dict:
    r = {"proto": proto, "status": "", "detail": "", "downloaded": 0, "counted": 0,
         "up": 0, "down": 0, "ratio": None, "dup_rules": "", "url": "", "tunnel_ip": "", "egress": ""}
    inb = None
    try:
        try:
            inb = SS.build_second_inbound(panel, proto)
        except Exception as e:  # noqa: BLE001
            r["status"], r["detail"] = "SETUP-FAIL", str(e)[:160]
            return r
        email = inb.accounts["A"].email
        stale = hard_reset(client)
        if stale:
            r["detail"] = f"(stale ifaces before connect: {stale}) "
        time.sleep(25)  # let the protocol's daemon boot and the sweep reconcile

        ok, tip, clog = CONNECT[proto](client, inb)
        r["tunnel_ip"] = tip
        if not ok:
            r["status"] = "NO-CONNECT"
            r["detail"] += clog.strip().replace("\n", " ")[-200:]
            return r

        # Assert the traffic will actually leave through the tunnel. Without this a
        # half-up tunnel that never took the default route still downloads fine over the
        # physical NIC, and the account legitimately counts ~0 -- which would be reported
        # as "this protocol cannot count" when nothing ever reached the server.
        _, eg = client.sh("curl -s -m 25 https://ifconfig.me")
        egress = eg.strip().split("\n")[-1].strip()
        r["egress"] = egress
        if egress != SERVER:
            r["status"] = "NOT-TUNNELED"
            r["detail"] += f"egress {egress or 'none'} != server {SERVER}; tunnel ip {tip}"
            return r

        # Wait until this session's accounting rules are actually installed before starting
        # the clock. The control plane discovers a tunnel on its own sweep tick, so a
        # download that begins first has its opening seconds counted by nobody. That lands
        # as a ratio BELOW 1 and reads as under-counting when it is really a racy probe:
        # the fast-handshaking protocols (WireGuard) hit it, the slow-dialling ones never do.
        if proto not in RELAY_PROTOCOLS:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and not acct_rules(proto):
                time.sleep(3)
            if not acct_rules(proto):
                r["status"] = "NO-ACCOUNTING"
                r["detail"] += f"no nft accounting rule appeared for {proto} within 45s"
                return r

        u0, d0 = counted(email)
        base = u0 + d0
        got, src = pull(client)
        r["downloaded"], r["url"] = got, src
        if got < N_BYTES * 0.9:
            r["status"] = "NO-TRAFFIC"
            r["detail"] += f"only pulled {got}B through tunnel (ip {tip})"
            return r

        delta = settle(email, base)
        u1, d1 = counted(email)
        r["up"], r["down"] = u1 - u0, d1 - d0
        r["counted"] = delta
        r["ratio"] = delta / got if got else None
        rules = acct_rules(proto)
        r["dup_rules"] = f"{len(rules)} rule(s)"
        # Exactly one up + one down rule per connected account is the invariant the
        # duplicate-billing bug broke; more than two means it is counting a packet twice.
        if len(rules) > 2:
            r["dup_rules"] += " DUPLICATED"
        r["status"] = "OK"
    except Exception as e:  # noqa: BLE001
        r["status"], r["detail"] = "ERROR", str(e)[:160]
    finally:
        try:
            client.disconnect_all()
        except Exception:  # noqa: BLE001
            pass
        if inb is not None:
            try:
                panel.del_inbound(inb.inbound_id)
            except Exception:  # noqa: BLE001
                pass
        time.sleep(5)
    return r


def main() -> int:
    protos = sys.argv[1:] or ALL
    panel = Panel(PANEL_HOST, PANEL_PORT, "/", "https", PANEL_USER, PANEL_PASS)
    panel.login()
    incus = Incus("", logger=lambda *a: None)
    client = Client(incus, VM, "A", logger=lambda *a: None)
    ok, plog = client.prep()
    print(f"client prep: ok={ok}\n{plog}\n", flush=True)
    client.pin_server_route(SERVER)

    results = []
    for p in protos:
        print(f"=== {p} ===", flush=True)
        res = audit(panel, client, p)
        results.append(res)
        print(f"  {res['status']} downloaded={res['downloaded']:,} "
              f"counted={res['counted']:,} "
              f"ratio={('%.3f' % res['ratio']) if res['ratio'] else 'n/a'} "
              f"{res['dup_rules']} {res['detail']}", flush=True)

    print("\n==== SUMMARY ====")
    print(f"{'proto':<13}{'status':<12}{'downloaded':>13}{'counted':>13}{'ratio':>9}  rules")
    for r in results:
        ratio = f"{r['ratio']:.3f}x" if r["ratio"] else "-"
        print(f"{r['proto']:<13}{r['status']:<12}{r['downloaded']:>13,}"
              f"{r['counted']:>13,}{ratio:>9}  {r['dup_rules']} {r['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
