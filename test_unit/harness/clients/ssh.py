"""SSH client driver: turn the in-binary Go SSH RELAY into a full system tunnel.

SSH is not a tunnel protocol at the wire level: the panel runs an x/crypto/ssh server
that accepts a password-authenticated connection and forwards each `direct-tcpip`
channel through Xray (per-client routing keyed on the account email = the socks
username). There is no ppp0/tun0 and no server-assigned address. To make it run the
SAME shared check suite as the tunnel protocols, this driver builds a client-side
tunnel:

  1. `ssh -N -D 127.0.0.1:1080 ...` (sshpass for the password) -> a dynamic SOCKS5 proxy
     whose every connection becomes an SSH direct-tcpip channel forwarded through Xray.
  2. `badvpn-tun2socks` on a `tun0` device -> pushes ALL of the VM's traffic into that
     SOCKS proxy (TCP natively; UDP via the badvpn-udpgw protocol pointed at the virtual
     endpoint 127.0.0.1:7300, which the SSH server terminates in-process and relays as
     SOCKS UDP-ASSOCIATE). So both TCP and UDP egress through the SSH server -> Xray.
  3. split-default routes (0.0.0.0/1 + 128.0.0.0/1) via tun0, with the server /32 pinned
     off-tunnel (via the original gateway) so the SSH control connection itself does not
     loop. DNS is pointed at the pushed resolver on tun0 (apply_tunnel_dns), so name
     lookups traverse the udpgw UDP path and dns-leak is testable.

The interface is named `tun0` on purpose: checks.tunnel_egress and checks.dns_leak
already accept tun0 (alongside ppp0/wgc), so ikev2's ppp0 trick has an exact ssh twin
with ZERO changes to checks.py.

RETURNED tunnel_ip: the tun device's own client-side address, made distinct per client
VM (10.55.<A|B|C=0|1|2>.2) so the multi-user-total / user-limit distinctness checks (which
assert a different address per simultaneous device) have something to compare. The panel
assigns no address, so this is purely a client-side label; the per-client ROUTING test
proves a different EGRESS public IP per account (Xray routes by socks username=email),
not a server tunnel IP.

`ok` is True once the SOCKS proxy is established AND tun0 is up: deliberately NOT gated on
internet, because the blackhole-routed account B must come up as a working tunnel yet
reach nothing (that contrast is exactly what the routing check reads). A device the SSH
server refuses (User-Limit reject, or a disabled/over-quota account) never gets a live
SOCKS proxy -> ok=False, which is what account-termination / strategy-reject need to see.
"""
from __future__ import annotations

import os
import time

from .base import Client

# Bundled static badvpn-tun2socks the harness pushes to each client. The `badvpn` apt
# package was dropped from recent Ubuntu (not in 26.04 universe), so it cannot be
# apt-installed; instead a static-musl build (via alpine docker/incus) lives beside the
# vpn-ui binary in test_subject/ and is pushed to /usr/local/bin on first connect.
_BADVPN_LOCAL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "test_subject", "badvpn-tun2socks")
_BADVPN_REMOTE = "/usr/local/bin/badvpn-tun2socks"

# Local dynamic-SOCKS port the ssh client opens and tun2socks dials.
SOCKS_PORT = 1080
# The udpgw virtual endpoint the SSH server intercepts (const sshUdpgwPort server-side).
# tun2socks reaches it THROUGH the SOCKS proxy; the server bridges it to SOCKS UDP.
UDPGW_ENDPOINT = "127.0.0.1:7300"
IFACE = "tun0"

# Distinct client-side tun subnet per client VM so simultaneous devices on ONE account
# (multi-user-total / user-limit) present distinct tunnel_ip values. A->0, B->1, C->2.
_LABEL_OCTET = {"A": 0, "B": 1, "C": 2}


def _net(label: str):
    """(device_ip, gateway_ip) for this client VM's tun. device_ip is returned as the
    tunnel_ip; gateway_ip is tun2socks's virtual router address (the route next-hop)."""
    o = _LABEL_OCTET.get(label, 0)
    return f"10.55.{o}.2", f"10.55.{o}.1"


def _ensure_badvpn(client: Client):
    """Push the bundled static badvpn-tun2socks to the client if absent (idempotent).
    `badvpn` is no longer an apt package on recent Ubuntu, so it cannot be installed the
    way sshpass is; the harness ships a static-musl build and pushes it here. No-op if
    it is already present, or if the local binary is missing (then _tools_present reports
    the gap loudly)."""
    _, out = client.sh("command -v badvpn-tun2socks >/dev/null 2>&1 && echo HAVE || echo MISSING")
    if "HAVE" in out:
        return
    if not os.path.isfile(_BADVPN_LOCAL):
        return
    try:
        client.incus.push(client.vm, _BADVPN_LOCAL, _BADVPN_REMOTE, mode="0755")
    except Exception:  # noqa: BLE001
        pass


def _tools_present(client: Client) -> tuple[bool, str]:
    """Both client tools must exist: sshpass (apt) and badvpn-tun2socks (pushed by
    _ensure_badvpn). A missing one is a loud failure, not a silent skip, so a broken
    image or a missing bundled binary is obvious in the report."""
    rc, out = client.sh(
        "command -v sshpass >/dev/null 2>&1 && command -v badvpn-tun2socks >/dev/null 2>&1 "
        "&& echo TOOLSOK || echo TOOLSMISSING")
    if "TOOLSOK" in out:
        return True, ""
    _, which = client.sh("command -v sshpass; command -v badvpn-tun2socks; true")
    return False, ("client VM lacks sshpass (apt) and/or badvpn-tun2socks (pushed from "
                   f"test_subject/badvpn-tun2socks); have:\n{which}")


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up the SSH-relay system tunnel for account A/B. Returns (ok, tunnel_ip, log).

    Signature matches the protocols.py dispatch: connect(client, inbound, which,
    server_ip=...). The SSH server listens on inbound.udp_port (a TCP listener; the field
    is a port label, reused so multi-inbound's `.udp_port` reads work)."""
    acct = inbound.accounts[which]
    port = inbound.udp_port or 2222
    dev_ip, gw_ip = _net(client.label)
    log = []

    _ensure_badvpn(client)
    ok, why = _tools_present(client)
    if not ok:
        return False, "", why

    # Clean slate: kill a prior ssh/tun2socks and drop a stale tun0.
    _kill(client)
    client.pin_server_route(server_ip)   # keep the SSH control connection off-tunnel

    # 1. dynamic-SOCKS ssh (sshpass for non-interactive password auth). -N (no shell,
    #    lockdown-friendly), ExitOnForwardFailure so a refused forward exits rather than
    #    hangs, keepalives so an evicted/torn session is noticed.
    #    setsid + `&` so it survives the incus-exec shell exiting: `incus.exec` is a
    #    blocking call whose process group is reaped when it returns, and nohup (SIGHUP
    #    only) is NOT enough to save a backgrounded child from that reap, so the SOCKS
    #    proxy died the instant connect() returned. setsid puts it in its own session,
    #    the exact trick clients/ikev2.py uses for charon. Placing setsid BEFORE sshpass
    #    (not `sshpass setsid ssh`) is what keeps password auth working: sshpass sets up
    #    ssh's controlling pty INSIDE the new session, so the password still reaches ssh.
    #    In a non-interactive `sh -c` (job control off) setsid does not fork, so $! is
    #    sshpass's PID, which lives exactly as long as its ssh child (sshpass waits on
    #    ssh), a faithful liveness handle.
    ssh_cmd = (
        f"setsid sshpass -p {_shq(acct.password)} ssh -N "
        f"-D 127.0.0.1:{SOCKS_PORT} "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 "
        "-o ConnectTimeout=15 "
        f"-p {port} {_shq(acct.user)}@{server_ip} "
        ">/var/log/ssh-vpn.log 2>&1 & echo $! >/run/ssh-vpn.pid; true"
    )
    client.sh(ssh_cmd)

    # 2. wait for the SOCKS proxy to be listening: proof the SSH transport + auth are up
    #    (a refused/limited account never gets here). Poll ss for 127.0.0.1:<SOCKS_PORT>.
    socks_up = False
    for _ in range(12):
        rc, out = client.sh(
            f"ss -ltnH 'sport = :{SOCKS_PORT}' 2>/dev/null | grep -q . && echo UP || echo DOWN")
        if "UP" in out:
            socks_up = True
            break
        # if ssh already died there is no point waiting the full window
        _, alive = client.sh("kill -0 $(cat /run/ssh-vpn.pid 2>/dev/null) 2>/dev/null "
                             "&& echo ALIVE || echo DEAD")
        if "DEAD" in alive:
            break
        time.sleep(2)
    _, ssh_log = client.sh("tail -n 25 /var/log/ssh-vpn.log 2>/dev/null")
    log.append("== ssh -D ==\n" + ssh_log)
    if not socks_up:
        return False, "", ("ssh dynamic-SOCKS proxy never came up (auth refused, or the "
                           f"server rejected the session)\n" + "\n".join(log))

    # 3. tun2socks on tun0: TCP + UDP (udpgw) through the SOCKS proxy. Pre-create the tun
    #    (tun2socks opens an EXISTING device; it does not create one) so the device name is
    #    deterministic, then tun2socks NATs it into SOCKS.
    client.sh(
        f"ip tuntap add dev {IFACE} mode tun 2>/dev/null; "
        f"ip addr flush dev {IFACE} 2>/dev/null; "
        f"ip addr add {dev_ip}/24 dev {IFACE}; ip link set {IFACE} up")
    t2s_cmd = (
        f"setsid badvpn-tun2socks --tundev {IFACE} --netif-ipaddr {gw_ip} "
        f"--netif-netmask 255.255.255.0 --socks-server-addr 127.0.0.1:{SOCKS_PORT} "
        f"--udpgw-remote-server-addr {UDPGW_ENDPOINT} --udpgw-transparent-dns "
        ">/var/log/tun2socks.log 2>&1 & echo $! >/run/tun2socks.pid; true"
    )
    client.sh(t2s_cmd)

    # tun2socks LIVENESS, not just the interface: the tun already has its IP from the
    # pre-assign above, so wait_iface would read "up" even if tun2socks crashed (e.g. an
    # older badvpn build that lacks --udpgw-transparent-dns). Check the process is still
    # alive so that failure surfaces here with its log, not later as a mystery "no
    # internet". Poll briefly since tun2socks either binds fast or exits fast.
    t2s_alive = False
    for _ in range(6):
        time.sleep(1)
        _, av = client.sh("kill -0 $(cat /run/tun2socks.pid 2>/dev/null) 2>/dev/null "
                          "&& echo ALIVE || echo DEAD")
        if "ALIVE" in av:
            t2s_alive = True
            break
    _, t2log = client.sh("tail -n 25 /var/log/tun2socks.log 2>/dev/null")
    tip = client.wait_iface(IFACE, timeout=10) if t2s_alive else ""
    if not t2s_alive or not tip:
        log.append("== tun2socks ==\n" + t2log)
        _kill(client)
        return False, "", (f"badvpn-tun2socks did not stay up on {IFACE} (account {which}; "
                           f"alive={t2s_alive}, iface_ip={tip!r}) - check the flags/build\n"
                           + "\n".join(log))

    # 4. route everything except the pinned server through tun0, and point DNS at the
    #    pushed resolver on tun0 (so lookups traverse the udpgw UDP path -> dns-leak
    #    testable). Split-default (openvpn's redirect-gateway def1 trick) leaves the
    #    physical default intact for the pinned server /32.
    client.sh(
        f"ip route replace 0.0.0.0/1 via {gw_ip} dev {IFACE}; "
        f"ip route replace 128.0.0.0/1 via {gw_ip} dev {IFACE}; true")
    client.apply_tunnel_dns(IFACE)

    # 5. warm the TPROXY->Xray path for the freedom-routed account (A) so the immediate
    #    per-variant dns-resolve / dns-leak checks don't race a cold data plane. Account B
    #    is blackholed and legitimately cannot resolve, so this is best-effort and never
    #    gates ok.
    warm = ""
    if which == "A":
        for _ in range(8):
            _, warm = client.sh(
                "getent hosts cloudflare.com >/dev/null 2>&1 && echo WARM || echo COLD")
            if "WARM" in warm:
                break
            time.sleep(2)

    # ok = the tunnel is established (SOCKS up + tun0 up). Deliberately NOT internet: B
    # comes up as a working tunnel yet reaches nothing (the routing contrast).
    _, alive = client.sh("kill -0 $(cat /run/ssh-vpn.pid 2>/dev/null) 2>/dev/null "
                         "&& echo ALIVE || echo DEAD")
    ok = "ALIVE" in alive
    _, rg = client.sh(f"ip route get 1.1.1.1 2>/dev/null | head -1")
    log.append(f"account={which} dev_ip={dev_ip} gw={gw_ip} port={port} "
               f"ssh_alive={'ALIVE' in alive} dns_warm={warm.strip()}\n"
               f"route get 1.1.1.1: {rg.strip()}")
    if not ok:
        _kill(client)
        return False, dev_ip, ("ssh session dropped right after tun2socks came up "
                               "(session refused post-auth?)\n" + "\n".join(log))
    return True, dev_ip, "\n".join(log)


def disconnect(client: Client):
    """Tear the client tunnel down: kill tun2socks + the ssh session, drop tun0 (which
    also drops its split-default routes, restoring the physical default) and the DNS."""
    _kill(client)
    time.sleep(1)


def _kill(client: Client):
    client.sh(
        # sshpass does NOT forward signals to its ssh child, so kill the child (pkill -P)
        # before sshpass itself; then tun2socks. All by saved PID (no pattern = no risk of
        # pkill matching this command's own shell).
        "pkill -P $(cat /run/ssh-vpn.pid 2>/dev/null) 2>/dev/null; "
        "kill $(cat /run/ssh-vpn.pid 2>/dev/null) 2>/dev/null; "
        "kill $(cat /run/tun2socks.pid 2>/dev/null) 2>/dev/null; "
        # orphan sweep for a leftover from a crashed prior run. The [x] brackets keep the
        # `pkill -f` pattern from matching the very shell that carries it (a real ssh/
        # tun2socks cmdline has no brackets, so it still matches those).
        f"pkill -f '[s]sh -N -D 127.0.0.1:{SOCKS_PORT}' 2>/dev/null; "
        "pkill -f '[b]advpn-tun2socks' 2>/dev/null; "
        f"ip link del {IFACE} 2>/dev/null; "
        "rm -f /run/tun2socks.pid /run/ssh-vpn.pid 2>/dev/null; true")


def _shq(s: str) -> str:
    """Single-quote a value for the shell (passwords/usernames may contain metachars)."""
    return "'" + str(s).replace("'", "'\\''") + "'"
