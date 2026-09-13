"""SSTP client connect/disconnect (sstp-client `sstpc` + pppd, MSCHAPv2 over TLS).

SSTP is PPP-over-HTTPS: `sstpc` opens a TLS session to the server on :443 and
launches pppd over it, producing a `ppp0` interface. The server cert is
self-signed, so `--cert-warn` accepts it (the openconnect `--no-cert-check`
analogue). There is NO MPPE — the TLS layer already encrypts — so the peers file
sets `noccp` (MPPE is negotiated inside CCP, which we disable). Mirrors
clients/pptp.py (peers file + pppd + wait_iface("ppp0") + pin_server_route + IP
detection) with the self-signed-cert acceptance of clients/openconnect.py.
"""
from __future__ import annotations

import time

from .base import Client

# pppd options sstpc feeds to pppd (via the trailing `file` argument). MSCHAPv2
# only (no PAP/EAP/plain-CHAP), no MPPE (noccp). `replacedefaultroute` forces the
# tunnel to become the default route — as pptp/l2tp do — so the egress/dns/internet
# checks actually traverse ppp0; `noipdefault` accepts the server-assigned peer
# address (the RADIUS Framed-IP the panel hands out).
_PEER = """require-mschap-v2
refuse-eap
refuse-pap
refuse-chap
refuse-mschap
noccp
noauth
noipdefault
usepeerdns
defaultroute
replacedefaultroute
lcp-echo-interval 15
lcp-echo-failure 8
"""


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up an SSTP tunnel. Returns (ok, tunnel_ip, log).

    Signature matches the protocols.py dispatch: connect(client, inbound, which,
    server_ip=...). The port is read from the inbound (443 for the primary, its
    own distinct port for a 2nd same-proto inbound)."""
    acct = inbound.accounts[which]
    port = inbound.udp_port or 443
    client.push(_PEER, "/etc/ppp/peers/sstp-vpn")
    client.sh("pkill sstpc 2>/dev/null; pkill pppd 2>/dev/null; "
              "mkdir -p /var/run/sstpc; rm -f /var/log/sstp.log; sleep 1; true")
    # Keep the server reachable via the physical NIC once ppp0 grabs the default
    # route, or the TLS/SSTP packets to <server>:<port> would loop into the tunnel.
    client.pin_server_route(server_ip)

    # sstpc opens the TLS session and launches pppd, passing our peers file as
    # additional pppd options (`file <path>`). --cert-warn accepts the self-signed
    # server cert; --log-stderr sends sstpc's own log to the redirected file.
    # setsid detaches it from the exec session so it survives once ppp0 is up.
    cmd = (
        f"setsid sstpc --cert-warn --log-stderr "
        f"--user '{acct.user}' --password '{acct.password}' "
        f"{server_ip}:{port} file /etc/ppp/peers/sstp-vpn "
        f"</dev/null >/var/log/sstp.log 2>&1 &"
    )
    client.sh(cmd)

    ip = client.wait_iface("ppp0", timeout=45)
    if ip:
        client.apply_tunnel_dns("ppp0")
    _, log = client.sh("cat /var/log/sstp.log 2>/dev/null | tail -n 40; "
                       "grep -i ppp /var/log/syslog 2>/dev/null | tail -n 20; "
                       "plog 2>/dev/null | tail -n 20")
    if not ip:
        return False, "", "sstp ppp0 never came up\n" + log
    return True, ip, log


def disconnect(client: Client):
    # Kill sstpc first (it owns the TLS session); pppd then tears its link down.
    client.sh("pkill sstpc 2>/dev/null; pkill pppd 2>/dev/null; true")
    time.sleep(2)
