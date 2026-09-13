"""OpenConnect (ocserv) client connect/disconnect via the `openconnect` CLI.

Authenticates with the account's username/password (RADIUS PAP on the server).
The server cert is self-signed, so --no-cert-check. A single listener carries
both TLS (TCP) and DTLS (UDP) on the inbound port; the "tls" variant forces the
TLS data channel with --no-dtls, "dtls" leaves DTLS on (the default/fast path).
"""
from __future__ import annotations

import time

from .base import Client


def connect(client: Client, inbound, which: str, variant: str = "dtls",
            server_ip: str = "", iface: str = "tun0",
            keep_existing: bool = False) -> tuple[bool, str, str]:
    """Bring up an OpenConnect tunnel for account A/B. Returns (ok, tunnel_ip, log).

    iface/keep_existing let a SECOND tunnel run from the same VM (a distinct tun +
    pid/log, without killing the first) so a single client can present two devices
    on one account behind ONE source IP — the same-NAT case ocserv can't tell apart
    (no NAS-Port). tun0 keeps its original pid/log paths for the normal flow."""
    acct = inbound.accounts[which]
    port = inbound.udp_port
    if server_ip:
        client.pin_server_route(server_ip)

    pid = "/run/oc.pid" if iface == "tun0" else f"/run/oc-{iface}.pid"
    logf = "/var/log/oc.log" if iface == "tun0" else f"/var/log/oc-{iface}.log"
    no_dtls = "--no-dtls " if variant == "tls" else ""
    if keep_existing:
        client.sh(f"rm -f {logf} {pid}; true")
    else:
        client.sh("pkill -f openconnect 2>/dev/null; rm -f /var/log/oc*.log /run/oc*.pid; true")
    # The server cert is self-signed and modern openconnect removed --no-cert-check,
    # so pin it. openconnect's native pin is pin-sha256:<base64> — the RFC7469
    # SHA-256 of the cert's SubjectPublicKeyInfo (NOT the cert-DER hash). Compute
    # that from the leaf cert over TLS. (Fall back to --no-cert-check for old
    # openconnect builds that still accept it.)
    _, fp = client.sh(
        f"echo | timeout 10 openssl s_client -connect {server_ip}:{port} 2>/dev/null | "
        "openssl x509 -pubkey -noout 2>/dev/null | "
        "openssl pkey -pubin -outform der 2>/dev/null | "
        "openssl dgst -sha256 -binary | openssl base64"
    )
    fp = fp.strip()
    trust = f"--servercert pin-sha256:{fp} " if fp else "--no-cert-check "
    # --interface pins the device name so wait_iface(iface) matches. openconnect
    # runs its bundled vpnc-script to configure the tunnel; --passwd-on-stdin feeds the
    # RADIUS password. --background daemonizes after the tunnel is up.
    cmd = (
        f"echo '{acct.password}' | openconnect --protocol=anyconnect "
        f"--user={acct.user} --passwd-on-stdin {trust}{no_dtls}"
        f"--interface={iface} --background --pid-file={pid} "
        f"{server_ip}:{port} >{logf} 2>&1"
    )
    client.sh(cmd)

    ip = client.wait_iface(iface, timeout=45)
    if ip:
        client.apply_tunnel_dns(iface)
    _, log = client.sh(f"cat {logf} 2>/dev/null | tail -n 40")
    if not ip:
        return False, "", f"{iface} never came up ({variant})\n{log}"
    time.sleep(2)
    _, log = client.sh(f"cat {logf} 2>/dev/null | tail -n 40")
    return True, ip, log


def disconnect(client: Client):
    client.sh("kill $(cat /run/oc.pid 2>/dev/null) 2>/dev/null; "
              "pkill -f openconnect 2>/dev/null; true")
    time.sleep(2)
