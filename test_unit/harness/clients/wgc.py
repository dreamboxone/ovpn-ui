"""WireGuard (C) client connect/disconnect (in-kernel wireguard via wg-quick).

Gateway model: the panel generates ONE keypair per account server-side, whose config
Address is the account's whole block CIDR (e.g. 10.7.8.8/29). The harness fetches that
single config via the wgc-configs endpoint and stores it on the Inbound as
wg_configs[which] = [ {ip(block CIDR), publicKey, config} ]. connect() uses the account's
one config, rewrites the Endpoint to <server_ip>:<port>, brings it up with wg-quick, and
CONFIRMS a real handshake.

Confirming the handshake is what makes disable/quota enforcement observable: a removed
peer (disabled or over-quota account) can never complete a WireGuard handshake, so
connect() returns ok=False even though wg-quick brought the interface up locally. That
is exactly what the account-termination test needs to see ("can no longer use the VPN").
"""
from __future__ import annotations

import re
import time

from .base import Client

IFACE = "wgc"
CONF = f"/etc/wireguard/{IFACE}.conf"
def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up a WireGuard tunnel for account `which`. Returns (ok, tunnel_ip, log).
    Gateway model: ONE config per account (its Address is the account's whole block CIDR,
    e.g. 10.7.8.8/29). ok is True only after a real handshake completes."""
    port = inbound.udp_port or 51820
    cfgs = (getattr(inbound, "wg_configs", {}) or {}).get(which, [])
    if not cfgs:
        return False, "", f"no wireguard config for account {which} (key mint / fetch failed)"
    entry = cfgs[0]
    conf_text = entry.get("config", "")
    # entry ip is the account's block CIDR; the tunnel IP is the block's first host address.
    ip = (entry.get("ip", "") or "").split("/")[0]
    if not conf_text:
        return False, "", f"empty wireguard config for account {which}"
    # Force the Endpoint to the reachable server IP:port (the panel renders it from the
    # request Host, which in some setups is not the data-plane address).
    conf_text = re.sub(r"(?m)^Endpoint\s*=.*$", f"Endpoint = {server_ip}:{port}", conf_text)

    client.push(conf_text, CONF, mode="0600")
    client.sh(f"wg-quick down {IFACE} 2>/dev/null; ip link del {IFACE} 2>/dev/null; true")
    time.sleep(1)
    _, up_log = client.sh(f"wg-quick up {IFACE} 2>&1")

    tip = client.wait_iface(IFACE, timeout=20)
    if not tip:
        _, dbg = client.sh(f"wg show {IFACE} 2>&1; ip -o addr show {IFACE} 2>&1 | tail -n5")
        return False, "", (f"wireguard {IFACE} never came up (account {which})\n{up_log}\n{dbg}")
    client.apply_tunnel_dns(IFACE)

    # Trigger + confirm a real handshake. WireGuard is lazy (a handshake is initiated by
    # the first outbound packet), so push a little traffic, then poll latest-handshakes.
    # A removed peer NEVER handshakes -> ok=False (hard-enforcement observation).
    handshook = False
    hs_log = ""
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        client.sh("curl -s --max-time 5 -o /dev/null https://1.1.1.1 2>/dev/null; "
                  "ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; true")
        _, hs_log = client.sh(f"wg show {IFACE} latest-handshakes 2>/dev/null")
        if _recent_handshake(hs_log):
            handshook = True
            break
        time.sleep(3)

    # Warm the TPROXY->Xray data path (incl. DNS) for the freedom-routed account so the
    # immediate per-variant dns-resolve / dns-leak checks don't race the cold path (a fast
    # WireGuard handshake returns before the first UDP DNS query has warmed the path). The
    # blackhole account (B) legitimately can't resolve, so this is best-effort and never
    # gates ok (which reflects the handshake). Only account "A" runs the DNS checks.
    warm_log = ""
    if handshook and which == "A":
        for _ in range(8):
            _, warm_log = client.sh(
                "getent hosts cloudflare.com >/dev/null 2>&1 && echo WARM || echo COLD")
            if "WARM" in warm_log:
                break
            time.sleep(2)

    _, wglog = client.sh(f"wg show {IFACE} 2>&1 | head -n30")
    log = (f"account={which} ip={ip or tip} port={port}\n"
           f"{up_log}\nlatest-handshakes:\n{hs_log}\ndns-warm={warm_log.strip()}\n{wglog}")
    if not handshook:
        return False, ip or tip, "wireguard handshake never completed (peer absent?)\n" + log
    return True, ip or tip, log


def _recent_handshake(latest_handshakes: str) -> bool:
    """`wg show <if> latest-handshakes` prints '<pubkey>\\t<unix_ts>' per peer; a
    non-zero timestamp means at least one handshake has completed."""
    for line in (latest_handshakes or "").strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 2:
            try:
                if int(parts[1].strip()) > 0:
                    return True
            except ValueError:
                pass
    return False


def disconnect(client: Client):
    client.sh(f"wg-quick down {IFACE} 2>/dev/null; ip link del {IFACE} 2>/dev/null; true")
    time.sleep(1)
