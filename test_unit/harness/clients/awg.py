"""AmneziaWG client connect/disconnect (in-kernel amneziawg via awg-quick).

Mirrors the wg-c driver (gateway model: ONE server-minted config per account whose Address
is the account's whole block CIDR; ok=True only after a real handshake completes) with three
differences:
  1. the `amneziawg` kernel module is NOT in-tree, so _ensure_awg() DKMS-builds it + the awg
     tools on the client on first use. Per the plan's OD4 the client is kernel-based too (no
     userspace amneziawg-go anywhere). The build is idempotent (fast no-op once present).
  2. the fetched config carries the AWG obfuscation params in [Interface] (rendered by the
     panel's awg-configs endpoint; the server device was configured with the SAME params).
  3. awg / awg-quick and /etc/amnezia/amneziawg/ replace wg / wg-quick and /etc/wireguard.
"""
from __future__ import annotations

import re
import time

from .base import Client

IFACE = "awg"
CONF = f"/etc/amnezia/amneziawg/{IFACE}.conf"

# Idempotently build + load the amneziawg kernel module and the awg userspace tools on the
# client. The leading check makes a warm client return immediately, so repeated connects are
# cheap; the first cold build takes a couple of minutes (apt + DKMS + tools).
_SETUP = r'''
set -e
if command -v awg-quick >/dev/null 2>&1 && { lsmod | grep -q '^amneziawg' || modprobe amneziawg 2>/dev/null; }; then
  echo AWG_READY; exit 0
fi
export DEBIAN_FRONTEND=noninteractive
LOG=/tmp/awg_client_setup.log
apt-get update -y >$LOG 2>&1 || true
apt-get install -y dkms build-essential linux-headers-$(uname -r) git make gcc >>$LOG 2>&1
cd /root; rm -rf awg-km awg-tools
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-linux-kernel-module awg-km >>$LOG 2>&1
cd awg-km/src
make dkms-install >>$LOG 2>&1
dkms add -m amneziawg -v 1.0.0 >>$LOG 2>&1 || true
dkms build -m amneziawg -v 1.0.0 >>$LOG 2>&1
dkms install -m amneziawg -v 1.0.0 >>$LOG 2>&1
modprobe amneziawg
cd /root; git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools awg-tools >>$LOG 2>&1
cd awg-tools/src && make >>$LOG 2>&1 && make install >>$LOG 2>&1
if command -v awg-quick >/dev/null 2>&1 && { lsmod | grep -q '^amneziawg' || modprobe amneziawg; }; then
  echo AWG_READY
else
  echo AWG_FAIL; tail -n 30 $LOG
fi
'''


def _ensure_awg(client: Client) -> tuple[bool, str]:
    """Build (once) the amneziawg module + tools on the client VM. Idempotent."""
    _, out = client.sh(_SETUP)
    return ("AWG_READY" in out), out


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up an AmneziaWG tunnel for account `which`. Returns (ok, tunnel_ip, log).
    ok is True only after a real handshake completes (a removed/disabled peer never
    handshakes, so quota/disable enforcement stays observable, exactly like wg-c)."""
    port = inbound.udp_port or 51821
    ready, setup_log = _ensure_awg(client)
    if not ready:
        return False, "", f"amneziawg module/tools build failed on client:\n{setup_log[-1500:]}"

    cfgs = (getattr(inbound, "wg_configs", {}) or {}).get(which, [])
    if not cfgs:
        return False, "", f"no amneziawg config for account {which} (key mint / fetch failed)"
    entry = cfgs[0]
    conf_text = entry.get("config", "")
    ip = (entry.get("ip", "") or "").split("/")[0]
    if not conf_text:
        return False, "", f"empty amneziawg config for account {which}"
    conf_text = re.sub(r"(?m)^Endpoint\s*=.*$", f"Endpoint = {server_ip}:{port}", conf_text)

    client.sh("mkdir -p /etc/amnezia/amneziawg")
    client.push(conf_text, CONF, mode="0600")
    client.sh(f"awg-quick down {IFACE} 2>/dev/null; ip link del {IFACE} 2>/dev/null; true")
    time.sleep(1)
    _, up_log = client.sh(f"awg-quick up {IFACE} 2>&1")

    tip = client.wait_iface(IFACE, timeout=20)
    if not tip:
        _, dbg = client.sh(f"awg show {IFACE} 2>&1; ip -o addr show {IFACE} 2>&1 | tail -n5")
        return False, "", (f"amneziawg {IFACE} never came up (account {which})\n{up_log}\n{dbg}")
    client.apply_tunnel_dns(IFACE)

    # Trigger + confirm a real handshake (AmneziaWG, like WireGuard, is lazy).
    handshook = False
    hs_log = ""
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        client.sh("curl -s --max-time 5 -o /dev/null https://1.1.1.1 2>/dev/null; "
                  "ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; true")
        _, hs_log = client.sh(f"awg show {IFACE} latest-handshakes 2>/dev/null")
        if _recent_handshake(hs_log):
            handshook = True
            break
        time.sleep(3)

    warm_log = ""
    if handshook and which == "A":
        for _ in range(8):
            _, warm_log = client.sh(
                "getent hosts cloudflare.com >/dev/null 2>&1 && echo WARM || echo COLD")
            if "WARM" in warm_log:
                break
            time.sleep(2)

    _, wglog = client.sh(f"awg show {IFACE} 2>&1 | head -n30")
    log = (f"account={which} ip={ip or tip} port={port}\n"
           f"{up_log}\nlatest-handshakes:\n{hs_log}\ndns-warm={warm_log.strip()}\n{wglog}")
    if not handshook:
        return False, ip or tip, "amneziawg handshake never completed (peer absent?)\n" + log
    return True, ip or tip, log


def _recent_handshake(latest_handshakes: str) -> bool:
    """`awg show <if> latest-handshakes` prints '<pubkey>\\t<unix_ts>' per peer; a
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
    client.sh(f"awg-quick down {IFACE} 2>/dev/null; ip link del {IFACE} 2>/dev/null; true")
    time.sleep(1)
