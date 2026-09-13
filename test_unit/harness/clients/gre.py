"""GRE client connect/disconnect (in-kernel ip_gre via iproute2).

GRE's client is a ROUTER, so this driver does what a router does: build a GRE netdev,
put the panel-assigned inner address on it, and route through it. There is no client
daemon, no key material and no credential of any kind, which makes this the simplest
driver in the harness. ip_gre is in-tree everywhere, so unlike the awg driver there is
nothing to build on the client.

Three modes are exercised, matching the three the panel offers:

  raw    plain protocol 47.
  ipsec  the same tunnel wrapped in ESP TRANSPORT mode, negotiated with the panel's
         shared charon over a PSK. strongSwan/swanctl are already installed on every
         client VM by base.prep(), so this only writes a conf and initiates.
  fou    GRE inside UDP, for peers behind a NAT that cannot pass protocol 47.

The panel demultiplexes peers two ways and BOTH are covered by the phase: account A is
given a static peer IP (so the server builds a point-to-point netdev for it) while
account B is left blank (so it is served by the shared catch-all netdev and its reverse
path is learned from its first packets). The kernel prefers an exact (local, remote)
match over the wildcard, so the two coexist without fighting.
"""
from __future__ import annotations

import re
import time

from .base import Client

IFACE = "gre-vpnui"
FOU_IFACE = "gre-fou"
SWAN_CONF = "/etc/swanctl/conf.d/gre-client.conf"


def lan_ip(client: Client) -> str:
    """The client's address on the test bridge: what the SERVER sees as this peer's
    public IP, and therefore what goes in the account's peer slot for the static path.
    Deliberately not base.orig_public_ip, which is the internet-facing address from a
    Cloudflare trace and is NOT the tunnel's outer source."""
    eth = client.eth or "enp5s0"
    _, out = client.sh(f"ip -4 -o addr show dev {eth} | awk '{{print $4}}' | head -n1")
    out = (out or "").strip()
    if "/" in out:
        return out.split("/")[0].strip()
    return out


def _teardown(client: Client):
    client.sh(
        f"ip link del {IFACE} 2>/dev/null; ip link del {FOU_IFACE} 2>/dev/null; "
        "swanctl --terminate --ike gre 2>/dev/null; "
        f"rm -f {SWAN_CONF} 2>/dev/null; swanctl --load-all 2>/dev/null; "
        "ip fou del port 15547 2>/dev/null; true")


def _pick(cfgs: list, client: Client, which: str) -> dict:
    """The peer slot this client VM should dial.

    Normally slot 0. But when a client OTHER than cA dials account A, the harness is
    opening a SECOND device on an account that is already up on cA (the user-limit check),
    and for GRE a second device is a second ROUTER: it must take the account's next peer
    slot, which has its own inner address. Reusing slot 0 would put two routers on one
    address, and the anti-spoof rule on cA's point-to-point device would drop the
    newcomer, which is exactly right but reads as an unexplained connect failure.
    """
    if not cfgs:
        return {}
    if client.label == "A":
        return cfgs[0]
    # Any OTHER client VM is a different router with a different public address, so it can
    # only be served by a slot that is NOT pinned to someone else's address. Prefer the
    # first dynamic slot; pinning it to slot 0 made the server's anti-spoof rule drop it
    # (correctly) and the test read that as an unexplained connect failure.
    for c in cfgs:
        if c.get("dynamic"):
            return c
    idx = 1 if client.label == "B" else 2
    return cfgs[idx] if idx < len(cfgs) else cfgs[0]


def _ipsec_up(client: Client, client_ip: str, server_ip: str, psk: str,
              server_id: str = "") -> tuple[bool, str]:
    """Negotiate an ESP transport-mode SA covering protocol 47 with the panel's charon."""
    # install_routes=no: we own routing here, and a charon-installed route would fight
    # the tunnel's default route. Same reason the panel sets it server-side.
    client.push(
        "charon {\n    install_routes = no\n    install_virtual_ip = no\n}\n",
        "/etc/strongswan.d/gre-client.conf", mode="0644")
    # The server presents a per-inbound identity and scopes its PSK to it, because an
    # id-less pre-shared key on a shared charon is ambiguous (see greIkeID in greipsec.go).
    # A peer that does not pin the remote id can end up verifying against another
    # protocol's key and fails with "MAC mismatched".
    remote_id = f"\n            id = {server_id}" if server_id else ""
    conf = f"""connections {{
    gre {{
        version = 0
        local_addrs = {client_ip}
        remote_addrs = {server_ip}
        local {{
            auth = psk
        }}
        remote {{
            auth = psk{remote_id}
        }}
        children {{
            gre {{
                mode = transport
                local_ts = {client_ip}/32[gre]
                remote_ts = {server_ip}/32[gre]
                esp_proposals = aes256gcm16,aes256-sha256,aes128-sha256,aes256-sha1,default
                start_action = none
            }}
        }}
    }}
}}
secrets {{
    ike-gre {{
        secret = "{psk}"
    }}
}}
"""
    client.sh("mkdir -p /etc/swanctl/conf.d")
    client.push(conf, SWAN_CONF, mode="0600")
    # Bring up a SWANCTL-MODE charon, mirroring clients/ikev2.py's _DAEMON_SETUP.
    #
    # Simply restarting `strongswan` is NOT enough, and fails in a way that looks like
    # success: on Ubuntu that unit is the legacy starter/stroke charon, which DOES load the
    # vici plugin, so `swanctl --load-all` happily reports "loaded connection", yet the SA
    # it then initiates never gets a socket (list-sas shows local port 0) and the exchange
    # times out with the responder never answering. So stop the starter and kill any running
    # charon FIRST, then start the swanctl-mode daemon and wait for its vici socket.
    _, daemon = client.sh(
        "ipsec stop 2>/dev/null; systemctl stop strongswan-starter 2>/dev/null; "
        "pkill -x charon 2>/dev/null; pkill -x charon-systemd 2>/dev/null; sleep 1; "
        "systemctl restart strongswan 2>/dev/null "
        "|| systemctl restart strongswan-swanctl 2>/dev/null || true; sleep 2; "
        "if ! swanctl --stats >/dev/null 2>&1; then "
        "  CH=\"$(command -v charon-systemd 2>/dev/null || ls /usr/libexec/ipsec/charon-systemd "
        "/usr/lib/ipsec/charon-systemd /usr/lib/strongswan/charon-systemd 2>/dev/null | head -n1)\"; "
        "  [ -n \"$CH\" ] && setsid \"$CH\" >/var/log/gre-charon.log 2>&1 & "
        "  sleep 3; "
        "fi; swanctl --stats 2>&1 | head -5")
    _, load = client.sh("swanctl --load-all 2>&1")
    _, init = client.sh("swanctl --initiate --child gre 2>&1")
    ok = False
    sas = ""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        _, sas = client.sh("swanctl --list-sas 2>&1")
        if "INSTALLED" in sas:
            ok = True
            break
        time.sleep(3)
    return ok, (f"daemon:\n{daemon}\nswanctl --load-all:\n{load}\n"
            f"initiate:\n{init}\nlist-sas:\n{sas}")


def connect(client: Client, inbound, which: str, server_ip: str = "",
            mode: str = "raw") -> tuple[bool, str, str]:
    """Bring up a GRE tunnel for account `which`. Returns (ok, tunnel_ip, log).

    ok is True only after the tunnel actually carries traffic to the server's inner
    gateway. That matters more here than for the other protocols: GRE has no handshake,
    so a misconfigured or revoked account produces a netdev that comes up perfectly and
    passes nothing. Pinging the gateway is the only real liveness proof.
    """
    cfgs = (getattr(inbound, "gre_configs", {}) or {}).get(which, [])
    entry = _pick(cfgs, client, which)
    if not entry:
        return False, "", f"no GRE peer config for account {which} (fetch failed?)"

    inner = (entry.get("innerIp") or "").strip()
    gw = (entry.get("gatewayIp") or "").strip()
    srv = server_ip or (entry.get("serverIp") or "").strip()
    psk = (entry.get("ipsecPsk") or "").strip()
    fou_port = int(entry.get("fouPort") or 0)
    if not inner or not gw or not srv:
        return False, "", (f"incomplete GRE peer config for {which}: "
                           f"inner={inner!r} gw={gw!r} server={srv!r}")

    my_ip = lan_ip(client)
    _teardown(client)
    client.sh("modprobe ip_gre 2>/dev/null; true")

    logs = [f"account={which} mode={mode} inner={inner} gw={gw} server={srv} local={my_ip}"]

    if mode == "ipsec":
        if not psk:
            return False, "", "ipsec mode requested but the panel returned no PSK"
        ok, ipsec_log = _ipsec_up(client, my_ip, srv, psk,
                                  server_id=(entry.get("ipsecId") or "").strip())
        logs.append(ipsec_log)
        if not ok:
            return False, "", "IPsec SA never reached INSTALLED\n" + "\n".join(logs)

    dev = IFACE
    if mode == "fou":
        if fou_port <= 0:
            fou_port = 15547
        dev = FOU_IFACE
        client.sh("modprobe fou 2>/dev/null; true")
        client.sh(f"ip fou add port {fou_port} ipproto 47 2>/dev/null; true")
        add = (f"ip link add {dev} type gre local {my_ip} remote {srv} ttl 64 "
               f"encap fou encap-sport auto encap-dport {fou_port}")
    else:
        add = f"ip link add {dev} type gre local {my_ip} remote {srv} ttl 64"

    # The server must stay reachable via the physical NIC before the tunnel takes the
    # default route, or the tunnel's own outer packets would try to route through it.
    client.pin_server_route(srv)
    _, add_log = client.sh(
        f"{add} 2>&1 && "
        f"ip addr add {inner}/32 dev {dev} 2>&1; "
        f"ip link set {dev} up 2>&1; "
        f"ip route replace {gw}/32 dev {dev} 2>&1; "
        f"ip route replace default dev {dev} 2>&1; true")
    logs.append(add_log)

    tip = client.wait_iface(dev, timeout=20)
    if not tip:
        _, dbg = client.sh(f"ip -d link show {dev} 2>&1; ip -o addr show {dev} 2>&1")
        return False, "", f"GRE {dev} never came up (account {which})\n" + "\n".join(logs + [dbg])
    client.apply_tunnel_dns(dev)

    # Real liveness: reach the server's inner gateway through the tunnel. For a dynamic
    # peer this is also what TRIGGERS the server-side learner, so it is retried: the
    # first packets are what teach the server where to send the reply, and the learner
    # samples in windows rather than continuously.
    alive = False
    ping_log = ""
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        okp, ping_log = client.ping(gw, count=2, timeout=12)
        if okp:
            alive = True
            break
        time.sleep(4)
    logs.append(f"gateway-ping:\n{ping_log}")

    if not alive:
        _, dbg = client.sh(f"ip -d link show {dev}; ip route show; ip neigh show dev {dev} 2>&1")
        return False, inner, ("GRE tunnel up but the inner gateway never answered "
                              "(peer not plumbed / learner never bound?)\n"
                              + "\n".join(logs + [dbg]))

    # Warm DNS through the tunnel the same way the wg drivers do, so the shared check
    # suite does not race a cold resolver.
    warm = ""
    for _ in range(8):
        _, warm = client.sh("getent hosts cloudflare.com >/dev/null 2>&1 && echo WARM || echo COLD")
        if "WARM" in warm:
            break
        time.sleep(2)
    logs.append(f"dns-warm={warm.strip()}")
    return True, inner, "\n".join(logs)


def disconnect(client: Client):
    _teardown(client)
    time.sleep(1)
