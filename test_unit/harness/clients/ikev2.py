"""IKEv2/IPsec client (strongSwan `charon` + `swanctl`) — eap-mschapv2 / psk / eap-tls.

The vpn-ui server runs ONE shared strongSwan charon on UDP 500/4500 serving every
ikev2 inbound. The CLIENT here is strongSwan too, driven via swanctl (the modern
VICI/charon-systemd interface, not the legacy `ipsec` stroke one used by
clients/l2tp.py's IPsec mode). connect() picks the auth blocks from inbound.auth_mode:

  - eap-mschapv2 (default): server-authoritative — charon's eap-radius plugin forwards
    the EAP-MSCHAPv2 exchange to the panel's in-process RADIUS, which returns the
    account's Framed-IP in its 10.6.<id>.<host> block. Client auths by username
    (eap_id) + password (secrets); server auth = pubkey against the trusted CA.
  - psk: a shared pre-shared key (inbound.psk); both ends auth = psk. charon leases the
    tunnel IP from a whole-block local pool; a reconcile sweep bills + limits it.
  - eap-tls: mutual certificate — the client presents client.pem (validated server-side
    against the inbound CA) and validates the server leaf against that same CA. Same
    local-pool + reconcile path as psk.

WHY A ROUTED (XFRM-INTERFACE) TUNNEL, NAMED ppp0
------------------------------------------------
The shared check suite keys on a tunnel *interface*: checks.tunnel_egress asserts
`ip route get 1.1.1.1` egresses `dev tun0|ppp0`, checks.dns_leak inspects tun0/ppp0,
and protocols._strategy_check / _iface_up watch `"tun0" if openvpn/openconnect else
"ppp0"`. A classic policy-based strongSwan road-warrior has NO interface (traffic
leaves the physical NIC, merely ESP-encrypted) — so `ip route get` would show the
physical dev and tunnel_egress would FAIL.

So we build a ROUTE-BASED tunnel with an XFRM interface and NAME it `ppp0`, exactly
so ikev2 flows through every shared check on the same `ppp0` path as sstp — with ZERO
changes to checks.py / _strategy_check. The child SA is bound to the interface by a
matching `if_id` (0x2a) on both the `ip link ... type xfrm if_id` and the swanctl
child (`if_id_in/out`); packets routed out ppp0 acquire that mark, match the ESP OUT
policy, and are encrypted. We then split-default 0.0.0.0/1 + 128.0.0.0/1 via ppp0
(the openvpn `redirect-gateway def1` trick) so external traffic resolves to `dev ppp0`
while the pinned server /32 keeps IKE/ESP flowing off-tunnel.

SERVER-CA TRUST
---------------
The server presents a self-signed leaf; the client must trust the CA that signed it.
server_setup captured that CA (the `caCert` from POST /generate-ikev2-cert) onto the
Inbound. We write it into swanctl's CA dir `/etc/swanctl/x509ca/vpn-ui-ca-<id>.pem`
and `swanctl --load-all` (which runs --load-creds, loading x509ca/) trusts it. We use a
PER-INBOUND filename and NEVER flush the dir, so across the multi-inbound test the dir
ACCUMULATES every inbound's CA — the one shared charon may present any inbound's leaf,
and the client validates it as long as SOME loaded CA signed it. The server leaf's SAN
is the server IP (serverAddr left empty in setup), so `remote { id = <server_ip> }`
matches whichever leaf is presented.

TUNNEL + ASSIGNED-IP DETECTION
------------------------------
After `swanctl --initiate --child tunnel`, the assigned virtual IP is the child SA's
narrowed local traffic selector — `swanctl --list-sas` prints `local-ts:  10.6.x.y/32`
(remote-ts is 0.0.0.0/0). We parse the first non-0.0.0.0, non-bridge 10.x from a
`local-ts:` line. We do NOT let strongSwan install the vip or routes itself
(`install_virtual_ip = no`, `install_routes = no` in the strongswan.conf drop-in) — we
assign the parsed vip to ppp0 and add the split-default routes ourselves, so the
kernel routing is fully deterministic. `wait_iface("ppp0")` then reads that same vip.

UNCERTAIN / LIVE-DEBUG POINTS (documented for the operator):
  1. swanctl daemon unit name: we try `systemctl restart strongswan` then
     `strongswan-swanctl`, else run `charon-systemd` directly. swanctl talks to
     WHICHEVER charon is up via the VICI socket (both the starter-charon and
     charon-systemd load the vici plugin), so any of these should serve --load-all.
  2. XFRM `if_id` base: we use `0x2a` on BOTH `ip link` and swanctl so there is no
     dec/hex mismatch. If a kernel/iproute2 rejects `type xfrm`, the tunnel comes up
     but egress won't route via ppp0 (tunnel_egress FAIL) — that's the first thing to
     check live.
  3. local-ts narrowing: relies on `local_ts` defaulting to `dynamic` (omitted) so the
     vip narrows it to /32. If a strongSwan build keeps local-ts 0.0.0.0/0, _parse_vip
     finds no 10.x and connect() reports the tunnel never got a virtual IP.
  4. strategy-accept eviction is detected server-side (RADIUS "evicted oldest device
     proto=ikev2" log) — the client-side ppp0 drop is not observed because the xfrm
     interface + vip persist after the SA is torn down (harmless; the check OR's the
     server signal, mirroring sstp).
"""
from __future__ import annotations

import re
import time

from .base import Client

# The XFRM if_id linking the ppp0 interface to the swanctl child SA policies. Written
# as hex on BOTH sides so there's no decimal/hex parse ambiguity between iproute2 and
# swanctl. IFACE is named ppp0 on purpose (see module docstring).
IF_ID = "0x2a"   # = 42
IFACE = "ppp0"

# The swanctl connection the client loads. The connection SHELL (version, remote,
# vips, proposals, dpd, if_id-bound child) is identical across auth modes; only the
# local/remote auth blocks + the secrets block differ, so those are injected via
# @@LOCAL@@ / @@REMOTE@@ / @@SECRETS@@ from _auth_blocks() (3-way on inbound.auth_mode:
# eap-mschapv2 / psk / eap-tls). `vips = 0.0.0.0` requests an IPv4 virtual IP;
# `local_ts` is OMITTED (=> dynamic) so it narrows to the assigned vip; if_id binds
# the child to ppp0.
_CONN_TMPL = """connections {
    ikev2-vpn {
        version = 2
        remote_addrs = @@SERVER@@
        vips = 0.0.0.0
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha256-ecp256,default
        dpd_delay = 30s
@@LOCAL@@
@@REMOTE@@
        children {
            tunnel {
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256,aes128-sha256,aes256gcm16,default
                if_id_in = @@IFID@@
                if_id_out = @@IFID@@
                dpd_action = clear
                start_action = none
            }
        }
    }
}
@@SECRETS@@
"""


def _auth_blocks(inbound, acct, remote_id):
    """Return (local_block, remote_block, secrets_block, pushes) for the inbound's auth
    mode. `pushes` is a list of (content, path, mode) files to write on the client VM
    before charon (re)loads creds (client cert/key + server CA for eap-tls; the server
    CA alone for eap-mschapv2; nothing for psk). Indentation matches _CONN_TMPL."""
    mode = getattr(inbound, "auth_mode", "eap-mschapv2") or "eap-mschapv2"
    ca = getattr(inbound, "ca_cert", "") or ""
    remote_pubkey = (
        "        remote {\n"
        "            auth = pubkey\n"
        f"            id = {remote_id}\n"
        "        }"
    )

    if mode == "psk":
        # Shared pre-shared key. Both ends auth = psk; the client's secret is keyed to
        # the server identity (its IP), matching the server's id-less secrets entry.
        psk = getattr(inbound, "psk", "") or ""
        local = "        local {\n            auth = psk\n        }"
        remote = (
            "        remote {\n"
            "            auth = psk\n"
            f"            id = {remote_id}\n"
            "        }"
        )
        secrets = (
            "secrets {\n"
            f'    ike-vpn {{\n        secret = "{psk}"\n    }}\n'
            "}"
        )
        return local, remote, secrets, []

    if mode == "eap-tls":
        # Mutual certificate: the client presents client.pem (validated server-side
        # against the inbound CA), the server presents a pubkey leaf (validated here
        # against that same CA in x509ca). No shared secret.
        cid = getattr(inbound, "client_id", "") or acct.user
        local = (
            "        local {\n"
            "            auth = eap-tls\n"
            "            certs = client.pem\n"
            f"            id = {cid}\n"
            "        }"
        )
        pushes = [
            (getattr(inbound, "client_cert", "") or "", "/etc/swanctl/x509/client.pem", "0644"),
            (getattr(inbound, "client_key", "") or "", "/etc/swanctl/private/client.key", "0600"),
        ]
        if ca:
            pushes.append((ca, f"/etc/swanctl/x509ca/vpn-ui-ca-{inbound.inbound_id}.pem", "0644"))
        return local, remote_pubkey, "", pushes

    # default: eap-mschapv2 (username via eap_id, password in the secrets block; server
    # auth = pubkey validated against the trusted CA). Byte-equivalent to the original.
    local = (
        "        local {\n"
        "            auth = eap-mschapv2\n"
        f"            eap_id = {acct.user}\n"
        "        }"
    )
    secrets = (
        "secrets {\n"
        f"    eap-{acct.user} {{\n"
        f"        id = {acct.user}\n"
        f'        secret = "{acct.password}"\n'
        "    }\n"
        "}"
    )
    pushes = [(ca, f"/etc/swanctl/x509ca/vpn-ui-ca-{inbound.inbound_id}.pem", "0644")] if ca else []
    return local, remote_pubkey, secrets, pushes

# strongswan.conf drop-in (read at charon startup; /etc/strongswan.conf includes
# strongswan.d/*.conf). We manage the vip + routes ourselves for determinism.
_STRONGSWAN_DROPIN = """charon {
    install_routes = no
    install_virtual_ip = no
    retransmit_tries = 3
}
"""

# Free legacy IPsec, (re)create the routed xfrm ppp0, ensure a swanctl-mode charon is
# up, load creds+conns. @@DEV@@ = `dev <eth>` (the xfrm underlay) when known.
_DAEMON_SETUP = """
ipsec stop 2>/dev/null; systemctl stop strongswan-starter 2>/dev/null
pkill -x charon 2>/dev/null; pkill -x charon-systemd 2>/dev/null
sleep 1
ip link del ppp0 2>/dev/null
ip link add ppp0 type xfrm @@DEV@@ if_id @@IFID@@ 2>/dev/null || ip link add ppp0 type xfrm if_id @@IFID@@
ip link set ppp0 up
systemctl restart strongswan 2>/dev/null || systemctl restart strongswan-swanctl 2>/dev/null || true
sleep 2
if ! swanctl --stats >/dev/null 2>&1; then
  CH="$(command -v charon-systemd 2>/dev/null || ls /usr/libexec/ipsec/charon-systemd /usr/lib/ipsec/charon-systemd /usr/lib/strongswan/charon-systemd 2>/dev/null | head -n1)"
  [ -n "$CH" ] && setsid "$CH" >/var/log/ikev2-charon.log 2>&1 &
  sleep 3
fi
swanctl --load-all >/var/log/ikev2-load.log 2>&1
true
"""


def _parse_vip(list_sas_out: str, bridge_net: str) -> str:
    """Pull the assigned virtual IP from `swanctl --list-sas`. Recent strongSwan prints
    the assigned vip as a bracketed `[10.6.x.y]` on the IKE_SA local line AND as the
    CHILD_SA's narrowed local traffic selector (`local  10.6.x.y/32`, or `local-ts:` on
    older builds). Match either form; skip 0.0.0.0 (un-narrowed) and the client's own
    bridge subnet (the vip is the only non-bridge 10.x)."""
    cands = re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", list_sas_out)                  # [vip]
    cands += re.findall(r"\blocal(?:-ts)?:?\s+(\d+\.\d+\.\d+\.\d+)/", list_sas_out)  # child TS
    for ip in cands:
        if ip == "0.0.0.0":
            continue
        if bridge_net and ip.startswith(bridge_net):
            continue
        return ip
    return ""


def _apply_tunnel(client: Client, vip: str):
    """Assign the vip to ppp0 and route external traffic through it (split default),
    so `ip route get <public>` egresses dev ppp0 for tunnel_egress/dns-leak."""
    client.sh(
        f"ip addr flush dev {IFACE} 2>/dev/null; "
        f"ip addr add {vip}/32 dev {IFACE} 2>/dev/null; "
        f"ip link set {IFACE} up; "
        f"ip route replace 0.0.0.0/1 dev {IFACE} src {vip}; "
        f"ip route replace 128.0.0.0/1 dev {IFACE} src {vip}; "
        f"sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.{IFACE}.rp_filter=2 "
        ">/dev/null 2>&1; true")


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up an IKEv2/EAP tunnel for account A/B. Returns (ok, tunnel_ip, log).

    Signature matches the protocols.py dispatch: connect(client, inbound, which,
    server_ip=...). Charon binds 500/4500 for every inbound, so the port is not used
    here — the account's creds land the client in its inbound's /16 block via RADIUS."""
    acct = inbound.accounts[which]
    remote_id = inbound.server_addr or server_ip   # cert SAN = server IP when serverAddr empty

    # 1. config: assemble the swanctl conn (auth blocks per inbound.auth_mode) + the
    #    strongswan.conf drop-in, then write every credential the mode needs — the
    #    server CA (accumulated so charon's shared daemon can present any inbound's
    #    leaf) for the cert modes, plus the client cert+key for eap-tls; none for psk.
    local_b, remote_b, secrets_b, pushes = _auth_blocks(inbound, acct, remote_id)
    conf = (_CONN_TMPL
            .replace("@@SERVER@@", server_ip)
            .replace("@@LOCAL@@", local_b)
            .replace("@@REMOTE@@", remote_b)
            .replace("@@SECRETS@@", secrets_b)
            .replace("@@IFID@@", IF_ID))
    client.push(conf, "/etc/swanctl/swanctl.conf", mode="0600")
    client.push(_STRONGSWAN_DROPIN, "/etc/strongswan.d/99-vpn-ui-client.conf")
    for content, path, mode in pushes:
        if content:
            client.push(content, path, mode=mode)

    # 2. keep the server reachable off-tunnel, then (re)build the routed xfrm iface +
    #    the swanctl-mode charon (fresh per connect: applies the drop-in + clean slate;
    #    one device per VM for ikev2, so a restart never drops another live device).
    client.pin_server_route(server_ip)
    dev = f"dev {client.eth}" if client.eth else ""
    client.sh(_DAEMON_SETUP.replace("@@IFID@@", IF_ID).replace("@@DEV@@", dev), timeout=90)

    # 3. initiate + read the server-assigned virtual IP off the child SA's local-ts.
    client.sh("timeout 45 swanctl --initiate --child tunnel "
              ">/var/log/ikev2-init.log 2>&1; true", timeout=60)
    vip = ""
    for _ in range(12):
        _, sas = client.sh("swanctl --list-sas 2>/dev/null")
        vip = _parse_vip(sas, client.bridge_net)
        if vip:
            break
        time.sleep(2)

    if vip:
        _apply_tunnel(client, vip)
        client.apply_tunnel_dns(IFACE)

    _, log = client.sh(
        "echo '== swanctl --list-sas =='; swanctl --list-sas 2>/dev/null | tail -n 40; "
        "echo '== initiate =='; tail -n 25 /var/log/ikev2-init.log 2>/dev/null; "
        "echo '== load =='; tail -n 10 /var/log/ikev2-load.log 2>/dev/null; "
        "echo '== charon =='; tail -n 20 /var/log/ikev2-charon.log 2>/dev/null; "
        f"echo '== ip addr {IFACE} =='; ip -4 addr show {IFACE} 2>/dev/null; "
        "echo '== route get 1.1.1.1 =='; ip route get 1.1.1.1 2>/dev/null")
    if not vip:
        return False, "", "ikev2 tunnel/virtual-IP never came up\n" + log
    return True, vip, log


def disconnect(client: Client):
    # Terminate the SA gracefully, kill the swanctl-mode daemon (it may be a direct
    # charon-systemd child, not a unit), and remove the routed xfrm interface.
    client.sh(
        "swanctl --terminate --ike ikev2-vpn 2>/dev/null; "
        "swanctl --terminate --child tunnel 2>/dev/null; "
        "pkill -x charon-systemd 2>/dev/null; pkill -x charon 2>/dev/null; "
        "systemctl stop strongswan strongswan-swanctl 2>/dev/null; "
        f"ip link del {IFACE} 2>/dev/null; true")
    time.sleep(2)
