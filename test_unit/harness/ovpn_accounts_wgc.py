#!/usr/bin/env python3
"""Does deleting an account break the OTHER accounts on WireGuard (C)?

An account's tunnel address comes from its POSITION in the client list, so deleting one
renumbers every account after it. For OpenVPN the client is pushed its address on each
dial, so a renumbered account recovers by redialling. WireGuard has no push: the address
is written into the .conf the subscriber already installed, and the server cryptokey-routes
the account's peer to the address the panel computes NOW. If the two disagree, the
installed config stops passing traffic with nothing to indicate why.

This runs that: three wg-c accounts on three clients, delete the middle one, then check the
survivors WITHOUT touching their configs.

Reuses the VMs from `ovpn_accounts_test --keep`:

    sudo python3 -m test_unit.harness.ovpn_accounts_wgc
"""
from __future__ import annotations

import sys
import time

from . import checks
from .clients import wgc as wgc_mod
from .clients.base import Client
from .incus import Incus
from .model import Status
from .ovpn_accounts_test import PREFIX, load_cfg, log
from .ovpn_accounts_matrix import SRV, CLS
from .panel import Panel
from .server_setup import Account, Inbound, _dict_client

WG_PORT = 51825

# Own accounts: emails are unique across the whole panel, so these cannot be the ones the
# openvpn scenarios use.
ACCOUNTS = [
    ("A", Account(user="wg-a", password="Pw-wg-A-9k", email="wg-a@t", index=0)),
    ("B", Account(user="wg-b", password="Pw-wg-B-9k", email="wg-b@t", index=1)),
    ("C", Account(user="wg-c", password="Pw-wg-C-9k", email="wg-c@t", index=2)),
]


def main() -> int:
    cfg = load_cfg()
    incus = Incus(PREFIX, logger=log)
    server_ip = incus.ipv4(SRV)
    panel = Panel(server_ip, cfg["panel"]["port"], cfg["panel"]["base_path"],
                  cfg["panel"]["scheme"], cfg["panel"]["username"],
                  cfg["panel"]["password"])
    panel.login()
    clients = {label: Client(incus, vm, label)
               for vm, (label, _) in zip(CLS, ACCOUNTS)}
    fails: list[str] = []

    # Clear whatever a previous scenario left: an openvpn inbound holding these VMs'
    # accounts would also collide on the panel-wide email uniqueness check.
    for ib0 in panel.list_inbounds():
        if ib0.get("protocol") in ("wg-c", "openvpn"):
            panel.del_inbound(ib0["id"])
    time.sleep(3)

    log(":: creating a wg-c inbound with account A, then adding B and C")
    settings = {
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420, "pskEnable": False,
        "clientToClient": True, "crossInbound": False, "userLimit": 1,
        "clients": [_dict_client(ACCOUNTS[0][1])],
    }
    inb = panel.add_inbound("wgc-accounts", WG_PORT, "wg-c", settings)
    iid = inb["id"]
    accounts = {"A": ACCOUNTS[0][1]}
    for label, acct in ACCOUNTS[1:]:
        panel.add_client(iid, _dict_client(acct))
        accounts[label] = acct
    time.sleep(5)

    ib = Inbound(protocol="wg-c", inbound_id=iid, udp_port=WG_PORT, tcp_port=0,
                 accounts=accounts, user_limit=1)
    ib.wg_configs = {label: panel.wgc_configs(iid, a.email)
                     for label, a in accounts.items()}

    addrs = {}
    for label in ("A", "B", "C"):
        ok, ip, clog = wgc_mod.connect(clients[label], ib, label, server_ip=server_ip)
        if not ok:
            fails.append(f"{label}: wg-c connect failed")
            log(f"   {label}: CONNECT FAILED\n{clog[-800:]}")
            continue
        inet = checks.internet(clients[label])
        log(f"   {label}: ip={ip} internet={inet.status.value} ({inet.detail})")
        addrs[label] = ip
        if inet.status is not Status.PASS:
            fails.append(f"{label}: no internet before the delete ({inet.detail})")
    log(f"-> connected: {addrs}")

    log("-> deleting account B (the middle one)")
    del_client_wgc(panel, iid, accounts["B"])
    time.sleep(10)

    # The survivors are NOT reconfigured: this is the subscriber who installed a .conf and
    # never touched it again.
    for label in ("A", "C"):
        c = clients[label]
        inet = checks.internet(c)
        _, hs = c.sh("wg show wgc latest-handshakes 2>/dev/null | tail -2")
        log(f"   {label}: internet={inet.status.value} ({inet.detail}) handshake={hs.strip()[:60]!r}")
        if inet.status is not Status.PASS:
            fails.append(f"{label}: its installed WireGuard config stopped passing traffic "
                         f"when another account was deleted ({inet.detail})")

    # What the panel now hands out for the survivors, for the record.
    after = {label: (panel.wgc_configs(iid, a.email) or [{}])[0].get("ip", "?")
             for label, a in accounts.items() if label != "B"}
    log(f"-> addresses the panel now assigns: {after} (they were {addrs})")
    for label, ipnow in after.items():
        if label in addrs and ipnow.split("/")[0] != addrs[label]:
            fails.append(f"{label}: the panel moved its address from {addrs[label]} to "
                         f"{ipnow} while its installed config still says {addrs[label]}")

    for c in clients.values():
        wgc_mod.disconnect(c)
    panel.del_inbound(iid)

    print("\n" + "=" * 70)
    if fails:
        print(f"FAILURES ({len(fails)}):")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: deleting an account left the other wg-c accounts working")
    return 0


def del_client_wgc(panel: Panel, inbound_id: int, acct):
    """wg-c identifies a client by its id/email, not the password the PPP family uses."""
    panel._post(f"/panel/api/inbounds/{inbound_id}/delClient/{acct.user}", {})


if __name__ == "__main__":
    sys.exit(main())
