#!/usr/bin/env python3
"""OpenVPN multi-account matrix: the orders and shapes a real deployment produces.

ovpn_accounts_test covers the plain case (accounts added one at a time, each client
connecting in creation order, UDP). It passes, so if accounts past the first are broken
for a user, the trigger is one of the variables that case fixes. This walks them:

  creation-order  three accounts, connecting in the order they were created (control)
  reverse-order   connecting newest-account-first: the pool hands out addresses in
                  arrival order while the panel pins them per account, so an inbound
                  whose pool and pins only line up when arrival == creation order fails
                  exactly here
  simultaneous    all three dialing at once: the connect hook is a separate short-lived
                  process per client, and the lease it takes is what keeps two accounts
                  off one address
  same-host       two accounts from ONE machine (one public IP, two tun devices), which
                  is how a single operator tests two accounts, and how any two users
                  behind one NAT arrive
  tcp             the same three accounts over the TCP transport
  user-limit-2    User Limit 2, so every account owns a BLOCK of addresses rather than
                  one, and the block maths is what separates account 2 from account 1

Reuses the VMs from `ovpn_accounts_test --keep`. Run from the repo root:

    sudo python3 -m test_unit.harness.ovpn_accounts_matrix [scenario ...]
"""
from __future__ import annotations

import concurrent.futures as cf
import sys
import time

from . import checks
from .clients import openvpn as ovpn
from .clients.base import Client
from .incus import Incus
from .model import Status
from .ovpn_accounts_test import ACCOUNTS, PREFIX, TCP_PORT, UDP_PORT, load_cfg, log
from .panel import Panel
from .server_setup import Account, Inbound, _dict_client

SRV = f"{PREFIX}-srv"
CLS = [f"{PREFIX}-cl{x}" for x in ("a", "b", "c")]


def make_inbound(panel: Panel, incus: Incus, server_ip: str, n_accounts: int,
                 user_limit: int = 1, strategy: str = "reject") -> Inbound:
    """A fresh openvpn inbound with account A, then the rest through addClient (the
    operator path). Any inbound from a previous scenario is removed first."""
    for ib in panel.list_inbounds():
        if ib.get("protocol") == "openvpn":
            panel.del_inbound(ib["id"])
    certs = panel.generate_openvpn_certs()
    settings = {
        "udpEnable": True, "tcpEnable": True, "tcpPort": TCP_PORT,
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
        "caCert": certs["caCert"], "caKey": certs["caKey"],
        "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
        "tlsCrypt": certs["tlsCrypt"], "cipherMode": "all",
        "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
        "clientToClient": True, "crossInbound": True,
        "userLimit": user_limit, "userLimitStrategy": strategy,
        "clients": [_dict_client(ACCOUNTS[0][1])],
    }
    inb = panel.add_inbound("ovpn-matrix", UDP_PORT, "openvpn", settings)
    iid = inb["id"]
    accounts = {"A": ACCOUNTS[0][1]}
    for label, acct in ACCOUNTS[1:n_accounts]:
        panel.add_client(iid, _dict_client(acct))
        accounts[label] = acct
    time.sleep(4)
    return Inbound(protocol="openvpn", inbound_id=iid, udp_port=UDP_PORT,
                   tcp_port=TCP_PORT, accounts=accounts,
                   ovpn_udp=panel.download_ovpn(iid, "udp"),
                   ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=user_limit)


def del_client(panel: Panel, inbound_id: int, acct: Account):
    """openvpn's client id in the delete/update routes is the PASSWORD
    (clientIdentityKey in web/service/inbound.go), not the username."""
    panel._post(f"/panel/api/inbounds/{inbound_id}/delClient/{acct.password}", {})


def update_client(panel: Panel, inbound_id: int, acct: Account, changes: dict):
    ib = panel.get_inbound(inbound_id)
    import json as _json
    settings = _json.loads(ib.get("settings") or "{}")
    target = next(c for c in settings["clients"] if c.get("email") == acct.email)
    target.update(changes)
    panel._post(f"/panel/api/inbounds/updateClient/{acct.password}", {
        "id": str(inbound_id), "remark": ib.get("remark", ""), "enable": "true",
        "listen": ib.get("listen") or "", "port": str(ib["port"]),
        "protocol": ib["protocol"],
        "settings": _json.dumps({"clients": [target]}),
        "streamSettings": "{}", "sniffing": "{}",
    })


def dump_state(incus: Incus, iid: int, note: str):
    """The three files the connect hook decides from, at this instant."""
    cmd = (f"d=/etc/openvpn/server-{iid}; "
           f"echo '-- blocks'; for f in $d/blocks-udp/*; do echo \"$(basename $f): $(cat $f)\"; done; "
           f"echo '-- leases'; ls -l --time-style=+%H:%M:%S $d/leases-udp/ | tail -n +2; "
           f"echo '-- status'; grep -E '^CLIENT_LIST' /var/run/openvpn/status-{iid}-udp.log")
    _, out, err = incus.exec(SRV, cmd, timeout=30)
    log(f"   [{note}]\n" + "\n".join("      " + l for l in (out or err).splitlines()))


def check_client(c: Client, label: str, ip: str, fails: list, scenario: str,
                 iface: str = "tun0"):
    egress = checks.tunnel_egress(c, ifaces=(iface,))
    inet = checks.internet(c)
    log(f"   {label}: ip={ip} egress={egress.status.value} internet={inet.status.value} "
        f"({inet.detail})")
    if egress.status is not Status.PASS:
        fails.append(f"{scenario}/{label}: traffic not on the tunnel ({egress.detail})")
    if inet.status is not Status.PASS:
        fails.append(f"{scenario}/{label}: no internet ({inet.detail})")


def connect_all(clients, ib, labels, transport, server_ip, fails, scenario):
    """Connect each label on its own client, sequentially, in the given order."""
    ips = {}
    for label in labels:
        c = clients[label]
        ok, ip, clog = ovpn.connect(c, ib, label, transport=transport, server_ip=server_ip)
        if not ok:
            fails.append(f"{scenario}/{label}: connect failed")
            log(f"   {label}: CONNECT FAILED\n{clog[-1200:]}")
            continue
        ips[label] = ip
        check_client(c, label, ip, fails, scenario)
    return ips


def scenario_order(panel, incus, clients, server_ip, fails, reverse: bool):
    name = "reverse-order" if reverse else "creation-order"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3)
    labels = ["C", "B", "A"] if reverse else ["A", "B", "C"]
    ips = connect_all(clients, ib, labels, "udp", server_ip, fails, name)
    log(f"-> {name}: {ips}")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_simultaneous(panel, incus, clients, server_ip, fails):
    name = "simultaneous"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3)
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {label: ex.submit(ovpn.connect, clients[label], ib, label,
                                transport="udp", server_ip=server_ip)
                for label in ("A", "B", "C")}
        results = {label: f.result() for label, f in futs.items()}
    ips = {}
    for label, (ok, ip, clog) in results.items():
        if not ok:
            fails.append(f"{name}/{label}: connect failed")
            log(f"   {label}: CONNECT FAILED\n{clog[-800:]}")
            continue
        ips[label] = ip
        check_client(clients[label], label, ip, fails, name)
    log(f"-> {name}: {ips}")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_same_host(panel, incus, clients, server_ip, fails):
    """Two accounts from one machine: same source IP, two tun devices."""
    name = "same-host"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 2)
    c = clients["A"]
    ok, ip1, clog = ovpn.connect(c, ib, "A", transport="udp", server_ip=server_ip)
    if not ok:
        fails.append(f"{name}/A: connect failed")
        log(f"   A: CONNECT FAILED\n{clog[-800:]}")
        return {}
    check_client(c, "A", ip1, fails, name)

    # Second account on the same host: its own tun device, log and pid so the first
    # tunnel is untouched.
    acct = ib.accounts["B"]
    c.push(f"{acct.user}\n{acct.password}\n", "/etc/vpn/creds2.txt", mode="0600")
    c.sh("openvpn --config /etc/vpn/client.ovpn --auth-user-pass /etc/vpn/creds2.txt "
         "--dev tun1 --route-nopull "
         "--data-ciphers AES-256-GCM --data-ciphers-fallback AES-256-GCM "
         "--connect-retry-max 3 --connect-timeout 15 "
         "--daemon --log /var/log/ovpn2.log --writepid /run/ovpn2.pid")
    ip2 = c.wait_iface("tun1", timeout=45)
    _, log2 = c.sh("tail -n 30 /var/log/ovpn2.log 2>/dev/null")
    if not ip2:
        fails.append(f"{name}/B: second account never got a tunnel on the same host")
        log(f"   B: NO tun1\n{log2[-1200:]}")
    else:
        log(f"   B: ip={ip2} (second tunnel on the same host)")
        if ip2 == ip1:
            fails.append(f"{name}: both accounts got {ip1} on one host")
        # Real traffic, not just an address: --route-nopull means tun1 has no default
        # route, so bind the request to it. This is the assertion that matters — the
        # second account's packets have to survive the server's per-source-IP path.
        _, code = c.sh("curl -s -o /dev/null -w '%{http_code}' --interface tun1 "
                       "--max-time 12 http://cp.cloudflare.com/generate_204 || true")
        _, gw = c.sh("ping -c 2 -W 3 -I tun1 10.2.0.1 2>&1 | tail -2")
        log(f"   B: via tun1 -> HTTP {code.strip() or '???'} | {gw.strip().splitlines()[-1] if gw.strip() else 'no ping output'}")
        if code.strip() != "204":
            fails.append(f"{name}/B: second tunnel carries no traffic (HTTP {code.strip()!r} "
                         f"binding to tun1)")
        still = c.wait_iface("tun0", timeout=5)
        if not still:
            fails.append(f"{name}: the first account's tunnel died when the second dialed")
    c.sh("kill $(cat /run/ovpn2.pid 2>/dev/null) 2>/dev/null; true")
    ovpn.disconnect(c)
    return {"A": ip1, "B": ip2}


def scenario_tcp(panel, incus, clients, server_ip, fails):
    name = "tcp"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3)
    ips = connect_all(clients, ib, ["A", "B", "C"], "tcp", server_ip, fails, name)
    log(f"-> {name}: {ips}")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_k2(panel, incus, clients, server_ip, fails):
    name = "user-limit-2"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3, user_limit=2)
    ips = connect_all(clients, ib, ["A", "B", "C"], "udp", server_ip, fails, name)
    log(f"-> {name}: {ips}")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_email_username(panel, incus, clients, server_ip, fails):
    """Connect with the account EMAIL as the username instead of its id.

    RADIUS accepts either (radius.go matches client.ID or client.Email) and the panel
    itself advertises the email as the username, but the per-account address pin is
    published under the id: openvpn sets the common name from the username, so an email
    login looks up a block file that does not exist. The account then falls back to
    whatever the shared pool hands out, which is the one thing that cannot be right for
    two accounts at once.
    """
    name = "email-username"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3)
    # Same accounts, but each dials with its email in the username field.
    by_email = {}
    for label, acct in ib.accounts.items():
        by_email[label] = Account(user=acct.email, password=acct.password,
                                  email=acct.email, index=acct.index)
    ib_email = Inbound(protocol="openvpn", inbound_id=ib.inbound_id,
                       udp_port=ib.udp_port, tcp_port=ib.tcp_port, accounts=by_email,
                       ovpn_udp=ib.ovpn_udp, ovpn_tcp=ib.ovpn_tcp, user_limit=1)
    expected = {"A": "10.2.0.2", "B": "10.2.0.3", "C": "10.2.0.4"}
    ips = connect_all(clients, ib_email, ["A", "B", "C"], "udp", server_ip, fails, name)
    log(f"-> {name}: {ips} (pinned addresses would be {expected})")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for label, ip in ips.items():
        if ip != expected[label]:
            fails.append(f"{name}/{label}: got {ip}, not its pinned {expected[label]} "
                         f"(per-account routing/quota keys on the pinned address)")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_no_limit(panel, incus, clients, server_ip, fails):
    """User Limit 0 = "no limit", which is NOT the same code path as 1: an explicit 0
    resolves to a 16-address block per account (noLimitDevices), so account 2 starts at
    .18 rather than .3 and the block maths carries the separation."""
    name = "no-limit"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3, user_limit=0)
    ips = connect_all(clients, ib, ["A", "B", "C"], "udp", server_ip, fails, name)
    log(f"-> {name}: {ips}")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_five_accounts(panel, incus, clients, server_ip, fails):
    """Five accounts, three clients: the last three (D, E on the reused clients) prove
    the pins keep working past the count a three-client run can hold at once."""
    name = "five-accounts"
    log(f":: {name}")
    extra = [("D", Account(user="acc-d", password="Pw-acc-D-9k", email="acc-d@t", index=3)),
             ("E", Account(user="acc-e", password="Pw-acc-E-9k", email="acc-e@t", index=4))]
    ib = make_inbound(panel, incus, server_ip, 3)
    for label, acct in extra:
        panel.add_client(ib.inbound_id, _dict_client(acct))
        ib.accounts[label] = acct
    time.sleep(4)
    ips = connect_all(clients, ib, ["A", "B", "C"], "udp", server_ip, fails, name)
    for c in clients.values():
        ovpn.disconnect(c)
    time.sleep(3)
    # Now the two newest accounts, on the same three clients.
    ips2 = connect_all({"D": clients["A"], "E": clients["B"]}, ib, ["D", "E"], "udp",
                       server_ip, fails, name)
    log(f"-> {name}: first three {ips} then {ips2}")
    allips = {**ips, **ips2}
    if len(set(allips.values())) != len(allips):
        fails.append(f"{name}: accounts share an address {allips}")
    for c in clients.values():
        ovpn.disconnect(c)
    return allips


def scenario_delete_middle(panel, incus, clients, server_ip, fails, strategy="reject"):
    """Delete the middle account of three while all three are connected.

    The pinned address comes from the account's POSITION in the client list, so removing
    one renumbers every account after it. Anything still holding the old address (a live
    session, or a lease that outlives it by up to 30s) then occupies the address the
    renumbered account was just handed, and whether that is survivable depends entirely on
    the User Limit Strategy.
    """
    name = f"delete-middle-{strategy}"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 3, strategy=strategy)
    ips = connect_all(clients, ib, ["A", "B", "C"], "udp", server_ip, fails, name)
    log(f"-> connected: {ips}")
    dump_state(incus, ib.inbound_id, "before the delete")

    log("-> deleting account B (the middle one)")
    del_client(panel, ib.inbound_id, ib.accounts["B"])
    time.sleep(8)
    dump_state(incus, ib.inbound_id, "after the delete")

    for label in ("A", "C"):
        c = clients[label]
        still = c.wait_iface("tun0", timeout=5)
        inet = checks.internet(c)
        log(f"   {label}: ip={still or 'GONE'} internet={inet.status.value} ({inet.detail})")
        if not still:
            fails.append(f"{name}/{label}: lost its tunnel when another account was deleted")
        elif inet.status is not Status.PASS:
            fails.append(f"{name}/{label}: lost internet when another account was deleted "
                         f"({inet.detail})")
        if still and still != ips.get(label):
            fails.append(f"{name}/{label}: its address moved from {ips.get(label)} to "
                         f"{still} because another account was deleted")

    # A reconnect right after the change is the everyday case (a client redials on any
    # blip), and it is where a renumbered pin meets the outgoing session's lease.
    ovpn.disconnect(clients["C"])
    time.sleep(3)
    ok, ip, clog = ovpn.connect(clients["C"], ib, "C", transport="udp", server_ip=server_ip)
    if not ok:
        fails.append(f"{name}/C: cannot reconnect after another account was deleted")
        log(f"   C reconnect FAILED: {[l for l in clog.splitlines() if 'AUTH' in l or 'TLS Error' in l][:3]}")
        dump_state(incus, ib.inbound_id, "at the failed reconnect")
    else:
        log(f"   C reconnected on {ip}")
        check_client(clients["C"], "C", ip, fails, name)
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_edit_account(panel, incus, clients, server_ip, fails):
    """Edit account A's password while A and B are connected: B must not care."""
    name = "edit-account"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 2)
    ips = connect_all(clients, ib, ["A", "B"], "udp", server_ip, fails, name)
    log(f"-> connected: {ips}")
    acct = ib.accounts["A"]
    log("-> changing account A's comment through updateClient")
    update_client(panel, ib.inbound_id, acct, {"comment": "edited"})
    time.sleep(8)
    c = clients["B"]
    still = c.wait_iface("tun0", timeout=5)
    inet = checks.internet(c)
    log(f"   B: ip={still or 'GONE'} internet={inet.status.value} ({inet.detail})")
    if not still:
        fails.append(f"{name}/B: lost its tunnel when another account was edited")
    elif inet.status is not Status.PASS:
        fails.append(f"{name}/B: lost internet when another account was edited "
                     f"({inet.detail})")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_empty_id(panel, incus, clients, server_ip, fails):
    """Accounts created WITHOUT an id (a script hitting the API, where the panel UI would
    have generated one).

    RADIUS still authenticates them by email, but writeClientConfigDir skips a client with
    an empty id, so no address is pinned for the account and openvpn falls back to whatever
    its shared pool hands out. With one account the pool address happens to equal the pin;
    with two it cannot, and every per-account thing keyed on the address (routing rules,
    accounting, User Limit) is then attributed to the wrong account.
    """
    name = "empty-id"
    log(f":: {name}")
    for ib0 in panel.list_inbounds():
        if ib0.get("protocol") == "openvpn":
            panel.del_inbound(ib0["id"])
    certs = panel.generate_openvpn_certs()
    noid = [Account(user="", password=f"Pw-noid-{x}-9k", email=f"noid-{x}@t", index=i)
            for i, x in enumerate(("a", "b"))]
    settings = {
        "udpEnable": True, "tcpEnable": True, "tcpPort": TCP_PORT,
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
        "caCert": certs["caCert"], "caKey": certs["caKey"],
        "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
        "tlsCrypt": certs["tlsCrypt"], "cipherMode": "all",
        "ciphers": ["AES-256-GCM"], "clientToClient": True, "crossInbound": True,
        "userLimit": 1, "userLimitStrategy": "reject",
        "clients": [{"id": "", "password": noid[0].password, "email": noid[0].email,
                     "enable": True}],
    }
    inb = panel.add_inbound("ovpn-noid", UDP_PORT, "openvpn", settings)
    iid = inb["id"]
    panel.add_client(iid, {"id": "", "password": noid[1].password,
                           "email": noid[1].email, "enable": True})
    time.sleep(4)
    # They log in with their email, the only identity they have.
    accounts = {"A": Account(user=noid[0].email, password=noid[0].password,
                             email=noid[0].email, index=0),
                "B": Account(user=noid[1].email, password=noid[1].password,
                             email=noid[1].email, index=1)}
    ib = Inbound(protocol="openvpn", inbound_id=iid, udp_port=UDP_PORT, tcp_port=TCP_PORT,
                 accounts=accounts, ovpn_udp=panel.download_ovpn(iid, "udp"),
                 ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=1)
    ips = connect_all(clients, ib, ["A", "B"], "udp", server_ip, fails, name)
    log(f"-> {name}: {ips} (pins would be A=10.2.0.2 B=10.2.0.3)")
    if len(set(ips.values())) != len(ips):
        fails.append(f"{name}: accounts share an address {ips}")
    expected = {"A": "10.2.0.2", "B": "10.2.0.3"}
    for label, ip in ips.items():
        if ip != expected[label]:
            fails.append(f"{name}/{label}: on {ip}, not its pinned {expected[label]} — "
                         f"the account has no id, so no address was pinned for it")
    for c in clients.values():
        ovpn.disconnect(c)
    return ips


def scenario_reconnect_fast(panel, incus, clients, server_ip, fails, strategy="reject"):
    """One account, one client: connect, drop, re-dial after N seconds.

    Nothing here exceeds the User Limit — it is the same account's only device coming
    back. What it probes is the connect hook's idea of "in use": openvpn rewrites its
    status file every 5s, so for a few seconds after a clean disconnect the account's
    address still looks occupied, and only the "accept" strategy has a path back out of
    that (ghost-lease reclaim). This is the everyday case of a client redialing after any
    network blip.
    """
    name = f"reconnect-fast-{strategy}"
    log(f":: {name}")
    ib = make_inbound(panel, incus, server_ip, 1, strategy=strategy)
    c = clients["A"]
    ok, ip, clog = ovpn.connect(c, ib, "A", transport="udp", server_ip=server_ip)
    if not ok:
        fails.append(f"{name}: initial connect failed")
        log(f"   initial connect FAILED\n{clog[-800:]}")
        return {}
    log(f"   first session on {ip}")
    for gap in (2, 8, 20):
        ovpn.disconnect(c)
        time.sleep(gap)
        ok, ip2, clog = ovpn.connect(c, ib, "A", transport="udp", server_ip=server_ip)
        verdict = "ok" if ok else "REFUSED"
        auth = [l.split("] ")[-1] for l in clog.splitlines() if "AUTH_FAILED" in l]
        log(f"   redial after {gap}s: {verdict} ip={ip2 or '-'} {auth[:1]}")
        if not ok:
            fails.append(f"{name}: the account could not redial {gap}s after a clean "
                         f"disconnect (AUTH_FAILED from the connect hook)")
            dump_state(incus, ib.inbound_id, f"refused redial after {gap}s")
        else:
            check_client(c, "A", ip2, fails, name)
    ovpn.disconnect(c)
    return {"A": ip}


SCENARIOS = {
    "creation-order": lambda *a: scenario_order(*a, reverse=False),
    "reverse-order": lambda *a: scenario_order(*a, reverse=True),
    "simultaneous": scenario_simultaneous,
    "same-host": scenario_same_host,
    "tcp": scenario_tcp,
    "user-limit-2": scenario_k2,
    "email-username": scenario_email_username,
    "no-limit": scenario_no_limit,
    "five-accounts": scenario_five_accounts,
    "delete-middle": lambda *a: scenario_delete_middle(*a, strategy="reject"),
    "delete-middle-accept": lambda *a: scenario_delete_middle(*a, strategy="accept"),
    "edit-account": scenario_edit_account,
    "empty-id": scenario_empty_id,
    "reconnect-fast": lambda *a: scenario_reconnect_fast(*a, strategy="reject"),
    "reconnect-fast-accept": lambda *a: scenario_reconnect_fast(*a, strategy="accept"),
}


def main() -> int:
    wanted = sys.argv[1:] or list(SCENARIOS)
    unknown = [w for w in wanted if w not in SCENARIOS]
    if unknown:
        sys.exit(f"unknown scenario(s): {unknown}; known: {list(SCENARIOS)}")

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
    for name in wanted:
        before = len(fails)
        try:
            SCENARIOS[name](panel, incus, clients, server_ip, fails)
        except Exception as e:  # noqa: BLE001
            fails.append(f"{name}: driver error {e}")
            log(f"-> {name}: driver error {e}")
        log(f"== {name}: {'FAIL' if len(fails) > before else 'pass'}")

    print("\n" + "=" * 70)
    if fails:
        print(f"FAILURES ({len(fails)}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS: {', '.join(wanted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
