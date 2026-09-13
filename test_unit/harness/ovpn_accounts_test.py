#!/usr/bin/env python3
"""OpenVPN multi-ACCOUNT repro: 1 ubuntu-24 server + 3 ubuntu-24 clients, one account each.

The full E2E creates its openvpn inbound with both accounts in a SINGLE add_inbound
call, which is not the order an operator uses: they create the inbound with one account
and add the others later, through addClient. That is a different server path (the panel
rewrites the per-account IP blocks WITHOUT restarting openvpn), and it is what a user
reported broken past the first account. This drives exactly that order:

    inbound + account A            -> client A connects
    addClient account B            -> client B connects, A must stay up
    addClient account C            -> client C connects, A and B must stay up

Each account must end up on its own tunnel IP with working egress. On any failure the
server side is dumped (openvpn status, the per-account block files, the connect-hook log)
so the cause is in the transcript rather than needing a second run.

Run from the repo root:

    sudo python3 -m test_unit.harness.ovpn_accounts_test [--keep] [--transport udp|tcp]
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import tomllib

from . import checks
from . import provision
from .clients import openvpn as ovpn
from .clients.base import Client
from .incus import Incus, Network
from .model import JobResult, Status, SubTest
from .panel import Panel
from .server_setup import Account, Inbound, _dict_client

NET_INDEX = 9                      # bridge vt9 / 10.109.0.0/24, clear of the matrix jobs
PREFIX = "ovacc"
UDP_PORT, TCP_PORT = 11194, 11443

ACCOUNTS = [
    ("A", Account(user="acc-a", password="Pw-acc-A-9k", email="acc-a@t", index=0)),
    ("B", Account(user="acc-b", password="Pw-acc-B-9k", email="acc-b@t", index=1)),
    ("C", Account(user="acc-c", password="Pw-acc-C-9k", email="acc-c@t", index=2)),
]


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def load_cfg() -> dict:
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "config.toml")
    with open(cfg_path, "rb") as f:
        cfg = tomllib.load(f)
    cfg_dir = os.path.dirname(cfg_path)
    if not os.path.isabs(cfg["binary"]):
        cfg["binary"] = os.path.normpath(os.path.join(cfg_dir, cfg["binary"]))
    if not os.path.isfile(cfg["binary"]):
        sys.exit(f"FATAL: binary not found: {cfg['binary']}")
    return cfg


def server_dump(server_exec, iid: int, transport: str) -> str:
    """Everything needed to explain a failed connect, in one blob."""
    d = f"/usr/local/vpn-ui/openvpn/{iid}"
    cmds = [
        ("status", f"cat {d}/status-{transport}.log 2>/dev/null | head -30"),
        ("blocks", f"for f in {d}/blocks-{transport}/*; do echo \"== $f\"; cat $f; done 2>/dev/null"),
        ("leases", f"ls -l {d}/leases-{transport}/ 2>/dev/null"),
        ("ccd", f"ls -l {d}/ccd-{transport}/ 2>/dev/null"),
        ("ovpn-conf", f"grep -E 'client-config-dir|duplicate-cn|username-as-common-name|server |max-clients|verify-client-cert|client-connect|auth-user-pass-verify' {d}/server-{transport}.conf 2>/dev/null"),
        ("panel-log", "tail -n 60 /var/log/vpn-ui/vpn-ui.log 2>/dev/null"),
        ("ovpn-proc", "ps ax | grep -c '[o]penvpn --config' ; true"),
    ]
    out = []
    for name, cmd in cmds:
        _, so, se = server_exec(cmd, timeout=30)
        out.append(f"--- {name}\n{(so or se or '').strip()}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the VMs running afterwards (for iterating on a fix)")
    ap.add_argument("--transport", default="udp", choices=("udp", "tcp"))
    ap.add_argument("--reuse", action="store_true",
                    help="reuse VMs from a previous --keep run instead of relaunching")
    args = ap.parse_args()

    cfg = load_cfg()
    image = next(s["image"] for s in cfg["servers"] if s["name"] == "ubuntu-24")
    result = JobResult(distro="ubuntu-24", image=image)
    incus = Incus(PREFIX, logger=log)
    srv, cas = f"{PREFIX}-srv", [f"{PREFIX}-cl{x}" for x in ("a", "b", "c")]
    failures: list[str] = []

    try:
        if not args.reuse:
            log(":: launching 1 server + 3 clients (all ubuntu-24)")
            incus.preclean(NET_INDEX)
            net = incus.create_network(NET_INDEX)
            incus.launch(image, "srv", net, cfg["vm"]["server"]["cpu"],
                         cfg["vm"]["server"]["memory"])
            for name in ("cla", "clb", "clc"):
                incus.launch(cfg["client_image"], name, net,
                             cfg["vm"]["client"]["cpu"], cfg["vm"]["client"]["memory"])
            for vm in [srv] + cas:
                log(f"-> waiting for agent: {vm}")
                incus.wait_agent(vm, cfg["vm"]["agent_timeout"])

        server_ip = incus.ipv4(srv)
        log(f"-> server {server_ip}:{cfg['panel']['port']}")
        panel = Panel(server_ip, cfg["panel"]["port"], cfg["panel"]["base_path"],
                      cfg["panel"]["scheme"], cfg["panel"]["username"],
                      cfg["panel"]["password"])

        def server_exec(cmd, timeout=30):
            return incus.exec(srv, cmd, timeout=timeout)

        if not args.reuse:
            log(":: core-init — pushing the binary, provisioning the openvpn core")
            if not provision.run(incus, srv, panel, cfg, result):
                for p in result.phases:
                    for st in p.subtests:
                        log(f"   {p.name}/{st.name}: {st.status.value} {st.detail}")
                return 2
        else:
            panel.login()

        clients = [Client(incus, vm, label) for vm, (label, _) in zip(cas, ACCOUNTS)]
        if not args.reuse:
            log(":: client-prep — installing openvpn on the three clients")
            for c in clients:
                ok, plog = c.prep()
                log(f"-> client {c.label} prep {'ok' if ok else 'FAILED'}")
                if not ok:
                    failures.append(f"client {c.label} prep failed: {plog[-300:]}")

        # --- the inbound, created with ONE account, as an operator would ---------
        log(":: creating the openvpn inbound with account A only")
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True, "tcpPort": TCP_PORT,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"], "cipherMode": "all",
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(ACCOUNTS[0][1])],
        }
        inb = panel.add_inbound("ovpn-accounts", UDP_PORT, "openvpn", settings)
        iid = inb["id"]
        log(f"-> inbound {iid} (udp {UDP_PORT}, tcp {TCP_PORT}) with 1 account")

        ib = Inbound(protocol="openvpn", inbound_id=iid, udp_port=UDP_PORT,
                     tcp_port=TCP_PORT, accounts={"A": ACCOUNTS[0][1]},
                     ovpn_udp=panel.download_ovpn(iid, "udp"),
                     ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=1)

        connected: list[tuple[Client, str, str]] = []   # (client, label, tunnel ip)
        for n, (label, acct) in enumerate(ACCOUNTS):
            if n > 0:
                log(f":: adding account {label} through addClient (the operator path)")
                panel.add_client(iid, _dict_client(acct))
                ib.accounts[label] = acct
                # The .ovpn is per inbound, not per account, but re-fetch anyway: if the
                # add changed anything about the profile this is where it shows.
                ib.ovpn_udp = panel.download_ovpn(iid, "udp")
                ib.ovpn_tcp = panel.download_ovpn(iid, "tcp")
                time.sleep(3)

            c = clients[n]
            log(f":: connecting client {label} as account {acct.user} ({args.transport})")
            ok, ip, clog = ovpn.connect(c, ib, label, transport=args.transport,
                                        server_ip=server_ip)
            if not ok:
                failures.append(f"account {label} could not connect")
                log(f"-> account {label} connect FAILED\n{clog[-1500:]}")
                log("-> server side:\n" + server_dump(server_exec, iid, args.transport))
                continue
            log(f"-> account {label} up on {ip}")

            egress = checks.tunnel_egress(c)
            inet = checks.internet(c)
            log(f"   egress: {egress.status.value} {egress.detail}")
            log(f"   internet: {inet.status.value} {inet.detail}")
            if egress.status is not Status.PASS:
                failures.append(f"account {label}: traffic does not use the tunnel "
                                f"({egress.detail})")
            if inet.status is not Status.PASS:
                failures.append(f"account {label}: no internet through the tunnel "
                                f"({inet.detail})")
            connected.append((c, label, ip))

            # Everything connected so far must STILL be up: a new account must not
            # disturb the accounts already on the server.
            for prev_c, prev_label, prev_ip in connected[:-1]:
                still = prev_c.wait_iface("tun0", timeout=5)
                alive = checks.internet(prev_c)
                log(f"   account {prev_label} still up: ip={still or 'GONE'} "
                    f"internet={alive.status.value}")
                if not still:
                    failures.append(f"account {prev_label} lost its tunnel when "
                                    f"{label} connected")
                elif alive.status is not Status.PASS:
                    failures.append(f"account {prev_label} lost internet when "
                                    f"{label} connected ({alive.detail})")

        ips = [ip for _, _, ip in connected]
        log(f":: {len(connected)}/3 accounts connected: {ips}")
        if len(set(ips)) != len(ips):
            failures.append(f"accounts share a tunnel IP: {ips}")

        log("\n:: server state with all accounts connected\n"
            + server_dump(server_exec, iid, args.transport))

        for c, label, _ in connected:
            ovpn.disconnect(c)
    finally:
        if args.keep:
            log(f"-> keeping VMs: {srv} {' '.join(cas)} (delete with "
                f"`incus delete --force {srv} {' '.join(cas)}` + `incus network delete vt{NET_INDEX}`)")
        else:
            log("-> tearing down VMs")
            for vm in [srv] + cas:
                incus.delete(vm)
            incus.delete_network(Network(f"vt{NET_INDEX}", ""))

    print("\n" + "=" * 70)
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        return 1
    print("PASS: three accounts, three clients, three tunnels, all with egress")
    return 0


if __name__ == "__main__":
    sys.exit(main())
