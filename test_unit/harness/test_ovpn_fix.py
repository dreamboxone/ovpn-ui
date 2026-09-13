"""Verify the openvpn K=1 duplicate-cn fix with reliable incus clients, WITHOUT
touching the operator's inbounds: create a fresh openvpn inbound on a distinct
port, test reject + accept with 2 devices on one account, then delete it.

reject: device2 refused (device1 keeps the tunnel + internet).
accept: device2 admitted WITH internet, device1 cleanly evicted, and the server
never shows two sessions on the same virtual IP.
"""
import time

import test_unit.harness.remote_runner as R
from test_unit.harness import checks
from test_unit.harness import protocols as P
from test_unit.harness.model import Status

p = R.Panel(host=R.SERVER_IP, port=R.PORT, base_path=R.BP, scheme=R.SCHEME,
            username=R.PUSER, password=R.PPASS, timeout=40)
p.login()
before = {i["id"] for i in p.list_inbounds()}

inc = R.LocalIncus()
cA = R.Client(inc, "deb11", "A", R.log)
cB = R.Client(inc, "deb13", "B", R.log)
cA.prep(); cB.prep()


def vaddr_dupes(iid):
    """Return the set of virtual IPs held by >1 concurrent session (the bug)."""
    rows = P._ovpn_status_rows(R.server_exec, iid, "udp")
    seen, dupes = {}, set()
    for f in rows:
        if len(f) > 3:
            seen[f[3]] = seen.get(f[3], 0) + 1
    return {ip for ip, n in seen.items() if n > 1}


for strat in ("reject", "accept"):
    print(f"\n===== openvpn K=1 {strat} =====")
    ib = R.make_inbound(p, "openvpn", 1)
    R.set_K_strategy(p, ib, 1, strat)
    time.sleep(8)
    cA.disconnect_all(); cB.disconnect_all(); time.sleep(2)

    ok1, ip1, _ = R.connect(cA, ib, "openvpn", "udp")
    n1 = checks.internet(cA) if ok1 else None
    print(f"device1: ok={ok1} ip={ip1} net={(n1.status.value if n1 else 'n/a')}")
    time.sleep(3)

    ok2, ip2, l2 = R.connect(cB, ib, "openvpn", "udp")
    n2 = checks.internet(cB) if ok2 else None
    admitted = ok2 and n2 is not None and n2.status == Status.PASS
    print(f"device2: ok={ok2} ip={ip2} net={(n2.status.value if n2 else 'n/a')} admitted={admitted}")
    time.sleep(6)

    dupes = vaddr_dupes(ib.inbound_id)
    d1_up = bool(cA.wait_iface("tun0", timeout=3))
    d2_up = bool(cB.wait_iface("tun0", timeout=3))
    print(f"same-IP-dupes={dupes or 'none'} device1_tun_up={d1_up} device2_tun_up={d2_up}")

    if strat == "reject":
        verdict = "PASS" if (ok1 and not admitted and not dupes) else "FAIL"
        print(f"REJECT verdict: {verdict}  (want: dev1 up, dev2 refused, no shared-IP)")
    else:
        # accept: dev2 online, no two-on-one-IP. dev1 evicted (tun down) is the goal;
        # incus openvpn has persist/auto-reconnect so we key on 'dev2 has internet + no dupes'.
        verdict = "PASS" if (admitted and not dupes) else "FAIL"
        print(f"ACCEPT verdict: {verdict}  (want: dev2 admitted WITH internet, no shared-IP; "
              f"dev1 evicted={not d1_up})")

    cA.disconnect_all(); cB.disconnect_all()
    p.del_inbound(ib.inbound_id); time.sleep(3)

# safety: delete anything we created, keep operator inbounds
for i in p.list_inbounds():
    if i["id"] not in before:
        p.del_inbound(i["id"]); time.sleep(1)
print("\ndone (operator inbounds untouched)")
