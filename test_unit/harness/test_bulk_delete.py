"""End-to-end check of the new bulk 'delete' op (non-destructive to operator data:
creates its own l2tp inbound on a distinct port, then deletes it)."""
import json
import time

import test_unit.harness.remote_runner as R

p = R.Panel(host=R.SERVER_IP, port=R.PORT, base_path=R.BP, scheme=R.SCHEME,
            username=R.PUSER, password=R.PPASS, timeout=40)
p.login()


def clients(iid):
    s = json.loads(p.get_inbound(iid).get("settings") or "{}")
    return [c["email"] for c in s.get("clients", [])]


def cl(n):
    return {"id": f"bd{n}", "password": f"Pw-bd{n}", "email": f"bd{n}@t", "enable": True}


settings = {"allowRaw": True, "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [cl(1), cl(2), cl(3), cl(4)]}
inb = p.add_inbound("bulk-del-test", 1801, "l2tp", settings)
iid = inb["id"]
print("created inbound", iid, "clients:", clients(iid))

# 1) delete 2 of 4
r = p.bulk_update_clients({"op": "delete", "skipFirstUse": False, "skipUnlimited": False,
                           "skipDisabled": False,
                           "targets": [{"inboundId": iid, "email": "bd2@t"},
                                       {"inboundId": iid, "email": "bd3@t"}]})
after = clients(iid)
print(f"after delete bd2,bd3: applied={r.get('applied')} skipped={r.get('skipped')} remaining={after}")
ok1 = set(after) == {"bd1@t", "bd4@t"}
print("  DELETE-2 verdict:", "PASS" if ok1 else "FAIL")

# 2) never-empty guard: target the 2 remaining -> one must be retained
r2 = p.bulk_update_clients({"op": "delete", "skipFirstUse": False, "skipUnlimited": False,
                            "skipDisabled": False,
                            "targets": [{"inboundId": iid, "email": "bd1@t"},
                                        {"inboundId": iid, "email": "bd4@t"}]})
after2 = clients(iid)
print(f"after delete-all: applied={r2.get('applied')} skipped={r2.get('skipped')} remaining={after2}")
ok2 = len(after2) == 1
print("  NEVER-EMPTY verdict:", "PASS" if ok2 else "FAIL")

p.del_inbound(iid)

# 3) mixed delete (simulates runBulkDelete): a whole INBOUND + a standalone CLIENT.
settingsA = dict(settings); settingsA["clients"] = [cl(5), cl(6), cl(7)]
settingsB = dict(settings); settingsB["clients"] = [cl(8), cl(9)]
ibA = p.add_inbound("bulk-del-A", 1802, "l2tp", settingsA)["id"]
ibB = p.add_inbound("bulk-del-B", 1803, "l2tp", settingsB)["id"]
before_ids = {i["id"] for i in p.list_inbounds()}
# runBulkDelete step 1: delete inbound A wholesale
p.del_inbound(ibA)
# step 2: delete standalone client bd8 from inbound B
p.bulk_update_clients({"op": "delete", "skipFirstUse": False, "skipUnlimited": False,
                       "skipDisabled": False, "targets": [{"inboundId": ibB, "email": "bd8@t"}]})
ids_after = {i["id"] for i in p.list_inbounds()}
b_clients = clients(ibB)
ok3 = (ibA not in ids_after) and (ibB in ids_after) and (b_clients == ["bd9@t"])
print(f"mixed: inboundA_gone={ibA not in ids_after} inboundB_kept={ibB in ids_after} B_clients={b_clients}")
print("  MIXED verdict:", "PASS" if ok3 else "FAIL")
p.del_inbound(ibB)

print("\ncleanup done. OVERALL:", "PASS" if (ok1 and ok2 and ok3) else "FAIL")
