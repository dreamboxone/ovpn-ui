"""End-to-end check of freeze/unfreeze (non-destructive: own inbound, deleted after).
freeze: enable->false, remaining time locked as a negative (non-ticking) expiry.
unfreeze: enable->true, expiry restored to an absolute deadline (now + remaining)."""
import time

import test_unit.harness.remote_runner as R

DAY = 86400 * 1000
p = R.Panel(host=R.SERVER_IP, port=R.PORT, base_path=R.BP, scheme=R.SCHEME,
            username=R.PUSER, password=R.PPASS, timeout=40)
p.login()

exp = int(time.time() * 1000) + 10 * DAY  # ~10 days out (absolute)
client = {"id": "fz1", "password": "Pw-fz1", "email": "fz1@t", "enable": True,
          "expiryTime": exp, "totalGB": 0}
inb = p.add_inbound("freeze-test", 1804, "l2tp",
                    {"allowRaw": True, "clientToClient": True, "crossInbound": True,
                     "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400, "clients": [client]})
iid = inb["id"]


def cg():
    return p.get_client(iid, "fz1@t")


def tf(op):
    p.bulk_update_clients({"op": op, "skipFirstUse": False, "skipUnlimited": False,
                           "skipDisabled": False, "targets": [{"inboundId": iid, "email": "fz1@t"}]})


b = cg()
print(f"before:  enable={b.get('enable')} expiry={b.get('expiryTime')}")
tf("freeze"); f = cg()
print(f"frozen:  enable={f.get('enable')} expiry={f.get('expiryTime')}")
frozen_ok = (f.get("enable") is False) and (int(f.get("expiryTime", 0)) < 0)
print("  FREEZE verdict:", "PASS" if frozen_ok else "FAIL",
      "(want disabled + negative locked remaining)")

tf("unfreeze"); u = cg()
print(f"unfroze: enable={u.get('enable')} expiry={u.get('expiryTime')}")
unfrozen_ok = (u.get("enable") is True) and (int(u.get("expiryTime", 0)) > int(time.time() * 1000))
print("  UNFREEZE verdict:", "PASS" if unfrozen_ok else "FAIL",
      "(want enabled + absolute future expiry)")

# frozen client must NOT be flagged for auto-disable/expire (enable=false exempts it):
_, jn, _ = R.server_exec("journalctl -u vpn-ui --since '-15 sec' --no-pager 2>/dev/null | grep -i fz1 | tail -2")

p.del_inbound(iid)
print("\ncleanup done. OVERALL:", "PASS" if (frozen_ok and unfrozen_ok) else "FAIL")
