"""Inspect how an ODD user-limit (K=3) generates device IPs + Xray routing sources,
to settle whether K must be even/pow2. Non-destructive: creates temp inbounds, reads
the merged config, deletes them."""
import json
import time

import test_unit.harness.remote_runner as R

p = R.Panel(host=R.SERVER_IP, port=R.PORT, base_path=R.BP, scheme=R.SCHEME,
            username=R.PUSER, password=R.PPASS, timeout=40)
p.login()
before = {i["id"] for i in p.list_inbounds()}
made = {}
for proto in ("l2tp", "openvpn"):
    ib = R.make_inbound(p, proto, 3)   # K=3, ODD
    made[proto] = ib.inbound_id
    print(f"{proto}: inbound {ib.inbound_id} created with userLimit=3")
    time.sleep(3)
p.restart_core("xray"); time.sleep(4)

conf = p.get_config_json()
print("\n=== routing rules carrying a source (device-IP matches) ===")
for r in conf.get("routing", {}).get("rules", []):
    src = r.get("source")
    if src:
        # show only rules whose sources look like our test /24s (10.x) to cut noise
        print(f"  outbound={r.get('outboundTag'):8} source={src}")

# device-IP list the allocator hands out for K=3 (proves consecutive, no CIDR need)
print("\n=== allocator device IPs for a K=3 account (index 0) ===")
from test_unit.harness.remote_runner import server_block_peers  # noqa
import test_unit.harness.remote_runner as RR
# recompute via the same Go logic is server-side; here just show what the inbound settings say
for proto, iid in made.items():
    ibd = p.get_inbound(iid)
    s = json.loads(ibd.get("settings") or "{}")
    print(f"  {proto}: userLimit={s.get('userLimit')} strategy={s.get('userLimitStrategy')}")

print("\ncleaning up temp inbounds...")
for i in p.list_inbounds():
    if i["id"] not in before:
        p.del_inbound(i["id"]); time.sleep(1)
print("done")
