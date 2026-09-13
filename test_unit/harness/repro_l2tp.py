"""Clean 2-device K=1 strategy prover for ANY protocol/transport. Wipes, creates a
fresh inbound at K + strategy, connects device1 then device2 (over-cap), and shows
the outcome + server evidence.
  reject: device2 denied, device1 stays up.
  accept: device2 admitted, device1 evicted (server logs 'evicted oldest device').
Usage: python3 -m test_unit.harness.repro_l2tp <proto> <transport> <K> <strategy>
  e.g. pptp - 1 reject | pptp - 1 accept | l2tp ipsec 1 accept | l2tp raw 1 reject
"""
import sys
import time

import test_unit.harness.remote_runner as R

proto = sys.argv[1] if len(sys.argv) > 1 else "pptp"
transport = sys.argv[2] if len(sys.argv) > 2 else ("udp" if proto == "openvpn" else "raw")
K = int(sys.argv[3]) if len(sys.argv) > 3 else 1
STRAT = sys.argv[4] if len(sys.argv) > 4 else "reject"
iface = "tun0" if proto == "openvpn" else "ppp0"

p = R.Panel(host=R.SERVER_IP, port=R.PORT, base_path=R.BP, scheme=R.SCHEME,
            username=R.PUSER, password=R.PPASS, timeout=40)
p.login()
print(f"=== PROVE {proto}/{transport} K={K} strategy={STRAT} ===")
R.wipe_inbounds(p)
IB = R.make_inbound(p, proto, K)
time.sleep(4)
R.set_K_strategy(p, IB, K, STRAT)
time.sleep(11)

inc = R.LocalIncus()
cA = R.Client(inc, "deb11", "A", R.log)
cB = R.Client(inc, "deb13", "B", R.log)
cA.prep(); cB.prep()
cA.disconnect_all(); cB.disconnect_all(); time.sleep(2)

ok1, ip1, l1 = R.connect(cA, IB, proto, transport)
print(f"device1: ok={ok1} ip={ip1}")
if not ok1:
    print("device1 FAIL log:", l1[-700:])
    print("server pptpd/l2tp:", R.server_exec("pgrep -af 'pptpd|xl2tpd' | head -3; "
          "journalctl -u vpn-ui --since '-30 sec' --no-pager 2>/dev/null | grep -iE 'pptp|GRE|CTRL' | tail -4")[1])
if ok1:
    R.checks.internet(cA)  # traffic-prime so the 2nd concurrent dial from one NAT sticks
time.sleep(2)

print(">>> device2 (OVER-CAP at K={}) <<<".format(K))
ok2, ip2, l2 = R.connect(cB, IB, proto, transport)
n2 = R.checks.internet(cB) if ok2 else None
admitted = ok2 and n2 is not None and n2.status.value == "pass"
print(f"device2: ok={ok2} ip={ip2} admitted={admitted}")

time.sleep(4)
print("--- server evidence (last 35s) ---")
print(R.server_exec('journalctl -u vpn-ui --since "-35 sec" --no-pager 2>/dev/null '
                    '| grep -iE "evicted oldest|user-limit|auth accepted|auth rejected|acct-start" | tail -8')[1])
d1_up = cA.wait_iface(iface, timeout=3)
print(f"device1 still up after device2: {d1_up or 'DOWN(evicted)'}")

if STRAT == "reject":
    verdict = "PASS" if (ok1 and not admitted and d1_up) else "FAIL"
    print(f"REJECT verdict: {verdict} (device1 held={bool(d1_up)}, device2 admitted={admitted})")
else:
    print(f"ACCEPT verdict: device2 admitted={admitted}, device1 evicted={not d1_up} "
          f"(PASS if admitted+evicted)")
cA.disconnect_all(); cB.disconnect_all()
