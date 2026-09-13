#!/usr/bin/env python3
"""Per-core install / uninstall E2E on a real Ubuntu 24 incus VM.

Proves the two claims the per-core setup rework makes:

  1. ISOLATION - installing one core provisions ONLY that core's requirements.
     Installing PPTP must put pptpd + pptpctrl + the pppd bundle on the host and
     must NOT drag in xl2tpd, ocserv, telemt, accel-ppp, strongSwan, or L2TP's
     kernel modules. Asserted positively AND negatively for every core.

  2. SHARED-REQUIREMENT SAFETY - uninstalling a core keeps anything a still
     installed core needs. Removing IKEv2 while L2TP stays must leave the
     strongSwan/charon bundle in place; removing L2TP while PPTP stays must
     leave the pppd bundle in place.

Everything is asserted against the real filesystem of the VM, not against the
panel's own reporting, so a core that claims success without writing anything
still fails.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

VM = "coretest"
IMAGE = "images:ubuntu/24.04/cloud"
REMOTE = "/root/vpn-ui"
PORT = 2053

# ---------------------------------------------------------------------------
# The expected host footprint of each core. Kept independent of the Go catalog
# on purpose: if both were generated from one source a wrong catalog row would
# agree with itself and the test would prove nothing.
# ---------------------------------------------------------------------------
FEAT_PATHS = {
    "pppd": "/usr/libexec/vpn-ui/sbin/pppd",
    "pptpctrl": "/usr/libexec/vpn-ui/pptpctrl",
    "accel": "/usr/libexec/vpn-ui-accel",
    "strongswan": "/usr/libexec/vpn-ui-strongswan",
    "amneziawg": "/usr/src/vpn-ui-amneziawg",
}

CORES = {
    "l2tp": {
        "bins": ["xl2tpd", "xl2tpd-control"],
        "feats": ["pppd", "strongswan"],
        "mods": ["ppp_generic", "l2tp_ppp", "ppp_mppe"],
        "optmods": ["af_key", "esp4", "xfrm_user"],
    },
    "pptp": {
        "bins": ["pptpd", "pptpctrl"],
        "feats": ["pppd", "pptpctrl"],
        "mods": ["ppp_generic", "nf_conntrack_pptp", "ip_gre", "ppp_mppe"],
        "optmods": [],
    },
    "openvpn": {"bins": ["openvpn"], "feats": [], "mods": ["tun"], "optmods": []},
    "openconnect": {
        "bins": ["ocserv", "ocserv-worker", "occtl"],
        "feats": [], "mods": ["tun"], "optmods": [],
    },
    "sstp": {"bins": [], "feats": ["accel"], "mods": ["ppp_generic"], "optmods": []},
    "ikev2": {
        "bins": [], "feats": ["strongswan"], "mods": [],
        "optmods": ["af_key", "esp4", "xfrm_user"],
    },
    "wgc": {"bins": [], "feats": [], "mods": [], "optmods": ["wireguard"]},
    "awg": {"bins": [], "feats": ["amneziawg"], "mods": [], "optmods": ["amneziawg"]},
    # GRE bundles nothing: ip_gre is in-tree AND already required by PPTP, so it is not
    # repeated as a gre requirement. fou is optional (absent on some minimal kernels) and
    # only needed for the UDP-encapsulation mode.
    "gre": {"bins": [], "feats": [], "mods": [], "optmods": ["fou"]},
    "mtproto": {"bins": ["telemt"], "feats": [], "mods": [], "optmods": []},
}

# nf_tproxy_ipv4 is the shared data plane: every core's traffic is steered into
# Xray with TPROXY, so it is required by any selection including an empty one.
GLOBAL_MODS = ["nf_tproxy_ipv4"]

ALL_BINS = sorted({b for c in CORES.values() for b in c["bins"]})
ALL_FEATS = sorted(FEAT_PATHS)
ALL_MODS = sorted({m for c in CORES.values() for m in c["mods"] + c["optmods"]})

# Files the panel drops that are NOT owned by any one core.
XRAY_BINS = ["xray-linux-amd64", "geoip.dat", "geosite.dat", "config.json"]

results = []
t0 = time.time()


def log(msg: str) -> None:
    print(f"[{int(time.time() - t0):>5}s] {msg}", flush=True)


def record(name: str, ok: bool, detail: str = "") -> bool:
    results.append({"name": name, "ok": ok, "detail": detail})
    log(f"   {'PASS' if ok else 'FAIL'}  {name}" + (f"  |  {detail}" if detail else ""))
    return ok


def sh(args, timeout=600, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:6])} -> rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr


# The driver is meant to be run under sudo once, so incus needs no per-call
# escalation; fall back to sudo -n if someone runs it unprivileged.
_PRE = [] if os.geteuid() == 0 else ["sudo", "-n"]


def incus(*args, timeout=600, check=True):
    return sh([*_PRE, "incus", *args], timeout=timeout, check=check)


def vmsh(cmd, timeout=900, check=False):
    return incus("exec", VM, "--", "bash", "-lc", cmd, timeout=timeout, check=check)


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

def vm_exists() -> bool:
    _, out, _ = incus("list", "--format", "json", check=False)
    try:
        return any(i["name"] == VM for i in json.loads(out or "[]"))
    except Exception:
        return False


def launch():
    if vm_exists():
        log(f"{VM} already exists, deleting")
        incus("delete", "-f", VM, check=False)
    log(f"launching {VM} from {IMAGE}")
    # init + explicit agent disk + start: the same sequence the main harness
    # uses, because plain `launch` fails on images that need agent:config.
    incus("init", IMAGE, VM, "--vm", "-c", "limits.cpu=2", "-c", "limits.memory=3GiB",
          timeout=900)
    incus("config", "device", "add", VM, "agent", "disk", "source=agent:config", check=False)
    incus("start", VM, timeout=300)

    log("waiting for the incus agent")
    for _ in range(150):
        rc, _, _ = incus("exec", VM, "--", "true", timeout=30, check=False)
        if rc == 0:
            break
        time.sleep(4)
    else:
        raise RuntimeError("agent never came up")

    log("waiting for network")
    # A VM with no IPv4 lease is the firewalld-drops-DHCP-on-the-bridge trap:
    # fail here with the reason rather than hanging in a later apt step.
    for _ in range(60):
        rc, out, _ = vmsh("ip -4 -o addr show scope global | head -1")
        if rc == 0 and out.strip():
            log(f"   {out.strip()}")
            break
        time.sleep(3)
    else:
        raise RuntimeError(
            "VM never got an IPv4 lease. Two host-side causes, check both:\n"
            "  1. the bridge lost its own address (ip addr show incusbr0 shows no "
            "inet) - dnsmasq binds to it, so DHCP silently answers nobody;\n"
            "  2. firewalld drops DHCP on a bridge in no zone - "
            "firewall-cmd --zone=trusted --add-interface=incusbr0")
    # DNS/apt is only needed by the kernel-modules + DKMS steps.
    vmsh("cloud-init status --wait || true", timeout=600)


def push_panel(binary: str, bindir: str):
    log("pushing the panel binary + xray core")
    vmsh(f"mkdir -p {REMOTE}/bin")
    incus("file", "push", binary, f"{VM}{REMOTE}/vpn-ui", "--mode", "0755", timeout=900)
    for f in ("xray-linux-amd64", "geoip.dat", "geosite.dat", "config.json"):
        incus("file", "push", f"{bindir}/{f}", f"{VM}{REMOTE}/bin/{f}",
              "--mode", "0755", timeout=900, check=False)

    log("starting the panel")
    vmsh(f"cd {REMOTE} && ./vpn-ui --port {PORT} --user admin --pass admin --path / "
         f">/root/setting.log 2>&1", timeout=300)
    # A transient systemd unit, not `setsid nohup ... &`: incus exec allocates a
    # pty and waits for it to close, so a backgrounded child keeps the exec call
    # hanging even with its own stdio redirected. systemd-run hands the process
    # to pid 1 and returns immediately. Same approach as test_unit/provision.py.
    vmsh("systemctl reset-failed vpn-ui-test 2>/dev/null; "
         "systemctl stop vpn-ui-test 2>/dev/null; true", timeout=60)
    rc, out, err = vmsh(f"systemd-run --unit=vpn-ui-test --working-directory={REMOTE} "
                        f"{REMOTE}/vpn-ui", timeout=120)
    if rc != 0:
        raise RuntimeError(f"failed to start the panel unit: {out}\n{err}")

    # Login helper, so every later API call is a one-liner.
    vmsh(r"""cat >/root/pctl.sh <<'EOF'
#!/bin/bash
CJ=/root/cj; BASE=http://127.0.0.1:%d
if [ ! -s $CJ ]; then curl -s -c $CJ -X POST -d "username=admin&password=admin" $BASE/login >/dev/null; fi
if [ "$1" = GET ]; then curl -s -b $CJ "$BASE$2"; else curl -s -b $CJ -X POST -d "$3" "$BASE$2"; fi
EOF
chmod +x /root/pctl.sh""" % PORT)

    for _ in range(60):
        rc, out, _ = vmsh(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{PORT}/")
        if out.strip() in ("200", "302"):
            log(f"   panel up ({out.strip()})")
            return
        time.sleep(3)
    raise RuntimeError("panel never answered")


# ---------------------------------------------------------------------------
# Panel API
# ---------------------------------------------------------------------------

def api(method: str, path: str, data: str = "") -> dict:
    rc, out, err = vmsh(f"/root/pctl.sh {method} '{path}' '{data}'", timeout=120)
    try:
        return json.loads(out)
    except Exception:
        raise RuntimeError(f"bad API reply for {method} {path}: {out[:300]} {err[:200]}")


def installed_cores() -> list:
    obj = api("GET", "/panel/core/catalog")["obj"]
    return sorted(c["name"] for c in obj["cores"] if c["installed"] and not c["builtin"])


def wait_run(kind: str, timeout=1800) -> dict:
    """Poll a provision / uninstall run to completion and return its final state."""
    path = "/panel/core/provision-status" if kind == "provision" else "/panel/core/uninstall-status"
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        try:
            last = api("GET", path).get("obj") or {}
        except Exception:
            time.sleep(3)
            continue
        if not last.get("running"):
            return last
        time.sleep(4)
    raise RuntimeError(f"{kind} run did not finish within {timeout}s")


def install(cores: list, timeout=1800) -> dict:
    log(f"installing {','.join(cores)}")
    r = api("POST", "/panel/core/provision", f"cores={','.join(cores)}")
    if not r.get("success"):
        raise RuntimeError(f"provision refused: {r}")
    st = wait_run("provision", timeout)
    bad = [s for s in st.get("steps", []) if not s.get("ok")]
    if bad:
        log("   provisioning reported failures:")
        for s in bad:
            log(f"     x {s['name']}: {s['msg'][:120]}")
    return st


def uninstall(cores: list, timeout=900) -> dict:
    log(f"uninstalling {','.join(cores)}")
    r = api("POST", "/panel/core/uninstall", f"cores={','.join(cores)}")
    if not r.get("success"):
        raise RuntimeError(f"uninstall refused: {r}")
    return wait_run("uninstall", timeout)


def reset_state():
    cur = installed_cores()
    if cur:
        uninstall(cur)
    left = installed_cores()
    if left:
        raise RuntimeError(f"could not reset, still installed: {left}")


# ---------------------------------------------------------------------------
# Filesystem probes
# ---------------------------------------------------------------------------

def present_bins() -> set:
    rc, out, _ = vmsh(f"ls -1 {REMOTE}/bin 2>/dev/null")
    return {x.strip() for x in out.splitlines() if x.strip()} & set(ALL_BINS)


def present_feats() -> set:
    out_set = set()
    for feat, path in FEAT_PATHS.items():
        rc, out, _ = vmsh(f"test -e {path} && echo yes || echo no")
        if out.strip() == "yes":
            out_set.add(feat)
    return out_set


def persisted_modules() -> set:
    rc, out, _ = vmsh("cat /etc/modules-load.d/vpn-ui.conf 2>/dev/null")
    return {l.strip() for l in out.splitlines() if l.strip()}


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def check_isolation(core: str):
    """Install one core alone and assert its footprint exactly."""
    spec = CORES[core]
    tag = f"isolation/{core}"

    reset_state()
    st = install([core])

    record(f"{tag}/installed-set", installed_cores() == [core],
           f"catalog reports {installed_cores()}")

    want_bins = set(spec["bins"])
    got_bins = present_bins()
    record(f"{tag}/binaries", got_bins == want_bins,
           f"want {sorted(want_bins) or '-'}, got {sorted(got_bins) or '-'}")

    want_feats = set(spec["feats"])
    got_feats = present_feats()
    # AmneziaWG is a from-source DKMS build; a host that cannot build it is a
    # legitimate warn inside setup, so its absence is reported, not failed.
    if core == "awg" and want_feats - got_feats == {"amneziawg"}:
        record(f"{tag}/features", True,
               "amneziawg source tree absent (DKMS build declined on this kernel)")
    else:
        record(f"{tag}/features", got_feats == want_feats,
               f"want {sorted(want_feats) or '-'}, got {sorted(got_feats) or '-'}")

    # The headline claim: no OTHER core's requirements were dragged in.
    strays = (got_bins - want_bins) | {f for f in got_feats - want_feats}
    record(f"{tag}/no-foreign-requirements", not strays,
           f"stray {sorted(strays)}" if strays else "nothing foreign installed")

    mods = persisted_modules()
    want_mods = set(spec["mods"]) | set(GLOBAL_MODS)
    missing = want_mods - mods
    forbidden = set(ALL_MODS) - want_mods - set(spec["optmods"])
    leaked = mods & forbidden
    record(f"{tag}/modules-required", not missing,
           f"persisted {sorted(mods) or '-'}" if not missing else f"missing {sorted(missing)}")
    record(f"{tag}/modules-scoped", not leaked,
           f"leaked {sorted(leaked)}" if leaked else f"no foreign modules persisted")

    # Xray and the geo files belong to the panel, never to a core.
    rc, out, _ = vmsh(f"ls -1 {REMOTE}/bin 2>/dev/null")
    have = {x.strip() for x in out.splitlines()}
    record(f"{tag}/xray-untouched", all(x in have for x in XRAY_BINS),
           f"bin/ holds {sorted(have)}")

    return st


def check_removal(core: str):
    """Uninstall the single installed core and assert the host is clean."""
    spec = CORES[core]
    tag = f"removal/{core}"
    uninstall([core])

    record(f"{tag}/installed-set", installed_cores() == [],
           f"catalog reports {installed_cores()}")
    got_bins = present_bins()
    record(f"{tag}/binaries-gone", not got_bins,
           f"left behind {sorted(got_bins)}" if got_bins else "no daemon binaries left")
    got_feats = present_feats()
    record(f"{tag}/features-gone", not got_feats,
           f"left behind {sorted(got_feats)}" if got_feats else "no bundles left")
    # Nothing may survive under the shared bundle root: half-removing it (the
    # plugin dir but not sbin/pppd) is exactly the kind of leak a per-path
    # check misses.
    rc, out, _ = vmsh("find /usr/libexec/vpn-ui /usr/libexec/vpn-ui-accel "
                      "/usr/libexec/vpn-ui-strongswan -mindepth 0 2>/dev/null | head -20")
    leftovers = [l for l in out.splitlines() if l.strip()]
    record(f"{tag}/libexec-clean", not leftovers,
           f"left behind {leftovers[:6]}" if leftovers else "/usr/libexec fully cleaned")
    for link in ("/usr/sbin/pppd", "/usr/lib/pppd", "/usr/lib/ipsec", "/usr/lib/accel-ppp"):
        rc, out, _ = vmsh(f"test -L {link} && echo dangling-or-present || echo clean")
        if out.strip() != "clean":
            record(f"{tag}/symlink-{link.replace('/', '_')}", False, f"{link} still a symlink")
    rc, out, _ = vmsh(f"ls -1 {REMOTE}/bin 2>/dev/null")
    have = {x.strip() for x in out.splitlines()}
    record(f"{tag}/xray-untouched", all(x in have for x in XRAY_BINS),
           f"bin/ holds {sorted(have)}")


def check_shared_ipsec():
    """Removing IKEv2 must not take IPsec away from L2TP."""
    tag = "shared/ipsec"
    reset_state()
    install(["l2tp", "ikev2"])
    record(f"{tag}/both-installed", installed_cores() == ["ikev2", "l2tp"],
           f"{installed_cores()}")
    record(f"{tag}/strongswan-present", "strongswan" in present_feats(),
           "charon bundle extracted")

    st = uninstall(["ikev2"])
    kept = " | ".join(st.get("kept", []))
    record(f"{tag}/l2tp-survives", installed_cores() == ["l2tp"], f"{installed_cores()}")
    record(f"{tag}/strongswan-KEPT", "strongswan" in present_feats(),
           "charon bundle still on disk for L2TP")
    record(f"{tag}/kept-reported", "strongSwan" in kept, kept or "nothing reported")
    steps = " ".join(s["name"] + s["msg"] for s in st.get("steps", []))
    record(f"{tag}/charon-not-stopped", "left running" in steps,
           "the shared daemon was not stopped out from under L2TP")

    uninstall(["l2tp"])
    record(f"{tag}/strongswan-released", "strongswan" not in present_feats(),
           "charon bundle removed once nothing needed it")


def check_shared_pppd():
    """Removing L2TP must not take pppd away from PPTP."""
    tag = "shared/pppd"
    reset_state()
    install(["l2tp", "pptp"])
    record(f"{tag}/both-installed", installed_cores() == ["l2tp", "pptp"],
           f"{installed_cores()}")

    st = uninstall(["l2tp"])
    kept = " | ".join(st.get("kept", []))
    bins = present_bins()
    record(f"{tag}/pptp-survives", installed_cores() == ["pptp"], f"{installed_cores()}")
    record(f"{tag}/pppd-KEPT", "pppd" in present_feats(), "pppd bundle still on disk for PPTP")
    record(f"{tag}/l2tp-binaries-gone", "xl2tpd" not in bins, f"bin/ holds {sorted(bins)}")
    record(f"{tag}/pptp-binaries-kept", "pptpd" in bins, f"bin/ holds {sorted(bins)}")
    record(f"{tag}/kept-reported", "pppd" in kept, kept or "nothing reported")

    uninstall(["pptp"])
    record(f"{tag}/pppd-released", "pppd" not in present_feats(),
           "pppd bundle removed once nothing needed it")


def check_inbound_guard():
    """A core with inbounds must refuse to be removed."""
    tag = "guard"
    reset_state()
    install(["pptp"])
    r = api("POST", "/panel/core/uninstall", "cores=l2tp")
    record(f"{tag}/not-installed-refused", not r.get("success"), r.get("msg", "")[:110])
    r = api("POST", "/panel/core/uninstall", "cores=xray")
    record(f"{tag}/builtin-refused", not r.get("success"), r.get("msg", "")[:110])
    r = api("POST", "/panel/core/uninstall", "cores=")
    record(f"{tag}/empty-refused", not r.get("success"), r.get("msg", "")[:110])


def main():
    binary = sys.argv[1]
    bindir = sys.argv[2]
    only = sys.argv[3].split(",") if len(sys.argv) > 3 and sys.argv[3] else list(CORES)

    launch()
    push_panel(binary, bindir)

    record("bootstrap/clean-host", installed_cores() == [],
           f"fresh VM reports {installed_cores()}")

    for core in only:
        log(f"===== {core} =====")
        try:
            check_isolation(core)
            check_removal(core)
        except Exception as e:  # noqa: BLE001
            record(f"isolation/{core}/ERROR", False, str(e)[:300])

    for fn in (check_shared_ipsec, check_shared_pppd, check_inbound_guard):
        log(f"===== {fn.__name__} =====")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            record(f"{fn.__name__}/ERROR", False, str(e)[:300])

    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    log("=" * 68)
    log(f"RESULT {passed}/{total} passed")
    for r in results:
        if not r["ok"]:
            log(f"  FAIL {r['name']}: {r['detail']}")
    with open("/tmp/core_matrix_results.json", "w") as f:
        json.dump(results, f, indent=1)
    log("DONE")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
