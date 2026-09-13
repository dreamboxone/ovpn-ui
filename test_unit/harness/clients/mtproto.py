"""MTProto proxy (telemt) client driver: NOT a tunnel.

Unlike the other 7 protocols there is no tunnel interface, no assigned client IP
and no ppp0/tun0: a client opens a TCP connection to the proxy port carrying a
per-account SECRET and the proxy relays MTProto to a Telegram DC. So this module
deliberately does NOT implement the connect()/disconnect() tunnel contract the
other drivers share: there is nothing to bring up or tear down, and none of
tunnel_egress / dns_leak / routing-by-source-IP / client_ip() apply.

What it drives instead is `mtproto_probe.py`, executed ON the client VM (raw
sockets from the client's own IP, which is what telemt's unique-IP limit counts).
The prober speaks the real client half of the protocol:

  * FakeTLS (`ee`), a ClientHello whose `random` is HMAC-SHA256(secret, hello);
    the proxy must answer with a ServerHello whose own random is
    HMAC-SHA256(secret, client_digest || serverhello). Only a secret-holder can
    produce that, so this mode is SELF-PROVING with no Telegram involved.
  * obfuscated2 (classic `ef` / secure `dd`), the 64-byte AES-CTR handshake keyed
    sha256(key || secret). The proxy sends NOTHING back, so acceptance is not
    observable client-side; the relayed resPQ below is the only proof.
  * req_pq_multi -> resPQ: the first UNAUTHENTICATED message of the MTProto
    auth-key exchange. A real DC echoes our 128-bit nonce. Needs no api_id/
    api_hash and no login, but does need the PROXY to reach a Telegram DC.

Verification limits (measured, not assumed: see the E2E design notes):
  * classic/secure CANNOT be verified without the relay probe. Confirmed against a
    socket that answers nothing: the handshake "succeeds". The prober returns exit
    4 (Inconclusive) there and the caller maps it to Status.NA, never PASS.
  * Telegram creds are NOT required for any subtest here. Telethon is not used: it
    silently strips an `ee` prefix + domain and downgrades to classic obfuscated2
    (normalize_secret), so driving the tls mode through it would test classic while
    claiming to test tls.
  * Throughput ceiling is ~1.6 KiB/s per connection (each req_pq is a DC round-trip
    and DCs do not pipeline unauthenticated requests), scaling ~linearly with
    connections. KiB-scale quotas are fine; MiB-scale ones are not.
"""
from __future__ import annotations

import json
import os

from .base import Client

# Executed on the client VM: the source IP telemt sees must be the client's own.
PROBE_SRC = os.path.join(os.path.dirname(__file__), "mtproto_probe.py")
PROBE_DST = "/root/mtproto_probe.py"

MODES = ("classic", "secure", "tls")

# Telegram production DCs (port 443). Used only as a PRECONDITION probe from the
# server: if telemt cannot reach a DC, the relay-dependent subtests are NA
# (environment) rather than FAIL (product).
TELEGRAM_DCS = ("149.154.175.50", "149.154.167.51", "149.154.175.100",
                "149.154.167.91", "91.108.56.130")


def ensure_probe(client: Client) -> tuple[bool, str]:
    """Push the prober to the client VM and verify its one dependency. Returns
    (ok, log). A missing dep is reported loudly: never silently degraded."""
    try:
        with open(PROBE_SRC) as f:
            client.push(f.read(), PROBE_DST, mode="0755")
    except OSError as e:
        return False, f"could not push the prober: {e}"
    _, out = client.sh(
        "python3 -c 'from cryptography.hazmat.primitives.ciphers import Cipher' "
        "2>&1 && echo DEPOK")
    if "DEPOK" not in out:
        return False, ("client VM lacks python3-cryptography (the prober needs "
                       f"AES-CTR); add it to CLIENT_PKGS_APT\n{out}")
    return True, f"prober ready at {PROBE_DST}"


def secret(inbound, which: str, mode: str) -> str:
    """The account's secret for one mode, as published by the panel.
    inbound.mt_secrets = {which: {mode: secret_hex}} (server_setup._fetch_mt_secrets)."""
    return ((getattr(inbound, "mt_secrets", {}) or {}).get(which) or {}).get(mode, "")


def dc_reachable(server_exec) -> tuple[bool, str]:
    """Can the SERVER open TCP 443 to any Telegram DC? telemt dials out from there,
    so this gates every relay-dependent subtest to NA instead of FAIL when the run
    happens behind a network that blocks Telegram."""
    if server_exec is None:
        return False, "no server_exec (cannot check Telegram DC reachability)"
    probe = "; ".join(
        f'timeout 5 bash -c "echo > /dev/tcp/{ip}/443" 2>/dev/null '
        f'&& {{ echo OPEN {ip}; exit 0; }}' for ip in TELEGRAM_DCS)
    try:
        _, out, _ = server_exec(f"({probe}); echo NONE", timeout=45)
    except Exception as e:  # noqa: BLE001
        return False, f"DC reachability probe failed: {e}"
    return ("OPEN" in (out or "")), (out or "").strip()


def _run(client: Client, args: list, timeout: int) -> tuple[int, dict, str]:
    """Run the prober; return (rc, parsed_json, raw_output). rc: 0=pass 2=fail
    4=inconclusive(NA) 3=usage."""
    rc, out = client.sh(f"python3 {PROBE_DST} " + " ".join(args), timeout=timeout)
    info = {}
    for ln in (out or "").strip().splitlines():
        if ln.startswith("{"):
            try:
                info = json.loads(ln)
            except ValueError:
                pass
    return rc, info, out


def probe(client: Client, inbound, which: str, mode: str, server_ip: str = "",
          relay: bool = True, expect_fail: bool = False, secret_override: str = "",
          hold: float = 0.0, timeout: int = 90) -> tuple[str, dict, str]:
    """One probe from the client VM.

    Returns (verdict, info, log) with verdict in {"pass","fail","na"}:
      * relay=True  -> requires resPQ from a real DC through the proxy (end-to-end).
      * relay=False -> tls only: the faketls HMAC alone proves the proxy holds the
        secret. classic/secure return "na" (the prober refuses to guess).
      * expect_fail -> negative control: "pass" only when the proxy REFUSES.
      * hold=N      -> keep the socket OPEN N more seconds after the proof, so a
        concurrent unique-IP limit still counts this device as connected. Call it in
        a thread (the run is blocking for ~N seconds).
    """
    sec = secret_override or secret(inbound, which, mode)
    if not sec:
        return "fail", {}, (f"no {mode} secret for account {which}, the panel did "
                            "not publish one (mtproto-links fetch failed?)")
    # MTProto is TCP-only: the inbound carries its listener in tcp_port and leaves
    # udp_port at 0. Reading udp_port here dials port 0 and every probe dies with
    # "connection refused" that looks exactly like a broken proxy.
    args = ["--host", server_ip, "--port", str(inbound.tcp_port), "--mode", mode,
            "--secret", sec, "--timeout", "20"]
    if not relay:
        args.append("--no-relay")
    if expect_fail:
        args.append("--expect-fail")
    if hold > 0:
        args += ["--hold", str(hold)]
    rc, info, log = _run(client, args, timeout)
    verdict = {0: "pass", 4: "na"}.get(rc, "fail")
    return verdict, info, log


def drive_bytes(client: Client, inbound, which: str, mode: str, server_ip: str,
                target_bytes: int, conns: int = 16,
                timeout: int = 120) -> tuple[int, dict, str]:
    """Push ~target_bytes through the proxy on `conns` parallel connections and
    report the EXACT bytes pushed (the prober counts them itself), so the caller can
    compare against the panel's counter without trusting either side's estimate.

    All connections come from ONE client VM = ONE source IP, so this does not trip a
    unique-IP limit. Returns (bytes_pushed, info, log)."""
    sec = secret(inbound, which, mode)
    if not sec:
        return 0, {}, f"no {mode} secret for account {which}"
    rc, info, log = _run(client, [
        "--host", server_ip, "--port", str(inbound.tcp_port), "--mode", mode,
        "--secret", sec, "--flood-bytes", str(target_bytes),
        "--conns", str(conns), "--timeout", str(min(timeout - 20, 60)),
    ], timeout)
    return int(info.get("bytes_total", 0) or 0), info, log


def disconnect(client: Client):
    """No tunnel and no daemon: each probe opens and closes its own sockets. Present
    so callers can treat this driver uniformly; killing a stray prober is enough."""
    client.sh("pkill -f mtproto_probe.py 2>/dev/null; true")
