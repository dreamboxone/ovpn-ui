#!/usr/bin/env python3
"""MTProto-proxy prober: proves an MTProxy really works, without Telegram creds.

Speaks the client half of the MTProxy protocol end to end:

  1. mode `tls`      -> FakeTLS wrapper (ee-secret): a real TLS1.3-shaped ClientHello
                        whose `random` field carries HMAC-SHA256(secret, hello). The
                        proxy answers with a ServerHello whose own random field is
                        HMAC-SHA256(secret, client_digest || serverhello). ONLY a server
                        holding the secret can produce that -> cryptographic proof.
  2. obfuscated2     -> the 64-byte AES-CTR handshake, keyed sha256(key || secret),
                        carrying the codec tag (ef=abridged, ee=intermediate,
                        dd=randomized-intermediate/"secure").
  3. req_pq_multi    -> the first, UNAUTHENTICATED message of the MTProto auth-key
                        exchange. A real Telegram DC answers `resPQ` echoing our
                        128-bit nonce. Needs NO api_id/api_hash and NO login, but does
                        need the PROXY to reach a Telegram DC -> proves end-to-end relay.

Exit code 0 = the probe met its goal, 2 = probe failed, 3 = usage/setup error.
Prints a single JSON object on stdout (the harness parses it).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---- codec tags (see Telethon tcpabridged/tcpintermediate obfuscate_tag) ----
TAG_ABRIDGED = b"\xef\xef\xef\xef"
TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
TAG_RANDOMIZED = b"\xdd\xdd\xdd\xdd"      # "secure" / dd-secret

# first 4 bytes an obfuscated2 nonce may never start with (would alias a real
# protocol): HEAD/POST/GET /OPTI, the dd/ee tags, and 16 03 01 02 (TLS hello)
_FORBIDDEN4 = {
    b"HEAD", b"POST", b"GET ", b"OPTI",
    b"\xdd\xdd\xdd\xdd", b"\xee\xee\xee\xee",
    b"\x16\x03\x01\x02",
}

RESPQ_ID = 0x05162463
REQ_PQ_MULTI_ID = 0xBE7E8EF1


class ProbeError(Exception):
    """The probe ran and the proxy failed it."""


class Inconclusive(Exception):
    """The probe CANNOT decide either way, so it must not report a pass.

    Only raised for classic/secure with relay probing off: obfuscated2 has no
    server->client handshake response, so a silent TCP listener is byte-for-byte
    indistinguishable from a working proxy. Verified: `--no-relay --mode classic`
    against a listener that speaks nothing "succeeds". The relayed resPQ is the
    only client-side proof for those modes; `tls` is exempt because its ServerHello
    digest is an HMAC only a secret-holder can produce."""


class _Ctr:
    """AES-256-CTR with a continuous keystream (obfuscated2 requires it)."""

    def __init__(self, key: bytes, iv: bytes):
        self._c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def crypt(self, data: bytes) -> bytes:
        return self._c.update(data)


# --------------------------------------------------------------------------
# FakeTLS
# --------------------------------------------------------------------------
DIGEST_POS, DIGEST_LEN = 11, 32
SESSION_ID_LEN_POS = DIGEST_POS + DIGEST_LEN     # 43
HELLO_TOTAL = 517          # proxies require the record to be >= 512+5 bytes


def _ext(typ: int, body: bytes) -> bytes:
    return struct.pack(">HH", typ, len(body)) + body


def _client_hello(digest32: bytes, session_id: bytes, sni: str) -> bytes:
    """A TLS1.3-shaped ClientHello, exactly HELLO_TOTAL bytes, `random`=digest32."""
    ciphers = struct.pack(
        ">16H", 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A)
    host = sni.encode()

    exts = b""
    exts += _ext(0x0000, struct.pack(">H", len(host) + 3) + b"\x00"
                 + struct.pack(">H", len(host)) + host)          # server_name (SNI)
    exts += _ext(0x0017, b"")                                     # extended_master_secret
    exts += _ext(0xFF01, b"\x00")                                 # renegotiation_info
    exts += _ext(0x000A, struct.pack(">H", 8)
                 + struct.pack(">4H", 0x001D, 0x0017, 0x0018, 0x0019))  # supported_groups
    exts += _ext(0x000B, b"\x01\x00")                             # ec_point_formats
    exts += _ext(0x0023, b"")                                     # session_ticket
    alpn = b"\x02h2\x08http/1.1"
    exts += _ext(0x0010, struct.pack(">H", len(alpn)) + alpn)     # ALPN
    exts += _ext(0x0005, b"\x01\x00\x00\x00\x00")                 # status_request
    sigalgs = struct.pack(">10H", 0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                          0x0501, 0x0806, 0x0601, 0x0201, 0x0203)
    exts += _ext(0x000D, struct.pack(">H", len(sigalgs)) + sigalgs)   # signature_algorithms
    exts += _ext(0x0012, b"")                                     # SCT
    ks = struct.pack(">HH", 0x001D, 32) + os.urandom(32)          # key_share x25519
    exts += _ext(0x0033, struct.pack(">H", len(ks)) + ks)
    exts += _ext(0x002D, b"\x01\x01")                             # psk_key_exchange_modes
    exts += _ext(0x002B, b"\x04\x03\x04\x03\x03")                 # supported_versions

    fixed = (b"\x03\x03" + digest32 + bytes([len(session_id)]) + session_id
             + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00")
    # pad (ext 0x0015) so the whole record lands on exactly HELLO_TOTAL
    used = 5 + 4 + len(fixed) + 2 + len(exts) + 4
    pad = HELLO_TOTAL - used
    if pad < 0:
        raise ProbeError("client hello template overflows 517 bytes")
    exts += _ext(0x0015, b"\x00" * pad)

    body = fixed + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    if len(rec) != HELLO_TOTAL:
        raise ProbeError(f"client hello is {len(rec)}B, expected {HELLO_TOTAL}")
    return rec


class _Sock:
    def __init__(self, host, port, timeout):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)

    def send(self, b):
        self.s.sendall(b)

    def recv_exact(self, n) -> bytes:
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise ProbeError(f"connection closed by peer after {len(buf)}/{n} bytes")
            buf += c
        return buf

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


class _FakeTLS:
    """Wraps a _Sock in TLS application-data records after a faketls handshake."""

    def __init__(self, sock: _Sock):
        self.sock = sock
        self._buf = b""

    def send(self, data: bytes):
        while data:
            chunk, data = data[:16384], data[16384:]
            self.sock.send(b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk)

    def recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            hdr = self.sock.recv_exact(5)
            if hdr[0] not in (0x14, 0x17):
                raise ProbeError(f"unexpected TLS record type 0x{hdr[0]:02x}")
            body = self.sock.recv_exact(struct.unpack(">H", hdr[3:5])[0])
            if hdr[0] == 0x17:
                self._buf += body
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        self.sock.close()


def _faketls_handshake(sock: _Sock, secret16: bytes, sni: str) -> _FakeTLS:
    """Do the FakeTLS handshake; raise ProbeError unless the server proves it
    holds `secret16` (its ServerHello digest is an HMAC only it could compute)."""
    session_id = os.urandom(32)
    hello = _client_hello(b"\x00" * DIGEST_LEN, session_id, sni)
    mac = hmac.new(secret16, hello, hashlib.sha256).digest()
    ts = struct.pack("<I", int(time.time()))
    digest = mac[:28] + bytes(a ^ b for a, b in zip(mac[28:32], ts))
    hello = hello[:DIGEST_POS] + digest + hello[DIGEST_POS + DIGEST_LEN:]
    sock.send(hello)

    # ServerHello record
    h1 = sock.recv_exact(5)
    if h1[0] != 0x16:
        raise ProbeError(
            f"expected a TLS handshake record (0x16), got 0x{h1[0]:02x} "
            "-> the proxy did not accept the faketls secret")
    resp = h1 + sock.recv_exact(struct.unpack(">H", h1[3:5])[0])
    # ChangeCipherSpec record
    h2 = sock.recv_exact(5)
    resp += h2 + sock.recv_exact(struct.unpack(">H", h2[3:5])[0])
    # first ApplicationData record (the fake cert payload)
    h3 = sock.recv_exact(5)
    resp += h3 + sock.recv_exact(struct.unpack(">H", h3[3:5])[0])

    got = resp[DIGEST_POS:DIGEST_POS + DIGEST_LEN]
    zeroed = resp[:DIGEST_POS] + b"\x00" * DIGEST_LEN + resp[DIGEST_POS + DIGEST_LEN:]
    want = hmac.new(secret16, digest + zeroed, hashlib.sha256).digest()
    if not hmac.compare_digest(got, want):
        raise ProbeError("faketls ServerHello digest mismatch -> the peer does NOT "
                         "hold this secret (a real TLS site or a wrong-secret reject)")
    return _FakeTLS(sock)


# --------------------------------------------------------------------------
# obfuscated2
# --------------------------------------------------------------------------
def _obf2_handshake(conn, secret16: bytes, dc_id: int, tag: bytes):
    while True:
        n = bytearray(os.urandom(64))
        if n[0] == 0xEF or bytes(n[:4]) in _FORBIDDEN4 or n[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    n[56:60] = tag
    n[60:62] = struct.pack("<h", dc_id)

    rev = bytes(n[8:56])[::-1]
    ekey, eiv = bytes(n[8:40]), bytes(n[40:56])
    dkey, div = rev[:32], rev[32:48]
    if secret16:
        ekey = hashlib.sha256(ekey + secret16).digest()
        dkey = hashlib.sha256(dkey + secret16).digest()

    enc, dec = _Ctr(ekey, eiv), _Ctr(dkey, div)
    conn.send(bytes(n[:56]) + enc.crypt(bytes(n))[56:64])
    return enc, dec


# --------------------------------------------------------------------------
# codecs
# --------------------------------------------------------------------------
def _encode(tag: bytes, data: bytes) -> bytes:
    if tag == TAG_ABRIDGED:
        ln = len(data) >> 2
        return (struct.pack("B", ln) if ln < 127
                else b"\x7f" + ln.to_bytes(3, "little")) + data
    if tag == TAG_RANDOMIZED:
        data += os.urandom(os.urandom(1)[0] % 4)
    return struct.pack("<i", len(data)) + data


def _read_packet(read_exact, tag: bytes) -> bytes:
    if tag == TAG_ABRIDGED:
        ln = struct.unpack("<B", read_exact(1))[0]
        if ln >= 127:
            ln = struct.unpack("<i", read_exact(3) + b"\0")[0]
        return read_exact(ln << 2)
    ln = struct.unpack("<i", read_exact(4))[0]
    if ln < 0 or ln > 1 << 20:
        raise ProbeError(f"bogus packet length {ln} (stream is not MTProto)")
    body = read_exact(ln)
    if tag == TAG_RANDOMIZED and len(body) % 4:
        body = body[:-(len(body) % 4)]
    return body


# --------------------------------------------------------------------------
# req_pq_multi / resPQ
# --------------------------------------------------------------------------
def _msg_id() -> int:
    return (int(time.time()) << 32) | (int.from_bytes(os.urandom(4), "big") & ~3)


def _req_pq(nonce: bytes) -> bytes:
    body = struct.pack("<I", REQ_PQ_MULTI_ID) + nonce
    return b"\x00" * 8 + struct.pack("<q", _msg_id()) + struct.pack("<i", len(body)) + body


def _parse_respq(pkt: bytes, nonce: bytes) -> dict:
    if len(pkt) < 24:
        raise ProbeError(f"reply too short ({len(pkt)}B) to be an MTProto message")
    auth_key_id = struct.unpack("<q", pkt[:8])[0]
    if auth_key_id != 0:
        raise ProbeError(f"reply auth_key_id={auth_key_id}, expected 0 (plaintext)")
    dlen = struct.unpack("<i", pkt[16:20])[0]
    data = pkt[20:20 + dlen]
    cid = struct.unpack("<I", data[:4])[0]
    if cid != RESPQ_ID:
        raise ProbeError(f"reply constructor 0x{cid:08x}, expected resPQ 0x{RESPQ_ID:08x}")
    if data[4:20] != nonce:
        raise ProbeError("resPQ nonce does not echo ours -> not a genuine DC reply")
    return {"server_nonce": data[20:36].hex()}


# --------------------------------------------------------------------------
# the probe
# --------------------------------------------------------------------------
MODE_TAG = {"classic": TAG_ABRIDGED, "secure": TAG_RANDOMIZED, "tls": TAG_RANDOMIZED}


def probe(host, port, secret_hex, mode, dc_id=2, timeout=15, relay=True, hold=0.0) -> dict:
    """One full probe. Returns a result dict; raises ProbeError on failure.

    `hold` keeps the connection OPEN for N more seconds after the proof lands. The
    unique-IP limit counts concurrently-connected source IPs, so the K admitted
    devices must still be holding their sockets when the (K+1)th dials in."""
    secret_hex = secret_hex.strip().lower()
    sni = ""
    if mode == "tls":
        if not secret_hex.startswith("ee"):
            raise ProbeError(f"mode=tls needs an 'ee' secret, got {secret_hex[:2]!r}")
        key = bytes.fromhex(secret_hex[2:34])
        sni = bytes.fromhex(secret_hex[34:]).decode("utf-8", "replace")
        if not sni:
            raise ProbeError("ee-secret carries no domain")
    elif mode == "secure":
        if not secret_hex.startswith("dd"):
            raise ProbeError(f"mode=secure needs a 'dd' secret, got {secret_hex[:2]!r}")
        key = bytes.fromhex(secret_hex[2:34])
    else:
        if len(secret_hex) != 32:
            raise ProbeError(f"mode=classic needs a bare 16-byte secret, got {len(secret_hex)//2}B")
        key = bytes.fromhex(secret_hex)
    if len(key) != 16:
        raise ProbeError(f"secret key is {len(key)}B, expected 16")

    res = {"mode": mode, "host": host, "port": port, "sni": sni,
           "faketls_verified": False, "relayed": False}
    t0 = time.monotonic()
    sock = _Sock(host, port, timeout)
    conn = sock
    try:
        if mode == "tls":
            conn = _faketls_handshake(sock, key, sni)
            res["faketls_verified"] = True

        tag = MODE_TAG[mode]
        enc, dec = _obf2_handshake(conn, key, dc_id, tag)
        res["codec"] = {TAG_ABRIDGED: "abridged", TAG_INTERMEDIATE: "intermediate",
                        TAG_RANDOMIZED: "randomized-intermediate"}[tag]
        if not relay:
            if mode != "tls":
                raise Inconclusive(
                    f"mode={mode} cannot be verified without probing the relay: "
                    "obfuscated2 has no server handshake response, so a socket that "
                    "answers nothing is indistinguishable from a working proxy")
            res["detail"] = ("faketls ServerHello HMAC verified: the proxy holds this "
                             "secret (upstream relay not probed)")
            return res

        nonce = os.urandom(16)
        conn.send(enc.crypt(_encode(tag, _req_pq(nonce))))
        pkt = _read_packet(lambda n: dec.crypt(conn.recv_exact(n)), tag)
        res.update(_parse_respq(pkt, nonce))
        res["relayed"] = True
        res["detail"] = "resPQ received from a real Telegram DC through the proxy"
        if hold > 0:
            time.sleep(hold)
            res["held_s"] = hold
        return res
    finally:
        res["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        conn.close()


def flood(host, port, secret_hex, mode, target, conns, dc_id, timeout) -> dict:
    """Drive ~`target` bytes through the proxy on `conns` parallel connections and
    report the EXACT byte counts we pushed, so the caller can compare them against
    the panel's counter.

    Unauthenticated MTProto is the only traffic available without api_id/api_hash,
    so this loops req_pq_multi. MEASURED ceiling: ~1.6 KiB/s per connection (each
    req_pq is a full round-trip to the DC and DCs do NOT pipeline unauthenticated
    requests - 400 sent got 4 answered). It scales ~linearly with connections
    (24 conns ~= 35 KiB/s), so this is fine for KiB-scale quotas and hopeless for
    MiB-scale ones. Size quotas accordingly."""
    import threading
    per = max(1, target // max(1, conns))
    tot = {"up": 0, "down": 0, "rt": 0, "err": ""}
    lock = threading.Lock()

    def worker():
        up = down = rt = 0
        err = ""
        try:
            secret_hex_l = secret_hex.strip().lower()
            key = bytes.fromhex(
                secret_hex_l[2:34] if mode in ("secure", "tls") else secret_hex_l)
            sock = _Sock(host, port, timeout)
            conn = sock
            if mode == "tls":
                conn = _faketls_handshake(
                    sock, key, bytes.fromhex(secret_hex_l[34:]).decode("utf-8", "replace"))
            tag = MODE_TAG[mode]
            enc, dec = _obf2_handshake(conn, key, dc_id, tag)
            end = time.monotonic() + timeout
            while up + down < per and time.monotonic() < end:
                nonce = os.urandom(16)
                pkt = _encode(tag, _req_pq(nonce))
                conn.send(enc.crypt(pkt))
                up += len(pkt)
                got = [0]

                def rd(n):
                    b = conn.recv_exact(n)
                    got[0] += n
                    return dec.crypt(b)

                _parse_respq(_read_packet(rd, tag), nonce)
                down += got[0]
                rt += 1
            conn.close()
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        with lock:
            tot["up"] += up
            tot["down"] += down
            tot["rt"] += rt
            if err and not tot["err"]:
                tot["err"] = err

    t0 = time.monotonic()
    ths = [threading.Thread(target=worker) for _ in range(conns)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=timeout + 10)
    el = max(0.001, time.monotonic() - t0)
    total = tot["up"] + tot["down"]
    return {"ok": total > 0, "mode": mode, "flood": True, "conns": conns,
            "bytes_up": tot["up"], "bytes_down": tot["down"], "bytes_total": total,
            "round_trips": tot["rt"], "elapsed_ms": int(el * 1000),
            "rate_kib_s": round(total / el / 1024, 1), "target": target,
            "first_error": tot["err"],
            "detail": f"pushed {total} B ({tot['rt']} req_pq round-trips) in {el:.1f}s"}


def main():
    ap = argparse.ArgumentParser(description="MTProxy prober")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secret", required=True, help="hex secret (bare / dd… / ee…)")
    ap.add_argument("--mode", required=True, choices=["classic", "secure", "tls"])
    ap.add_argument("--dc", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--no-relay", action="store_true",
                    help="stop after the proxy handshake (do not require Telegram)")
    ap.add_argument("--expect-fail", action="store_true",
                    help="negative control: exit 0 only if the probe FAILS")
    ap.add_argument("--flood-bytes", type=int, default=0,
                    help="drive ~N bytes through the proxy and report exact counts")
    ap.add_argument("--conns", type=int, default=16,
                    help="parallel connections for --flood-bytes")
    ap.add_argument("--hold", type=float, default=0.0,
                    help="hold the connection open N seconds after the proof "
                         "(so a unique-IP limit sees it as still connected)")
    a = ap.parse_args()

    if a.flood_bytes:
        r = flood(a.host, a.port, a.secret, a.mode, a.flood_bytes, a.conns,
                  a.dc, a.timeout)
        print(json.dumps(r, sort_keys=True))
        return 0 if r["ok"] else 2

    try:
        r = probe(a.host, a.port, a.secret, a.mode, a.dc, a.timeout,
                  not a.no_relay, a.hold)
        r["ok"] = True
    except Inconclusive as e:
        # Exit 4 is NOT a product failure and NOT a pass: the harness maps it to NA.
        print(json.dumps({"ok": False, "inconclusive": True, "mode": a.mode,
                          "error": str(e)}, sort_keys=True))
        return 4
    except (ProbeError, OSError, ValueError) as e:
        r = {"ok": False, "mode": a.mode, "error": f"{type(e).__name__}: {e}"}

    if a.expect_fail:
        r["expect_fail"] = True
        r["ok"] = not r["ok"]
        r["detail"] = ("negative control passed: the proxy REFUSED this connection"
                       if r["ok"] else
                       "negative control FAILED: the proxy ACCEPTED a connection it should have refused")
    print(json.dumps(r, sort_keys=True))
    return 0 if r["ok"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(3)
