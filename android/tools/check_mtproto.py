"""Cross-check of the Android MTProto handshake algorithm.

Mirrors android/src/com/miiko3/mtprotofinder/{MainActivity,LocalBridge}.java
exactly, so we can tell "proxies are dead" apart from "our handshake is wrong".
"""
import hashlib
import os
import re
import socket
import struct
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from Crypto.Cipher import AES

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
ABRIDGED = b"\xef\xef\xef\xef"
SECURE_DD = b"\xdd\xdd\xdd\xdd"
RESERVED = (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02")

MT_SOURCES = [
    "https://cdn.jsdelivr.net/gh/tgmtproxy/telegram-mtproto-proxy-list@main/proxies.txt",
    "https://cdn.jsdelivr.net/gh/kort0881/telegram-proxy-collector@main/proxy_list.txt",
    "https://cdn.jsdelivr.net/gh/Argh94/telegram-proxy-scraper@main/proxy.txt",
    "https://cdn.jsdelivr.net/gh/kort0881/telegram-proxy-collector@main/proxy_all_mtproto.txt",
    "https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt",
    "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt",
    "https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt",
    "https://cdn.jsdelivr.net/gh/horizonpaz-create/mtproto-live@main/mtproto.txt",
]

LINK_RE = re.compile(r"(server|port|secret)=([^&\s]+)")


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "MTProtoFinder"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse(text):
    out = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        m = dict((k, v) for k, v in LINK_RE.findall(line))
        if "server" in m and "port" in m:
            sec = m.get("secret", "")
            # same gate as Net.normSecret in the Android app
            if not re.fullmatch(r"[0-9a-fA-F]{32,}", sec or ""):
                continue
            try:
                out.append((m["server"].strip().rstrip("."), int(m["port"]), sec.lower()))
            except ValueError:
                pass
    return out


def secret_bytes(secret_hex):
    h = (secret_hex or "").strip().lower()
    if h.startswith("dd") and len(h) == 34:
        h = h[2:]
    h = h[:32]
    return bytes.fromhex(h)


def derive(region48, secret):
    fk = hashlib.sha256(region48[:32] + secret).digest()
    fiv = region48[32:48]
    rr = region48[::-1]
    rk = hashlib.sha256(rr[:32] + secret).digest()
    riv = rr[32:48]
    return fk, fiv, rk, riv


def good_nonce(tag, dc_id):
    while True:
        r = bytearray(os.urandom(64))
        if r[0] == 0xEF or bytes(r[:4]) in RESERVED or r[4:8] == b"\x00\x00\x00\x00":
            continue
        r[56:60] = tag
        r[60:62] = (dc_id & 0xFFFF).to_bytes(2, "little")
        r[62:64] = b"\x00\x00"
        return r


def build_head(secret, dc_id, tag):
    raw = secret_bytes(secret)
    r = good_nonce(tag, dc_id)
    fk, fiv, rk, riv = derive(bytes(r[8:56]), raw)
    enc = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
    full = enc.encrypt(bytes(r))
    return bytes(r[:56]) + full[56:64], enc, AES.new(rk, AES.MODE_CTR, nonce=b"", initial_value=riv)


def frame_consumed(data, pi):
    if len(data) < 1:
        return None
    if not pi:
        b0 = data[0]
        if b0 == 0x7F:
            if len(data) < 4:
                return None
            ln = int.from_bytes(data[1:4], "little") * 4
            if len(data) < 4 + ln:
                return None
            return 4 + ln, 4
        ln = b0 * 4
        if len(data) < 1 + ln:
            return None
        return 1 + ln, 1
    if len(data) < 4:
        return None
    ln = int.from_bytes(data[:4], "little") & 0x7FFFFFFF
    if len(data) < 4 + ln:
        return None
    return 4 + ln, 4


def mtproto_ping(host, port, secret, timeout=3.0):
    """Returns (ms, ok). Mirrors Net.handshakePing's non-ee branch."""
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return -2.0, "connect:%s" % type(e).__name__
    try:
        s.settimeout(timeout)
        sec = (secret or "").lower()
        pi = sec.startswith("dd") and len(sec) == 34
        tag = SECURE_DD if pi else ABRIDGED
        head, enc, dec = build_head(secret, 2, tag)
        s.sendall(head)
        return _exchange(s, enc, dec, pi, timeout, t0)
    except OSError as e:
        return -2.0, "io:%s" % type(e).__name__
    finally:
        s.close()


def _exchange(s, enc, dec, pi, timeout, t0):
    nonce = os.urandom(16)
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
    frame = (struct.pack("<I", len(body)) if pi else bytes([len(body) // 4])) + body
    s.sendall(enc.encrypt(frame))

    data = b""
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return -2.0, "timeout"
        if not chunk:
            return -2.0, "eof"
        data += dec.encrypt(chunk)
        while True:
            parsed = frame_consumed(data, pi)
            if parsed is None:
                break
            used, off = parsed
            payload = data[off:used]
            data = data[used:]
            if len(payload) >= 20 and int.from_bytes(payload[:4], "little") == RES_PQ and payload[4:20] == nonce:
                return (time.perf_counter() - t0) * 1000, "OK"
    return -2.0, "norespq"


def domain_from_secret(sec):
    h = (sec or "").lower()
    if not h.startswith("ee") or len(h) < 36:
        return "www.cloudflare.com"
    offs = [34] + [o for o in range(2, min(64, len(h) - 6), 2) if o != 34]
    for off in offs:
        out, clean, i = "", True, off
        while i + 1 < len(h):
            try:
                ch = bytes([int(h[i:i + 2], 16)]).decode("ascii")
            except Exception:
                clean = False
                break
            if not (ch.isalnum() or ch in ".-"):
                break
            out += ch
            i += 2
        if clean and len(out) >= 4 and "." in out and not re.fullmatch(r"[\d.]+", out):
            return out
    return "www.cloudflare.com"


def obf_secret_bytes(secret_hex):
    raw = bytes.fromhex(secret_hex.strip().lower())
    if len(raw) >= 17 and raw[0] == 0xEE:
        return raw[1:17]
    return secret_bytes(secret_hex)


def build_head_ee(secret_hex, dc_id, tag):
    raw = obf_secret_bytes(secret_hex)
    r = good_nonce(tag, dc_id)
    fk, fiv, rk, riv = derive(bytes(r[8:56]), raw)
    enc = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
    full = enc.encrypt(bytes(r))
    return bytes(r[:56]) + full[56:64], enc, AES.new(rk, AES.MODE_CTR, nonce=b"", initial_value=riv)


def faketsls_ping(host, port, secret, timeout=4.0):
    """Mirrors Net.faketslsPing: real MTProto handshake inside a TLS tunnel."""
    import ssl
    t0 = time.perf_counter()
    dom = domain_from_secret(secret)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return -2.0, "connect:%s" % type(e).__name__
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = ctx.wrap_socket(raw, server_hostname=dom)
    except Exception as e:
        raw.close()
        return -2.0, "tls:%s" % type(e).__name__
    try:
        s.settimeout(timeout)
        head, enc, dec = build_head_ee(secret, 2, ABRIDGED)
        s.sendall(head)
        return _exchange(s, enc, dec, False, timeout, t0)
    except Exception as e:
        return -2.0, "io:%s" % type(e).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


def tls_hello(domain, rnd=None):
    """Mirrors Net.tlsHello(): a randomized ClientHello that only *looks* like TLS."""
    rnd = rnd or os.urandom
    host = domain.encode()
    random32 = rnd(32)
    sid = rnd(32)

    def ext(t, data):
        return struct.pack(">HH", t, len(data)) + data

    sni_entry = b"\x00" + bytes([len(host)]) + host
    sni_list = b"\x00" + bytes([len(sni_entry)]) + sni_entry
    groups = bytes([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19])
    sigalgs = bytes([0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01])
    exts = b"".join([
        ext(0x0000, b"\x00\x00" + sni_list),
        ext(0x000A, b"\x00" + bytes([len(groups)]) + groups),
        ext(0x000B, b"\x01\x00"),
        ext(0x000D, b"\x00" + bytes([len(sigalgs)]) + sigalgs),
        ext(0x002B, bytes([0x02, 0x03, 0x04, 0x03, 0x03])),
        ext(0x0023, b""),
    ])
    ciphers = bytes([0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
                     0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
                     0x00, 0x35, 0x00, 0x0a])
    body = (b"\x03\x03" + random32 + b"\x20" + sid
            + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def record(payload):
    return b"\x17\x03\x03" + len(payload).to_bytes(2, "big") + payload


def strip_records(buf):
    out = b""
    while len(buf) >= 5:
        ln = int.from_bytes(buf[3:5], "big")
        if ln <= 0 or ln > 18432:
            break
        if len(buf) < 5 + ln:
            break
        out += buf[5:5 + ln]
        buf = buf[5 + ln:]
    return out, buf


def faketsls_record_ping(host, port, secret, timeout=5.0):
    """Mirrors the LocalBridge fallback: fake ClientHello, then MTProto frames
    wrapped in TLS application-data records."""
    t0 = time.perf_counter()
    try:
        u = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return -2.0, "connect:%s" % type(e).__name__
    try:
        u.settimeout(timeout)
        dom = domain_from_secret(secret)
        u.sendall(tls_hello(dom))
        buf = b""
        deadline = time.perf_counter() + min(5.0, timeout)
        while time.perf_counter() < deadline:
            try:
                chunk = u.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) >= 5 and len(buf) >= 5 + int.from_bytes(buf[3:5], "big"):
                break
        if not buf or buf[0] != 0x16:
            return -2.0, "noTLSflight"
        head, enc, dec = build_head_ee(secret, 2, ABRIDGED)
        u.settimeout(timeout)
        u.sendall(record(head))

        nonce = os.urandom(16)
        body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
        u.sendall(record(enc.encrypt(bytes([len(body) // 4]) + body)))

        plain, rest = strip_records(buf)
        data = dec.encrypt(plain) if plain else b""
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            parsed = frame_consumed(data, False)
            if parsed is not None:
                used, off = parsed
                payload = data[off:used]
                data = data[used:]
                if len(payload) >= 20 and int.from_bytes(payload[:4], "little") == RES_PQ and payload[4:20] == nonce:
                    return (time.perf_counter() - t0) * 1000, "OK"
            try:
                chunk = u.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            more, rest = strip_records(chunk + rest)
            data += dec.encrypt(more) if more else b""
        return -2.0, "norespq"
    except OSError as e:
        return -2.0, "io:%s" % type(e).__name__
    finally:
        try:
            u.close()
        except Exception:
            pass


def check_one(item):
    h, p, sec = item
    if (sec or "").lower().startswith("ee"):
        return faketsls_record_ping(h, p, sec)
    return mtproto_ping(h, p, sec)



def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    cands = []
    for u in MT_SOURCES:
        try:
            got = parse(fetch(u))
            print("source %-72s %5d entries" % (u.split("/gh/")[-1], len(got)))
            cands += got
        except Exception as e:
            print("source FAIL %-65s %s" % (u.split("/gh/")[-1], e))
    seen, uniq = set(), []
    for h, p, sec in cands:
        k = (h, p)
        if k not in seen:
            seen.add(k)
            uniq.append((h, p, sec))
    print("\ntotal unique: %d" % len(uniq))
    kinds = {}
    for h, p, sec in uniq:
        k = (sec or "").lower()[:2] if (sec or "").lower().startswith(("ee", "dd")) else "other"
        kinds[k] = kinds.get(k, 0) + 1
    print("secret types: " + ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    print("\ntesting %d ...\n" % min(limit, len(uniq)))

    sample = uniq[:limit]
    tally = {}
    works = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        for (h, p, sec), (ms, why) in zip(sample, ex.map(check_one, sample)):
            tally[why] = tally.get(why, 0) + 1
            if why == "OK":
                works.append((ms, h, p, sec[:12], "TLS" if (sec or "").lower().startswith("ee") else "mt"))

    print("result tally:")
    for k, v in sorted(tally.items(), key=lambda x: -x[1]):
        print("  %-22s %5d  (%.1f%%)" % (k, v, 100.0 * v / max(1, len(sample))))
    works.sort()
    print("\nWORKING (%d):" % len(works))
    for ms, h, p, sec, kind in works[:25]:
        print("  %7.0f ms  %-5s %s:%d  %s..." % (ms, kind, h, p, sec))


if __name__ == "__main__":
    main()
