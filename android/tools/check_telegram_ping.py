"""Validates the SOCKS5 -> Telegram DC path used by Net.telegramPing().

Same sequence as the Android code:
  TCP -> proxy, SOCKS5 greeting/auth, CONNECT <DC ip>:443,
  then a full MTProto req_pq_multi -> ResPQ exchange with that DC id.
A success here means the in-app "Telegram NN ms" badge can return a real number.
"""
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
DC_ADDRS = [
    ("149.154.175.53", "1"),
    ("149.154.167.51", "2"),
    ("149.154.175.100", "3"),
    ("149.154.167.91", "4"),
    ("149.154.171.5", "5"),
]
RESERVED = (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02")

SOCKS_SOURCES = [
    "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt",
    "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
    "https://cdn.jsdelivr.net/gh/ALIILAPRO/Proxy@main/socks5.txt",
    "https://cdn.jsdelivr.net/gh/hproxy-com/free-proxy-list@main/socks5.txt",
    "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
]

SOCKS_RE = re.compile(r"(?:socks5://)?([\w.\-]+):(\d+)(?::([^:@\s]+):([^:@\s]+))?")


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
        m = SOCKS_RE.search(line)
        if m:
            auth = (m.group(3) or "") + ":" + (m.group(4) or "")
            try:
                out.append((m.group(1), int(m.group(2)), auth))
            except ValueError:
                pass
    return out


def recvn(sock, n, timeout):
    buf = b""
    sock.settimeout(timeout)
    try:
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    except OSError:
        pass
    return buf


def good_nonce(dc_id):
    while True:
        r = bytearray(os.urandom(64))
        if r[0] == 0xEF or bytes(r[:4]) in RESERVED or r[4:8] == b"\x00\x00\x00\x00":
            continue
        r[56:60] = b"\xef\xef\xef\xef"
        r[60:62] = (dc_id & 0xFFFF).to_bytes(2, "little")
        r[62:64] = b"\x00\x00"
        return r


def build(dc_id):
    secret = os.urandom(16)
    r = good_nonce(dc_id)
    region = bytes(r[8:56])
    fk = __import__("hashlib").sha256(region[:32] + secret).digest()
    fiv = region[32:48]
    rr = region[::-1]
    rk = __import__("hashlib").sha256(rr[:32] + secret).digest()
    riv = rr[32:48]
    enc = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
    full = enc.encrypt(bytes(r))
    return bytes(r[:56]) + full[56:64], enc, AES.new(rk, AES.MODE_CTR, nonce=b"", initial_value=riv)


def frame_consumed(data):
    if not data:
        return None
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


def socks_connect(sock, user, pw, addr, port, timeout):
    t = int(timeout * 1000) / 1000.0
    if user:
        sock.sendall(b"\x05\x01\x02")
        g = recvn(sock, 2, t)
        if len(g) == 2 and g[0] == 5 and g[1] == 0:
            authed = True
        elif len(g) == 2 and g[0] == 5 and g[1] == 2:
            u, p = user.encode(), pw.encode()
            sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            g = recvn(sock, 2, t)
            authed = len(g) == 2 and g[0] == 1 and g[1] == 0
        else:
            authed = False
    else:
        sock.sendall(b"\x05\x01\x00")
        g = recvn(sock, 2, t)
        authed = len(g) == 2 and g[0] == 5 and g[1] == 0
    if not authed:
        return False
    host = addr.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + port.to_bytes(2, "big"))
    rep = recvn(sock, 10, t)
    return len(rep) >= 2 and rep[0] == 5 and rep[1] == 0


def telegram_ping(host, port, auth, dc_idx, timeout=4.0):
    ip, dc_id = DC_ADDRS[dc_idx]
    dc_id = int(dc_id)
    user, pw = "", ""
    if auth and ":" in auth:
        user, pw = auth.split(":", 1)
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return -1, "connect:%s" % type(e).__name__
    try:
        s.settimeout(timeout)
        if not socks_connect(s, user, pw, ip, 443, timeout):
            return -1, "socksfail"
        head, enc, dec = build(dc_id)
        s.sendall(head)
        nonce = os.urandom(16)
        body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
        s.sendall(enc.encrypt(bytes([len(body) // 4]) + body))
        data = b""
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                return -1, "dc-timeout"
            if not chunk:
                return -1, "dc-eof"
            data += dec.encrypt(chunk)
            while True:
                p = frame_consumed(data)
                if p is None:
                    break
                used, off = p
                payload = data[off:used]
                data = data[used:]
                if len(payload) >= 20 and int.from_bytes(payload[:4], "little") == RES_PQ and payload[4:20] == nonce:
                    return (time.perf_counter() - t0) * 1000, "OK"
        return -1, "norespq"
    except OSError as e:
        return -1, "io:%s" % type(e).__name__
    finally:
        s.close()


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    cands = []
    for u in SOCKS_SOURCES:
        try:
            got = parse(fetch(u))
            print("source %-58s %6d" % (u.split("/gh/")[-1], len(got)))
            cands += got
        except Exception as e:
            print("source FAIL %-48s %s" % (u.split("/gh/")[-1], e))
    seen, uniq = set(), []
    for h, p, a in cands:
        if (h, p) not in seen:
            seen.add((h, p))
            uniq.append((h, p, a))
    print("\nunique: %d" % len(uniq))
    print("testing %d proxies against DC2...\n" % min(limit, len(uniq)))

    sample = uniq[:limit]
    tally, hits = {}, []
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(telegram_ping, h, p, a, 1): (h, p) for h, p, a in sample}
        for f in futs:
            pass
        for f, (h, p) in futs.items():
            ms, why = f.result()
            tally[why] = tally.get(why, 0) + 1
            if why == "OK":
                hits.append((ms, h, p))
    print("tally:")
    for k, v in sorted(tally.items(), key=lambda x: -x[1]):
        print("  %-22s %4d" % (k, v))
    hits.sort()
    print("\nTELEGRAM REACHABLE via proxy (%d):" % len(hits))
    for ms, h, p in hits[:20]:
        print("  %7.0f ms  %s:%d" % (ms, h, p))


if __name__ == "__main__":
    main()
