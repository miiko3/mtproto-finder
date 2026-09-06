import hashlib
import os
import socket
import sys
import struct
import threading
import time

from Crypto.Cipher import AES

ABRIDGED = b"\xef\xef\xef\xef"
INTERMEDIATE = b"\xee\xee\xee\xee"
SECURE_DD = b"\xdd\xdd\xdd\xdd"

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463

RESERVED_NONCE_BEGINNINGS = (
    b"HEAD",
    b"POST",
    b"GET ",
    b"OPTI",
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",
)

LOCAL_SECRET = bytes.fromhex("dddddddddddddddddddddddddddddddd")
_SECRET_CACHE = {}


def _secret_bytes(secret_val):
    if isinstance(secret_val, bytes):
        raw = secret_val[:16]
        if len(raw) >= 17 and raw[0] == 0xEE:
            raw = raw[1:17]
        return raw
    key = secret_val.strip().lower()
    if key in _SECRET_CACHE:
        return _SECRET_CACHE[key]
    h = key
    if h.startswith("dd") and len(h) == 34:
        h = h[2:]
    raw = bytes.fromhex(h)
    if len(raw) >= 17 and raw[0] == 0xEE:
        raw = raw[1:17]
    if len(raw) < 16:
        raise ValueError("bad secret")
    raw = raw[:16]
    _SECRET_CACHE[key] = raw
    return raw


def _derive(region48, secret):
    fk = hashlib.sha256(region48[:32] + secret).digest()
    fiv = region48[32:48]
    rr = region48[::-1]
    rk = hashlib.sha256(rr[:32] + secret).digest()
    riv = rr[32:48]
    return fk, fiv, rk, riv


def _good_nonce(tag, dc_id):
    while True:
        r = bytearray(os.urandom(64))
        if r[0] == 0xEF:
            continue
        if bytes(r[:4]) in RESERVED_NONCE_BEGINNINGS:
            continue
        if r[4:8] == b"\x00\x00\x00\x00":
            continue
        r[56:60] = tag
        r[60:62] = (dc_id & 0xFFFF).to_bytes(2, "little")
        r[62:64] = b"\x00\x00"
        return r


class Obf:
    def __init__(self, secret, dc_id=2, tag=ABRIDGED):
        raw = _secret_bytes(secret)
        r = _good_nonce(tag, dc_id)
        fk, fiv, rk, riv = _derive(bytes(r[8:56]), raw)
        self.enc = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
        self.dec = AES.new(rk, AES.MODE_CTR, nonce=b"", initial_value=riv)
        full = self.enc.encrypt(bytes(r))
        self.head = bytes(r[:56]) + full[56:64]


def obf_head(secret, dc_id=2):
    return Obf(secret, dc_id).head


def _recvn(sock, n, timeout):
    buf = b""
    sock.settimeout(timeout)
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    except OSError:
        pass
    return buf


def _server_side(client_header, secret=LOCAL_SECRET):
    fk, fiv, rk, riv = _derive(client_header[8:56], secret)
    recv = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
    send = AES.new(rk, AES.MODE_CTR, nonce=b"", initial_value=riv)
    plain = recv.encrypt(client_header)
    return recv, send, plain[56:60], plain[60:62]


def _frame_consumed(data, framing):
    if framing == "abridged":
        if len(data) < 1:
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
    if len(data) < 4:
        return None
    ln = int.from_bytes(data[:4], "little") & 0x7FFFFFFF
    if len(data) < 4 + ln:
        return None
    return 4 + ln, 4


def _deep_mtproto_ping(s, secret, timeout, dc_id=2):
    h = secret.lower()
    if h.startswith("dd") and len(h) == 34:
        tag = SECURE_DD
        framing = "pi"
    else:
        tag = ABRIDGED
        framing = "abridged"
    obf = Obf(secret, dc_id, tag)
    s.sendall(obf.head)
    nonce = os.urandom(16)
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
    if framing == "abridged":
        frame = bytes([len(body) // 4]) + body
    else:
        frame = struct.pack("<I", len(body)) + body
    s.sendall(obf.enc.encrypt(frame))

    data = b""
    deadline = time.perf_counter() + timeout
    s.settimeout(timeout)
    while time.perf_counter() < deadline:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        data += obf.dec.encrypt(chunk)
        while True:
            parsed = _frame_consumed(data, framing)
            if parsed is None:
                break
            used, off = parsed
            if used > len(data):
                break
            payload = data[off:used]
            data = data[used:]
            if len(payload) >= 20:
                ctor = int.from_bytes(payload[:4], "little")
                rnonce = payload[4:20]
                if ctor == RES_PQ and rnonce == nonce:
                    return True
    return False


def _ssl_obf_ping(proxy, dom, timeout):
    import ssl as _ssl

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        raw = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        ss = ctx.wrap_socket(raw, server_hostname=dom)
    except (OSError, _ssl.SSLError):
        return False
    try:
        ss.settimeout(timeout)
        h = proxy.secret.lower()
        if h.startswith("dd") and len(h) == 34:
            tag = SECURE_DD
            framing = "pi"
        else:
            tag = ABRIDGED
            framing = "abridged"
        obf = Obf(proxy.secret, 2, tag)
        nonce = os.urandom(16)
        body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
        if framing == "abridged":
            frame = bytes([len(body) // 4]) + body
        else:
            frame = struct.pack("<I", len(body)) + body
        ss.sendall(obf.head + obf.enc.encrypt(frame))
        data = b""
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                chunk = ss.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            data += obf.dec.encrypt(chunk)
            while True:
                parsed = _frame_consumed(data, framing)
                if parsed is None:
                    break
                used, off = parsed
                if used > len(data):
                    break
                payload = data[off:used]
                data = data[used:]
                if len(payload) >= 20:
                    ctor = int.from_bytes(payload[:4], "little")
                    if ctor == RES_PQ and payload[4:20] == nonce:
                        return True
        return False
    finally:
        try:
            ss.close()
        except OSError:
            pass


def handshake_ping(proxy, timeout=2.0):
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError:
        return -2.0, False
    s.settimeout(timeout)
    ok = False
    try:
        if proxy.proto == "socks5":
            s.sendall(b"\x05\x01\x00")
            d = _recvn(s, 2, timeout)
            if len(d) == 2 and d[0] == 5 and d[1] == 0:
                host = proxy.host.encode()
                req = (
                    b"\x05\x01\x00\x03"
                    + bytes([len(host)])
                    + host
                    + proxy.port.to_bytes(2, "big")
                )
                s.sendall(req)
                rep = _recvn(s, 10, timeout)
                ok = len(rep) >= 2 and rep[0] == 5 and rep[1] == 0
        elif proxy.secret.lower().startswith("ee"):
            from main import _tls_client_hello, _sni_candidates

            flight_ok = False
            for dom in _sni_candidates(proxy):
                try:
                    c = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
                except OSError:
                    break
                c.settimeout(timeout)
                try:
                    c.sendall(_tls_client_hello(proxy, dom))
                    d = _recvn(c, 6, timeout)
                except OSError:
                    d = b""
                c.close()
                if len(d) >= 5 and d[0] == 0x16 and d[1] == 0x03:
                    flight_ok = True
                    if _ssl_obf_ping(proxy, dom, timeout):
                        ok = True
                    break
            if not ok and flight_ok:
                ok = True
        else:
            ok = _deep_mtproto_ping(s, proxy.secret, timeout)
    except OSError:
        ok = False
    except (ValueError, TypeError):
        ok = False
    total = (time.perf_counter() - t0) * 1000
    s.close()
    return (total if ok else -2.0), ok


class LocalBridge:
    def __init__(self, port=10811):
        self.port = port
        self.pick = None
        self.server = None
        self.running = False
        self.threads = []

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen(16)
        self.server.settimeout(1.0)
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
            self.server = None

    def _loop(self):
        while self.running:
            try:
                c, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(c,), daemon=True).start()

    def _client(self, c):
        u = None
        c.settimeout(10)
        try:
            head = _recvn(c, 64, 10)
            if len(head) != 64:
                c.close()
                return
            recv_c, send_c, tag, dc_le = _server_side(head, LOCAL_SECRET)
            if tag not in (ABRIDGED, INTERMEDIATE, SECURE_DD):
                c.close()
                return
            p = self.pick()
            if p is None or p.proto != "mtproto":
                c.close()
                return
            try:
                dc = abs(struct.unpack("<h", dc_le)[0])
            except (struct.error, ValueError):
                dc = 0
            if not p.secret.lower().startswith("ee"):
                obf = Obf(p.secret, dc or 2, tag)
                u = socket.create_connection((p.host, p.port), timeout=8)
                u.settimeout(15)
                u.sendall(obf.head)
                self._relay(c, u, recv_c, send_c, obf.dec, obf.enc, tls_wrap=False)
                return
            from main import _tls_client_hello, _sni_candidates
            obf = Obf(p.secret, dc or 2, tag)
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                raw = socket.create_connection((p.host, p.port), timeout=8)
                u = ctx.wrap_socket(raw, server_hostname=_sni_candidates(p)[0])
                u.settimeout(15)
                u.sendall(obf.head)
                self._relay(c, u, recv_c, send_c, obf.dec, obf.enc, tls_wrap=False)
                return
            except Exception:
                if u is not None:
                    try:
                        u.close()
                    except OSError:
                        pass
                    u = None
            for sni in _sni_candidates(p):
                try:
                    u = socket.create_connection((p.host, p.port), timeout=8)
                    u.settimeout(6)
                    u.sendall(_tls_client_hello(p, sni))
                    buf = b""
                    deadline = time.time() + 5
                    while time.time() < deadline:
                        try:
                            chunk = u.recv(16384)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) >= 5 and len(buf) >= 5 + int.from_bytes(buf[3:5], "big"):
                            break
                    if not buf or buf[0] != 0x16:
                        try:
                            u.close()
                        except OSError:
                            pass
                        u = None
                        continue
                    u.settimeout(15)
                    u.sendall(self._wrap_records(obf.head))
                    _, trailing = self._strip_records(buf)
                    self._relay(c, u, recv_c, send_c, obf.dec, obf.enc, tls_wrap=True, leftover=trailing)
                    return
                except Exception:
                    if u is not None:
                        try:
                            u.close()
                        except OSError:
                            pass
                        u = None
            c.close()
            return
        except Exception:
            try:
                c.close()
            except OSError:
                pass
            if u is not None:
                try:
                    u.close()
                except OSError:
                    pass

    @staticmethod
    def _wrap_records(data):
        out = b""
        while data:
            chunk, data = data[:16384], data[16384:]
            out += b"\x17\x03\x03" + len(chunk).to_bytes(2, "big") + chunk
        return out

    @staticmethod
    def _strip_records(buf):
        out = b""
        while len(buf) >= 5:
            ln = int.from_bytes(buf[3:5], "big")
            if ln <= 0 or ln > 18432:
                return buf, b""
            if len(buf) < 5 + ln:
                break
            out += buf[5:5 + ln]
            buf = buf[5 + ln:]
        return out, buf

    def _relay(self, c, u, recv_c, send_c, dec_u, enc_u, tls_wrap=False, leftover=b""):
        stop = threading.Event()

        def one(src, dst, decr, encr, to_tls, from_tls, initial):
            buf = initial
            try:
                while not stop.is_set():
                    progressed = False
                    if from_tls and len(buf) >= 5:
                        ln = int.from_bytes(buf[3:5], "big")
                        if 0 < ln <= 18432 and 5 + ln <= len(buf):
                            payload = buf[5:5 + ln]
                            buf = buf[5 + ln:]
                            plain = decr.encrypt(payload) if decr is not None else payload
                            out = encr.encrypt(plain) if encr is not None else plain
                            dst.sendall(out)
                            progressed = True
                        elif ln > 18432:
                            break
                    elif not from_tls and buf:
                        plain = decr.encrypt(buf) if decr is not None else buf
                        out = encr.encrypt(plain) if encr is not None else plain
                        if to_tls:
                            dst.sendall(self._wrap_records(out))
                        else:
                            dst.sendall(out)
                        buf = b""
                        progressed = True
                    if not progressed:
                        chunk = src.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
            except OSError:
                pass
            finally:
                stop.set()
                for sock in (src, dst):
                    try:
                        sock.close()
                    except OSError:
                        pass

        t1 = threading.Thread(target=one, args=(c, u, recv_c, enc_u, tls_wrap, False, b""), daemon=True)
        t2 = threading.Thread(target=one, args=(u, c, dec_u, send_c, False, tls_wrap, leftover), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()