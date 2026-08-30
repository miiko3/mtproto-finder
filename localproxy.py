import hashlib
import os
import socket
import threading
import time

from Crypto.Cipher import AES

DC_BY_PORT = {443: 2, 80: 2, 5222: 2, 88: 2, 8443: 2}


class Obf:
    def __init__(self, secret, dc_id=2):
        key16 = secret[:32]
        self.raw = bytes.fromhex(key16) if len(key16) == 32 else bytes.fromhex("0123456789abcdef0123456789abcdef")
        r = bytearray(os.urandom(64))
        r[56:60] = dc_id.to_bytes(4, "little")
        r[60:64] = b"\xEE" * 4
        dec_key = hashlib.sha256(bytes(r[8:40]) + self.raw).digest()
        dec_iv = hashlib.sha256(bytes(r[40:56]) + self.raw).digest()[:16]
        rr = bytes(r[::-1])
        enc_key = hashlib.sha256(rr[8:40] + self.raw).digest()
        enc_iv = hashlib.sha256(rr[40:56] + self.raw).digest()[:16]
        self.dec = AES.new(dec_key, AES.MODE_CTR, nonce=b"", initial_value=dec_iv)
        self.enc = AES.new(enc_key, AES.MODE_CTR, nonce=b"", initial_value=enc_iv)
        self.head = bytes(r[:56]) + self.dec.encrypt(bytes(r[56:64]))


def obf_head(secret, dc_id=2):
    return Obf(secret, dc_id).head


def handshake_ping(proxy, timeout=2.0):
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError:
        return -2.0, False
    s.settimeout(timeout)
    ok = True
    try:
        if proxy.proto == "socks5":
            s.sendall(b"\x05\x01\x00")
            d = s.recv(2)
            ok = len(d) >= 2 and d[0] == 5
        elif proxy.secret.lower().startswith("ee"):
            from main import _tls_client_hello
            s.sendall(_tls_client_hello(proxy))
            d = s.recv(6)
            ok = len(d) >= 2 and d[0] == 0x16
        else:
            s.sendall(obf_head(proxy.secret, 2))
            s.settimeout(0.35)
            try:
                s.recv(64)
            except socket.timeout:
                pass
    except OSError:
        ok = False
    s.close()
    return (time.perf_counter() - t0) * 1000, ok


class LocalBridge:
    def __init__(self, port=10808):
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
        try:
            c.settimeout(5)
            if c.recv(2)[:1] != b"\x05":
                c.close()
                return
            c.sendall(b"\x05\x00")
            head = c.recv(4)
            if len(head) < 4 or head[1] != 1:
                c.close()
                return
            atyp = head[3]
            if atyp == 1:
                raw = c.recv(6)
                ip = socket.inet_ntoa(raw[:4])
                port = int.from_bytes(raw[4:6], "big")
            elif atyp == 3:
                ln = c.recv(1)[0]
                host = c.recv(ln).decode("utf-8", "replace")
                raw = c.recv(2)
                ip, port = host, int.from_bytes(raw, "big")
            else:
                c.close()
                return
            p = self.pick()
            if p is None:
                c.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                c.close()
                return
            dc = DC_BY_PORT.get(port, 2)
            obf = Obf(p.secret, dc)
            u = socket.create_connection((p.host, p.port), timeout=6)
            u.settimeout(15)
            u.sendall(obf.head)
            c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + port.to_bytes(2, "big"))
            self._relay(c, u, obf)
        except Exception:
            try:
                c.close()
            except OSError:
                pass

    def _relay(self, a, b, obf):
        stop = threading.Event()

        def one(src, dst, cipher=None):
            try:
                while not stop.is_set():
                    data = src.recv(65536)
                    if not data:
                        break
                    if cipher:
                        data = cipher.encrypt(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                stop.set()
                try:
                    src.close()
                except OSError:
                    pass
                try:
                    dst.close()
                except OSError:
                    pass

        t1 = threading.Thread(target=one, args=(a, b), daemon=True)
        t2 = threading.Thread(target=one, args=(b, a, obf.dec), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
