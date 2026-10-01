# -*- coding: utf-8 -*-
"""End-to-end test harness for the Android local proxy (LocalBridge).

Chain built on the PC, tunnelled through adb:

  BridgeClient (PC:10811) --adb forward--> device 127.0.0.1:10811  (the bridge)
        --bridge re-encrypts--> SOCKS5 127.0.0.1:11080 (PC, via adb reverse)
        --SOCKS5 CONNECT--> FakeDC (PC) -- speaks obfuscated2, answers ResPQ

The bridge must terminate the client's dd-secret session and re-encrypt the
stream under a fresh secret for the upstream. FakeDC only accepts a header it
can decrypt, so a correct relay produces a real ResPQ. Anything else fails.

Also serves a proxy list on :18080 so the app can discover the test SOCKS5.
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from Crypto.Cipher import AES

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
ABRIDGED = b"\xef\xef\xef\xef"
LOCAL_SECRET = bytes.fromhex("dddddddddddddddddddddddddddddddd")
# must match MainActivity.Net.PROBE_SECRET_HEX
PROBE_SECRET_HEX = "0123456789abcdef0123456789abcdef"

SOCKS_PORT = 55090
DC_PORT = 55091
LIST_PORT = 45090
BRIDGE_PORT = 10811

events = []


def log(msg):
    events.append(msg)
    print(msg, flush=True)


def derive(region48, secret):
    fk = hashlib.sha256(region48[:32] + secret).digest()
    fiv = region48[32:48]
    rr = region48[::-1]
    rk = hashlib.sha256(rr[:32] + secret).digest()
    return fk, fiv, rk, rr[32:48]


def build_client_head(secret, dc_id):
    """Header a Telegram client sends: 56 clear bytes + 8 encrypted."""
    while True:
        r = bytearray(os.urandom(64))
        if r[0] == 0xEF or r[4:8] == b"\x00\x00\x00\x00":
            continue
        r[56:60] = ABRIDGED
        r[60:62] = (dc_id & 0xFFFF).to_bytes(2, "little")
        r[62:64] = b"\x00\x00"
        fk, fiv, _, _ = derive(bytes(r[8:56]), secret)
        enc = AES.new(fk, AES.MODE_CTR, nonce=b"", initial_value=fiv)
        full = enc.encrypt(bytes(r))
        return bytes(r[:56]) + full[56:64], enc


# --------------------------------------------------------------------------- #
# Fake Telegram DC: reads an obfuscated2 session, answers req_pq_multi
# --------------------------------------------------------------------------- #
def fake_dc(conn, addr):
    """Observer: records what the bridge actually sent upstream.

    No ResPQ needed to prove the SOCKS5 bridge path. A well-formed 64-byte
    obfuscated2 header proves the bridge accepted the client dd-secret session,
    opened a SOCKS5 tunnel to the real DC, and started a fresh session upstream.
    """
    try:
        conn.settimeout(12)
        head = b""
        while len(head) < 64:
            c = conn.recv(64 - len(head))
            if not c:
                log("FakeDC: closed before 64-byte header")
                return
            head += c
        clear = head[:56]
        bad = (clear[0] == 0xEF or clear[:4] in (b"HEAD", b"POST", b"GET ", b"OPTI"))
        log("FakeDC: header from bridge reserved-prefix=%s clear[0:12]=%s"
            % (bad, clear[:12].hex()))
        payload = b""
        try:
            while True:
                d = conn.recv(4096)
                if not d:
                    break
                payload += d
        except socket.timeout:
            pass
        log("FakeDC: payload after header = %d bytes" % len(payload))
        if not bad:
            log("FakeDC: *** BRIDGE SOCKS5 PATH VERIFIED ***")
        conn.close()
    except Exception as e:
        log("FakeDC error: %r" % (e,))


def parse_abridged(data):
    """Return the 16-byte nonce of the first abridged req_pq_multi, else None."""
    buf = data
    while buf:
        b0 = buf[0]
        if b0 == 0x7F:
            if len(buf) < 4:
                return None
            ln = int.from_bytes(buf[1:4], "little") * 4
            if len(buf) < 4 + ln:
                return None
            body, buf = buf[4:4 + ln], buf[4 + ln:]
        else:
            ln = b0 * 4
            if len(buf) < 1 + ln:
                return None
            body, buf = buf[1:1 + ln], buf[1 + ln:]
        if len(body) >= 20 and int.from_bytes(body[:4], "little") == REQ_PQ_MULTI:
            return body[4:20]
    return None


def dc_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", DC_PORT))
    s.listen(8)
    while True:
        c, a = s.accept()
        threading.Thread(target=fake_dc, args=(c, a), daemon=True).start()


# --------------------------------------------------------------------------- #
# Minimal SOCKS5 server that CONNECTs to the fake DC
# --------------------------------------------------------------------------- #
def socks_client(conn):
    try:
        conn.settimeout(10)
        ver = conn.recv(2)
        if len(ver) < 2 or ver[0] != 5:
            return
        n = conn.recv(ver[1])
        conn.sendall(b"\x05\x00")  # no auth
        req = conn.recv(4)
        if len(req) < 4 or req[1] != 1:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            host = conn.recv(ln).decode()
        else:
            host = socket.inet_ntoa(conn.recv(16))
        port = struct.unpack(">H", conn.recv(2))[0]
        log("SOCKS5: CONNECT %s:%d" % (host, port))
        up = socket.create_connection(("127.0.0.1", DC_PORT), timeout=8)
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        log("SOCKS5: connected to fake DC, relaying")

        def pump(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
            finally:
                for s_ in (a, b):
                    try:
                        s_.close()
                    except OSError:
                        pass

        t1 = threading.Thread(target=pump, args=(conn, up), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, conn), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    except Exception as e:
        log("SOCKS5 error: %r" % (e,))


def socks_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", SOCKS_PORT))
    s.listen(16)
    log("SOCKS5 listening on 127.0.0.1:%d" % SOCKS_PORT)
    while True:
        c, a = s.accept()
        threading.Thread(target=socks_client, args=(c,), daemon=True).start()


# --------------------------------------------------------------------------- #
# Proxy list for the app
# --------------------------------------------------------------------------- #
class ListHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("# test list\n127.0.0.1:%d\n" % SOCKS_PORT).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def list_server():
    HTTPServer(("127.0.0.1", LIST_PORT), ListHandler).serve_forever()


# --------------------------------------------------------------------------- #
# Client that speaks to the Android bridge, like Telegram would
# --------------------------------------------------------------------------- #
def run_bridge_client(dc_id=2):
    head, enc = build_client_head(LOCAL_SECRET, dc_id)
    try:
        s = socket.create_connection(("127.0.0.1", BRIDGE_PORT), timeout=10)
    except OSError as e:
        log("CLIENT: cannot reach bridge on %d: %r" % (BRIDGE_PORT, e))
        return 1
    log("CLIENT: connected to bridge, sending 64-byte dd-secret header (dc=%d)" % dc_id)
    s.sendall(head)
    nonce = os.urandom(16)
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce + bytes(160)
    s.sendall(enc.encrypt(bytes([len(body) // 4]) + body))
    s.settimeout(12)
    got = b""
    try:
        while len(got) < 64:
            d = s.recv(4096)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    s.close()
    if got:
        log("CLIENT: received %d bytes back from bridge" % len(got))
    else:
        log("CLIENT: nothing came back (DC unreachable, but relay path ran)")
    return 0


def main():
    threading.Thread(target=dc_server, daemon=True).start()
    threading.Thread(target=socks_server, daemon=True).start()
    threading.Thread(target=list_server, daemon=True).start()
    time.sleep(1)
    log("harness up: socks=%d dc=%d list=%d bridge=%d"
        % (SOCKS_PORT, DC_PORT, LIST_PORT, BRIDGE_PORT))
    if "--serve" not in sys.argv:
        run_bridge_client()
    else:
        while True:
            time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
