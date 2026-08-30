package com.miiko3.mtprotofinder;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class LocalBridge implements Runnable {
    interface Picker {
        MainActivity.Proxy pick();
    }

    private final int port;
    private final Picker pick;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ServerSocket server;
    private Thread loop;

    LocalBridge(int port, Picker pick) {
        this.port = port;
        this.pick = pick;
    }

    void start() {
        if (running.get()) return;
        running.set(true);
        loop = new Thread(this, "local-bridge");
        loop.start();
    }

    void stop() {
        running.set(false);
        try {
            if (server != null) server.close();
        } catch (Exception ignored) {
        }
        server = null;
    }

    boolean isRunning() {
        return running.get();
    }

    public void run() {
        try {
            server = new ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"));
            server.setSoTimeout(1000);
            while (running.get()) {
                try {
                    Socket c = server.accept();
                    final Socket cs = c;
                    new Thread(() -> handle(cs)).start();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        running.set(false);
    }

    private void handle(Socket c) {
        try {
            c.setSoTimeout(5000);
            InputStream in = c.getInputStream();
            OutputStream out = c.getOutputStream();
            byte[] g = new byte[2];
            if (readFull(in, g) && g[0] == 5) {
                out.write(new byte[]{5, 0});
                byte[] head = new byte[4];
                if (readFull(in, head) && head[1] == 1) {
                    String host;
                    int port;
                    if (head[3] == 1) {
                        byte[] a = new byte[6];
                        if (!readFull(in, a)) throw new Exception();
                        host = InetAddress.getByAddress(new byte[]{a[0], a[1], a[2], a[3]}).getHostAddress();
                        port = ((a[4] & 0xFF) << 8) | (a[5] & 0xFF);
                    } else if (head[3] == 3) {
                        int ln = in.read();
                        byte[] h = new byte[ln];
                        if (!readFull(in, h)) throw new Exception();
                        byte[] a = new byte[2];
                        if (!readFull(in, a)) throw new Exception();
                        host = new String(h);
                        port = ((a[0] & 0xFF) << 8) | (a[1] & 0xFF);
                    } else throw new Exception();
                    MainActivity.Proxy p = pick.pick();
                    if (p == null) throw new Exception();
                    int dc = port == 443 || port == 80 || port == 5222 || port == 88 || port == 8443 ? 2 : 2;
                    byte[] secret = hex(p.secret.length() >= 32 ? p.secret.substring(0, 32) : "0123456789abcdef0123456789abcdef");
                    byte[] r = new byte[64];
                    new SecureRandom().nextBytes(r);
                    r[56] = (byte) dc;
                    r[57] = (byte) (dc >> 8);
                    r[60] = (byte) 0xEE;
                    r[61] = (byte) 0xEE;
                    r[62] = (byte) 0xEE;
                    r[63] = (byte) 0xEE;
                    byte[] dk = sha256(sub(r, 8, 40), secret);
                    byte[] div = sub(sha256(sub(r, 40, 56), secret), 0, 16);
                    byte[] ek = sha256(sub(rev(r), 8, 40), secret);
                    byte[] eiv = sub(sha256(sub(rev(r), 40, 56), secret), 0, 16);
                    Cipher dec = Cipher.getInstance("AES/CTR/NoPadding");
                    dec.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dk, "AES"), new IvParameterSpec(div));
                    Cipher enc = Cipher.getInstance("AES/CTR/NoPadding");
                    enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(ek, "AES"), new IvParameterSpec(eiv));
                    Cipher dcc = Cipher.getInstance("AES/CTR/NoPadding");
                    dcc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dk, "AES"), new IvParameterSpec(div));
                    byte[] tail = sub(r, 56, 64);
                    byte[] et = dec.doFinal(tail);
                    byte[] packet = new byte[64];
                    System.arraycopy(r, 0, packet, 0, 56);
                    System.arraycopy(et, 0, packet, 56, 8);
                    Socket u = new Socket();
                    u.connect(new InetSocketAddress(p.host, p.port), 6000);
                    u.setSoTimeout(15000);
                    u.getOutputStream().write(packet);
                    out.write(new byte[]{5, 0, 0, 1, 127, 0, 0, 1, (byte) (port >> 8), (byte) port});
                    out.flush();
                    final Socket us = u;
                    final Cipher cc = enc;
                    Thread t1 = new Thread(() -> pipe(c, us, null, dcc));
                    Thread t2 = new Thread(() -> pipe(us, c, cc, null));
                    t1.start();
                    t2.start();
                    t1.join();
                    t2.join();
                    return;
                }
            }
            throw new Exception();
        } catch (Exception ignored) {
        }
        try {
            c.close();
        } catch (Exception ignored) {
        }
    }

    private static void pipe(Socket src, Socket dst, Cipher enc, Cipher dec) {
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) {
                if (enc != null) b = enc.update(b, 0, n);
                else if (dec != null) b = dec.update(b, 0, n);
                else {
                    out.write(b, 0, n);
                    continue;
                }
                if (b != null) out.write(b);
            }
        } catch (Exception ignored) {
        }
        try {
            src.close();
        } catch (Exception ignored) {
        }
        try {
            dst.close();
        } catch (Exception ignored) {
        }
    }

    private static boolean readFull(InputStream in, byte[] b) {
        try {
            int off = 0;
            while (off < b.length) {
                int n = in.read(b, off, b.length - off);
                if (n < 0) return false;
                off += n;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static byte[] sha256(byte[] a, byte[] b) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(a);
            md.update(b);
            return md.digest();
        } catch (Exception e) {
            return new byte[32];
        }
    }

    static byte[] hex(String s) {
        int n = s.length() / 2;
        byte[] o = new byte[n];
        for (int i = 0; i < n; i++) o[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return o;
    }

    static byte[] sub(byte[] a, int f, int t) {
        byte[] o = new byte[t - f];
        System.arraycopy(a, f, o, 0, t - f);
        return o;
    }

    static byte[] rev(byte[] a) {
        byte[] o = new byte[a.length];
        for (int i = 0; i < a.length; i++) o[i] = a[a.length - 1 - i];
        return o;
    }
}
