package com.miiko3.mtprotofinder;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class LocalBridge implements Runnable {
    interface Picker {
        MainActivity.Proxy pick();
    }

    interface HS {
        byte[] head();
        Cipher send();
        Cipher recv();
    }

    static final String LOCAL_SECRET_HEX = "dddddddddddddddddddddddddddddddd";
    static final byte[] LOCAL_SECRET = hex(LOCAL_SECRET_HEX);
    static final byte[] TAG_ABRIDGED = {(byte) 0xEF, (byte) 0xEF, (byte) 0xEF, (byte) 0xEF};
    static final byte[] TAG_INTERMEDIATE = {(byte) 0xEE, (byte) 0xEE, (byte) 0xEE, (byte) 0xEE};
    static final byte[] TAG_SECURE = {(byte) 0xDD, (byte) 0xDD, (byte) 0xDD, (byte) 0xDD};

    private static final byte[][] RESERVED = {
        new byte[]{'H', 'E', 'A', 'D'},
        new byte[]{'P', 'O', 'S', 'T'},
        new byte[]{'G', 'E', 'T', ' '},
        new byte[]{'O', 'P', 'T', 'I'},
        TAG_INTERMEDIATE,
        TAG_SECURE,
        new byte[]{0x16, 0x03, 0x01, 0x02},
    };

    static class KS {
        byte[] fKey, fIv, rKey, rIv;
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
                    new Thread(() -> handle(c)).start();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        running.set(false);
    }

    static KS derive(byte[] region, byte[] secret) {
        KS k = new KS();
        k.fKey = sha256(copy(region, 0, 32), secret);
        k.fIv = copy(region, 32, 48);
        byte[] rev = rev(region);
        k.rKey = sha256(copy(rev, 0, 32), secret);
        k.rIv = copy(rev, 32, 48);
        return k;
    }

    static boolean validTag(byte[] t) {
        return Arrays.equals(t, TAG_ABRIDGED) || Arrays.equals(t, TAG_INTERMEDIATE) || Arrays.equals(t, TAG_SECURE);
    }

    static HS build(byte[] tag, int dc, byte[] secret) {
        byte[] r = new byte[64];
        SecureRandom rnd = new SecureRandom();
        while (true) {
            rnd.nextBytes(r);
            if (r[0] == (byte) 0xEF) continue;
            if (reserved(r)) continue;
            if (r[4] == 0 && r[5] == 0 && r[6] == 0 && r[7] == 0) continue;
            break;
        }
        r[56] = tag[0];
        r[57] = tag[1];
        r[58] = tag[2];
        r[59] = tag[3];
        r[60] = (byte) (dc & 0xFF);
        r[61] = (byte) ((dc >> 8) & 0xFF);
        r[62] = 0;
        r[63] = 0;

        KS k = derive(copy(r, 8, 56), secret);
        final Cipher send = cipher(Cipher.ENCRYPT_MODE, k.fKey, k.fIv);
        final Cipher recv = cipher(Cipher.ENCRYPT_MODE, k.rKey, k.rIv);
        byte[] full = send.update(r);
        byte[] head = new byte[64];
        System.arraycopy(r, 0, head, 0, 56);
        System.arraycopy(full, 56, head, 56, 8);
        return new HS() {
            public byte[] head() { return head; }
            public Cipher send() { return send; }
            public Cipher recv() { return recv; }
        };
    }

    private static boolean reserved(byte[] r) {
        for (byte[] p : RESERVED) {
            boolean m = true;
            for (int i = 0; i < 4 && m; i++) if (r[i] != p[i]) m = false;
            if (m) return true;
        }
        return false;
    }

    private void handle(Socket c) {
        Socket u = null;
        try {
            c.setSoTimeout(10000);
            InputStream in = c.getInputStream();
            OutputStream out = c.getOutputStream();
            byte[] cHead = new byte[64];
            if (!readFull(in, cHead)) {
                c.close();
                return;
            }
            KS ck = derive(copy(cHead, 8, 56), LOCAL_SECRET);
            Cipher recvC = cipher(Cipher.ENCRYPT_MODE, ck.fKey, ck.fIv);
            Cipher sendC = cipher(Cipher.ENCRYPT_MODE, ck.rKey, ck.rIv);
            byte[] plain64 = recvC.update(cHead);

            byte[] tag = copy(plain64, 56, 60);
            if (!validTag(tag)) {
                c.close();
                return;
            }
            int dc = (short) ((plain64[60] & 0xFF) | ((plain64[61] & 0xFF) << 8));
            if (dc == 0) dc = 2;

            MainActivity.Proxy p = pick.pick();
            if (p == null || !"mtproto".equals(p.proto) || p.secret.toLowerCase().startsWith("ee")) {
                c.close();
                return;
            }
            byte[] secret = secretBytes(p.secret);

            HS up = build(tag, dc, secret);
            u = new Socket();
            u.connect(new InetSocketAddress(p.host, p.port), 8000);
            u.setSoTimeout(10000);
            u.getOutputStream().write(up.head());
            u.getOutputStream().flush();

            final Socket cs = c;
            final Socket us = u;
            Thread t1 = new Thread(() -> pipe(cs, us, recvC, up.send()));
            Thread t2 = new Thread(() -> pipe(us, cs, up.recv(), sendC));
            t1.start();
            t2.start();
            t1.join();
            t2.join();
            return;
        } catch (Exception ignored) {
        }
        try {
            c.close();
        } catch (Exception ignored) {
        }
        if (u != null) {
            try {
                u.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void pipe(Socket src, Socket dst, Cipher dec, Cipher enc) {
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) {
                byte[] plain = dec.update(b, 0, n);
                byte[] x = enc.update(plain);
                if (x != null && x.length > 0) out.write(x);
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

    static byte[] secretBytes(String secretHex) {
        String h = (secretHex == null ? "" : secretHex.trim());
        if (h.toLowerCase().startsWith("dd") && h.length() == 34) h = h.substring(2);
        if (h.length() >= 32) h = h.substring(0, 32);
        else h = "0123456789abcdef0123456789abcdef";
        return hex(h);
    }

    static Cipher cipher(int mode, byte[] key, byte[] iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c;
        } catch (Exception e) {
            return null;
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
            MessageDigest md = MessageDigest.getInstance("SHA-256");
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

    static byte[] copy(byte[] a, int f, int t) {
        return Arrays.copyOfRange(a, f, t);
    }

    static byte[] rev(byte[] a) {
        byte[] o = new byte[a.length];
        for (int i = 0; i < a.length; i++) o[i] = a[a.length - 1 - i];
        return o;
    }
}