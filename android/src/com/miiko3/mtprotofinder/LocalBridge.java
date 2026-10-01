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
    private volatile boolean bound;
    private volatile String error;
    private Thread loop;

    LocalBridge(int port, Picker pick) {
        this.port = port;
        this.pick = pick;
    }

    // Успело ли сокет реально открыться. run() выполняется в отдельном потоке,
    // поэтому результат проверяется отдельно, а не по факту вызова start().
    boolean isBound() {
        return bound && running.get();
    }

    String lastError() {
        return error;
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
            bound = true;
            error = null;
            MainActivity.log("bridge: listening on 127.0.0.1:%d", port);
            server.setSoTimeout(1000);
            while (running.get()) {
                try {
                    Socket c = server.accept();
                    new Thread(() -> handle(c)).start();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e) {
            // Раньше исключение молча проглатывалось, и кнопка «Локальный»
            // выглядела как «ничего не делает» — теперь причина видна в логе.
            bound = false;
            error = String.valueOf(e);
            MainActivity.log("bridge: FAILED to bind %d: %s", port, e);
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
            if (dc < 0) dc = -dc;

            MainActivity.Proxy p = pick.pick();
            if (p == null) {
                c.close();
                return;
            }
            // Мост принимает и MTProto, и SOCKS5 апстрим. Telegram к нам всегда
            // приходит по MTProto, а дальше мост сам решает, как доставить поток
            // выбранному прокси. Раньше здесь стоял жёсткий отказ по типу, и при
            // мёртвом MTProto-списке локальный прокси не поднимался вообще.
            boolean socks = "socks5".equals(p.proto);
            boolean fakeTls = !socks && p.secret != null && p.secret.toLowerCase().startsWith("ee");
            byte[] secret = socks ? LOCAL_SECRET
                    : (fakeTls ? obfSecret(p.secret) : secretBytes(p.secret));
            MainActivity.log("bridge: dc=%d upstream=%s %s:%d", dc, p.proto, p.host, p.port);

            if (!fakeTls) {
                final HS up = build(tag, dcIndex(dc), secret);
                final Socket us;
                if (socks) {
                    us = socksToDc(p, dc);
                } else {
                    us = new Socket();
                    us.connect(new InetSocketAddress(p.host, p.port), 8000);
                }
                us.setSoTimeout(10000);
                us.getOutputStream().write(up.head());
                us.getOutputStream().flush();
                MainActivity.log("bridge: relaying via %s", p.proto);
                Thread t1 = new Thread(() -> pipePlain(c, us, recvC, up.send(), false));
                Thread t2 = new Thread(() -> pipePlain(us, c, up.recv(), sendC, false));
                t1.start(); t2.start(); t1.join(); t2.join();
                return;
            }

            java.util.List<String> snis = MainActivity.Net.sniList(p);

            // Тот же путь, которым прокси был проверен при пинге (нативный TLS
            // по SNI из секрета), — если пинг прошёл, релей тоже пройдёт.
            try {
                javax.net.ssl.SSLSocket ss = MainActivity.Net.tlsSocket(p.host, p.port, snis.get(0), 8);
                final HS up = build(tag, dc, secret);
                final javax.net.ssl.SSLSocket fss = ss;
                OutputStream uo = fss.getOutputStream();
                uo.write(up.head());
                uo.flush();
                Thread t1 = new Thread(() -> pipePlain(c, fss, recvC, up.send(), false));
                Thread t2 = new Thread(() -> pipeTls(fss, c, up.recv(), sendC, new byte[0]));
                t1.start(); t2.start(); t1.join(); t2.join();
                return;
            } catch (Exception ignored) {
                try { if (u != null) u.close(); } catch (Exception ignored2) {}
                u = null;
            }

            for (String sni : snis) {
                try {
                    u = new Socket();
                    u.connect(new InetSocketAddress(p.host, p.port), 8000);
                    u.setSoTimeout(6000);
                    OutputStream uo = u.getOutputStream();
                    uo.write(MainActivity.Net.tlsHello(sni));
                    uo.flush();
                    byte[] sh = readFlight(u);
                    if (sh == null || sh.length < 5 || sh[0] != 0x16) {
                        u.close(); u = null; continue;
                    }
                    u.setSoTimeout(10000);
                    final HS up = build(tag, dc, secret);
                    final Socket us = u;
                    OutputStream uo2 = us.getOutputStream();
                    uo2.write(record(up.head()));
                    uo2.flush();
                    Thread t1 = new Thread(() -> pipeWrap(c, us, recvC, up.send()));
                    Thread t2 = new Thread(() -> pipeTls(us, c, up.recv(), sendC, new byte[0]));
                    t1.start(); t2.start(); t1.join(); t2.join();
                    return;
                } catch (Exception ignored) {
                    try { if (u != null) u.close(); } catch (Exception ignored2) {}
                    u = null;
                }
            }
            c.close();
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

    // Индекс реального DC в таблице адресов. Telegram шлёт 1..5, но может
    // прислать и служебное значение — тогда берём DC2.
    static int dcIndex(int dc) {
        return (dc >= 1 && dc < MainActivity.Net.DC_ADDRS.length) ? dc - 1 : 1;
    }

    static byte[] anySecret() {
        byte[] b = new byte[16];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }

    // SOCKS5-апстрим: подключаемся к прокси и просим его открыть соединение с
    // настоящим DC Telegram, который выбрал клиент. Дальше по туннелю идёт
    // тот же обфусцированный поток, что и для MTProto-апстрима.
    private Socket socksToDc(MainActivity.Proxy p, int dc) throws Exception {
        String ip = MainActivity.Net.DC_ADDRS[dcIndex(dc)][0];
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(p.host, p.port), 8000);
            s.setSoTimeout(8000);
            if (!MainActivity.Net.socksConnect(s, p, ip, 443, 8)) {
                throw new java.io.IOException("socks CONNECT to " + ip + " refused");
            }
            MainActivity.log("bridge: socks tunnelled to DC%d %s:443", dcIndex(dc) + 1, ip);
            return s;
        } catch (Exception e) {
            MainActivity.log("bridge: socks upstream %s failed: %s", p.host, e);
            try { s.close(); } catch (Exception ignored) {}
            throw e;
        }
    }

    static byte[] record(byte[] payload) {
        byte[] out = new byte[payload.length + 5];
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (byte) ((payload.length >> 8) & 0xFF);
        out[4] = (byte) (payload.length & 0xFF);
        System.arraycopy(payload, 0, out, 5, payload.length);
        return out;
    }

    static byte[] readFlight(Socket s) {
        try {
            InputStream in = s.getInputStream();
            byte[] head5 = new byte[5];
            if (!readFull(in, head5)) return null;
            int ln = ((head5[3] & 0xFF) << 8) | (head5[4] & 0xFF);
            if (ln <= 0 || ln > 18432) return null;
            byte[] rest = new byte[ln];
            if (!readFull(in, rest)) return null;
            byte[] flight = new byte[5 + ln];
            System.arraycopy(head5, 0, flight, 0, 5);
            System.arraycopy(rest, 0, flight, 5, ln);
            return flight;
        } catch (Exception e) {
            return null;
        }
    }

    void pipePlain(Socket src, Socket dst, Cipher dec, Cipher enc, boolean wrapRecords) {
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) {
                byte[] plain = dec.update(b, 0, n);
                byte[] x = enc.update(plain);
                if (x != null && x.length > 0) out.write(wrapRecords ? record(x) : x);
            }
        } catch (Exception ignored) {
        }
        closeBoth(src, dst);
    }

    void pipeWrap(Socket src, Socket dst, Cipher dec, Cipher enc) {
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) {
                byte[] plain = dec.update(b, 0, n);
                byte[] x = enc.update(plain);
                if (x != null && x.length > 0) out.write(record(x));
            }
        } catch (Exception ignored) {
        }
        closeBoth(src, dst);
    }

    void pipeTls(Socket src, Socket dst, Cipher decUp, Cipher encC, byte[] initial) {
        try {
            InputStream in = src.getInputStream();
            OutputStream out = dst.getOutputStream();
            byte[] buf = initial;
            byte[] b = new byte[65536];
            while (true) {
                boolean progressed = false;
                if (buf.length >= 5) {
                    int ln = ((buf[3] & 0xFF) << 8) | (buf[4] & 0xFF);
                    if (ln > 0 && ln <= 18432 && buf.length >= 5 + ln) {
                        byte[] payload = Arrays.copyOfRange(buf, 5, 5 + ln);
                        byte[] rest = new byte[buf.length - 5 - ln];
                        System.arraycopy(buf, 5 + ln, rest, 0, rest.length);
                        buf = rest;
                        byte[] plain = decUp.update(payload);
                        byte[] x = encC.update(plain);
                        if (x != null && x.length > 0) out.write(x);
                        progressed = true;
                    } else if (ln > 18432) {
                        break;
                    }
                }
                if (!progressed) {
                    int n = in.read(b);
                    if (n < 0) break;
                    byte[] nb = new byte[buf.length + n];
                    System.arraycopy(buf, 0, nb, 0, buf.length);
                    System.arraycopy(b, 0, nb, buf.length, n);
                    buf = nb;
                }
            }
        } catch (Exception ignored) {
        }
        closeBoth(src, dst);
    }

    void closeBoth(Socket a, Socket b) {
        for (Socket s : new Socket[]{a, b}) {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    static byte[] secretBytes(String secretHex) {
        String h = (secretHex == null ? "" : secretHex.trim());
        if (h.toLowerCase().startsWith("dd") && h.length() == 34) h = h.substring(2);
        if (h.length() >= 32) h = h.substring(0, 32);
        else h = "0123456789abcdef0123456789abcdef";
        return hex(h);
    }

    static byte[] obfSecret(String secretHex) {
        try {
            byte[] all = hex(secretHex.trim().toLowerCase());
            if (all.length >= 17 && all[0] == (byte) 0xEE) return Arrays.copyOfRange(all, 1, 17);
            return secretBytes(secretHex);
        } catch (Exception e) {
            return secretBytes(secretHex);
        }
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