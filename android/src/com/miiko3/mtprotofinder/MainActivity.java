package com.miiko3.mtprotofinder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.BitmapShader;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;

public class MainActivity extends Activity {

    static final String AUTHOR_URL = "https://t.me/yetilov";
    static final String APP_VERSION = "0.1.3.4b";
    static final int MAX_SERVERS = 30;
    static final int LOCAL_PORT = 10811;
    static final int REPING_MS = 6000;
    static final int RESCAN_MS = 600000;
    static final String INFO_TEXT = "Пинг считается по-честному: приложение делает полноценное рукопожатие с сервером. Для MTProto это реальный запрос req_pq_multi к прокси и ответ Telegram-DC, для SOCKS5 — полный CONNECT, для FakeTLS — TLS ClientHello.\n\nЦветной бейдж получают только те серверы, которые реально работают с Telegram: зелёный — до 300 мс, жёлтый — до 1000 мс, красный — выше. Серый ✖ — рукопожатие не прошло: такой прокси в Telegram работать не будет.";

    static final int
        C_BG_TOP = 0xFF7B5F7D,
        C_BG_MID = 0xFF69496B,
        C_BG_BOT = 0xFF5B375C,
        C_FG = 0xFFFFFFFF,
        C_MUTED = 0xB3FFFFFF,
        GLASS = 0x12FFFFFF,
        GLASS_HI = 0x1EFFFFFF,
        GLASS_ACC = 0x24FFFFFF,
        GREEN_BG = 0xFF6E8F7C,
        GREEN_FG = 0xFF2BE05E,
        YELLOW_BG = 0xFF9A7A5C,
        YELLOW_FG = 0xFFF6D808,
        RED_BG = 0xFF985060,
        RED_FG = 0xFFFF4252;

    static class Proxy {
        String host;
        int port;
        String secret;
        double ping = -1;
        boolean valid = true;
        String proto = "mtproto";

        Proxy(String h, int p, String s) { host = h; port = p; secret = s; }
        Proxy(String h, int p, String s, String pr) { host = h; port = p; secret = s; proto = pr; }

        String label() {
            if ("socks5".equals(proto)) return "SOCKS5";
            return secret.toLowerCase().startsWith("ee") ? "Fake TLS" : "MTProto";
        }

        String link() {
            if ("socks5".equals(proto)) {
                String u = "", pw = "";
                int c = secret.indexOf(':');
                if (c > 0) { u = secret.substring(0, c); pw = secret.substring(c + 1); }
                String l = "tg://socks?server=" + host + "&port=" + port;
                if (!u.isEmpty()) l += "&user=" + enc(u) + "&pass=" + enc(pw);
                return l;
            }
            return "tg://proxy?server=" + host + "&port=" + port + "&secret=" + secret;
        }

        static String enc(String s) {
            try { return java.net.URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; }
        }
    }

    static class Net {
        static final int REQ_PQ_MULTI = 0xBE7E8EF1;
        static final int RES_PQ = 0x05162463;

        static final String[] SOURCES = {
            "https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json",
            "https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt",
            "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt",
            "https://cdn.jsdelivr.net/gh/MhdiTaheri/ProxyCollector@main/proxy.txt",
            "https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt",
            "https://cdn.jsdelivr.net/gh/Chumbayoumba/free-telegram-proxy-russia-2026@main/proxy-list.txt",
            "https://cdn.jsdelivr.net/gh/horizonpaz-create/mtproto-live@main/mtproto.txt"
        };
        static final String[] SOCKS_SOURCES = {
            "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
            "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/SOCKS5_RAW.txt",
            "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/socks5.txt",
            "https://cdn.jsdelivr.net/gh/casals-ar/proxy-list@main/socks5",
            "https://cdn.jsdelivr.net/gh/ShiftyTR/Proxy-List@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/SOCKS5.txt"
        };
        static final Pattern LINK_RE = Pattern.compile("(server|port|secret)=([^&\\s]+)");
        static String[] concat() { String[] o = new String[SOURCES.length + SOCKS_SOURCES.length]; System.arraycopy(SOURCES, 0, o, 0, SOURCES.length); System.arraycopy(SOCKS_SOURCES, 0, o, SOURCES.length, SOCKS_SOURCES.length); return o; }
        static final Set<String> SOCKSSET = new HashSet<>(Arrays.asList(SOCKS_SOURCES));

        static List<Proxy> fetch() {
            List<Proxy> found = Collections.synchronizedList(new ArrayList<>());
            Set<String> seen = Collections.synchronizedSet(new HashSet<>());
            String[] urls = concat();
            ExecutorService ex = Executors.newFixedThreadPool(urls.length);
            List<Future<?>> fs = new ArrayList<>();
            for (String url : urls) {
                fs.add(ex.submit(() -> {
                    try {
                        HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
                        c.setConnectTimeout(15000);
                        c.setReadTimeout(15000);
                        c.setRequestProperty("User-Agent", "MTProtoFinder");
                        BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), "UTF-8"));
                        StringBuilder sb = new StringBuilder();
                        String l;
                        while ((l = r.readLine()) != null) sb.append(l).append('\n');
                        c.disconnect();
                        String text = sb.toString();
                        if (url.endsWith(".json")) parseJson(text, found, seen);
                        else if (SOCKSSET.contains(url)) parseSocks(text, found, seen);
                        else parseText(text, found, seen);
                    } catch (Exception ignored) { }
                }));
            }
            for (Future<?> f : fs) try { f.get(25, TimeUnit.SECONDS); } catch (Exception ignored) { }
            ex.shutdown();
            return new ArrayList<>(found);
        }

        static void add(Proxy p, List<Proxy> f, Set<String> s) {
            if (p != null && s.add(p.host + ":" + p.port)) f.add(p);
        }

        static void parseSocks(String t, List<Proxy> f, Set<String> s) {
            for (String line : t.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) continue;
                Matcher m = Pattern.compile("(?:socks5://)?([\\w.\\-]+):(\\d+)(?::([^:@\\s]+):([^:@\\s]+))?").matcher(line);
                if (m.find()) {
                    try {
                        String auth = (m.group(3) != null) ? m.group(3) + ":" + m.group(4) : "";
                        add(new Proxy(m.group(1), Integer.parseInt(m.group(2)), auth, "socks5"), f, s);
                    } catch (Exception ignored) { }
                }
            }
        }

        static void parseJson(String t, List<Proxy> f, Set<String> s) {
            int i = 0;
            while (true) {
                i = t.indexOf("\"host\"", i);
                if (i < 0) return;
                int e = t.indexOf('}', i);
                if (e < 0) return;
                String seg = t.substring(i, e);
                Matcher mh = Pattern.compile("\"host\"\\s*:\\s*\"([^\"]+)\"").matcher(seg);
                Matcher mp = Pattern.compile("\"port\"\\s*:\\s*(\\d+)").matcher(seg);
                Matcher ms = Pattern.compile("\"secret\"\\s*:\\s*\"([^\"]+)\"").matcher(seg);
                if (mh.find() && mp.find() && ms.find()) {
                    String sec = normSecret(ms.group(1));
                    if (sec != null) {
                        try {
                            add(new Proxy(mh.group(1), Integer.parseInt(mp.group(1)), sec), f, s);
                        } catch (Exception ignored) { }
                    }
                }
                i = e;
            }
        }

        static void parseText(String t, List<Proxy> f, Set<String> s) {
            for (String line : t.split("\n")) {
                Matcher m = LINK_RE.matcher(line);
                String host = null, port = null, secret = null;
                while (m.find()) {
                    String k = m.group(1), v = m.group(2);
                    if ("server".equals(k)) host = decode(v);
                    else if ("port".equals(k)) port = decode(v);
                    else if ("secret".equals(k)) secret = decode(v);
                }
                if (host != null && port != null) {
                    String sec = normSecret(decode(secret));
                    if (sec != null) {
                        try {
                            add(new Proxy(host.trim().replaceAll("\\.$", ""), Integer.parseInt(port), sec), f, s);
                        } catch (Exception ignored) { }
                    }
                }
            }
        }

        static String normSecret(String s) {
            if (s == null) return null;
            s = s.trim();
            return s.matches("[0-9a-fA-F]{32,}") ? s.toLowerCase() : null;
        }

        static String decode(String s) {
            try { return java.net.URLDecoder.decode(s, "UTF-8"); } catch (Exception e) { return s; }
        }

        static int recvN(Socket s, byte[] b, int timeOutMs) {
            try {
                s.setSoTimeout(timeOutMs);
                java.io.InputStream in = s.getInputStream();
                int off = 0;
                while (off < b.length) { int n = in.read(b, off, b.length - off); if (n < 0) break; off += n; }
                return off;
            } catch (Exception e) { return -1; }
        }

        static double[] handshakePing(Proxy p, double timeout) {
            long t0 = System.nanoTime();
            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress(p.host, p.port), (int) (timeout * 1000));
                s.setSoTimeout((int) (timeout * 1000));
                boolean ok = false;
                if ("socks5".equals(p.proto)) {
                    OutputStream os = s.getOutputStream();
                    String user = "", pass = "";
                    int ci = p.secret.indexOf(':');
                    if (ci > 0) { user = p.secret.substring(0, ci); pass = p.secret.substring(ci + 1); }
                    byte[] g = new byte[2];
                    if (!user.isEmpty()) {
                        os.write(new byte[]{0x05, 0x01, 0x02});
                        int rn = recvN(s, g, (int) (timeout * 1000));
                        if (rn >= 2 && g[0] == 5 && g[1] == 2) {
                            byte[] u = user.getBytes("UTF-8"), pw = pass.getBytes("UTF-8");
                            ByteArrayOutputStream ab = new ByteArrayOutputStream();
                            ab.write(1); ab.write(u.length); ab.write(u); ab.write(pw.length); ab.write(pw);
                            os.write(ab.toByteArray());
                            rn = recvN(s, g, (int) (timeout * 1000));
                            ok = rn >= 2 && g[0] == 1 && g[1] == 0;
                        } else if (rn >= 2 && g[0] == 5 && g[1] == 0) {
                            ok = true;
                        }
                    } else {
                        os.write(new byte[]{0x05, 0x01, 0x00});
                        int rn = recvN(s, g, (int) (timeout * 1000));
                        ok = rn >= 2 && g[0] == 5 && g[1] == 0;
                    }
                    if (ok) {
                        byte[] host = p.host.getBytes("UTF-8");
                        ByteArrayOutputStream req = new ByteArrayOutputStream();
                        req.write(new byte[]{0x05, 0x01, 0x00, 0x03});
                        req.write(host.length);
                        req.write(host);
                        req.write((p.port >> 8) & 0xFF);
                        req.write(p.port & 0xFF);
                        os.write(req.toByteArray());
                        byte[] rep = new byte[10];
                        int rn = recvN(s, rep, (int) (timeout * 1000));
                        ok = rn >= 2 && rep[0] == 5 && rep[1] == 0;
                    }
                } else if (p.secret.toLowerCase().startsWith("ee")) {
                    List<String> snis = new ArrayList<>();
                    for (String d : new String[]{domainFromSecret(p.secret), p.host, "www.cloudflare.com"}) {
                        if (d != null && d.contains(".") && !snis.contains(d)) snis.add(d);
                    }
                    for (String dom : snis) {
                        try {
                            Socket c2 = new Socket();
                            c2.connect(new InetSocketAddress(p.host, p.port), (int) (timeout * 1000));
                            c2.setSoTimeout((int) (timeout * 1000));
                            c2.getOutputStream().write(tlsHello(dom));
                            byte[] b = new byte[6];
                            int rn = recvN(c2, b, (int) (timeout * 1000));
                            c2.close();
                            if (rn >= 5 && (b[0] & 0xFF) == 0x16 && (b[1] & 0xFF) == 0x03) { ok = true; break; }
                        } catch (Exception ignored) { }
                    }
                } else {
                    OutputStream os = s.getOutputStream();
                    String sec = p.secret;
                    boolean pi = sec.toLowerCase().startsWith("dd") && sec.length() == 34;
                    byte[] tag = pi ? LocalBridge.TAG_SECURE : LocalBridge.TAG_ABRIDGED;
                    LocalBridge.HS hs = LocalBridge.build(tag, 2, LocalBridge.secretBytes(sec));
                    os.write(hs.head());
                    byte[] nonce = new byte[16];
                    new SecureRandom().nextBytes(nonce);
                    ByteArrayOutputStream body = new ByteArrayOutputStream();
                    body.write(intLE(REQ_PQ_MULTI));
                    body.write(nonce);
                    body.write(new byte[160]);
                    byte[] ba = body.toByteArray();
                    ByteArrayOutputStream fr = new ByteArrayOutputStream();
                    if (pi) fr.write(intLE(ba.length), 0, 4);
                    else fr.write(ba.length / 4);
                    fr.write(ba);
                    os.write(cipherU(hs.send(), fr.toByteArray()));
                    os.flush();

                    byte[] data = new byte[0];
                    long deadline = System.currentTimeMillis() + (long) (timeout * 1000);
                    java.io.InputStream in = s.getInputStream();
                    while (System.currentTimeMillis() < deadline) {
                        byte[] buf = new byte[4096];
                        int n;
                        try { n = in.read(buf); } catch (java.net.SocketTimeoutException st) { break; }
                        if (n < 0) break;
                        data = cat(data, cipherU(hs.recv(), Arrays.copyOf(buf, n)));
                        if (checkFrame(data, pi, nonce)) { ok = true; break; }
                    }
                }
                s.close();
                double ms = (System.nanoTime() - t0) / 1e6;
                return new double[]{ok ? ms : -2.0, ok ? 1 : 0};
            } catch (Exception e) {
                return new double[]{-2, 0};
            }
        }

        static boolean checkFrame(byte[] data, boolean pi, byte[] nonce) {
            byte[] d = data;
            while (d.length > 0) {
                int used, off;
                if (pi) {
                    if (d.length < 4) return false;
                    int L = intLE(d, 0) & 0x7FFFFFFF;
                    if (d.length < 4 + L) return false;
                    used = 4 + L; off = 4;
                } else {
                    int b = d[0] & 0xFF;
                    if (b == 0x7F) {
                        if (d.length < 4) return false;
                        int ln = intLE3(d, 1) * 4;
                        if (d.length < 4 + ln) return false;
                        used = 4 + ln; off = 4;
                    } else {
                        int ln = b * 4;
                        if (d.length < 1 + ln) return false;
                        used = 1 + ln; off = 1;
                    }
                }
                byte[] payload = Arrays.copyOfRange(d, off, Math.min(used, d.length));
                d = Arrays.copyOfRange(d, Math.min(used, d.length), d.length);
                if (payload.length >= 20 && intLE(payload, 0) == RES_PQ && eq(payload, 4, nonce)) return true;
            }
            return false;
        }

        static byte[] intLE(int v) {
            return new byte[]{(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
        }

        static int intLE(byte[] a, int off) {
            return (a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8) | ((a[off + 2] & 0xFF) << 16) | ((a[off + 3] & 0xFF) << 24);
        }

        static int intLE3(byte[] a, int off) {
            return (a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8) | ((a[off + 2] & 0xFF) << 16);
        }

        static boolean eq(byte[] a, int off, byte[] b) {
            if (off + b.length > a.length) return false;
            for (int i = 0; i < b.length; i++) if (a[off + i] != b[i]) return false;
            return true;
        }

        static byte[] cat(byte[] a, byte[] b) {
            byte[] o = new byte[a.length + b.length];
            System.arraycopy(a, 0, o, 0, a.length);
            System.arraycopy(b, 0, o, a.length, b.length);
            return o;
        }

        static byte[] cipherU(Cipher c, byte[] a) {
            try { return c.update(a); } catch (Exception e) { return new byte[0]; }
        }

        static double tcpPing(Proxy p, double timeout) {
            long st = System.nanoTime();
            try { Socket sock = new Socket(); sock.connect(new InetSocketAddress(p.host, p.port), (int) (timeout * 1000)); sock.close(); return (System.nanoTime() - st) / 1e6; }
            catch (Exception e) { return -2; }
        }

        static String domainFromSecret(String sec) {
            String h = sec == null ? "" : sec.toLowerCase();
            if (!h.startsWith("ee") || h.length() < 36) return "www.cloudflare.com";
            List<Integer> offs = new ArrayList<>();
            offs.add(34);
            for (int o = 2; o < Math.min(64, h.length() - 6); o += 2) if (o != 34) offs.add(o);
            for (int off : offs) {
                StringBuilder out = new StringBuilder();
                boolean clean = true;
                int i = off;
                while (i + 1 < h.length()) {
                    String ch = hexStr(h.substring(i, i + 2));
                    if (ch == null) { clean = false; break; }
                    char c = ch.charAt(0);
                    if (!(Character.isLetterOrDigit(c) || c == '.' || c == '-')) break;
                    out.append(c);
                    i += 2;
                }
                String d = out.toString();
                if (clean && d.length() >= 4 && d.indexOf('.') > 0 && !d.matches("[\\d.]+")) return d;
            }
            return "www.cloudflare.com";
        }

        static String hexStr(String s) {
            try { return new String(new byte[]{(byte) Integer.parseInt(s, 16)}); } catch (Exception e) { return null; }
        }

        static void ext(ByteArrayOutputStream exts, int type, byte[] data) {
            exts.write((type >> 8) & 0xFF);
            exts.write(type & 0xFF);
            exts.write((data.length >> 8) & 0xFF);
            exts.write(data.length & 0xFF);
            exts.write(data, 0, data.length);
        }

        static byte[] tlsHello(String domain) {
            SecureRandom rnd = new SecureRandom();
            try {
                byte[] host = domain.getBytes("UTF-8");
                byte[] random = new byte[32];
                rnd.nextBytes(random);
                byte[] sid = new byte[32];
                rnd.nextBytes(sid);
                ByteArrayOutputStream sniEntry = new ByteArrayOutputStream();
                sniEntry.write(0x00);
                sniEntry.write(host.length);
                sniEntry.write(host);
                byte[] sniListData = cat(new byte[]{0x00, (byte) sniEntry.size()}, sniEntry.toByteArray());
                byte[] sniExtData = cat(new byte[]{0x00, 0x00}, sniListData);
                byte[] groups = new byte[]{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19};
                byte[] groupsData = cat(new byte[]{0x00, (byte) groups.length}, groups);
                byte[] epfData = new byte[]{0x01, 0x00};
                byte[] sigalgs = new byte[]{0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01};
                byte[] sigData = cat(new byte[]{0x00, (byte) sigalgs.length}, sigalgs);
                byte[] versData = new byte[]{0x02, 0x03, 0x04, 0x03, 0x03};
                byte[] xkey = new byte[32];
                rnd.nextBytes(xkey);
                byte[] ksEntry = cat(new byte[]{0x00, 0x1d, 0x00, (byte) xkey.length}, xkey);
                byte[] ksData = cat(new byte[]{0x00, (byte) ksEntry.length}, ksEntry);
                ByteArrayOutputStream exts = new ByteArrayOutputStream();
                ext(exts, 0x0000, sniExtData);
                ext(exts, 0x000a, groupsData);
                ext(exts, 0x000b, epfData);
                ext(exts, 0x000d, sigData);
                ext(exts, 0x002b, versData);
                ext(exts, 0x0033, ksData);
                ext(exts, 0x0023, new byte[0]);
                byte[] ciphers = new byte[]{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, (byte) 0xc0, 0x2b, (byte) 0xc0, 0x2f, (byte) 0xc0, 0x2c, (byte) 0xc0, 0x30, (byte) 0xcc, (byte) 0xa9, (byte) 0xcc, (byte) 0xa8, (byte) 0xc0, 0x13, (byte) 0xc0, 0x14, 0x00, (byte) 0x9c, 0x00, (byte) 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a};
                byte[] cl = cat(new byte[]{(byte) ((ciphers.length >> 8) & 0xFF), (byte) (ciphers.length & 0xFF)}, ciphers);
                ByteArrayOutputStream body = new ByteArrayOutputStream();
                body.write(new byte[]{0x03, 0x03});
                body.write(random);
                body.write(32);
                body.write(sid);
                body.write(cl);
                body.write(new byte[]{0x01, 0x00});
                byte[] eb = exts.toByteArray();
                body.write((eb.length >> 8) & 0xFF);
                body.write(eb.length & 0xFF);
                body.write(eb);
                byte[] bl = body.toByteArray();
                byte[] hs = cat(new byte[]{0x01, (byte) ((bl.length >> 16) & 0xFF), (byte) ((bl.length >> 8) & 0xFF), (byte) (bl.length & 0xFF)}, bl);
                ByteArrayOutputStream rec = new ByteArrayOutputStream();
                rec.write(new byte[]{0x16, 0x03, 0x01});
                rec.write((hs.length >> 8) & 0xFF);
                rec.write(hs.length & 0xFF);
                rec.write(hs);
                return rec.toByteArray();
            } catch (Exception e) { return new byte[]{0x16, 0x03, 0x01, 0x00, 0x00}; }
        }
    }

    Handler h = new Handler(Looper.getMainLooper());
    List<Proxy> all = new ArrayList<>(), top = new ArrayList<>();
    String mode = "mtproto";
    boolean manual = false, refreshPending = false, pingBusy = false, rescanQueued = false;
    ExecutorService pool = Executors.newFixedThreadPool(64);
    List<Future<?>> futures = new ArrayList<>();
    Proxy selected = null;
    LocalBridge bridge;

    LinearLayout rootLayout;
    GridView grid;
    TextView titleView, verView, status;
    Button btnMt, btnFt, btnConnect, btnPing, btnLocal, authorBtn, infoBtn;

    BaseAdapter adapter = new BaseAdapter() {
        public int getCount() { return top.size(); }
        public Object getItem(int i) { return top.get(i); }
        public long getItemId(int i) { return i; }
        public View getView(int i, View v, ViewGroup parent) {
            Proxy pr = top.get(i);
            if (v == null) {
                LinearLayout card = new LinearLayout(MainActivity.this);
                card.setOrientation(LinearLayout.HORIZONTAL);
                card.setGravity(Gravity.CENTER_VERTICAL);
                card.setPadding(dp(18), 0, dp(10), 0);
                card.setBackground(glass(27));

                TextView host = new TextView(MainActivity.this);
                host.setTextColor(C_FG);
                host.setTextSize(16);
                host.setTypeface(null, Typeface.BOLD);
                host.setSingleLine(true);
                host.setEllipsize(TextUtils.TruncateAt.END);

                TextView ping = new TextView(MainActivity.this);
                ping.setTextSize(14);
                ping.setTypeface(null, Typeface.BOLD);
                ping.setGravity(Gravity.CENTER);
                ping.setMinWidth(dp(94));
                ping.setMaxLines(1);

                LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(36));
                bp.setMargins(dp(10), 0, 0, 0);
                card.addView(host, hp);
                card.addView(ping, bp);
                card.setTag(new Object[]{host, ping});
                v = card;
            }
            Object[] t = (Object[]) v.getTag();
            TextView host = (TextView) t[0], ping = (TextView) t[1];
            host.setText(pr.host + ":" + pr.port);
            GradientDrawable pb = new GradientDrawable();
            pb.setCornerRadius(dp(18));
            ping.setBackground(pb);
            if (pr.ping == -1) {
                ping.setText("…");
                pb.setColor(GLASS_HI);
                ping.setTextColor(C_MUTED);
            } else if (pr.valid && pr.ping > 0) {
                ping.setText(String.format("%.0f ms", pr.ping));
                if (pr.ping < 300) { pb.setColor(GREEN_BG); ping.setTextColor(GREEN_FG); }
                else if (pr.ping < 1000) { pb.setColor(YELLOW_BG); ping.setTextColor(YELLOW_FG); }
                else { pb.setColor(RED_BG); ping.setTextColor(RED_FG); }
            } else if (pr.ping > 0) {
                ping.setText("✖");
                pb.setColor(GLASS_HI);
                ping.setTextColor(C_MUTED);
            } else {
                ping.setText("—");
                pb.setColor(GLASS_HI);
                ping.setTextColor(C_MUTED);
            }
            v.setBackground(pr == selected ? glassAccent(27) : glass(27));
            return v;
        }
    };

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);
        rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setBackground(bgGradient());
        rootLayout.setPadding(dp(13), dp(14), dp(13), dp(10));

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.setPadding(dp(2), 0, dp(2), dp(12));

        LinearLayout chip = new LinearLayout(this);
        chip.setOrientation(LinearLayout.HORIZONTAL);
        chip.setGravity(Gravity.CENTER_VERTICAL);
        chip.setPadding(dp(10), dp(9), dp(20), dp(9));
        chip.setBackground(rounded(0x16FFFFFF, 32));

        ImageView logo = new ImageView(this);
        logo.setImageDrawable(circularLogo());
        chip.addView(logo, new LinearLayout.LayoutParams(dp(56), dp(56)));

        LinearLayout tw = new LinearLayout(this);
        tw.setOrientation(LinearLayout.VERTICAL);
        tw.setPadding(dp(12), 0, 0, 0);
        titleView = new TextView(this);
        titleView.setText("MTProto Finder");
        titleView.setTextSize(18);
        titleView.setTypeface(null, Typeface.BOLD);
        titleView.setTextColor(C_FG);
        verView = new TextView(this);
        verView.setText("v" + APP_VERSION);
        verView.setTextSize(12);
        verView.setTextColor(C_MUTED);
        tw.addView(titleView);
        tw.addView(verView);

        chip.addView(tw);
        head.addView(chip);
        LinearLayout spacer = new LinearLayout(this);
        head.addView(spacer, new LinearLayout.LayoutParams(0, 1, 1f));
        infoBtn = roundBtn("?");
        infoBtn.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("О пинге · v" + APP_VERSION)
            .setMessage(INFO_TEXT)
            .setPositiveButton("Понятно", null)
            .show());
        authorBtn = roundBtn("✈");
        authorBtn.setOnClickListener(v -> open(AUTHOR_URL));
        LinearLayout.LayoutParams rb = new LinearLayout.LayoutParams(dp(48), dp(48));
        rb.setMargins(dp(8), 0, 0, 0);
        infoBtn.setLayoutParams(rb);
        authorBtn.setLayoutParams(rb);
        head.addView(infoBtn);
        head.addView(authorBtn);
        rootLayout.addView(head);

        LinearLayout seg = new LinearLayout(this);
        seg.setOrientation(LinearLayout.HORIZONTAL);
        seg.setGravity(Gravity.CENTER);
        btnMt = pill("MTProto");
        btnFt = pill("SOCKS5");
        btnMt.setOnClickListener(v -> setMode("mtproto"));
        btnFt.setOnClickListener(v -> setMode("socks5"));
        seg.addView(btnMt);
        seg.addView(btnFt, segGap());
        LinearLayout.LayoutParams tip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tip.setMargins(0, 0, 0, dp(10));
        rootLayout.addView(seg, tip);

        grid = new GridView(this);
        grid.setNumColumns(2);
        grid.setStretchMode(GridView.STRETCH_COLUMN_WIDTH);
        int colW = (int) (getResources().getDisplayMetrics().widthPixels / 2f - dp(22));
        grid.setColumnWidth(colW);
        grid.setHorizontalSpacing(dp(10));
        grid.setVerticalSpacing(dp(10));
        grid.setPadding(dp(2), dp(2), dp(2), dp(2));
        grid.setBackground(null);
        grid.setAdapter(adapter);
        grid.setOnItemClickListener((p, v, pos, id) -> { selected = top.get(pos); adapter.notifyDataSetChanged(); });
        grid.setOnItemLongClickListener((p, v, pos, id) -> { cardMenu(top.get(pos)); return true; });
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        gp.setMargins(0, dp(2), 0, dp(10));
        rootLayout.addView(grid, gp);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER);
        bar.setPadding(dp(8), dp(8), dp(8), dp(8));
        bar.setBackground(rounded(0x14FFFFFF, 28));
        btnConnect = action("Подключиться", true);
        btnConnect.setOnClickListener(v -> {
            if (selected != null) { open(selected.link()); toast("Открываю " + selected.host + " в Telegram"); }
            else toast("Сначала выберите сервер из списка");
        });
        btnPing = action("Пинг", false);
        btnPing.setOnClickListener(v -> toggleManual());
        btnLocal = action("Локальный прокси", false);
        btnLocal.setOnClickListener(v -> toggleLocal());
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        ap.setMargins(dp(5), 0, dp(5), 0);
        btnConnect.setLayoutParams(ap);
        btnPing.setLayoutParams(ap);
        btnLocal.setLayoutParams(ap);
        bar.addView(btnConnect);
        bar.addView(btnPing);
        bar.addView(btnLocal);
        rootLayout.addView(bar);

        status = new TextView(this);
        status.setTextSize(10);
        status.setTextColor(C_MUTED);
        status.setGravity(Gravity.CENTER);
        status.setPadding(dp(8), dp(8), dp(8), dp(2));
        rootLayout.addView(status);

        setContentView(rootLayout);
        setFilterUI();
        h.postDelayed(this::startScan, 100);
    }

    android.graphics.drawable.Drawable circularLogo() {
        Bitmap src = BitmapFactory.decodeResource(getResources(), R.drawable.logo);
        int s = dp(56);
        Bitmap out = Bitmap.createBitmap(s, s, Bitmap.Config.ARGB_8888);
        Canvas cv = new Canvas(out);
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        BitmapShader sh = new BitmapShader(src, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
        float sc = s / (float) Math.min(src.getWidth(), src.getHeight());
        Matrix m = new Matrix();
        m.setScale(sc, sc);
        m.postTranslate((s - src.getWidth() * sc) / 2f, (s - src.getHeight() * sc) / 2f);
        sh.setLocalMatrix(m);
        p.setShader(sh);
        cv.drawCircle(s / 2f, s / 2f, s / 2f, p);
        return new BitmapDrawable(getResources(), out);
    }

    GradientDrawable rounded(int color, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(radius));
        return d;
    }

    int dp(float v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    GradientDrawable bgGradient() {
        return new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{C_BG_TOP, C_BG_MID, C_BG_BOT});
    }

    GradientDrawable glass(float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(GLASS);
        d.setCornerRadius(dp(radius));
        return d;
    }

    GradientDrawable glassAccent(float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(GLASS_ACC);
        d.setCornerRadius(dp(radius));
        d.setStroke(dp(2), 0xD9FFFFFF);
        return d;
    }

    Button roundBtn(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(17);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setTextColor(C_FG);
        btn.setPadding(0, 0, 0, 0);
        btn.setGravity(Gravity.CENTER);
        btn.setBackground(rounded(GLASS, 24));
        btn.setElevation(dp(1));
        return btn;
    }

    Button pill(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(15);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setPadding(dp(28), dp(12), dp(28), dp(12));
        btn.setBackground(rounded(0x18FFFFFF, 23));
        btn.setTextColor(C_FG);
        return btn;
    }

    LinearLayout.LayoutParams segGap() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(10), 0, 0, 0);
        return lp;
    }

    Button action(String t, boolean bright) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(13);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setPadding(dp(4), dp(13), dp(4), dp(13));
        btn.setBackground(rounded(bright ? 0x3EFFFFFF : 0x22FFFFFF, 22));
        btn.setTextColor(C_FG);
        return btn;
    }

    void setFilterUI() {
        tint(btnMt, "mtproto".equals(mode));
        tint(btnFt, "socks5".equals(mode));
    }

    void tint(Button btn, boolean on) {
        btn.setBackground(rounded(on ? 0x36FFFFFF : 0x18FFFFFF, 23));
        btn.setTextColor(C_FG);
    }

    void cardMenu(Proxy p) {
        if (p == null) return;
        selected = p;
        adapter.notifyDataSetChanged();
        String[] opts = {"Подключиться", "Скопировать ссылку", "Скопировать адрес", "Пинг"};
        new AlertDialog.Builder(this)
            .setTitle(p.host + ":" + p.port)
            .setItems(opts, (d, which) -> {
                if (which == 0) {
                    open(p.link());
                    toast("Открываю в Telegram");
                } else if (which == 1) {
                    copyText(p.link());
                } else if (which == 2) {
                    copyText(p.host + ":" + p.port);
                } else {
                    quickPing(p);
                }
            })
            .show();
    }

    void copyText(String text) {
        android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(android.content.ClipData.newPlainText("mtproto", text));
        toast("Скопировано");
    }

    void quickPing(Proxy p) {
        toast("Пингую " + p.host + "…");
        pool.submit(() -> {
            double[] r = Net.handshakePing(p, 3);
            h.post(() -> toast(r[0] > 0 ? "Пинг " + String.format("%.0f", r[0]) + " ms" : "Недоступен"));
        });
    }

    void toast(String s) { android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show(); }

    void open(String url) {
        try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))); }
        catch (Exception e) { toast("Не найдено приложение для ссылки"); }
    }

    void toggleLocal() {
        if (bridge != null && bridge.isRunning()) {
            bridge.stop();
            bridge = null;
            btnLocal.setBackground(rounded(0x22FFFFFF, 22));
            setStatus("Локальный прокси остановлен");
            toast("Локальный прокси остановлен");
            return;
        }
        Proxy best = null;
        for (Proxy p : all)
            if ("mtproto".equals(p.proto) && p.ping > 0 && p.valid)
                if (best == null || p.ping < best.ping) best = p;
        if (best == null) { toast("Нет рабочего MTProto — подождите проверки"); return; }
        if (Net.handshakePing(best, 2)[0] < 0) {
            toast("Прокси сейчас недоступен — выберите другой");
            setStatus("⚠ " + best.host + " недоступен прямо сейчас");
            return;
        }
        final Proxy bp = best;
        bridge = new LocalBridge(LOCAL_PORT, () -> bp);
        bridge.start();
        btnLocal.setBackground(rounded(0x48FFFFFF, 22));
        setStatus("🔌 Локальный MTProto 127.0.0.1:" + LOCAL_PORT + " через " + best.host);
        open("tg://proxy?server=127.0.0.1&port=" + LOCAL_PORT + "&secret=" + LocalBridge.LOCAL_SECRET_HEX);
    }

    List<Proxy> pool() {
        List<Proxy> r = new ArrayList<>();
        for (Proxy p : all) if (p.proto.equals(mode)) r.add(p);
        return r;
    }

    void setMode(String m) {
        if (manual) toggleManual();
        mode = m;
        setFilterUI();
        refreshNow();
    }

    void startScan() {
        setStatus("🔍 Поиск прокси в интернете…");
        new Thread(() -> {
            List<Proxy> r = Net.fetch();
            h.post(() -> {
                if (!r.isEmpty()) {
                    all = r;
                    setStatus("Найдено " + r.size() + " прокси, измеряю пинг…");
                    top = first(pool(), MAX_SERVERS);
                    adapter.notifyDataSetChanged();
                    startPing(untested());
                    h.removeCallbacks(rescanRun);
                    h.postDelayed(rescanRun, RESCAN_MS);
                } else {
                    setStatus("⚠ Нет интернета или выключен VPN — включите VPN");
                    h.postDelayed(this::startScan, 15000);
                }
            });
        }).start();
    }

    List<Proxy> first(List<Proxy> l, int n) { return new ArrayList<>(l.subList(0, Math.min(n, l.size()))); }

    List<Proxy> untested() {
        List<Proxy> r = new ArrayList<>();
        for (Proxy p : pool()) if (p.ping == -1) r.add(p);
        return r;
    }

    Runnable rescanRun = this::startScan;

    void cancelPings() {
        for (Future<?> f : futures) f.cancel(true);
        futures.clear();
        pingBusy = false;
    }

    void startPing(List<Proxy> targets) {
        if (pingBusy || targets.isEmpty()) return;
        pingBusy = true;
        for (Proxy p : targets) futures.add(pool.submit(() -> {
            if (Thread.currentThread().isInterrupted()) return;
            double[] r = Net.handshakePing(p, 2);
            double ms = r[0];
            boolean ok = r[1] == 1;
            if (ms < 0) { ms = Net.tcpPing(p, 1); ok = false; }
            p.ping = ms;
            p.valid = ok;
            if (!Thread.currentThread().isInterrupted() && !refreshPending) h.post(this::scheduleRefresh);
        }));
        pool.submit(() -> h.post(() -> pingBusy = false));
    }

    void scheduleRefresh() {
        if (refreshPending) return;
        refreshPending = true;
        h.postDelayed(() -> { refreshPending = false; refreshNow(); }, 400);
    }

    void refreshNow() {
        List<Proxy> pl = pool();
        List<Proxy> alive = new ArrayList<>(), un = new ArrayList<>(), dead = new ArrayList<>();
        for (Proxy p : pl) {
            if (p.ping > 0) alive.add(p);
            else if (p.ping == -1) un.add(p);
            else dead.add(p);
        }
        Collections.sort(alive, (a, b) -> Double.compare(a.ping, b.ping));
        List<Proxy> t = new ArrayList<>(alive);
        t.addAll(un);
        t.addAll(dead);
        top = first(t, MAX_SERVERS);
        if (selected != null && !top.contains(selected) && manual) selected = top.isEmpty() ? null : top.get(0);
        adapter.notifyDataSetChanged();
        if (manual) return;
        if (alive.isEmpty() && !pl.isEmpty() && !rescanQueued) {
            rescanQueued = true;
            setStatus("⚠ Рабочих не найдено — включите VPN, повтор через 30 секунд…");
            h.postDelayed(() -> { rescanQueued = false; startScan(); }, 30000);
        } else if (!alive.isEmpty()) {
            setStatus("✅ Рабочих: " + alive.size() + " · показано " + top.size());
        }
    }

    void toggleManual() {
        manual = !manual;
        if (manual) {
            btnPing.setBackground(rounded(0x48FFFFFF, 22));
            cancelPings();
            h.removeCallbacks(repingRun);
            manualStep();
        } else {
            btnPing.setBackground(rounded(0x22FFFFFF, 22));
            h.postDelayed(repingRun, REPING_MS);
        }
    }

    void manualStep() {
        if (!manual) return;
        if (selected == null) {
            setStatus("Выберите сервер — пингую только его");
            h.postDelayed(this::manualStep, 2000);
            return;
        }
        setStatus("🎯 Пингую только " + selected.host + ":" + selected.port + " · остальные остановлены");
        Proxy p = selected;
        pool.submit(() -> {
            double[] r = Net.handshakePing(p, 2);
            h.post(() -> { p.ping = r[0]; p.valid = r[1] == 1 || r[0] > 0; scheduleRefresh(); manualStep(); });
        });    }

    Runnable repingRun = new Runnable() {
        public void run() {
            if (manual) return;
            List<Proxy> un = untested();
            if (!un.isEmpty()) startPing(un);
            else if (!top.isEmpty()) for (Proxy p : new ArrayList<>(top)) pool.submit(() -> {
                double[] r = Net.handshakePing(p, 2);
                p.ping = r[0];
                p.valid = r[1] == 1 || r[0] > 0;
                if (!refreshPending) h.post(MainActivity.this::scheduleRefresh);
            });
            h.postDelayed(this, REPING_MS);
        }
    };

    void setStatus(String s) { status.setText(s); }
}