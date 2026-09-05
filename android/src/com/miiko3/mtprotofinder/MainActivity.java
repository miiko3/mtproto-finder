package com.miiko3.mtprotofinder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Typeface;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class MainActivity extends Activity {

    static final String AUTHOR_URL = "https://t.me/yetilov";
    static final String APP_VERSION = "0.1.3.2b";
    static final int MAX_SERVERS = 30;
    static final int LOCAL_PORT = 10811;
    static final int REPING_MS = 5000;
    static final int RESCAN_MS = 600000;
    static final String INFO_TEXT = "Пинг считается по реальному «рукопожатию» MTProto: устанавливаем TCP-коннект, проводим obfuscated2-обмен и отправляем date-центру запрос req_pq_multi, дожидаясь корректного ответа resPQ. Поэтому зелёный пинг = прокси действительно релеи в Telegram.\n\nЕсли сервер не отвечает — он помечается «✖», а не рисуется с фейковыми 1 мс.";

    static final int
        C_BG_TOP = 0xFFA18BB0,
        C_BG_BOT = 0xFF5E3F70,
        C_FG = 0xFFFFFFFF,
        C_MUTED = 0xCCFFFFFF,
        GLASS_TOP = 0x40FFFFFF,
        GLASS_BOT = 0x26FFFFFF,
        GLASS2_TOP = 0x59FFFFFF,
        GLASS2_BOT = 0x33FFFFFF,
        STROKE = 0x59FFFFFF,
        ACC_TOP = 0x66FFFFFF,
        ACC_BOT = 0x2EFFFFFF,
        GREEN_BG = 0x335EFF5E,
        GREEN_FG = 0xFF5EFF5E,
        YELLOW_BG = 0x33D8C81E,
        YELLOW_FG = 0xFFD8C81E,
        RED_BG = 0x40FF3B3B,
        RED_FG = 0xFFFF3B3B;

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
            "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt"
        };
        static final String[] SOCKS_SOURCES = {
            "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
            "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt"
        };
        static final Pattern LINK_RE = Pattern.compile("(server|port|secret)=([^&\\s]+)");
        static String[] concat() { String[] o = new String[SOURCES.length + SOCKS_SOURCES.length]; System.arraycopy(SOURCES, 0, o, 0, SOURCES.length); System.arraycopy(SOCKS_SOURCES, 0, o, SOURCES.length, SOCKS_SOURCES.length); return o; }
        static final Set<String> SOCKSSET = new HashSet<>(Arrays.asList(SOCKS_SOURCES));

        static List<Proxy> fetch() {
            List<Proxy> found = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (String url : concat()) {
                try {
                    System.out.println("MTProtoFinder: fetching " + url);
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
                    System.out.println("MTProtoFinder: got " + text.length() + " bytes");
                    if (url.endsWith(".json")) parseJson(text, found, seen);
                    else if (SOCKSSET.contains(url)) parseSocks(text, found, seen);
                    else parseText(text, found, seen);
                } catch (Exception e) {
                    System.out.println("MTProtoFinder: fetch error " + e);
                }
            }
            return found;
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
                    try {
                        add(new Proxy(mh.group(1), Integer.parseInt(mp.group(1)), ms.group(1)), f, s);
                    } catch (Exception ignored) { }
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
                if (host != null && port != null && secret != null) {
                    try {
                        add(new Proxy(host.trim().replaceAll("\\.$", ""), Integer.parseInt(port), secret), f, s);
                    } catch (Exception ignored) { }
                }
            }
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
                    s.getOutputStream().write(tlsHello(domainFromSecret(p.secret)));
                    byte[] b = new byte[6];
                    int rn = recvN(s, b, (int) (timeout * 1000));
                    ok = rn >= 2 && (b[0] & 0xFF) == 0x16 && (b[1] & 0xFF) == 0x03;
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
            if (sec == null || !sec.toLowerCase().startsWith("ee") || sec.length() < 4) return "www.cloudflare.com";
            try {
                StringBuilder o = new StringBuilder();
                int i = 2;
                while (i + 1 < sec.length()) {
                    String ch = hexStr(sec.substring(i, i + 2));
                    if (ch == null || !(Character.isLetterOrDigit(ch.charAt(0)) || ch.equals(".") || ch.equals("-"))) break;
                    o.append(ch);
                    i += 2;
                }
                String d = o.toString().replaceAll("\\.$", "");
                return (d.contains(".") && !d.isEmpty()) ? d : "www.cloudflare.com";
            } catch (Exception e) { return "www.cloudflare.com"; }
        }

        static String hexStr(String s) {
            try { return new String(new byte[]{(byte) Integer.parseInt(s, 16)}); } catch (Exception e) { return null; }
        }

        static byte[] tlsHello(String domain) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            byte[] host = domain.getBytes();
            try {
                ByteArrayOutputStream sni = new ByteArrayOutputStream();
                sni.write(new byte[]{(byte) 0x00, (byte) domain.length()});
                sni.write(host);
                ByteArrayOutputStream sniList = new ByteArrayOutputStream();
                sniList.write(new byte[]{0x00, 0x00});
                sniList.write(new byte[]{(byte) ((sni.size() >> 8) & 0xFF), (byte) (sni.size() & 0xFF)});
                sniList.write(sni.toByteArray());
                ByteArrayOutputStream sniExt = new ByteArrayOutputStream();
                sniExt.write(new byte[]{0x00, 0x00});
                sniExt.write(new byte[]{(byte) ((sniList.size() >> 8) & 0xFF), (byte) (sniList.size() & 0xFF)});
                sniExt.write(sniList.toByteArray());
                byte[] ciphers = new byte[]{(byte) 0x13, 0x01, (byte) 0x13, 0x02, (byte) 0x13, 0x03, 0x00, (byte) 0x9c, 0x00, 0x35};
                ByteArrayOutputStream cl = new ByteArrayOutputStream();
                cl.write(new byte[]{(byte) ((ciphers.length >> 8) & 0xFF), (byte) (ciphers.length & 0xFF)});
                cl.write(ciphers);
                body.write(new byte[]{0x03, 0x03});
                body.write(new byte[32]);
                body.write(new byte[]{0x00});
                body.write(cl.toByteArray());
                body.write(new byte[]{0x01, 0x00});
                body.write(sniExt.toByteArray());
                ByteArrayOutputStream hs = new ByteArrayOutputStream();
                hs.write(new byte[]{0x01});
                byte[] bl = body.toByteArray();
                hs.write(new byte[]{(byte) ((bl.length >> 16) & 0xFF), (byte) ((bl.length >> 8) & 0xFF), (byte) (bl.length & 0xFF)});
                hs.write(bl);
                ByteArrayOutputStream rec = new ByteArrayOutputStream();
                rec.write(new byte[]{0x16, 0x03, 0x01});
                rec.write(new byte[]{(byte) ((hs.size() >> 8) & 0xFF), (byte) (hs.size() & 0xFF)});
                rec.write(hs.toByteArray());
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
                card.setOrientation(LinearLayout.VERTICAL);
                card.setGravity(Gravity.CENTER_VERTICAL);
                card.setPadding(dp(12), dp(12), dp(12), dp(12));
                card.setBackground(glass(16));
                card.setElevation(dp(2));

                LinearLayout row = new LinearLayout(MainActivity.this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);

                TextView rank = new TextView(MainActivity.this);
                rank.setTextSize(10);
                rank.setTypeface(null, Typeface.BOLD);
                rank.setTextColor(0x99FFFFFF);
                rank.setGravity(Gravity.CENTER);

                LinearLayout mid = new LinearLayout(MainActivity.this);
                mid.setOrientation(LinearLayout.VERTICAL);
                mid.setPadding(dp(6), 0, 0, 0);
                TextView host = new TextView(MainActivity.this);
                host.setTextColor(C_FG);
                host.setTextSize(14);
                host.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
                host.setSingleLine(true);
                host.setEllipsize(TextUtils.TruncateAt.END);
                TextView info = new TextView(MainActivity.this);
                info.setTextColor(C_MUTED);
                info.setTextSize(11);
                info.setSingleLine(true);
                info.setEllipsize(TextUtils.TruncateAt.END);
                mid.addView(host);
                mid.addView(info);
                row.addView(rank, new LinearLayout.LayoutParams(dp(18), ViewGroup.LayoutParams.WRAP_CONTENT));
                row.addView(mid, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

                TextView ping = new TextView(MainActivity.this);
                ping.setTextSize(12);
                ping.setTypeface(null, Typeface.BOLD);
                ping.setGravity(Gravity.CENTER);
                ping.setPadding(dp(8), dp(4), dp(8), dp(4));
                ping.setBackground(glass(12));

                card.addView(row);
                card.addView(ping, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                card.setTag(new Object[]{rank, host, info, ping});
                v = card;
            }
            Object[] t = (Object[]) v.getTag();
            ((TextView) t[0]).setText(String.valueOf(i + 1));
            ((TextView) t[1]).setText(pr.host);
            String infoTxt = pr.port + " · " + pr.label();
            if (pr.ping != -1) infoTxt += pr.valid ? "  ✅" : "  ⚠";
            ((TextView) t[2]).setText(infoTxt);
            TextView pv = (TextView) t[3];
            GradientDrawable pb = glass(12);
            pv.setBackground(pb);
            if (pr.ping > 0) {
                pv.setText(String.format("%.0f мс", pr.ping));
                if (pr.ping < 150) { pb.setColor(GREEN_BG); pv.setTextColor(GREEN_FG); }
                else if (pr.ping < 400) { pb.setColor(YELLOW_BG); pv.setTextColor(YELLOW_FG); }
                else { pb.setColor(RED_BG); pv.setTextColor(RED_FG); }
            } else if (pr.ping == -2) {
                pv.setText("✖");
                pb.setColor(0x12FFFFFF);
                pv.setTextColor(C_MUTED);
            } else {
                pv.setText("…");
                pb.setColor(0x12FFFFFF);
                pv.setTextColor(C_MUTED);
            }
            ((View) v).setBackground(pr == selected ? glassAccent(16) : glass(16));
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
        head.setPadding(dp(2), 0, dp(2), dp(10));

        LinearLayout logoWrap = new LinearLayout(this);
        logoWrap.setGravity(Gravity.CENTER);
        logoWrap.setBackground(glass(20));
        logoWrap.setPadding(dp(5), dp(5), dp(5), dp(5));
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.logo);
        logoWrap.addView(logo, new LinearLayout.LayoutParams(dp(30), dp(30)));

        LinearLayout tw = new LinearLayout(this);
        tw.setOrientation(LinearLayout.VERTICAL);
        tw.setPadding(dp(10), 0, 0, 0);
        titleView = new TextView(this);
        titleView.setText("MTProto Finder");
        titleView.setTextSize(18);
        titleView.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        titleView.setTextColor(C_FG);
        verView = new TextView(this);
        verView.setText("v" + APP_VERSION + " · реальный пинг");
        verView.setTextSize(11);
        verView.setTextColor(C_MUTED);
        verView.setBackground(glass(10));
        verView.setPadding(dp(6), dp(2), dp(6), dp(2));
        tw.addView(titleView);
        tw.addView(verView);

        head.addView(logoWrap);
        head.addView(tw, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        infoBtn = roundBtn("🗣");
        infoBtn.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("О пинге · v" + APP_VERSION)
            .setMessage(INFO_TEXT)
            .setPositiveButton("Понятно", null)
            .show());
        authorBtn = roundBtn("✈️");
        authorBtn.setOnClickListener(v -> open(AUTHOR_URL));
        head.addView(infoBtn);
        head.addView(authorBtn);
        rootLayout.addView(head);

        LinearLayout track = new LinearLayout(this);
        track.setOrientation(LinearLayout.HORIZONTAL);
        track.setGravity(Gravity.CENTER);
        track.setPadding(dp(3), dp(3), dp(3), dp(3));
        track.setBackground(glass(24));
        track.addView(btnMt = tab("MTPROTO"), tabLp());
        track.addView(btnFt = tab("SOCKS5"), tabLp());
        btnMt.setOnClickListener(v -> setMode("mtproto"));
        btnFt.setOnClickListener(v -> setMode("socks5"));
        LinearLayout.LayoutParams tip = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tip.setMargins(0, 0, 0, dp(8));
        rootLayout.addView(track, tip);

        grid = new GridView(this);
        grid.setNumColumns(2);
        grid.setStretchMode(GridView.STRETCH_COLUMN_WIDTH);
        int colW = (int) (getResources().getDisplayMetrics().widthPixels / 2f - dp(24));
        grid.setColumnWidth(colW);
        grid.setHorizontalSpacing(dp(8));
        grid.setVerticalSpacing(dp(8));
        grid.setPadding(dp(2), dp(2), dp(2), dp(2));
        grid.setBackground(null);
        grid.setAdapter(adapter);
        grid.setOnItemClickListener((p, v, pos, id) -> { selected = top.get(pos); adapter.notifyDataSetChanged(); });
        grid.setOnItemLongClickListener((p, v, pos, id) -> { open(top.get(pos).link()); return true; });
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        gp.setMargins(0, dp(2), 0, dp(6));
        rootLayout.addView(grid, gp);

        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(C_MUTED);
        status.setGravity(Gravity.CENTER);
        status.setPadding(dp(8), dp(6), dp(8), dp(4));
        rootLayout.addView(status);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER);
        bar.setPadding(dp(5), dp(6), dp(5), dp(6));
        bar.setBackground(glass(26));
        bar.setElevation(dp(3));
        btnConnect = action("🚀 Подключиться");
        btnConnect.setOnClickListener(v -> {
            if (selected != null) { open(selected.link()); toast("Открываю " + selected.host + " в Telegram"); }
            else toast("Сначала выберите сервер из списка");
        });
        btnPing = action("🎯 Пинг");
        btnPing.setOnClickListener(v -> toggleManual());
        btnLocal = action("🔌 Локальный");
        btnLocal.setOnClickListener(v -> toggleLocal());
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        ap.setMargins(dp(3), 0, dp(3), 0);
        btnConnect.setLayoutParams(ap);
        btnPing.setLayoutParams(ap);
        btnLocal.setLayoutParams(ap);
        bar.addView(btnConnect);
        bar.addView(btnPing);
        bar.addView(btnLocal);
        rootLayout.addView(bar);

        setContentView(rootLayout);
        setFilterUI();
        h.postDelayed(this::startScan, 100);
    }

    int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    GradientDrawable bgGradient() {
        return new GradientDrawable(GradientDrawable.Orientation.TL_BR, new int[]{C_BG_TOP, C_BG_BOT});
    }

    GradientDrawable glass(float radius) { return glass(radius, false, false); }
    GradientDrawable glassAccent(float radius) { return glass(radius, true, true); }

    GradientDrawable glass(float radius, boolean dense, boolean accent) {
        int top = accent ? ACC_TOP : (dense ? GLASS2_TOP : GLASS_TOP);
        int bot = accent ? ACC_BOT : (dense ? GLASS2_BOT : GLASS_BOT);
        GradientDrawable d = new GradientDrawable(GradientDrawable.Orientation.TL_BR, new int[]{top, bot});
        d.setCornerRadius(radius);
        d.setStroke(dp(1), accent ? 0x99FFFFFF : STROKE);
        return d;
    }

    Button roundBtn(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(15);
        btn.setTextColor(C_FG);
        btn.setPadding(dp(4), dp(4), dp(4), dp(4));
        btn.setBackground(glass(20));
        btn.setElevation(dp(1));
        return btn;
    }

    Button tab(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(12);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setPadding(dp(8), dp(9), dp(8), dp(9));
        btn.setBackground(glass(20));
        btn.setTextColor(C_MUTED);
        return btn;
    }

    LinearLayout.LayoutParams tabLp() {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    Button action(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(12);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setPadding(dp(4), dp(11), dp(4), dp(11));
        btn.setBackground(glass(16));
        btn.setElevation(dp(1));
        btn.setTextColor(C_FG);
        return btn;
    }

    void setFilterUI() {
        tint(btnMt, "mtproto".equals(mode));
        tint(btnFt, "socks5".equals(mode));
    }

    void tint(Button btn, boolean on) {
        if (on) {
            btn.setBackground(glass(20, true, true));
            btn.setTextColor(C_FG);
        } else {
            btn.setBackground(glass(20));
            btn.setTextColor(C_MUTED);
        }
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
            btnLocal.setBackground(glass(16));
            btnLocal.setTextColor(C_FG);
            setStatus("Локальный прокси остановлен");
            toast("Локальный прокси остановлен");
            return;
        }
        Proxy best = null;
        for (Proxy p : all)
            if ("mtproto".equals(p.proto) && !p.secret.toLowerCase().startsWith("ee") && p.ping > 0 && p.valid)
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
        btnLocal.setBackground(glass(16, true, true));
        btnLocal.setTextColor(C_FG);
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
            final double fms = ms;
            final boolean fok = ok;
            if (!Thread.currentThread().isInterrupted()) h.post(() -> { p.ping = fms; p.valid = fok; scheduleRefresh(); });
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
            btnPing.setBackground(glass(16, true, true));
            btnPing.setTextColor(C_FG);
            cancelPings();
            h.removeCallbacks(repingRun);
            manualStep();
        } else {
            btnPing.setBackground(glass(16));
            btnPing.setTextColor(C_FG);
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
        });
    }

    Runnable repingRun = new Runnable() {
        public void run() {
            if (manual) return;
            List<Proxy> un = untested();
            if (!un.isEmpty()) startPing(un);
            else if (!top.isEmpty()) for (Proxy p : new ArrayList<>(top)) pool.submit(() -> {
                double[] r = Net.handshakePing(p, 2);
                h.post(() -> { p.ping = r[0]; p.valid = r[1] == 1 || r[0] > 0; scheduleRefresh(); });
            });
            h.postDelayed(this, REPING_MS);
        }
    };

    void setStatus(String s) { status.setText(s); }
}