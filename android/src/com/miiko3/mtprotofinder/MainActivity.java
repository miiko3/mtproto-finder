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
    static final String APP_VERSION = "0.2.0";
    static final int MAX_SERVERS = 30;
    static final int LOCAL_PORT = 10811;
    static final int REPING_MS = 6000;
    static final int PING_BATCH = 128;
    static final int MAX_TEST = 600;
    static final int RESCAN_MS = 600000;
    static final String INFO_TEXT =
        "Как считается пинг\n\n"
        + "Бейдж «NNN ms» — это полное рукопожатие с прокси, а не просто TCP-коннект. "
        + "Приложение отправляет настоящий запрос req_pq_multi и ждёт ответ ResPQ "
        + "с тем же nonce:\n"
        + "• MTProto — прямо по протоколу прокси;\n"
        + "• FakeTLS (секрет на ee…) — внутри TLS-туннеля по SNI из секрета;\n"
        + "• SOCKS5 — полный CONNECT.\n\n"
        + "Цветной бейдж получают только прокси, которые реально работают с Telegram: "
        + "зелёный — до 300 мс, жёлтый — до 1000 мс, красный — выше. "
        + "Серый «N ms · нет MTProto» — порт отвечает, но протокол не проходит: "
        + "в Telegram такой прокси не подключится. Серый «недоступен» — сервер мёртв.\n\n"
        + "Бейдж «Telegram NN ms» — замер сквозь прокси до настоящего DC Telegram "
        + "(по всем пяти, берётся лучший). Это то, что вы реально почувствуете "
        + "в приложении, поэтому при выборе прокси смотрите на него, а не на пинг до порта.\n\n"
        + "Если бейджей нет совсем — скорее всего, список источников недоступен из вашей сети. "
        + "Включите VPN и нажмите «Обновить»: приложение перечитает списки и пересортирует результат.";

    static void log(String fmt, Object... a) {
        android.util.Log.i("MTPF", String.format(fmt, a));
    }

    // Палитра в духе Google Pixel / Material 3: плоско, монотонно, без теней.
    // Один синий акцент (совпадает с логотипом), серые контейнеры по ролям.
    static final int
        C_BG = 0xFFF1F3F4,          // фон страницы
        C_SURFACE = 0xFFFFFFFF,      // карточки
        C_ON = 0xFF1F1F1F,           // основной текст
        C_MUTED = 0xFF5F6368,        // вторичный текст
        C_OUTLINE = 0xFFE2E5E9,      // волосяная линия
        C_PRIMARY = 0xFF1A73E8,      // Google Blue
        C_ON_PRIMARY = 0xFFFFFFFF,
        C_CONTAINER = 0xFFE8F0FE,    // контейнеры (сегменты, тональные кнопки)
        C_CONTAINER_2 = 0xFFF8F9FA,  // «не выбрано»
        BAR_SCRIM = 0xF2F1F3F4,      // полупрозрачные панели поверх списка
        GOOD_BG = 0xFFE6F4EA, GOOD_FG = 0xFF137333,
        MID_BG = 0xFFFEF7E0,  MID_FG = 0xFFB06000,
        BAD_BG = 0xFFFCE8E6,  BAD_FG = 0xFFC5221F,
        DEAD_BG = 0xFFF1F3F4, DEAD_FG = 0xFF80868B,
        TG_BG = 0xFFE6F4EA, TG_FG = 0xFF137333;

    static class Proxy {
        String host;
        int port;
        String secret;
        double ping = -1;
        boolean valid = true;
        // true when the server answers at the transport level (TCP connect /
        // TLS ClientHello) but does not complete the MTProto handshake.
        boolean alive;
        // Реальная задержка до Telegram DC через этот прокси (мс), -1 = не меряли.
        double tgPing = -1;
        boolean tgChecked;
        int tgDc = -1;
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
            "https://cdn.jsdelivr.net/gh/horizonpaz-create/mtproto-live@main/mtproto.txt",
            // Telegram-специфичные сборки, без которых FakeTLS-прокси почти
            // не попадали в выборку.
            "https://cdn.jsdelivr.net/gh/tgmtproxy/telegram-mtproto-proxy-list@main/proxies.txt",
            "https://cdn.jsdelivr.net/gh/kort0881/telegram-proxy-collector@main/proxy_list.txt",
            "https://cdn.jsdelivr.net/gh/Argh94/telegram-proxy-scraper@main/proxy.txt",
            "https://cdn.jsdelivr.net/gh/kort0881/telegram-proxy-collector@main/proxy_all_mtproto.txt",
            "https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt",
            "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_list.txt"
        };
        static final String[] SOCKS_SOURCES = {
            "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
            "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/SOCKS5_RAW.txt",
            "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/socks5.txt",
            "https://cdn.jsdelivr.net/gh/casals-ar/proxy-list@main/socks5",
            "https://cdn.jsdelivr.net/gh/ShiftyTR/Proxy-List@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/SOCKS5.txt",
            // Проверенные живые списки, которых не было в первой версии.
            "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt",
            "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/ALIILAPRO/Proxy@main/socks5.txt",
            "https://cdn.jsdelivr.net/gh/hproxy-com/free-proxy-list@main/socks5.txt",
            "https://cdn.jsdelivr.net/gh/VPSLabCloud/VPSLab-Free-Proxy-List@main/socks5_all.txt",
            "https://cdn.jsdelivr.net/gh/iplocate/free-proxy-list@main/protocols/socks5.txt",
            "https://cdn.jsdelivr.net/gh/Zaeem20/FREE_PROXIES_LIST@master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/Vann-Dev/proxy-list@main/proxies/socks5.txt",
            "https://cdn.jsdelivr.net/gh/sunny9577/proxy-scraper@master/generated/socks5_proxies.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
        };
        // Все источники шли через один хост cdn.jsdelivr.net: когда он
        // недоступен (а в РФ это обычное дело), приложение находило ровно
        // ноль прокси и пустой список без единого пинга. Дублируем списки
        // прямыми адресами raw.githubusercontent.com — это независимый хост
        // с другими IP, поэтому переживает блокировку CDN.
        static final String[] MT_RAW = {
            "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
            "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
            "https://raw.githubusercontent.com/MhdiTaheri/ProxyCollector/main/proxy.txt",
            "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
            "https://raw.githubusercontent.com/Chumbayoumba/free-telegram-proxy-russia-2026/main/proxy-list.txt",
            "https://raw.githubusercontent.com/horizonpaz-create/mtproto-live/main/mtproto.txt"
        };
        static final String[] SOCKS_RAW = {
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
            "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt"
        };
        static final Pattern LINK_RE = Pattern.compile("(server|port|secret)=([^&\\s]+)");
        static String[] concat() {
            List<String> o = new ArrayList<>();
            o.addAll(Arrays.asList(SOURCES));
            o.addAll(Arrays.asList(SOCKS_SOURCES));
            o.addAll(Arrays.asList(MT_RAW));
            o.addAll(Arrays.asList(SOCKS_RAW));
            return o.toArray(new String[0]);
        }
        static final Set<String> SOCKSSET = new HashSet<String>() {{
            addAll(Arrays.asList(SOCKS_SOURCES));
            addAll(Arrays.asList(SOCKS_RAW));
        }};

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
                        log("source ok %s (%d bytes)", url, text.length());
                    } catch (Exception e) {
                        log("source FAIL %s: %s", url, e);
                    }
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
                line = line.trim();
                // у списков встречаются заголовки-комментарии с датой обновления
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) continue;
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
                boolean ok = false, alive = false;
                if ("socks5".equals(p.proto)) {
                    alive = true;
                    // Для живучести достаточно CONNECT; для честного «работает с
                    // Telegram» — только успешный CONNECT (прокси обязан уметь
                    // открывать соединение наружу).
                    ok = socksConnect(s, p, p.host, p.port, timeout);
                } else if (p.secret.toLowerCase().startsWith("ee")) {
                    // Честная проверка FakeTLS: живым считается только прокси,
                    // ответивший настоящим ResPQ на req_pq_multi ВНУТРИ
                    // TLS-туннеля. Раньше здесь хватало ответа 0x16 на
                    // ClientHello — любой TLS-порт получал зелёный бейдж, но в
                    // Telegram такие прокси не подключались.
                    for (String dom : sniList(p)) {
                        if (!tlsAlive(p, dom, timeout)) continue;
                        alive = true;
                        ok = faketslsPing(p, dom, timeout);
                        break;
                    }
                } else {
                    alive = true;
                    ok = mtprotoPing(s, p.secret, 2, timeout);
                }
                s.close();
                double ms = (System.nanoTime() - t0) / 1e6;
                return new double[]{ok ? ms : -2.0, ok ? 1 : 0, alive ? 1 : 0};
            } catch (Exception e) {
                return new double[]{-2, 0, 0};
            }
        }

        // Полный SOCKS5: приветствие -> (логин/пароль) -> CONNECT к addr:port.
        // addr — реальный адрес назначения (для проверки Telegram это IP-DC).
        static boolean socksConnect(Socket s, Proxy p, String addr, int port, double timeout) {
            try {
                OutputStream os = s.getOutputStream();
                String user = "", pass = "";
                int ci = p.secret == null ? -1 : p.secret.indexOf(':');
                if (ci > 0) { user = p.secret.substring(0, ci); pass = p.secret.substring(ci + 1); }
                int t = (int) (timeout * 1000);
                byte[] g = new byte[2];
                boolean authed;
                if (!user.isEmpty()) {
                    os.write(new byte[]{0x05, 0x01, 0x02});
                    int rn = recvN(s, g, t);
                    if (rn >= 2 && g[0] == 5 && g[1] == 0) {
                        authed = true;
                    } else if (rn >= 2 && g[0] == 5 && g[1] == 2) {
                        byte[] u = user.getBytes("UTF-8"), pw = pass.getBytes("UTF-8");
                        ByteArrayOutputStream ab = new ByteArrayOutputStream();
                        ab.write(1); ab.write(u.length); ab.write(u); ab.write(pw.length); ab.write(pw);
                        os.write(ab.toByteArray());
                        rn = recvN(s, g, t);
                        authed = rn >= 2 && g[0] == 1 && g[1] == 0;
                    } else authed = false;
                } else {
                    os.write(new byte[]{0x05, 0x01, 0x00});
                    int rn = recvN(s, g, t);
                    authed = rn >= 2 && g[0] == 5 && g[1] == 0;
                }
                if (!authed) return false;
                byte[] host = addr.getBytes("UTF-8");
                ByteArrayOutputStream req = new ByteArrayOutputStream();
                req.write(new byte[]{0x05, 0x01, 0x00, 0x03});
                req.write(host.length);
                req.write(host);
                req.write((port >> 8) & 0xFF);
                req.write(port & 0xFF);
                os.write(req.toByteArray());
                byte[] rep = new byte[10];
                int rn = recvN(s, rep, t);
                return rn >= 2 && rep[0] == 5 && rep[1] == 0;
            } catch (Exception e) {
                return false;
            }
        }

        // Настоящая задержка до Telegram через этот прокси: поднимаем туннель до
        // реального DC и меряем полный обмен req_pq_multi -> ResPQ. Это то же,
        // что почувствует Telegram, а не просто TCP-рукопожатие с прокси.
        // Возвращает мс или -1, если DC не ответил.
        static double telegramPing(Proxy p, int dc, double timeout) {
            if (dc < 0 || dc >= DC_ADDRS.length) return -1;
            String ip = DC_ADDRS[dc][0];
            int dcId = Integer.parseInt(DC_ADDRS[dc][1]);
            Socket s = null;
            long t0 = System.nanoTime();
            try {
                s = new Socket();
                s.connect(new InetSocketAddress(p.host, p.port), (int) (timeout * 1000));
                s.setSoTimeout((int) (timeout * 1000));
                if ("socks5".equals(p.proto)) {
                    if (!socksConnect(s, p, ip, 443, timeout)) return -1;
                    if (!mtprotoPing(s, randomSecretHex(), dcId, timeout)) return -1;
                } else if (p.secret.toLowerCase().startsWith("ee")) {
                    // нативный TLS-туннель по SNI из секрета
                    s.close(); s = null;
                    javax.net.ssl.SSLSocket ss = null;
                    try {
                        ss = tlsSocket(p.host, p.port, domainFromSecret(p.secret), timeout);
                        if (!mtprotoPing(ss, p.secret, dcId, timeout)) return -1;
                    } catch (Exception e) {
                        return -1;
                    } finally {
                        if (ss != null) try { ss.close(); } catch (Exception ignored) {}
                    }
                    return (System.nanoTime() - t0) / 1e6;
                } else {
                    if (!mtprotoPing(s, p.secret, dcId, timeout)) return -1;
                }
                return (System.nanoTime() - t0) / 1e6;
            } catch (Exception e) {
                return -1;
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }

        static String randomSecretHex() {
            byte[] b = new byte[16];
            new SecureRandom().nextBytes(b);
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            return sb.toString();
        }

        static java.util.List<String> sniList(Proxy p) {
            java.util.List<String> snis = new ArrayList<>();
            for (String d : new String[]{domainFromSecret(p.secret), p.host, "www.cloudflare.com"})
                if (d != null && d.contains(".") && !snis.contains(d)) snis.add(d);
            return snis;
        }

        // Ответил ли сервер TLS-флайтом (0x16 0x03) на наш ClientHello.
        static boolean tlsAlive(Proxy p, String dom, double timeout) {
            try {
                Socket c2 = new Socket();
                c2.connect(new InetSocketAddress(p.host, p.port), (int) (timeout * 1000));
                c2.setSoTimeout((int) (timeout * 1000));
                c2.getOutputStream().write(tlsHello(dom));
                byte[] b = new byte[6];
                int rn = recvN(c2, b, (int) (timeout * 1000));
                c2.close();
                return rn >= 5 && (b[0] & 0xFF) == 0x16 && (b[1] & 0xFF) == 0x03;
            } catch (Exception e) {
                return false;
            }
        }

        static javax.net.ssl.SSLSocket tlsSocket(String host, int port, String sni, double timeout) throws Exception {
            javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(null, new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager(){
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
            }}, null);
            javax.net.ssl.SSLSocket ss = (javax.net.ssl.SSLSocket) ctx.getSocketFactory().createSocket();
            ss.connect(new InetSocketAddress(host, port), (int) (timeout * 1000));
            javax.net.ssl.SSLParameters sp = new javax.net.ssl.SSLParameters();
            sp.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(sni)));
            ss.setSSLParameters(sp);
            ss.setSoTimeout((int) (timeout * 1000));
            ss.startHandshake();
            return ss;
        }

        // Настоящее MTProto-рукопожатие внутри нативного TLS-туннеля по SNI
        // из секрета. Аналог _ssl_obf_ping() в localproxy.py.
        static boolean faketslsPing(Proxy p, String dom, double timeout) {
            javax.net.ssl.SSLSocket ss = null;
            try {
                ss = tlsSocket(p.host, p.port, dom, timeout);
                return mtprotoPing(ss, p.secret, 2, timeout);
            } catch (Exception e) {
                log("faketsls %s sni=%s failed: %s", p.host, dom, e);
                return false;
            } finally {
                if (ss != null) try { ss.close(); } catch (Exception ignored) {}
            }
        }

        // Настоящие адреса Telegram DC (production, порт 443).
        static final String[][] DC_ADDRS = {
            {"149.154.175.53", "1"},
            {"149.154.167.51", "2"},
            {"149.154.175.100", "3"},
            {"149.154.167.91", "4"},
            {"149.154.171.5", "5"},
        };

        // Обмен req_pq_multi -> ResPQ по уже открытому потоку (Socket или
        // SSLSocket) с указанием номера DC, к которому идёт трафик.
        static boolean mtprotoPing(Object io, String secret, int dc, double timeout) {
            try {
                java.net.Socket sock = (java.net.Socket) io;
                OutputStream os = sock.getOutputStream();
                java.io.InputStream in = sock.getInputStream();
                String sec = secret == null ? "" : secret;
                boolean pi = sec.toLowerCase().startsWith("dd") && sec.length() == 34;
                byte[] tag = pi ? LocalBridge.TAG_SECURE : LocalBridge.TAG_ABRIDGED;
                LocalBridge.HS hs = LocalBridge.build(tag, dc <= 0 ? 2 : dc, LocalBridge.secretBytes(sec));
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
                sock.setSoTimeout((int) (timeout * 1000));
                while (System.currentTimeMillis() < deadline) {
                    byte[] buf = new byte[4096];
                    int n;
                    try { n = in.read(buf); } catch (java.net.SocketTimeoutException st) { break; }
                    if (n < 0) break;
                    data = cat(data, cipherU(hs.recv(), Arrays.copyOf(buf, n)));
                    if (checkFrame(data, pi, nonce)) return true;
                }
                return false;
            } catch (Exception e) {
                return false;
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
    boolean refreshPending = false, pingBusy = false;
    ExecutorService pool = Executors.newFixedThreadPool(64);
    List<Future<?>> futures = new ArrayList<>();
    Proxy selected = null;
    LocalBridge bridge;

    LinearLayout rootLayout;
    GridView grid;
    TextView titleView, verView, status;
    Button btnMt, btnFt, btnConnect, btnTg, btnLocal, authorBtn, infoBtn, refreshBtn;

    BaseAdapter adapter = new BaseAdapter() {
        public int getCount() { return top.size(); }
        public Object getItem(int i) { return top.get(i); }
        public long getItemId(int i) { return i; }
        public View getView(int i, View v, ViewGroup parent) {
            Proxy pr = top.get(i);
            if (v == null) {
                LinearLayout card = new LinearLayout(MainActivity.this);
                card.setOrientation(LinearLayout.VERTICAL);
                card.setPadding(dp(14), dp(11), dp(14), dp(11));
                card.setBackground(cardBg(false));

                TextView host = new TextView(MainActivity.this);
                host.setTextColor(C_ON);
                host.setTextSize(15);
                host.setSingleLine(true);
                host.setEllipsize(TextUtils.TruncateAt.END);

                LinearLayout badges = new LinearLayout(MainActivity.this);
                badges.setOrientation(LinearLayout.HORIZONTAL);
                badges.setGravity(Gravity.CENTER_VERTICAL);
                LinearLayout.LayoutParams btlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                btlp.setMargins(0, dp(7), 0, 0);
                badges.setLayoutParams(btlp);

                TextView kind = badge(MainActivity.this, 11);
                TextView ping = badge(MainActivity.this, 12);
                TextView tg = badge(MainActivity.this, 12);
                LinearLayout.LayoutParams bgap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                bgap.setMargins(0, 0, dp(6), 0);
                badges.addView(kind, bgap);
                badges.addView(ping, bgap);
                badges.addView(tg, bgap);

                card.addView(host);
                card.addView(badges);
                card.setTag(new Object[]{host, kind, ping, tg});
                v = card;
            }
            Object[] t = (Object[]) v.getTag();
            TextView host = (TextView) t[0], kind = (TextView) t[1], ping = (TextView) t[2], tg = (TextView) t[3];
            host.setText(pr.host + ":" + pr.port);

            kind.setText(pr.label());
            // Метку типа показываем только когда она несёт смысл: в режиме
            // MTProto почти все карточки одинаковые, лишний чип только шумит.
            kind.setVisibility("MTProto".equals(pr.label()) ? View.GONE : View.VISIBLE);
            styleBadge(kind, C_CONTAINER, C_PRIMARY);

            if (pr.ping == -1) {
                setBadge(ping, "проверяю…", C_CONTAINER_2, C_MUTED);
            } else if (pr.ping > 0 && pr.valid) {
                String s = String.format("%.0f ms", pr.ping);
                if (pr.ping < 300) setBadge(ping, s, GOOD_BG, GOOD_FG);
                else if (pr.ping < 1000) setBadge(ping, s, MID_BG, MID_FG);
                else setBadge(ping, s, BAD_BG, BAD_FG);
            } else if (pr.ping > 0) {
                // Порт отвечает, но протокол не проходит. Число здесь вводит в
                // заблуждение — выглядит как отличный пинг, поэтому не пишем его.
                setBadge(ping, "не работает", DEAD_BG, DEAD_FG);
            } else {
                setBadge(ping, "недоступен", DEAD_BG, DEAD_FG);
            }

            if (pr.tgPing > 0) {
                setBadge(tg, String.format("Telegram %.0f ms", pr.tgPing), TG_BG, TG_FG);
            } else if (pr.tgChecked) {
                setBadge(tg, "Telegram нет связи", BAD_BG, BAD_FG);
            } else {
                setBadge(tg, "Telegram ?", C_CONTAINER_2, C_MUTED);
            }

            v.setBackground(cardBg(pr == selected));
            return v;
        }
    };

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);

        // Корень: страница + две «плавающие» полупрозрачные панели поверх
        // списка. Панели перекрывают контент, поэтому у страницы ровно такие же
        // отступы сверху и снизу — ничего не наезжает и не прыгает.
        android.widget.FrameLayout root = new android.widget.FrameLayout(this);
        root.setBackgroundColor(C_BG);

        int topBarH = dp(60), botBarH = dp(64);

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(12), topBarH + dp(8), dp(12), botBarH + dp(8));

        LinearLayout seg = new LinearLayout(this);
        seg.setOrientation(LinearLayout.HORIZONTAL);
        seg.setPadding(dp(4), dp(4), dp(4), dp(4));
        seg.setBackground(rounded(C_CONTAINER_2, 24));
        seg.setOutlineProvider(android.view.ViewOutlineProvider.BACKGROUND);
        seg.setClipToOutline(true);
        btnMt = segBtn("MTProto");
        btnFt = segBtn("SOCKS5");
        btnMt.setOnClickListener(v -> setMode("mtproto"));
        btnFt.setOnClickListener(v -> setMode("socks5"));
        LinearLayout.LayoutParams s1 = new LinearLayout.LayoutParams(0, dp(38), 1f);
        LinearLayout.LayoutParams s2 = new LinearLayout.LayoutParams(0, dp(38), 1f);
        seg.addView(btnMt, s1);
        seg.addView(btnFt, s2);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.setMargins(0, 0, 0, dp(10));
        page.addView(seg, slp);

        grid = new GridView(this);
        // Две колонки на телефоне обрезали имя хоста до четырёх символов
        // («guar…») — прокси становилось невозможно опознать и подключить.
        int screenW = getResources().getDisplayMetrics().widthPixels;
        int cols = screenW >= dp(600) ? 2 : 1;
        grid.setNumColumns(cols);
        grid.setStretchMode(GridView.STRETCH_COLUMN_WIDTH);
        int colW = (int) (screenW / (float) cols - dp(24));
        grid.setColumnWidth(colW);
        grid.setHorizontalSpacing(dp(8));
        grid.setVerticalSpacing(dp(8));
        grid.setPadding(0, 0, 0, 0);
        grid.setClipToPadding(false);
        grid.setBackgroundColor(0x00000000);
        grid.setCacheColorHint(0x00000000);
        grid.setAdapter(adapter);
        grid.setOnItemClickListener((p, v, pos, id) -> { selected = top.get(pos); adapter.notifyDataSetChanged(); });
        grid.setOnItemLongClickListener((p, v, pos, id) -> { cardMenu(top.get(pos)); return true; });
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        gp.setMargins(0, 0, 0, dp(8));
        page.addView(grid, gp);

        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(C_MUTED);
        status.setGravity(Gravity.CENTER);
        status.setSingleLine(true);
        status.setEllipsize(TextUtils.TruncateAt.END);
        page.addView(status);

        root.addView(page, new android.widget.FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        // --- верхняя панель ---
        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setPadding(dp(12), 0, dp(8), 0);
        topBar.setBackground(barScrim(true));
        ImageView logo = new ImageView(this);
        logo.setImageDrawable(logoDrawable(dp(30)));
        topBar.addView(logo, new LinearLayout.LayoutParams(dp(30), dp(30)));

        LinearLayout tw = new LinearLayout(this);
        tw.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams twlp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        twlp.setMargins(dp(10), 0, 0, 0);
        titleView = new TextView(this);
        titleView.setText("MTProto Finder");
        titleView.setTextSize(17);
        titleView.setTextColor(C_ON);
        titleView.setSingleLine(true);
        verView = new TextView(this);
        verView.setText("версия " + APP_VERSION);
        verView.setTextSize(11);
        verView.setTextColor(C_MUTED);
        verView.setSingleLine(true);
        tw.addView(titleView);
        tw.addView(verView);
        topBar.addView(tw, twlp);

        infoBtn = iconBtn("i");
        infoBtn.setContentDescription("О пинге");
        infoBtn.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("Как считается пинг · v" + APP_VERSION)
            .setMessage(INFO_TEXT)
            .setPositiveButton("Понятно", null)
            .show());
        refreshBtn = iconBtn("↻");
        refreshBtn.setContentDescription("Обновить списки");
        refreshBtn.setOnClickListener(v -> {
            cancelPings();
            h.removeCallbacks(repingRun);
            h.removeCallbacks(rescanRun);
            setStatus("Обновляю списки…");
            startScan();
        });
        authorBtn = iconBtn("@");
        authorBtn.setContentDescription("Автор");
        authorBtn.setOnClickListener(v -> open(AUTHOR_URL));
        topBar.addView(infoBtn, new LinearLayout.LayoutParams(dp(40), dp(40)));
        topBar.addView(refreshBtn, new LinearLayout.LayoutParams(dp(40), dp(40)));
        topBar.addView(authorBtn, new LinearLayout.LayoutParams(dp(40), dp(40)));

        android.widget.FrameLayout.LayoutParams tblp = new android.widget.FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, topBarH, android.view.Gravity.TOP);
        root.addView(topBar, tblp);

        // --- нижняя панель ---
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(12), dp(8), dp(12), dp(8));
        bar.setBackground(barScrim(false));
        btnConnect = flatBtn("Подключить", true);
        btnConnect.setOnClickListener(v -> {
            if (selected != null) { open(selected.link()); toast("Открываю " + selected.host + " в Telegram"); }
            else toast("Сначала выберите сервер из списка");
        });
        btnTg = flatBtn("Пинг TG", false);

        btnTg.setOnClickListener(v -> checkTelegram());
        btnLocal = flatBtn("Локальный", false);
        btnLocal.setOnClickListener(v -> toggleLocal());
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(0, dp(44), 1f);
        ap.setMargins(dp(3), 0, dp(3), 0);
        btnConnect.setLayoutParams(ap);
        btnTg.setLayoutParams(ap);
        btnLocal.setLayoutParams(ap);
        bar.addView(btnConnect);
        bar.addView(btnTg);
        bar.addView(btnLocal);
        android.widget.FrameLayout.LayoutParams bblp = new android.widget.FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, botBarH, android.view.Gravity.BOTTOM);
        root.addView(bar, bblp);

        setContentView(root);
        rootLayout = page;
        setFilterUI();
        h.postDelayed(this::startScan, 100);
    }

    // Плоские карточки: заливка + волосяная линия, без тени и градиента.
    android.graphics.drawable.Drawable cardBg(boolean selected) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(selected ? C_CONTAINER : C_SURFACE);
        d.setCornerRadius(dp(14));
        d.setStroke(dp(selected ? 2 : 1), selected ? C_PRIMARY : C_OUTLINE);
        return d;
    }

    // Полупрозрачная панель поверх списка + тонкая линия по краю. Вместо
    // отдельного окна со стеклом — лёгкий скрим, чтобы контент под панелью
    // оставался читаемым, но не спорил с кнопками.
    android.graphics.drawable.Drawable barScrim(boolean top) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(BAR_SCRIM);
        d.setStroke(dp(1), C_OUTLINE);
        if (top) {
            d.setCornerRadii(new float[]{0, 0, 0, 0, 0, 0, dp(0), dp(0), dp(18), dp(18), dp(18), dp(18)});
        } else {
            d.setCornerRadii(new float[]{dp(18), dp(18), dp(18), dp(18), 0, 0, 0, 0, 0, 0, 0, 0});
        }
        return d;
    }

    android.graphics.drawable.Drawable logoDrawable(int s) {
        Bitmap src = BitmapFactory.decodeResource(getResources(), R.drawable.logo);
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
        float r = dp(8);
        cv.drawRoundRect(0, 0, s, s, r, r, p);
        return new BitmapDrawable(getResources(), out);
    }

    GradientDrawable rounded(int color, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(radius));
        return d;
    }

    int dp(float v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    TextView badge(android.content.Context ctx, float size) {
        TextView t = new TextView(ctx);
        t.setTextSize(size);
        t.setTextColor(C_MUTED);
        t.setSingleLine(true);
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(9), dp(4), dp(9), dp(4));
        t.setIncludeFontPadding(false);
        return t;
    }

    void setBadge(TextView t, String text, int bg, int fg) {
        t.setText(text);
        t.setTextColor(fg);
        GradientDrawable d = new GradientDrawable();
        d.setColor(bg);
        d.setCornerRadius(dp(8));
        t.setBackground(d);
    }

    void styleBadge(TextView t, int bg, int fg) { setBadge(t, t.getText().toString(), bg, fg); }

    // Кнопки без тени и без анимации подъёма (stateListAnimator = null) —
    // иначе система сама добавляет «эффект», даже если фон плоский.
    Button flatBtn(String t, boolean primary) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(12);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setTextColor(primary ? C_ON_PRIMARY : C_ON);
        btn.setSingleLine(true);
        btn.setEllipsize(TextUtils.TruncateAt.END);
        btn.setGravity(Gravity.CENTER);
        btn.setStateListAnimator(null);
        btn.setElevation(0f);
        btn.setBackground(pressable(
                primary ? C_PRIMARY : C_CONTAINER,
                primary ? 0xFF175FBF : 0xFFDCE7FB));
        return btn;
    }

    Button iconBtn(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(15);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setTextColor(C_ON);
        btn.setPadding(0, 0, 0, 0);
        btn.setGravity(Gravity.CENTER);
        btn.setStateListAnimator(null);
        btn.setElevation(0f);
        btn.setBackground(pressable(0x00000000, C_CONTAINER));
        return btn;
    }

    Button segBtn(String t) {
        Button btn = new Button(this);
        btn.setText(t);
        btn.setAllCaps(false);
        btn.setTextSize(14);
        btn.setTypeface(null, Typeface.BOLD);
        btn.setTextColor(C_MUTED);
        btn.setPadding(0, 0, 0, 0);
        btn.setGravity(Gravity.CENTER);
        btn.setStateListAnimator(null);
        btn.setElevation(0f);
        btn.setBackground(pressable(0x00000000, 0x00000000));
        return btn;
    }

    android.graphics.drawable.Drawable pressable(int normal, int pressed) {
        android.graphics.drawable.StateListDrawable s = new android.graphics.drawable.StateListDrawable();
        s.addState(new int[]{android.R.attr.state_pressed}, rounded(pressed, 20));
        s.addState(new int[]{}, rounded(normal, 20));
        return s;
    }

    void setFilterUI() {
        tint(btnMt, "mtproto".equals(mode));
        tint(btnFt, "socks5".equals(mode));
    }

    void tint(Button btn, boolean on) {
        btn.setBackground(pressable(on ? C_PRIMARY : 0x00000000, on ? 0xFF175FBF : C_CONTAINER));
        btn.setTextColor(on ? C_ON_PRIMARY : C_MUTED);
    }

    void cardMenu(Proxy p) {
        if (p == null) return;
        selected = p;
        adapter.notifyDataSetChanged();
        String[] opts = {"Подключиться в Telegram", "Проверить пинг в Telegram", "Перемерить прокси", "Скопировать ссылку", "Скопировать адрес"};
        new AlertDialog.Builder(this)
            .setTitle(p.host + ":" + p.port)
            .setItems(opts, (d, which) -> {
                if (which == 0) {
                    open(p.link());
                    toast("Открываю в Telegram");
                } else if (which == 1) {
                    selected = p;
                    adapter.notifyDataSetChanged();
                    checkTelegram();
                } else if (which == 2) {
                    quickPing(p);
                } else if (which == 3) {
                    copyText(p.link());
                } else {
                    copyText(p.host + ":" + p.port);
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
            double ms = r[0];
            if (ms < 0 && r.length > 2 && r[2] == 1) ms = Net.tcpPing(p, 2);
            final double shown = ms;
            h.post(() -> toast(shown > 0 ? "Пинг " + String.format("%.0f", shown) + " ms" : "Недоступен"));
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
            btnLocal.setBackground(pressable(C_CONTAINER, 0xFFDCE7FB));
            setStatus("Локальный прокси остановлен");
            toast("Локальный прокси остановлен");
            return;
        }
        Proxy best = bestLive();
        if (best == null) { toast("Нет рабочего MTProto — подождите проверки"); return; }
        if (Net.handshakePing(best, 2)[0] < 0) {
            toast("Прокси сейчас недоступен — выберите другой");
            setStatus("⚠ " + best.host + " недоступен прямо сейчас");
            return;
        }
        // Мост сам перебирает живые серверы на каждом подключении: раньше
        // выбранный прокси замораживался на момент нажатия, и после его смерти
        // локальный прокси не поднимался вообще.
        bridge = new LocalBridge(LOCAL_PORT, this::bestLive);
        bridge.start();
        btnLocal.setBackground(pressable(C_PRIMARY, 0xFF175FBF));
        setStatus("Локальный прокси 127.0.0.1:" + LOCAL_PORT + " через " + best.host);
        open("tg://proxy?server=127.0.0.1&port=" + LOCAL_PORT + "&secret=" + LocalBridge.LOCAL_SECRET_HEX);
    }

    // Лучший сейчас рабочий MTProto, перепроверяемый на лету.
    synchronized Proxy bestLive() {
        List<Proxy> cands = new ArrayList<>();
        for (Proxy p : all)
            if ("mtproto".equals(p.proto) && p.valid && p.ping > 0) cands.add(p);
        if (cands.isEmpty()) return null;
        Collections.sort(cands, (a, b) -> Double.compare(a.ping, b.ping));
        for (int i = 0; i < Math.min(3, cands.size()); i++) {
            Proxy p = cands.get(i);
            if (Net.handshakePing(p, 2)[0] > 0) return p;
            p.valid = false;
        }
        return null;
    }

    List<Proxy> pool() {
        List<Proxy> r = new ArrayList<>();
        for (Proxy p : all) if (p.proto.equals(mode)) r.add(p);
        return r;
    }

    // Проверять все 39 тысяч найденных нельзя — за полчаса. Ограничиваем
    // выборку: список перемешан один раз, поэтому окно репрезентативно.
    List<Proxy> candidates() {
        List<Proxy> r = pool();
        return r.size() > MAX_TEST ? new ArrayList<>(r.subList(0, MAX_TEST)) : r;
    }

    void setMode(String m) {
        mode = m;
        selected = null;
        setFilterUI();
        refreshNow();
        startPing(untested());
    }

    void startScan() {
        setStatus("🔍 Поиск прокси в интернете…");
        new Thread(() -> {
            List<Proxy> r = Net.fetch();
            log("fetch: %d proxies", r.size());
            h.post(() -> {
                if (!r.isEmpty()) {
                    // Перечитывание источников не должно стирать уже измеренный
                    // пинг: раньше `all = r` затирал все результаты, и при
                    // Пересканы каждые 30 секунд и пинг не успевал проявиться.
                    mergeProxies(r);
                    java.util.Collections.shuffle(all, new java.util.Random(0x5eed));
                    setStatus("Найдено " + all.size() + " прокси, измеряю пинг…");
                    top = first(candidates(), MAX_SERVERS);
                    adapter.notifyDataSetChanged();
                    startPing(untested());
                    h.removeCallbacks(repingRun);
                    h.postDelayed(repingRun, REPING_MS);
                    h.removeCallbacks(rescanRun);
                    h.postDelayed(rescanRun, RESCAN_MS);
                } else {
                    setStatus("⚠ Источники недоступны — включите VPN и повторите");
                    h.postDelayed(this::startScan, 15000);
                }
            });
        }).start();
    }

    static String proxyKey(Proxy p) { return p.proto + "|" + p.host + ":" + p.port; }

    // Переносим измеренное состояние на свежие объекты того же сервера.
    void mergeProxies(List<Proxy> fresh) {
        java.util.Map<String, Proxy> prev = new java.util.HashMap<>();
        for (Proxy p : all) prev.put(proxyKey(p), p);
        List<Proxy> out = new ArrayList<>(fresh.size());
        int kept = 0;
        for (Proxy p : fresh) {
            Proxy old = prev.get(proxyKey(p));
            if (old != null) {
                p.ping = old.ping;
                p.valid = old.valid;
                p.alive = old.alive;
                kept++;
            }
            out.add(p);
        }
        log("merge: %d fresh, %d kept measured state", fresh.size(), kept);
        all = out;
    }

    List<Proxy> first(List<Proxy> l, int n) { return new ArrayList<>(l.subList(0, Math.min(n, l.size()))); }

    List<Proxy> untested() {
        List<Proxy> r = new ArrayList<>();
        for (Proxy p : candidates()) if (p.ping == -1) r.add(p);
        return r;
    }

    Runnable rescanRun = this::startScan;

    void cancelPings() {
        for (Future<?> f : futures) f.cancel(true);
        futures.clear();
        pingBusy = false;
    }

    // Пингуем пачку целиком, но ограничиваем её размер: раньше уходили в сеть
    // сразу все найденные прокси (их сотни), очередь в пуле растягивала
    // обновление списка на десятки секунд, а флаг pingBusy сбрасывался задачей,
    // которая стояла в конце этой же очереди.
    void startPing(List<Proxy> targets) {
        if (pingBusy || targets.isEmpty()) return;
        List<Proxy> batch = targets.size() > PING_BATCH ? new ArrayList<>(targets.subList(0, PING_BATCH)) : targets;
        pingBusy = true;
        List<Future<?>> batchFutures = new ArrayList<>();
        for (Proxy p : batch) {
            batchFutures.add(pool.submit(() -> {
                try {
                    if (Thread.currentThread().isInterrupted()) return;
                    double[] r = Net.handshakePing(p, 2);
                    p.valid = r[1] == 1;
                    p.alive = r.length > 2 && r[2] == 1;
                    if (p.valid) {
                        p.ping = r[0];
                    } else if (p.alive) {
                        // порт отвечает, но MTProto не прошёл — честная задержка
                        // до сервера, помечаем как непригодный
                        p.ping = Net.tcpPing(p, 1);
                        if (p.ping < 0) p.ping = -2;
                    } else {
                        p.ping = -2;
                    }
                    if (!Thread.currentThread().isInterrupted() && !refreshPending) h.post(this::scheduleRefresh);
                } catch (Throwable t) {
                    log("ping crash %s: %s", p.host, t);
                }
            }));
        }
        futures.addAll(batchFutures);
        pool.submit(() -> {
            for (Future<?> f : batchFutures) {
                try { f.get(30, TimeUnit.SECONDS); } catch (Exception ignored) { }
            }
            h.post(() -> {
                futures.removeAll(batchFutures);
                pingBusy = false;
            });
        });
    }

    void scheduleRefresh() {
        if (refreshPending) return;
        refreshPending = true;
        h.postDelayed(() -> { refreshPending = false; refreshNow(); }, 400);
    }

    void refreshNow() {
        List<Proxy> pl = candidates();
        List<Proxy> alive = new ArrayList<>(), un = new ArrayList<>(), dead = new ArrayList<>();
        for (Proxy p : pl) {
            if (p.ping > 0) alive.add(p);
            else if (p.ping == -1) un.add(p);
            else dead.add(p);
        }
        // Рабочие (прошедшие MTProto-рукопожатие) всегда выше «живых, но без MTProto».
        Collections.sort(alive, (a, b) -> {
            if (a.valid != b.valid) return a.valid ? -1 : 1;
            return Double.compare(a.ping, b.ping);
        });
        int working = 0;
        for (Proxy p : alive) if (p.valid) working++;
        List<Proxy> t = new ArrayList<>(alive);
        t.addAll(un);
        t.addAll(dead);
        top = first(t, MAX_SERVERS);
        adapter.notifyDataSetChanged();
        int tested = alive.size() + dead.size();
        if (pl.isEmpty()) return;
        // Перескан больше не привязан к «нет рабочих»: раньше это затирало
        // результаты каждые 30 секунд и пинг не успевал проявиться.
        if (working > 0) setStatus("Рабочих: " + working + " · проверено " + tested + " из " + pl.size());
        else if (un.isEmpty()) setStatus("Рабочих нет · проверено " + tested + " из " + pl.size());
        else setStatus("Проверено " + tested + " из " + pl.size() + "…");
    }

    // Замеряем настоящую задержку до Telegram через выбранный прокси: для
    // MTProto — рукопожатие с конкретным DC, для SOCKS5 — CONNECT на реальный
    // адрес DC и тот же обмен внутри туннеля. Это ровно то, что почувствует
    // Telegram, в отличие от TCP-пинга до прокси.
    void checkTelegram() {
        final Proxy p = selected;
        if (p == null) { toast("Сначала выберите сервер из списка"); return; }
        final int n = Net.DC_ADDRS.length;
        double[] bestMs = new double[n];
        int[] bestDc = new int[n];
        for (int i = 0; i < n; i++) bestMs[i] = -1;
        setStatus("Проверяю связь с Telegram через " + p.host + "…");
        btnTg.setEnabled(false);
        pool.submit(() -> {
            for (int dc = 0; dc < n; dc++) {
                if (Thread.currentThread().isInterrupted()) return;
                double ms = Net.telegramPing(p, dc, 4);
                if (ms > 0) { bestMs[dc] = ms; bestDc[dc] = dc + 1; }
            }
            final double min = minOf(bestMs);
            final int minDc = min > 0 ? bestDc[indexOfMin(bestMs)] : -1;
            h.post(() -> {
                btnTg.setEnabled(true);
                p.tgChecked = true;
                p.tgDc = minDc;
                p.tgPing = min;
                if (min > 0) {
                    setStatus("Telegram через " + p.host + ": " + String.format("%.0f", min) + " мс (DC" + minDc + ")");
                    toast("Telegram: " + String.format("%.0f", min) + " мс");
                } else {
                    setStatus("Telegram через " + p.host + ": нет связи с DC");
                    toast("Telegram не отвечает через этот прокси");
                }
                scheduleRefresh();
            });
        });
    }

    static double minOf(double[] a) {
        double m = -1;
        for (double x : a) if (x > 0 && (m < 0 || x < m)) m = x;
        return m;
    }

    static int indexOfMin(double[] a) {
        int idx = -1;
        double m = -1;
        for (int i = 0; i < a.length; i++) if (a[i] > 0 && (m < 0 || a[i] < m)) { m = a[i]; idx = i; }
        return idx;
    }

    Runnable repingRun = new Runnable() {
        public void run() {
            List<Proxy> un = untested();
            if (!un.isEmpty()) startPing(un);
            else if (!top.isEmpty()) startPing(new ArrayList<>(top));
            h.postDelayed(this, REPING_MS);
        }
    };


    void setStatus(String s) { status.setText(s); }
}