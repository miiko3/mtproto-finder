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
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class MainActivity extends Activity {

    static final String AUTHOR_URL = "https://t.me/yetilov";
    static final int MAX_SERVERS = 30;
    static final int LOCAL_PORT = 10808;
    static final int REPING_MS = 5000;
    static final int RESCAN_MS = 600000;
    static final String INFO_TEXT = "Пинг в приложении отличается от пинга в Telegram? Все из за разности подхода к проверки его доступности.\n\nMTProto Finder предоставляет пинг (число) путем подключение мобильной/WiFi сети к серверу.\n\nА Telegram обрабатывает прокси сервер через HTTPS, то есть, чтобы установить соединение, нужно выполнить «рукопожатие» (3 пакета TCP + обмен ключами шифрования) - это занимает время и требует больше ресурсов.";

    static final int
        C_BG = 0xFF0E1116,
        C_CARD = 0xFF161B22,
        C_CHIP = 0xFF1C232D,
        C_FG = 0xFFE6EDF3,
        C_MUTED = 0xFF8B949E,
        C_ACCENT = 0xFF1F6FEB;

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

    static class Net{
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
    static String[]concat(){String[]o=new String[SOURCES.length+SOCKS_SOURCES.length];System.arraycopy(SOURCES,0,o,0,SOURCES.length);System.arraycopy(SOCKS_SOURCES,0,o,SOURCES.length,SOCKS_SOURCES.length);return o;}
    static List<Proxy>fetch(){
    List<Proxy>found=new ArrayList<>();Set<String>seen=new HashSet<>();
    for(String url:concat()){
    try{
    System.out.println("MTProtoFinder: fetching "+url);
    HttpsURLConnection c=(HttpsURLConnection)new URL(url).openConnection();
    c.setConnectTimeout(15000);c.setReadTimeout(15000);c.setRequestProperty("User-Agent","MTProtoFinder");
    BufferedReader r=new BufferedReader(new InputStreamReader(c.getInputStream(),"UTF-8"));
    StringBuilder sb=new StringBuilder();String l;while((l=r.readLine())!=null)sb.append(l).append('\n');
    c.disconnect();String text=sb.toString();
    System.out.println("MTProtoFinder: got "+text.length()+" bytes");
    if(url.endsWith(".json"))parseJson(text,found,seen);
    else if(SOCKSSET.contains(url))parseSocks(text,found,seen);
    else parseText(text,found,seen);
    }catch(Exception e){System.out.println("MTProtoFinder: fetch error "+e);}}
    return found;}
    static final Set<String>SOCKSSET=new HashSet<>(java.util.Arrays.asList(SOCKS_SOURCES));
    static void parseSocks(String t,List<Proxy>f,Set<String>s){
    for(String line:t.split("\n")){line=line.trim();if(line.isEmpty()||line.startsWith("#")||line.startsWith("!"))continue;
    java.util.regex.Matcher m=Pattern.compile("(?:socks5://)?([\\w.\\-]+):(\\d+)(?::([^:@\\s]+):([^:@\\s]+))?").matcher(line);
    if(m.find()){try{String auth=(m.group(3)!=null)?m.group(3)+":"+m.group(4):"";add(new Proxy(m.group(1),Integer.parseInt(m.group(2)),auth,"socks5"),f,s);}catch(Exception ignored){}}}}
    static void add(Proxy p,List<Proxy>f,Set<String>s){if(p!=null&&s.add(p.host+":"+p.port))f.add(p);}
    static void parseJson(String t,List<Proxy>f,Set<String>s){
    int i=0;
    while(true){i=t.indexOf("\"host\"",i);if(i<0)return;
    int e=t.indexOf('}',i);if(e<0)return;
    String seg=t.substring(i,e);
    Matcher mh=Pattern.compile("\"host\"\\s*:\\s*\"([^\"]+)\"").matcher(seg);
    Matcher mp=Pattern.compile("\"port\"\\s*:\\s*(\\d+)").matcher(seg);
    Matcher ms=Pattern.compile("\"secret\"\\s*:\\s*\"([^\"]+)\"").matcher(seg);
    if(mh.find()&&mp.find()&&ms.find()){try{add(new Proxy(mh.group(1),Integer.parseInt(mp.group(1)),ms.group(1)),f,s);}catch(Exception ignored){}}
    i=e;}}
    static void parseText(String t,List<Proxy>f,Set<String>s){
    for(String line:t.split("\n")){
    Matcher m=LINK_RE.matcher(line);
    String host=null,port=null,secret=null;
    while(m.find()){String k=m.group(1),v=m.group(2);if("server".equals(k))host=decode(v);else if("port".equals(k))port=decode(v);else if("secret".equals(k))secret=decode(v);}
    if(host!=null&&port!=null&&secret!=null){try{add(new Proxy(host.trim().replaceAll("\\.$",""),Integer.parseInt(port),secret),f,s);}catch(Exception ignored){}}}}
    static String decode(String s){try{return java.net.URLDecoder.decode(s,"UTF-8");}catch(Exception e){return s;}}
    static double[]handshakePing(Proxy p,double timeout){
    long t0=System.nanoTime();boolean ok=true;
    try{
    Socket s=new Socket();s.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));s.setSoTimeout((int)(timeout*1000));
    if("socks5".equals(p.proto)){s.getOutputStream().write(new byte[]{0x05,0x01,0x00});byte[]b=new byte[2];int n=s.getInputStream().read(b);ok=n>=2&&(b[0]&0xFF)==0x05;}
    else if(p.secret.toLowerCase().startsWith("ee")){s.getOutputStream().write(tlsHello(domainFromSecret(p.secret)));byte[]b=new byte[6];int n=s.getInputStream().read(b);ok=n>=2&&(b[0]&0xFF)==0x16;}
    else{s.getOutputStream().write(obfHead(p.secret,2));}
    s.close();
    }catch(Exception e){return new double[]{-2,0};}
    return new double[]{(System.nanoTime()-t0)/1e6,ok?1:0};}
    static byte[]obfHead(String secretHex,int dcId){
    try{
    byte[]sec=hex(secretHex.length()>=32?secretHex.substring(0,32):"0123456789abcdef0123456789abcdef");
    byte[]r=new byte[64];new java.security.SecureRandom().nextBytes(r);
    r[56]=(byte)dcId;r[57]=(byte)(dcId>>8);r[58]=0;r[59]=0;r[60]=(byte)0xEE;r[61]=(byte)0xEE;r[62]=(byte)0xEE;r[63]=(byte)0xEE;
    byte[]dk=sha256(java.util.Arrays.copyOfRange(r,8,40),sec);
    byte[]div=java.util.Arrays.copyOfRange(sha256(java.util.Arrays.copyOfRange(r,40,56),sec),0,16);
    byte[]rr=new byte[64];for(int i=0;i<64;i++)rr[i]=r[63-i];
    byte[]ek=sha256(java.util.Arrays.copyOfRange(rr,8,40),sec);
    byte[]eiv=java.util.Arrays.copyOfRange(sha256(java.util.Arrays.copyOfRange(rr,40,56),sec),0,16);
    javax.crypto.Cipher dec=javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
    dec.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(dk,"AES"),new javax.crypto.spec.IvParameterSpec(div));
    byte[]tail=java.util.Arrays.copyOfRange(r,56,64);
    byte[]et=dec.doFinal(tail);
    byte[]out=new byte[64];System.arraycopy(r,0,out,0,56);System.arraycopy(et,0,out,56,8);
    return out;
    }catch(Exception e){return new byte[64];}}
    static byte[]sha256(byte[]a,byte[]b){try{java.security.MessageDigest md=java.security.MessageDigest.getInstance("SHA-256");md.update(a);md.update(b);return md.digest();}catch(Exception e){return new byte[32];}}
    static double tcpPing(Proxy p,double timeout){
    long s=System.nanoTime();
    try{Socket sock=new Socket();sock.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));sock.close();return(System.nanoTime()-s)/1e6;}
    catch(Exception e){return-2;}}
    static boolean validate(Proxy p,double timeout){
    try{
    if("socks5".equals(p.proto)){
    Socket s=new Socket();s.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));s.setSoTimeout((int)(timeout*1000));
    s.getOutputStream().write(new byte[]{0x05,0x01,0x00});
    byte[]b=new byte[2];int n=s.getInputStream().read(b);s.close();
    return n>=2&&(b[0]&0xFF)==0x05;
    }
    if("faketls".equals(p.proto)){
    Socket s=new Socket();s.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));s.setSoTimeout((int)(timeout*1000));
    String dom=domainFromSecret(p.secret);
    byte[]hello=tlsHello(dom);
    s.getOutputStream().write(hello);
    byte[]b=new byte[6];int n=s.getInputStream().read(b);s.close();
    return n>=2&&(b[0]&0xFF)==0x16;
    }else{
    byte[]sec;try{sec=hex(p.secret);}catch(Exception e){return false;}
    Socket s=new Socket();s.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));s.setSoTimeout((int)(timeout*1000));
    byte[]req=new byte[sec.length+1];req[0]=(byte)0xEE;System.arraycopy(sec,0,req,1,sec.length);
    s.getOutputStream().write(req);
    byte[]b=new byte[4];int n=s.getInputStream().read(b);s.close();
    return n>=1&&(b[0]&0xFF)==0xEE;
    }
    }catch(Exception e){return true;}
    }
    static String domainFromSecret(String sec){
    if(sec==null||!sec.toLowerCase().startsWith("ee")||sec.length()<4)return"www.cloudflare.com";
    try{StringBuilder o=new StringBuilder();int i=2;
    while(i+1<sec.length()){String ch=hexStr(sec.substring(i,i+2));if(ch==null||!(Character.isLetterOrDigit(ch.charAt(0))||ch.equals(".")||ch.equals("-")))break;o.append(ch);i+=2;}
    String d=o.toString().replaceAll("\\.$","");return(d.contains(".")&&!d.isEmpty())?d:"www.cloudflare.com";
    }catch(Exception e){return"www.cloudflare.com";}
    }
    static String hexStr(String s){try{return new String(new byte[]{(byte)Integer.parseInt(s,16)});}catch(Exception e){return null;}}
    static byte[]hex(String s){int n=s.length()/2;byte[]o=new byte[n];for(int i=0;i<n;i++)o[i]=(byte)Integer.parseInt(s.substring(2*i,2*i+2),16);return o;}
    static byte[]tlsHello(String domain){
    java.io.ByteArrayOutputStream body=new java.io.ByteArrayOutputStream();
    byte[]host=domain.getBytes();
    java.io.ByteArrayOutputStream sni=new java.io.ByteArrayOutputStream();
    try{
    sni.write(new byte[]{(byte)0x00,(byte)domain.length()});sni.write(host);
    java.io.ByteArrayOutputStream sniList=new java.io.ByteArrayOutputStream();
    sniList.write(new byte[]{0x00,0x00});sniList.write(new byte[]{(byte)((sni.size()>>8)&0xFF),(byte)(sni.size()&0xFF)});sniList.write(sni.toByteArray());
    java.io.ByteArrayOutputStream sniExt=new java.io.ByteArrayOutputStream();
    sniExt.write(new byte[]{0x00,0x00});sniExt.write(new byte[]{(byte)((sniList.size()>>8)&0xFF),(byte)(sniList.size()&0xFF)});sniExt.write(sniList.toByteArray());
    byte[]ciphers=new byte[]{(byte)0x13,0x01,(byte)0x13,0x02,(byte)0x13,0x03,0x00,(byte)0x9c,0x00,0x35};
    java.io.ByteArrayOutputStream cl=new java.io.ByteArrayOutputStream();
    cl.write(new byte[]{(byte)((ciphers.length>>8)&0xFF),(byte)(ciphers.length&0xFF)});cl.write(ciphers);
    body.write(new byte[]{0x03,0x03});body.write(new byte[32]);body.write(new byte[]{0x00});body.write(cl.toByteArray());
    body.write(new byte[]{0x01,0x00});body.write(sniExt.toByteArray());
    java.io.ByteArrayOutputStream hs=new java.io.ByteArrayOutputStream();
    hs.write(new byte[]{0x01});byte[]bl=body.toByteArray();hs.write(new byte[]{(byte)((bl.length>>16)&0xFF),(byte)((bl.length>>8)&0xFF),(byte)(bl.length&0xFF)});hs.write(bl);
    java.io.ByteArrayOutputStream rec=new java.io.ByteArrayOutputStream();
    rec.write(new byte[]{0x16,0x03,0x01});rec.write(new byte[]{(byte)((hs.size()>>8)&0xFF),(byte)(hs.size()&0xFF)});rec.write(hs.toByteArray());
    return rec.toByteArray();
    }catch(Exception e){return new byte[]{0x16,0x03,0x01,0x00,0x00};}
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
    ListView list;
    TextView titleView, verView, status;
    Button btnMt, btnFt, btnConnect, btnPing, btnLocal, authorBtn, infoBtn;

    BaseAdapter adapter = new BaseAdapter() {
        public int getCount() { return top.size(); }
        public Object getItem(int i) { return top.get(i); }
        public long getItemId(int i) { return i; }
        public View getView(int i, View v, ViewGroup parent) {
            Proxy p = top.get(i);
            if (v == null) {
                LinearLayout card = new LinearLayout(MainActivity.this);
                card.setOrientation(LinearLayout.HORIZONTAL);
                card.setGravity(Gravity.CENTER_VERTICAL);
                card.setPadding(dp(14), dp(11), dp(14), dp(11));
                GradientDrawable cb = new GradientDrawable();
                cb.setColor(C_CARD);
                cb.setCornerRadius(dp(16));
                card.setBackground(cb);
                LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                cp.setMargins(dp(6), dp(5), dp(6), dp(5));
                card.setLayoutParams(cp);

                TextView rank = new TextView(MainActivity.this);
                rank.setGravity(Gravity.CENTER);
                rank.setTextSize(12);
                rank.setTypeface(null, Typeface.BOLD);
                rank.setTextColor(C_MUTED);
                GradientDrawable rb = new GradientDrawable();
                rb.setColor(C_CHIP);
                rb.setCornerRadius(dp(10));
                rank.setBackground(rb);
                rank.setPadding(dp(2), dp(6), dp(2), dp(6));
                card.addView(rank, new LinearLayout.LayoutParams(dp(30), ViewGroup.LayoutParams.WRAP_CONTENT));

                LinearLayout mid = new LinearLayout(MainActivity.this);
                mid.setOrientation(LinearLayout.VERTICAL);
                mid.setPadding(dp(12), 0, dp(10), 0);
                TextView host = new TextView(MainActivity.this);
                host.setTextColor(C_FG);
                host.setTextSize(15);
                host.setTypeface(null, Typeface.BOLD);
                host.setSingleLine(true);
                host.setEllipsize(TextUtils.TruncateAt.END);
                TextView info = new TextView(MainActivity.this);
                info.setTextColor(C_MUTED);
                info.setTextSize(12);
                info.setSingleLine(true);
                info.setEllipsize(TextUtils.TruncateAt.END);
                mid.addView(host);
                mid.addView(info);
                card.addView(mid, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

                TextView ping = new TextView(MainActivity.this);
                ping.setTextSize(13);
                ping.setTypeface(null, Typeface.BOLD);
                ping.setGravity(Gravity.CENTER);
                ping.setPadding(dp(10), dp(6), dp(10), dp(6));
                GradientDrawable pbg = new GradientDrawable();
                pbg.setCornerRadius(dp(20));
                ping.setBackground(pbg);
                card.addView(ping, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

                card.setTag(new Object[]{rank, host, info, ping});
                v = card;
            }
            Object[] t = (Object[]) v.getTag();
            Proxy pr = top.get(i);
            GradientDrawable pb = new GradientDrawable();
            pb.setCornerRadius(dp(20));
            ((TextView) t[3]).setBackground(pb);
            ((TextView) t[0]).setText(String.valueOf(i + 1));
            ((TextView) t[1]).setText(pr.host);
            String info = pr.port + " · " + pr.label();
            if (pr.ping != -1) info += pr.valid ? "  ✅" : "  ⚠️";
            ((TextView) t[2]).setText(info);
            TextView pv = (TextView) t[3];
            if (pr.ping > 0) {
                pv.setText(String.format("%.0f мс", pr.ping));
                pb.setColor(pr.ping < 150 ? 0xFF12351F : pr.ping < 400 ? 0xFF3A2E10 : 0xFF3B1D1D);
                pv.setTextColor(pr.ping < 150 ? 0xFF3FB950 : pr.ping < 400 ? 0xFFD29922 : 0xFFF85149);
            } else if (pr.ping == -2) {
                pv.setText("✖");
                pb.setColor(0x14FFFFFF);
                pv.setTextColor(0xFF484F58);
            } else {
                pv.setText("…");
                pb.setColor(C_CHIP);
                pv.setTextColor(C_MUTED);
            }
            if (pr == selected) ((GradientDrawable) v.getBackground()).setStroke(dp(2), C_ACCENT);
            else ((GradientDrawable) v.getBackground()).setStroke(0, 0);
            return v;
        }
    };

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);
        rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setBackgroundColor(C_BG);
        rootLayout.setPadding(0, dp(14), 0, 0);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.setPadding(dp(16), 0, dp(16), dp(10));
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.logo);
        head.addView(logo, new LinearLayout.LayoutParams(dp(38), dp(38)));
        LinearLayout tw = new LinearLayout(this);
        tw.setOrientation(LinearLayout.VERTICAL);
        tw.setPadding(dp(10), 0, 0, 0);
        titleView = new TextView(this);
        titleView.setText("MTProto Finder");
        titleView.setTextSize(18);
        titleView.setTypeface(null, Typeface.BOLD);
        titleView.setTextColor(C_FG);
        verView = new TextView(this);
        verView.setText("v0.1.2.1 · пинг как в Telegram");
        verView.setTextSize(11);
        verView.setTextColor(C_MUTED);
        tw.addView(titleView);
        tw.addView(verView);
        head.addView(tw, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        infoBtn = roundBtn("ⓘ");
        infoBtn.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("О пинге")
            .setMessage(INFO_TEXT)
            .setPositiveButton("Понятно", null)
            .show());
        head.addView(infoBtn);
        authorBtn = roundBtn("👤");
        authorBtn.setOnClickListener(v -> open(AUTHOR_URL));
        head.addView(authorBtn);
        rootLayout.addView(head);

        LinearLayout chips = new LinearLayout(this);
        chips.setOrientation(LinearLayout.HORIZONTAL);
        chips.setGravity(Gravity.CENTER);
        chips.setPadding(dp(12), 0, dp(12), dp(8));
        btnMt = chip("MTPROTO");
        btnFt = chip("SOCKS5");
        btnMt.setOnClickListener(v -> setMode("mtproto"));
        btnFt.setOnClickListener(v -> setMode("socks5"));
        chips.addView(btnMt);
        chips.addView(btnFt);
        rootLayout.addView(chips);

        list = new ListView(this);
        list.setDivider(null);
        list.setDividerHeight(0);
        list.setAdapter(adapter);
        list.setOnItemClickListener((p, v, pos, id) -> { selected = top.get(pos); adapter.notifyDataSetChanged(); });
        list.setOnItemLongClickListener((p, v, pos, id) -> { open(top.get(pos).link()); return true; });
        rootLayout.addView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(C_MUTED);
        status.setGravity(Gravity.CENTER);
        status.setPadding(dp(8), dp(6), dp(8), dp(2));
        rootLayout.addView(status);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.CENTER);
        actions.setPadding(dp(10), dp(6), dp(10), dp(8));
        btnConnect = action("🚀 Подключиться");
        btnConnect.setOnClickListener(v -> {
            if (selected != null) { open(selected.link()); toast("Открываю " + selected.host + " в Telegram"); }
        });
        btnPing = action("🎯 Пинг");
        btnPing.setOnClickListener(v -> toggleManual());
        btnLocal = action("🔌 Локальный");
        btnLocal.setOnClickListener(v -> toggleLocal());
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        ap.setMargins(dp(4), 0, dp(4), 0);
        btnConnect.setLayoutParams(ap);
        btnPing.setLayoutParams(ap);
        btnLocal.setLayoutParams(ap);
        actions.addView(btnConnect);
        actions.addView(btnPing);
        actions.addView(btnLocal);
        rootLayout.addView(actions);

        TextView banner = new TextView(this);
        banner.setTextSize(11);
        banner.setTextColor(C_MUTED);
        banner.setPadding(dp(14), dp(10), dp(14), dp(12));
        GradientDrawable bb = new GradientDrawable();
        bb.setColor(0x11FFFFFF);
        bb.setCornerRadius(dp(14));
        banner.setBackground(bb);
        banner.setText("Уважаемые (будущие/нынешние) пользователи (тестировщики).\nЕсли приложение не отдает пинг (не показывает его) на GitHub пуште баг с подробным описанием проблемы, или пишите в Телеграм указанный в правом углу приложения.");
        rootLayout.addView(banner);

        setContentView(rootLayout);
        setFilterUI();
        h.postDelayed(this::startScan, 100);
    }

    int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    Button roundBtn(String t) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setTextSize(15);
        b.setTextColor(C_FG);
        b.setPadding(dp(6), dp(6), dp(6), dp(6));
        b.setBackground(bgDrawable(C_CHIP, dp(20)));
        return b;
    }

    Button chip(String t) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setTextSize(12);
        b.setTypeface(null, Typeface.BOLD);
        b.setPadding(dp(20), dp(9), dp(20), dp(9));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(5), 0, dp(5), 0);
        b.setLayoutParams(lp);
        b.setBackground(bgDrawable(C_CHIP, dp(18)));
        return b;
    }

    Button action(String t) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setTextSize(13);
        b.setTypeface(null, Typeface.BOLD);
        b.setPadding(dp(6), dp(11), dp(6), dp(11));
        b.setBackground(bgDrawable(C_CHIP, dp(14)));
        b.setTextColor(C_FG);
        return b;
    }

    GradientDrawable bgDrawable(int color, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        return d;
    }

    void setFilterUI() {
        tint(btnMt, "mtproto".equals(mode));
        tint(btnFt, "socks5".equals(mode));
    }

    void tint(Button b, boolean on) {
        b.setBackground(bgDrawable(on ? C_ACCENT : C_CHIP, dp(18)));
        b.setTextColor(on ? 0xFFFFFFFF : C_MUTED);
    }

    void toast(String s) { android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show(); }

    void open(String url) {
        try { startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))); }
        catch (Exception e) { toast("Не найдено приложение для ссылки"); }
    }

    void toggleLocal() {
        if (bridge != null && bridge.isRunning()) {
            bridge.stop();
            bridge = null;
            btnLocal.setBackground(bgDrawable(C_CHIP, dp(14)));
            btnLocal.setTextColor(C_FG);
            setStatus("Локальный прокси остановлен");
            toast("Локальный прокси остановлен");
            return;
        }
        Proxy best = null;
        for (Proxy p : all)
            if ("mtproto".equals(p.proto) && p.ping > 0 && p.valid)
                if (best == null || p.ping < best.ping) best = p;
        if (best == null) { toast("Нет рабочего MTProto — подождите проверки"); return; }
        final Proxy bp = best;
        bridge = new LocalBridge(LOCAL_PORT, () -> bp);
        bridge.start();
        btnLocal.setBackground(bgDrawable(C_ACCENT, dp(14)));
        btnLocal.setTextColor(0xFFFFFFFF);
        setStatus("🔌 SOCKS5 127.0.0.1:" + LOCAL_PORT + " через " + best.host);
        open("tg://socks?server=127.0.0.1&port=" + LOCAL_PORT);
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
                    setStatus("⚠ Нет интернета — повтор через 15 секунд…");
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
            setStatus("⚠ Рабочих не найдено — повторный поиск через 30 секунд…");
            h.postDelayed(() -> { rescanQueued = false; startScan(); }, 30000);
        } else if (!alive.isEmpty()) {
            setStatus("✅ Рабочих: " + alive.size() + " · показано " + top.size());
        }
    }

    void toggleManual() {
        manual = !manual;
        if (manual) {
            btnPing.setBackground(bgDrawable(0xFFD29922, dp(14)));
            btnPing.setTextColor(0xFF161B22);
            cancelPings();
            h.removeCallbacks(repingRun);
            manualStep();
        } else {
            btnPing.setBackground(bgDrawable(C_CHIP, dp(14)));
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
