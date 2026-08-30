package com.miiko3.mtprotofinder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.text.TextUtils;import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;

public class MainActivity extends Activity{
static final String[]SOURCES={"https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json","https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt","https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt"};
static final String[]SOCKS_SOURCES={"https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt","https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt"};
static final String AUTHOR_URL="https://t.me/yetilov";
static final int MAX_SERVERS=30,REPING_MS=5000,RESCAN_MS=600000,LOCAL_PORT=10808;
static final String INFO_TEXT="Пинг в приложении отличается от пинга в Telegram? Все из за разности подхода к проверки его доступности.\n\nMTProto Finder предоставляет пинг (число) путем подключение мобильной/WiFi сети к серверу.\n\nА Telegram обрабатывает прокси сервер через HTTPS, то есть, чтобы установить соединение, нужно выполнить «рукопожатие» (3 пакета TCP + обмен ключами шифрования) - это занимает время и требует больше ресурсов.";
static final Pattern LINK_RE=Pattern.compile("(server|port|secret)=([^&\\s]+)");
static final int[]ACCENTS={0xFF1F6FEB,0xFF238636,0xFF8250DF,0xFFF85149,0xFFD29922,0xFF58A6FF};
static final String[]ACCENT_NAMES={"Синий","Зелёный","Фиолетовый","Красный","Оранжевый","Голубой"};
enum Theme{DARK}

Theme theme=Theme.DARK;
int accent=0xFF1F6FEB;
boolean accentAuto=true;

int bg,fg,muted,divider,accentCur,accentFg,statusCol;
int darkColor(){return 0x33262D;}
boolean dark;

static class Proxy{
String host;int port;String secret;double ping=-1;boolean valid=true;String proto="mtproto";
Proxy(String h,int p,String s){host=h;port=p;secret=s;}
Proxy(String h,int p,String s,String pr){host=h;port=p;secret=s;proto=pr;}
String ptype(){return proto;}
String label(){return"socks5".equals(proto)?"SOCKS5":secret.toLowerCase().startsWith("ee")?"Fake TLS":"MTProto";}
String link(){if("socks5".equals(proto)){String u="",pw="";int c=secret.indexOf(':');if(c>0){u=secret.substring(0,c);pw=secret.substring(c+1);}String l="tg://socks?server="+host+"&port="+port;if(!u.isEmpty())l+="&user="+enc(u)+"&pass="+enc(pw);return l;}return"tg://proxy?server="+host+"&port="+port+"&secret="+secret;}
static String enc(String s){try{return java.net.URLEncoder.encode(s,"UTF-8");}catch(Exception e){return s;}}
}
static class Net{
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
if("socks5".equals(p.ptype())){
Socket s=new Socket();s.connect(new InetSocketAddress(p.host,p.port),(int)(timeout*1000));s.setSoTimeout((int)(timeout*1000));
s.getOutputStream().write(new byte[]{0x05,0x01,0x00});
byte[]b=new byte[2];int n=s.getInputStream().read(b);s.close();
return n>=2&&(b[0]&0xFF)==0x05;
}
if("faketls".equals(p.ptype())){
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
class Row{TextView rank,host,sub,type,ping;}
Handler h=new Handler(Looper.getMainLooper());
List<Proxy>all=new ArrayList<>(),top=new ArrayList<>();
String mode="mtproto";boolean manual=false,refreshPending=false,pingBusy=false,rescanQueued=false;
ExecutorService pool=Executors.newFixedThreadPool(64);
List<Future<?>>futures=new ArrayList<>();
Proxy selected=null;
LinearLayout rootView,statusRow;TextView title,sub,status,typeLbl;Button btnMt,btnFt,btnConnect,btnPing,btnLocal,themeBtn,settingsBtn,authorBtn;
LocalBridge bridge;
ListView list;
BaseAdapter adapter=new BaseAdapter(){
public int getCount(){return top.size();}
public Object getItem(int i){return top.get(i);}
public long getItemId(int i){return i;}
public View getView(int i,View v,ViewGroup p){
Proxy pr=top.get(i);
if(v==null){
LinearLayout row=new LinearLayout(MainActivity.this);row.setOrientation(LinearLayout.HORIZONTAL);row.setGravity(Gravity.CENTER_VERTICAL);row.setPadding(dp(6),dp(8),dp(6),dp(8));
TextView rank=new TextView(MainActivity.this);rank.setWidth(dp(28));rank.setGravity(Gravity.CENTER);rank.setTextColor(muted);rank.setTypeface(null,Typeface.BOLD);
LinearLayout mid=new LinearLayout(MainActivity.this);mid.setOrientation(LinearLayout.VERTICAL);mid.setPadding(dp(6),0,0,0);LinearLayout.LayoutParams mp=new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1f);mid.setLayoutParams(mp);
TextView host=new TextView(MainActivity.this);host.setTextColor(fg);host.setTextSize(15);host.setTypeface(null,Typeface.BOLD);host.setSingleLine(true);host.setEllipsize(TextUtils.TruncateAt.END);
TextView sub=new TextView(MainActivity.this);sub.setTextColor(muted);sub.setTextSize(12);sub.setSingleLine(true);sub.setEllipsize(TextUtils.TruncateAt.END);
LinearLayout right=new LinearLayout(MainActivity.this);right.setOrientation(LinearLayout.VERTICAL);right.setGravity(Gravity.CENTER_HORIZONTAL|Gravity.CENTER_VERTICAL);
TextView ping=new TextView(MainActivity.this);ping.setTextSize(15);ping.setTypeface(null,Typeface.BOLD);
mid.addView(host);mid.addView(sub);
right.addView(ping);
row.addView(rank);row.addView(mid);row.addView(right);
row.setTag(new Object[]{rank,host,sub,ping});
v=row;}
Object[]t=(Object[])v.getTag();
((TextView)t[0]).setText(String.valueOf(i+1));
((TextView)t[1]).setText(pr.host);
String info=pr.port+" · "+pr.label();
if(pr.ping!=-1)info+=pr.valid?"  ✅":"  ⚠️";
((TextView)t[2]).setText(info);
TextView pv=(TextView)t[3];
String ptext;int pcol;
if(pr.ping>0){ptext=String.format("%.0f мс",pr.ping);pcol=pingColor(pr.ping);}
else if(pr.ping==-2){ptext="✖";pcol=0xFF484F58;}
else{ptext="…";pcol=muted;}
pv.setText(ptext);pv.setTextColor(pcol);
if(pr==selected){rowSel(v,true);}else{rowSel(v,false);}
return v;}
};
void rowSel(View v,boolean on){
v.setBackgroundColor(on?(accentCur&0x33FFFFFF)|0x33000000:Color.TRANSPARENT);
}
public void onCreate(Bundle b){
super.onCreate(b);
loadPrefs();
rootView=new LinearLayout(this);rootView.setOrientation(LinearLayout.VERTICAL);rootView.setPadding(dp(12),dp(16),dp(12),dp(8));
LinearLayout head=new LinearLayout(this);head.setOrientation(LinearLayout.HORIZONTAL);head.setGravity(Gravity.CENTER_VERTICAL);
title=new TextView(this);title.setText("⚡ MTProto Finder");title.setTextSize(18);title.setTypeface(null,Typeface.BOLD);title.setSingleLine(true);
sub=new TextView(this);sub.setText("  v0.1.2.0");sub.setTextSize(11);sub.setTypeface(null,Typeface.BOLD);
LinearLayout.LayoutParams sp=new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1f);
LinearLayout tw=new LinearLayout(this);tw.setOrientation(LinearLayout.HORIZONTAL);tw.setGravity(Gravity.CENTER_VERTICAL);tw.setLayoutParams(sp);tw.addView(title);tw.addView(sub);
Button infoBtn=mkBtn("ⓘ",0,muted);infoBtn.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("О пинге").setMessage(INFO_TEXT).setPositiveButton("Понятно",null).show());
authorBtn=mkBtn("👤 @yetilov",0,0xFF58A6FF);authorBtn.setOnClickListener(v->open(AUTHOR_URL));
head.addView(tw);head.addView(infoBtn);head.addView(authorBtn);
rootView.addView(head);
LinearLayout fr=new LinearLayout(this);fr.setOrientation(LinearLayout.HORIZONTAL);fr.setGravity(Gravity.CENTER_VERTICAL);fr.setPadding(0,dp(10),0,dp(6));
typeLbl=new TextView(this);typeLbl.setText("ТИП:  ");typeLbl.setTextSize(11);typeLbl.setTypeface(null,Typeface.BOLD);typeLbl.setPadding(dp(2),0,dp(6),0);
btnMt=mkFilter("MTPROTO");btnFt=mkFilter("SOCKS5");btnMt.setOnClickListener(v->setMode("mtproto"));btnFt.setOnClickListener(v->setMode("socks5"));
fr.addView(typeLbl);fr.addView(btnMt);fr.addView(btnFt);
rootView.addView(fr);
list=new ListView(this);list.setDivider(new ColorDrawable(0x33000000));list.setDividerHeight(1);
list.setAdapter(adapter);
list.setOnItemClickListener((p,v,pos,id)->{selected=top.get(pos);adapter.notifyDataSetChanged();});
list.setOnItemLongClickListener((p,v,pos,id)->{open(top.get(pos).link());return true;});
LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,0,1f);
list.setLayoutParams(lp);
rootView.addView(list);
LinearLayout bottom=new LinearLayout(this);bottom.setOrientation(LinearLayout.HORIZONTAL);bottom.setGravity(Gravity.CENTER);bottom.setPadding(dp(6),dp(10),dp(6),dp(6));
btnConnect=mkBtn("🚀 Подключиться",0,0);btnConnect.setOnClickListener(v->{if(selected!=null){open(selected.link());toast("Открываю "+selected.host+" в Telegram");}});
btnPing=mkBtn("🎯 Пинг",0,0);btnPing.setOnClickListener(v->toggleManual());
btnLocal=mkBtn("🔌 Локальный",0,0);btnLocal.setOnClickListener(v->toggleLocal());
LinearLayout.LayoutParams cParams=new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1f);cParams.setMargins(dp(3),0,dp(3),0);
btnConnect.setLayoutParams(cParams);btnPing.setLayoutParams(cParams);btnLocal.setLayoutParams(cParams);
bottom.addView(btnConnect);bottom.addView(btnPing);bottom.addView(btnLocal);
rootView.addView(bottom);
status=new TextView(this);status.setText("Готов");status.setTextSize(12);status.setPadding(dp(4),dp(4),dp(4),dp(4));
rootView.addView(status);
TextView banner=new TextView(this);banner.setTextSize(12);banner.setTextColor(muted);banner.setPadding(dp(10),dp(8),dp(10),dp(10));
GradientDrawable bb=new GradientDrawable();bb.setColor(darkColor());bb.setCornerRadius(dp(10));banner.setBackground(bb);
banner.setText("Уважаемые (будущие/нынешние) пользователи (тестировщики).\nЕсли приложение не отдает пинг (не показывает его) на GitHub пуште баг с подробным описанием проблемы, или пишите в Телеграм указанный в правом углу приложения.");
rootView.addView(banner);
setContentView(rootView);
        applyTheme();
        h.postDelayed(this::startScan,100);
}
public void onWindowFocusChanged(boolean hasFocus){
        super.onWindowFocusChanged(hasFocus);
        if(hasFocus&&Build.VERSION.SDK_INT>=Build.VERSION_CODES.S){
                try{getWindow().setBackgroundBlurRadius(40);}catch(Exception e){}
        }
}
int dp(int v){return(Math.round(v*getResources().getDisplayMetrics().density));}
void loadPrefs(){SharedPreferences sp=getSharedPreferences("mtproto",0);theme=Theme.DARK;accentAuto=sp.getBoolean("accentAuto",true);accent=sp.getInt("accent",0xFF1F6FEB);}
void savePrefs(){SharedPreferences.Editor e=getSharedPreferences("mtproto",0).edit();e.putString("theme",theme.name().toLowerCase());e.putBoolean("accentAuto",accentAuto);e.putInt("accent",accent);e.apply();}
boolean isDark(){return true;}
void computePalette(){
dark=isDark();
accentCur=accentAuto?0xFF1F6FEB:accent;
accentFg=Color.luminance(accentCur)>0.5?0xFF1F2328:0xFFFFFFFF;
if(dark){bg=0x900D1117;fg=0xFFE6EDF3;muted=0xFF8B949E;divider=0x33FFFFFF;statusCol=0xFF0D1117;}
else{bg=0xD8F0F3F6;fg=0xFF1F2328;muted=0xFF57606A;divider=0x33000000;statusCol=0xFFE6EDF3;}
}
String themeIcon(){return "🌙";}
void applyTheme(){
computePalette();
getWindow().setBackgroundDrawable(new ColorDrawable(bg));
if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.S)getWindow().setBackgroundBlurRadius(40);
try{getWindow().setStatusBarColor(statusCol);getWindow().setNavigationBarColor(statusCol);}catch(Exception e){}
rootView.setBackgroundColor(bg);
title.setTextColor(fg);sub.setTextColor(muted);status.setTextColor(muted);typeLbl.setTextColor(muted);
authorBtn.setTextColor(accentCur);paint(authorBtn,0,accentCur);
setFilterUI();
paint(btnConnect,accentCur,accentFg);
paint(btnPing,dark?0x33262D:0x22000000,fg);
list.setDivider(new ColorDrawable(divider));
adapter.notifyDataSetChanged();
}
void paint(Button b,int bgc,int fgc){GradientDrawable d=new GradientDrawable();d.setColor(bgc);d.setCornerRadius(dp(10));b.setBackground(d);b.setTextColor(fgc);}
Button mkBtn(String t,int bgc,int fgc){Button b=new Button(this);b.setText(t);b.setAllCaps(false);b.setTextColor(fgc);b.setTextSize(13);b.setTypeface(null,Typeface.BOLD);b.setPadding(dp(14),dp(8),dp(14),dp(8));GradientDrawable d=new GradientDrawable();d.setColor(bgc);d.setCornerRadius(dp(10));b.setBackground(d);return b;}
Button mkFilter(String t){Button b=mkBtn(t,0,muted);return b;}
void setFilterUI(){tint(btnMt,"mtproto".equals(mode));tint(btnFt,"socks5".equals(mode));}
void tint(Button b,boolean on){GradientDrawable d=(GradientDrawable)b.getBackground();if(on){d.setColor(accentCur);b.setTextColor(accentFg);}else{d.setColor(dark?0x33262D:0x22000000);b.setTextColor(muted);}}
void toast(String s){android.widget.Toast.makeText(this,s,android.widget.Toast.LENGTH_SHORT).show();}
void open(String url){try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(url)));}catch(Exception e){toast("Не найдено приложение для ссылки");}}
void toggleLocal(){
if(bridge!=null&&bridge.isRunning()){bridge.stop();bridge=null;paint(btnLocal,dark?0x33262D:0x22000000,fg);setStatus("Локальный прокси остановлен");toast("Локальный прокси остановлен");return;}
MainActivity.Proxy best=null;
for(Proxy p:all)if("mtproto".equals(p.proto)&&p.ping>0){if(best==null||p.ping<best.ping)best=p;}
if(best==null){toast("Нет рабочего MTProto — подождите проверки");return;}
final Proxy bp=best;
bridge=new LocalBridge(LOCAL_PORT,()->bp);
bridge.start();
paint(btnLocal,accentCur,accentFg);
setStatus("🔌 SOCKS5 127.0.0.1:"+LOCAL_PORT+" через "+best.host);
toast("Прокси: 127.0.0.1:"+LOCAL_PORT);
}
List<Proxy>pool(){List<Proxy>r=new ArrayList<>();for(Proxy p:all)if(p.ptype().equals(mode))r.add(p);return r;}
void setMode(String m){if(manual)toggleManual();mode=m;setFilterUI();refreshNow();savePrefs();}
 void openSettingsUnused(){
 final Theme[]st={theme};final boolean[]sa={accentAuto};final int[]ac={accent};
 LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);v.setPadding(dp(18),dp(14),dp(18),dp(14));
 TextView ht=new TextView(this);ht.setText("Тема");ht.setTextSize(13);ht.setTypeface(null,Typeface.BOLD);ht.setTextColor(muted);
 v.addView(ht);
 final Button[]tb=new Button[3];String[]tn={"Авто","Тёмная","Светлая"};
 LinearLayout tr=new LinearLayout(this);tr.setOrientation(LinearLayout.HORIZONTAL);
 for(int i=0;i<3;i++){final int idx=i;tb[i]=mkFilter(tn[i]);tb[i].setOnClickListener(x->{st[0]=Theme.values()[idx];for(int j=0;j<3;j++)tint(tb[j],j==idx);});tr.addView(tb[i]);tr.setPadding(0,dp(6),0,dp(6));}
 for(int j=0;j<3;j++)tint(tb[j],j==st[0].ordinal());
 v.addView(tr);
 TextView ha=new TextView(this);ha.setText("Акцент");ha.setTextSize(13);ha.setTypeface(null,Typeface.BOLD);ha.setTextColor(muted);ha.setPadding(0,dp(10),0,0);
 v.addView(ha);
 final Button[]ab=new Button[ACCENTS.length+1];
 LinearLayout ar=new LinearLayout(this);ar.setOrientation(LinearLayout.HORIZONTAL);ar.setPadding(0,dp(6),0,dp(6));
 ab[0]=mkFilter("Авто");
 ab[0].setOnClickListener(x->{sa[0]=true;for(int j=0;j<ab.length;j++)tint(ab[j],j==0);});
 ar.addView(ab[0]);
 for(int i=0;i<ACCENTS.length;i++){final int idx=i;ab[i+1]=new Button(this);ab[i+1].setText(ACCENT_NAMES[i]);ab[i+1].setAllCaps(false);ab[i+1].setTextSize(12);ab[i+1].setTypeface(null,Typeface.BOLD);ab[i+1].setPadding(dp(10),dp(8),dp(10),dp(8));final int col=ACCENTS[idx];GradientDrawable d=new GradientDrawable();d.setColor(col);d.setCornerRadius(dp(10));ab[i+1].setBackground(d);ab[i+1].setTextColor(Color.luminance(col)>0.5?0xFF1F2328:0xFFFFFFFF);ab[i+1].setOnClickListener(xx->{sa[0]=false;ac[0]=col;for(int j=0;j<ab.length;j++)tint(ab[j],j==idx+1);});ar.addView(ab[i+1]);}
 for(int j=0;j<ab.length;j++)tint(ab[j],j==0?sa[0]:(!sa[0]&&ac[0]==ACCENTS[j-1]));
 v.addView(ar);
 AlertDialog dlg=new AlertDialog.Builder(this).setTitle("Настройки оформления").setView(v)
 .setPositiveButton("Применить",(dia,w)->{theme=st[0];accentAuto=sa[0];accent=ac[0];savePrefs();applyTheme();})
 .setNegativeButton("Отмена",null).create();
 dlg.show();
 }
void startScan(){
setStatus("🔍 Поиск MTProto-прокси в интернете…");
new Thread(()->{
List<Proxy>r=Net.fetch();
h.post(()->{
if(!r.isEmpty()){
all=r;setStatus("Найдено "+r.size()+" прокси, измеряю пинг…");
top=first(pool(),MAX_SERVERS);adapter.notifyDataSetChanged();startPing(untestedPool());scheduleRescan();
}else{setStatus("⚠ Нет интернета — повтор через 15 секунд…");h.postDelayed(this::startScan,15000);}});}).start();
}
List<Proxy>first(List<Proxy>l,int n){return new ArrayList<>(l.subList(0,Math.min(n,l.size())));}
List<Proxy>untestedPool(){List<Proxy>r=new ArrayList<>();for(Proxy p:pool())if(p.ping==-1)r.add(p);return r;}
void scheduleRescan(){h.removeCallbacks(rescanRun);h.postDelayed(rescanRun,RESCAN_MS);}
Runnable rescanRun=this::startScan;
void cancelPings(){for(Future<?>f:futures)f.cancel(true);futures.clear();pingBusy=false;}
void startPing(List<Proxy>targets){
if(pingBusy||targets.isEmpty())return;
pingBusy=true;
for(Proxy p:targets)futures.add(pool.submit(()->{
if(Thread.currentThread().isInterrupted())return;
double[]r=Net.handshakePing(p,2);
double ms=r[0];boolean ok=r[1]==1;
if(ms<0){ms=Net.tcpPing(p,1);ok=false;}
final double fms=ms;final boolean fok=ok;
if(!Thread.currentThread().isInterrupted())h.post(()->{p.ping=fms;p.valid=fok;scheduleRefresh();});
}));
pool.submit(()->{h.post(()->pingBusy=false);});
}
void scheduleRefresh(){if(refreshPending)return;refreshPending=true;h.postDelayed(()->{refreshPending=false;refreshNow();},400);}
void refreshNow(){
List<Proxy>pl=pool();
List<Proxy>alive=new ArrayList<>(),un=new ArrayList<>();
for(Proxy p:pl){if(p.ping>0)alive.add(p);else if(p.ping==-1)un.add(p);}
Collections.sort(alive,(a,c)->Double.compare(a.ping,c.ping));
List<Proxy>dead=new ArrayList<>();for(Proxy p:pl)if(p.ping==-2)dead.add(p);
List<Proxy>t=new ArrayList<>(alive);t.addAll(un);t.addAll(dead);top=first(t,MAX_SERVERS);
if(selected!=null&&!top.contains(selected)&&manual)selected=top.isEmpty()?null:top.get(0);
adapter.notifyDataSetChanged();
int tested=0,live=alive.size();for(Proxy p:pl)if(p.ping!=-1)tested++;
if(manual)return;
if(tested<pl.size())setStatus("📶 Проверено "+tested+" из "+pl.size()+" · рабочих: "+live);
else if(live>0)setStatus("✅ Рабочих: "+live+" · топ "+Math.min(live,MAX_SERVERS)+" · обновление каждые "+(REPING_MS/1000)+" с");
else if(!rescanQueued){rescanQueued=true;setStatus("⚠ Рабочих не найдено — повторный поиск через 30 секунд…");h.postDelayed(()->{rescanQueued=false;startScan();},30000);}
}
void toggleManual(){
manual=!manual;
GradientDrawable d=(GradientDrawable)btnPing.getBackground();
if(manual){d.setColor(0xFFD29922);btnPing.setTextColor(0xFF161B22);cancelPings();h.removeCallbacks(repingRun);manualStep();}
else{d.setColor(dark?0x33262D:0x22000000);btnPing.setTextColor(fg);h.postDelayed(repingRun,REPING_MS);}
}
void manualStep(){
if(!manual)return;
if(selected==null){setStatus("Выберите сервер — пингую только его");h.postDelayed(this::manualStep,2000);return;}
setStatus("🎯 Пингую только "+selected.host+":"+selected.port+" · остальные остановлены");
Proxy p=selected;
pool.submit(()->{double[]r=Net.handshakePing(p,2);h.post(()->{p.ping=r[0];p.valid=r[1]==1||r[0]>0;scheduleRefresh();manualStep();});});
}
Runnable repingRun=new Runnable(){public void run(){
if(manual)return;
List<Proxy>un=untestedPool();
if(!un.isEmpty())startPing(un);
else if(!top.isEmpty())for(Proxy p:new ArrayList<>(top))pool.submit(()->{double[]r=Net.handshakePing(p,2);h.post(()->{p.ping=r[0];p.valid=r[1]==1||r[0]>0;scheduleRefresh();});});
h.postDelayed(this,REPING_MS);}};
int pingColor(double ms){return ms<150?0xFF3FB950:(ms<400?0xFFD29922:0xFFF85149);}
void setStatus(String s){status.setText(s);}
}
