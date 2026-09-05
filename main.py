#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64,json,os,re,socket,ssl,struct,subprocess,sys,time,urllib.parse,urllib.request
from localproxy import handshake_ping,LocalBridge,LOCAL_SECRET

_SSL_CTX=None
def ssl_context():
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX=ssl.create_default_context()
    return _SSL_CTX
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import dataclass
from PyQt6.QtCore import Qt,QThread,pyqtSignal,QTimer
from PyQt6.QtGui import QColor,QIcon,QPixmap,QKeySequence,QShortcut,QGuiApplication,QPalette
from PyQt6.QtWidgets import QApplication,QFrame,QGridLayout,QHBoxLayout,QLabel,QMainWindow,QDialog,QMessageBox,QPushButton,QVBoxLayout,QWidget,QColorDialog,QComboBox,QRadioButton,QButtonGroup,QDialogButtonBox,QFormLayout,QScrollArea

APP_NAME="MTProto Finder"
APP_VERSION="1.4.0"
AUTHOR_URL="https://t.me/yetilov"
MT_SOURCES=[
"https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json",
"https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt",
"https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt",
"https://cdn.jsdelivr.net/gh/MhdiTaheri/ProxyCollector@main/proxy.txt",
"https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt",
"https://cdn.jsdelivr.net/gh/Chumbayoumba/free-telegram-proxy-russia-2026@main/proxy-list.txt",
"https://cdn.jsdelivr.net/gh/horizonpaz-create/mtproto-live@main/mtproto.txt",
]
SOCKS_SOURCES=[
"https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
"https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
"https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/SOCKS5_RAW.txt",
"https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/socks5.txt",
"https://cdn.jsdelivr.net/gh/casals-ar/proxy-list@main/socks5",
"https://cdn.jsdelivr.net/gh/ShiftyTR/Proxy-List@master/socks5.txt",
"https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/SOCKS5.txt",
]
SOURCES=MT_SOURCES
MAX_SERVERS=32
REPING_INTERVAL=6
RESCAN_INTERVAL=600
LOCAL_PROXY_PORT=10811
VPN_SOCKS_PORT=10808
VPN_HTTP_PORT=10809
LINK_RE=re.compile(r"(server|port|secret)=([^&\s]+)")

CONFIG_DIR=os.path.join(os.path.expanduser("~"),".config")
CONFIG_PATH=os.path.join(CONFIG_DIR,"mtproto-finder.json")

def resource_path(name):
    base=getattr(sys,"_MEIPASS",os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base,name)

LOGO=resource_path("logo.png")

def load_config():
    try:
        with open(CONFIG_PATH,"r",encoding="utf-8") as f:
            cfg=json.load(f)
    except Exception:
        cfg={}
    if cfg.get("theme") not in("auto","dark","light"):
        cfg["theme"]="auto"
    ac=cfg.get("accent","auto")
    if ac!="auto" and not QColor(ac).isValid():
        ac="auto"
    cfg["accent"]=ac
    return cfg

def save_config(cfg):
    try:
        os.makedirs(CONFIG_DIR,exist_ok=True)
        with open(CONFIG_PATH,"w",encoding="utf-8") as f:
            json.dump(cfg,f,ensure_ascii=False,indent=2)
    except Exception:
        pass

@dataclass
class Proxy:
    host:str
    port:int
    secret:str
    ping:float=-1.0
    valid:object=None
    proto:str="mtproto"

    @property
    def tg_link(self):
        if self.proto=="socks5":
            user,_,pwd=self.secret.partition(":")
            link="tg://socks?server={}&port={}".format(self.host,self.port)
            if user:
                link+="&user={}&pass={}".format(urllib.parse.quote(user,safe=""),urllib.parse.quote(pwd,safe=""))
            return link
        return"tg://proxy?server={}&port={}&secret={}".format(self.host,self.port,urllib.parse.quote(self.secret,safe=""))

def parse_socks_line(line):
    s=line.strip()
    if not s or s.startswith("#"):
        return None
    cred=""
    if "://" in s:
        scheme,_,s=s.partition("://")
        if scheme.lower()not in("socks5","socks"):
            return None
    if"@"in s:
        cred,_,s=s.rpartition("@")
    s=s.split("|")[0]
    m=re.match(r"^([\w.\-]+):(\d{1,5})(?::|$)",s)
    if not m:
        return None
    host,port=m.group(1),int(m.group(2))
    if not(0<port<65536):
        return None
    return Proxy(host,port,cred,proto="socks5")

def normalize_secret(sec):
    s=sec.strip()
    if not s:
        return None
    try:
        b=bytes.fromhex(s)
        if len(b)>=16:
            return s.lower()
    except ValueError:
        pass
    if s.lower().startswith("ee"):
        tail=s[2:]
        try:
            raw=base64.urlsafe_b64decode(tail+"="*(-len(tail)%4))
        except Exception:
            return None
        if len(raw)>=16 and all(32<=c<127 for c in raw[16:64]):
            return"ee"+raw[:16].hex()+raw[16:].hex()
    return None

def parse_proxy_link(link):
    if"server="not in link or"port="not in link:
        return None
    params=dict(LINK_RE.findall(link))
    try:
        host=urllib.parse.unquote(params["server"]).rstrip(".")
        port=int(params["port"])
        secret=normalize_secret(urllib.parse.unquote(params.get("secret","")))
        if not host or not secret:
            return None
        return Proxy(host,port,secret)
    except(KeyError,ValueError):
        return None

def _vpn_http_proxy():
    try:
        s = socket.create_connection(("127.0.0.1", VPN_HTTP_PORT), timeout=0.5)
        s.close()
        return "http://127.0.0.1:{}".format(VPN_HTTP_PORT)
    except OSError:
        return None


def _vpn_socks_up():
    try:
        s = socket.create_connection(("127.0.0.1", VPN_SOCKS_PORT), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


def _fetch_via_vpn(url):
    proxy = _vpn_http_proxy()
    if not proxy:
        return None
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def _fetch_source(url):
    text = _fetch_via_vpn(url)
    if text is not None:
        return url, text
    parsed = urllib.parse.urlparse(url)
    try:
        host=parsed.hostname
        port=parsed.port or(443 if parsed.scheme=="https"else 80)
        ip=_resolve(host)
        if not ip:
            return url,None
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(4)
        try:
            sock.connect((ip,port))
        except OSError:
            sock.close()
            return url,None
        sock.settimeout(12)
        if parsed.scheme=="https":
            ctx=ssl_context()
            sock=ctx.wrap_socket(sock,server_hostname=host)
        path=parsed.path or"/"
        if parsed.query:
            path+="?"+parsed.query
        sock.sendall("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n".format(path,host,APP_NAME).encode())
        chunks=[]
        while True:
            data=sock.recv(8192)
            if not data:
                break
            chunks.append(data)
        sock.close()
        raw=b"".join(chunks)
        head,_,body=raw.partition(b"\r\n\r\n")
        if b"200"not in head.split(b"\r\n")[0]:
            return url,None
        return url,body.decode("utf-8","replace")
    except Exception:
        return url,None

def _parse_source(url,text):
    parsed=[]
    if url.endswith(".json"):
        try:
            for item in json.loads(text):
                link=item.get("connect_url")or"tg://proxy?server={}&port={}&secret={}".format(item.get("host",""),item.get("port",""),item.get("secret",""))
                p=parse_proxy_link(link)
                if p:
                    parsed.append(p)
        except(json.JSONDecodeError,AttributeError):
            pass
    else:
        for line in text.splitlines():
            p=parse_proxy_link(line.strip())
            if p:
                parsed.append(p)
    return parsed

def fetch_proxies():
    found,seen=[],set()
    urls=list(SOURCES)+list(SOCKS_SOURCES)
    pool=ThreadPoolExecutor(max_workers=len(urls))
    try:
        futures=[pool.submit(_fetch_source,url)for url in urls]
        for fut in as_completed(futures):
            url,text=fut.result()
            if not text:
                continue
            if url in SOCKS_SOURCES:
                parsed=[parse_socks_line(l)for l in text.splitlines()]
            else:
                parsed=_parse_source(url,text)
            for p in parsed:
                if p and(p.host,p.port)not in seen:
                    seen.add((p.host,p.port));found.append(p)
    finally:
        pool.shutdown(wait=False,cancel_futures=True)
    return found

_DNS_CACHE={}
def _resolve(host):
    ip=_DNS_CACHE.get(host)
    if not ip:
        try:
            ip=socket.gethostbyname(host)
        except OSError:
            return None
        if len(_DNS_CACHE)>2000:
            _DNS_CACHE.clear()
        _DNS_CACHE[host]=ip
    return ip

def tcp_ping_one(proxy,timeout=1.0):
    ip=_resolve(proxy.host)
    if not ip:
        return-2.0
    start=time.perf_counter()
    try:
        with socket.create_connection((ip,proxy.port),timeout=timeout):
            return(time.perf_counter()-start)*1000
    except OSError:
        return-2.0

def _extract_domain(secret):
    h=secret.lower()
    if not h.startswith("ee") or len(h)<36:
        return"www.cloudflare.com"
    offsets=[34]+[o for o in range(2,min(64,len(h)-6),2) if o!=34]
    for off in offsets:
        out="";i=off;clean=True
        while i+1<len(h):
            try:
                b=bytes.fromhex(h[i:i+2])
            except ValueError:
                clean=False
                break
            ch=b.decode("ascii","ignore")
            if not(ch.isalnum() or ch in".-"):
                break
            out+=ch
            i+=2
        if clean and len(out)>=4 and out.count(".")>=1 and not out.replace(".","").isdigit():
            return out
    return"www.cloudflare.com"

def _sni_candidates(proxy):
    out=[]
    for d in(_extract_domain(proxy.secret),proxy.host,"www.cloudflare.com"):
        d=(d or"").strip(".")
        if d and"." in d and d not in out:
            out.append(d)
    return out

def _tls_client_hello(proxy,host=None):
    host=(host or _extract_domain(proxy.secret)).encode()
    name_entry=struct.pack("!B",0x00)+struct.pack("!H",len(host))+host
    sni_list=struct.pack("!H",len(name_entry))+name_entry
    ext_sni=struct.pack("!H",0x0000)+struct.pack("!H",len(sni_list))+sni_list
    groups=struct.pack("!HHHH",0x001d,0x0017,0x0018,0x0019)
    ext_groups=struct.pack("!HH",0x000a,len(groups)+2)+struct.pack("!H",len(groups))+groups
    ext_epf=struct.pack("!HH",0x000b,2)+b"\x01\x00"
    sigalgs=struct.pack("!8H",0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601)
    ext_sig=struct.pack("!HH",0x000d,len(sigalgs)+2)+struct.pack("!H",len(sigalgs))+sigalgs
    vers=struct.pack("!HH",0x0304,0x0303)
    ext_vers=struct.pack("!HH",0x002b,len(vers)+1)+struct.pack("!B",len(vers))+vers
    xkey=os.urandom(32)
    entry=struct.pack("!HH",0x001d,len(xkey))+xkey
    ext_ks=struct.pack("!HH",0x0033,len(entry)+2)+struct.pack("!H",len(entry))+entry
    ext_ticket=struct.pack("!HH",0x0023,0)
    ciphers=struct.pack("!16H",0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035,0x000a)
    cipher_list=struct.pack("!H",len(ciphers))+ciphers
    exts=ext_sni+ext_groups+ext_epf+ext_sig+ext_vers+ext_ks+ext_ticket
    body=struct.pack("!H",0x0303)+os.urandom(32)
    body+=struct.pack("!B",32)+os.urandom(32)
    body+=cipher_list
    body+=struct.pack("!B",0x01)+b"\x00"
    body+=struct.pack("!H",len(exts))+exts
    handshake=struct.pack("!B",0x01)+struct.pack("!I",len(body))[1:]+body
    return struct.pack("!B",0x16)+struct.pack("!H",0x0301)+struct.pack("!H",len(handshake))+handshake

def probe_proxy(proxy,ping_timeout=2.5,validate_timeout=2.0):
    ping,ok=handshake_ping(proxy,timeout=ping_timeout)
    if ok and ping>0:
        proxy.ping=ping
        proxy.valid=True
        return
    tcp=tcp_ping_one(proxy,1.2)
    proxy.ping=-2.0 if tcp<0 else tcp
    proxy.valid=False

class ScanThread(QThread):
    finished_scan=pyqtSignal(list)
    failed=pyqtSignal(str)

    def run(self):
        proxies=fetch_proxies()
        if proxies:
            self.finished_scan.emit(proxies)
        else:
            self.failed.emit("Не удалось получить список прокси.\nПроверьте подключение к интернету — повтор будет выполнен автоматически.")

class PingThread(QThread):
    one_done=pyqtSignal(object,float)

    def __init__(self,proxies,timeout=2.5):
        super().__init__()
        self.proxies=proxies
        self.timeout=timeout

    def run(self):
        with ThreadPoolExecutor(max_workers=200)as pool:
            futures={pool.submit(probe_proxy,p,self.timeout):p for p in self.proxies}
            for fut in as_completed(futures):
                if self.isInterruptionRequested():
                    for f in futures:
                        f.cancel()
                    break
                p=futures[fut]
                try:
                    fut.result()
                except OSError:
                    p.ping=-2.0
                    p.valid=False
                self.one_done.emit(p,p.ping)

def system_accent():
    try:
        return QApplication.palette().color(QPalette.ColorRole.Highlight)
    except Exception:
        return QColor("#c586c0")

def is_system_dark():
    try:
        scheme=QGuiApplication.styleHints().colorScheme()
        if scheme==Qt.ColorScheme.Dark:
            return True
        if scheme==Qt.ColorScheme.Light:
            return False
    except Exception:
        pass
    try:
        return QApplication.palette().color(QPalette.ColorRole.Window).lightness()<128
    except Exception:
        return True

class ProxyCard(QFrame):
    def __init__(self,win,proxy):
        super().__init__()
        self.win=win
        self.proxy=proxy
        self.setObjectName("pcard")
        self.setFixedHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay=QHBoxLayout(self)
        lay.setContentsMargins(16,0,8,0)
        lay.setSpacing(8)
        self.host_lbl=QLabel()
        self.host_lbl.setObjectName("phost")
        lay.addWidget(self.host_lbl,1)
        self.badge=QLabel("…")
        self.badge.setObjectName("badge")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setMinimumWidth(76)
        lay.addWidget(self.badge)
        self._avail=220
        self.refresh()

    def set_avail(self,avail):
        if avail==self._avail:
            return
        self._avail=avail
        self.refresh()

    def refresh(self):
        p=self.proxy
        if p.valid and p.ping>0:
            ms=p.ping
            st="good" if ms<300 else("mid" if ms<1000 else"bad")
            text=f"{ms:.0f} ms"
        elif p.ping==-1.0:
            st,text="test","…"
        elif p.ping>0:
            st,text="dead","✖"
        else:
            st,text="dead","—"
        if self.badge.property("st")!=st:
            self.badge.setProperty("st",st)
            s=self.badge.style()
            s.unpolish(self.badge)
            s.polish(self.badge)
        self.badge.setText(text)
        self.host_lbl.setText(self.fontMetrics().elidedText(f"{p.host}:{p.port}",Qt.TextElideMode.ElideMiddle,self._avail))
        sel=self.proxy is self.win.selected
        if self.property("sel")!=sel:
            self.setProperty("sel",sel)
            s=self.style()
            s.unpolish(self)
            s.polish(self)

    def mousePressEvent(self,e):
        if e.button()==Qt.MouseButton.LeftButton:
            self.win.select(self.proxy)

    def mouseDoubleClickEvent(self,e):
        self.win.connect_proxy()

class MainWindow(QMainWindow):
    INFO_TEXT=("Пинг считается по-честному: приложение делает полноценное рукопожатие с сервером —\n"
"для MTProto это реальный запрос req_pq_multi к прокси и ответ Telegram-DC, для SOCKS5 — полный CONNECT, для FakeTLS — TLS ClientHello.\n\n"
"Значит цветной бейдж получают только те серверы, которые реально работают с Telegram:\n"
"• зелёный — до 300 мс\n• жёлтый — до 1000 мс\n• красный — больше\n• серый ✖ — TCP отвечает, но MTProto-рукопожатие не прошло: такой прокси в Telegram работать не будет.\n\n"
"Список обновляется каждые {} с, полный пересканирование источников — каждые {} с.").format(REPING_INTERVAL,RESCAN_INTERVAL//60)

    def __init__(self):
        super().__init__()
        self.cfg=load_config()
        self.bridge=LocalBridge(LOCAL_PROXY_PORT)
        self._bridge_pick=None
        self.all_proxies=[]
        self.top=[]
        self.cards={}
        self.selected=None
        self.scan_thread=None
        self.ping_thread=None
        self.no_internet=False
        self._rescan_scheduled=False
        self.mode="mtproto"
        self.manual_mode=False
        self._drag_pos=None
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(QIcon(LOGO))
        self.resize(740,780)
        self.setMinimumSize(600,540)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._build_ui()
        self._apply_style()
        self.ping_timer=QTimer(self,interval=REPING_INTERVAL*1000,timeout=self.start_ping)
        self.scan_timer=QTimer(self,interval=RESCAN_INTERVAL*1000,timeout=self.start_scan)
        self.retry_timer=QTimer(self,interval=15000,timeout=self.start_scan)
        self.start_scan()

    def _build_ui(self):
        root_widget=QWidget(self)
        root_widget.setObjectName("central")
        self.setCentralWidget(root_widget)
        outer=QVBoxLayout(root_widget)
        outer.setContentsMargins(14,14,14,14)
        outer.setSpacing(10)

        card=QFrame()
        card.setObjectName("glass")
        body=QVBoxLayout(card)
        body.setContentsMargins(12,12,12,12)
        body.setSpacing(10)
        outer.addWidget(card)

        bar=QHBoxLayout()
        bar.setSpacing(8)
        chip=QFrame()
        chip.setObjectName("chip")
        chip_l=QHBoxLayout(chip)
        chip_l.setContentsMargins(8,6,16,6)
        chip_l.setSpacing(10)
        icon=QLabel()
        icon.setObjectName("logo")
        icon.setPixmap(QPixmap(LOGO).scaled(38,38,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        chip_l.addWidget(icon)
        col=QVBoxLayout()
        col.setSpacing(0)
        title=QLabel(APP_NAME)
        title.setObjectName("title")
        ver=QLabel(f"v{APP_VERSION}")
        ver.setObjectName("ver")
        col.addWidget(title)
        col.addWidget(ver)
        chip_l.addLayout(col)
        bar.addWidget(chip)
        bar.addStretch()

        def rbtn(text,slot,tip,name="round"):
            b=QPushButton(text)
            b.setObjectName(name)
            b.setFixedSize(44,44)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(tip)
            b.clicked.connect(slot)
            bar.addWidget(b)
            return b

        self.info_btn=rbtn("?",self.show_info,"Как считается пинг")
        self.settings_btn=rbtn("⚙",self.open_settings,"Настройки")
        self.author_btn=rbtn("✈",self.open_author,"Автор @yetilov")
        self.min_btn=rbtn("—",self.showMinimized,"Свернуть","win")
        self.close_btn=rbtn("✕",self.close,"Закрыть","win")
        bar_widget=QWidget()
        bar_widget.setObjectName("bar")
        bar_widget.setLayout(bar)
        bar_widget.mousePressEvent=self._bar_pressed
        bar_widget.mouseMoveEvent=self._bar_moved
        bar_widget.mouseDoubleClickEvent=lambda e:self.showMaximized() if not self.isMaximized()else self.showNormal()
        body.addWidget(bar_widget)

        seg=QHBoxLayout()
        seg.addStretch()
        self.btn_mtproto=QPushButton("MTProto")
        self.btn_socks=QPushButton("SOCKS5")
        for b in(self.btn_mtproto,self.btn_socks):
            b.setCheckable(True)
            b.setObjectName("seg")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mtproto.setChecked(True)
        self.btn_mtproto.clicked.connect(lambda:self.set_mode("mtproto"))
        self.btn_socks.clicked.connect(lambda:self.set_mode("socks5"))
        seg.addWidget(self.btn_mtproto)
        seg.addSpacing(10)
        seg.addWidget(self.btn_socks)
        seg.addStretch()
        seg_wrap=QWidget()
        seg_wrap.setLayout(seg)
        body.addWidget(seg_wrap)

        self.list=QScrollArea()
        self.list.setObjectName("list")
        self.list.setWidgetResizable(True)
        self.list.setFrameShape(QFrame.Shape.NoFrame)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.viewport().setAutoFillBackground(False)
        self.grid_w=QWidget()
        self.grid_w.setObjectName("gridw")
        self.grid_lay=QGridLayout(self.grid_w)
        self.grid_lay.setContentsMargins(2,2,10,2)
        self.grid_lay.setHorizontalSpacing(10)
        self.grid_lay.setVerticalSpacing(10)
        self.grid_lay.setColumnStretch(0,1)
        self.grid_lay.setColumnStretch(1,1)
        self.list.setWidget(self.grid_w)
        body.addWidget(self.list,1)

        self.empty_lbl=QLabel("🔍 Ищу рабочие прокси…")
        self.empty_lbl.setObjectName("empty")
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.status_lbl=QLabel("Готов")
        self.status_lbl.setObjectName("status")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.addWidget(self.status_lbl)

        dock=QFrame()
        dock.setObjectName("dock")
        bottom=QHBoxLayout(dock)
        bottom.setContentsMargins(8,8,8,8)
        bottom.setSpacing(10)
        self.connect_btn=QPushButton("Подключиться")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.setEnabled(False)
        self.connect_btn.clicked.connect(self.connect_proxy)
        self.ping_btn=QPushButton("Пинг")
        self.ping_btn.setObjectName("pill")
        self.ping_btn.setCheckable(True)
        self.ping_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ping_btn.clicked.connect(self.toggle_manual_ping)
        self.local_btn=QPushButton("Локальный прокси")
        self.local_btn.setObjectName("pill")
        self.local_btn.setCheckable(True)
        self.local_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.local_btn.clicked.connect(self.toggle_local)
        bottom.addWidget(self.connect_btn,1)
        bottom.addWidget(self.ping_btn,1)
        bottom.addWidget(self.local_btn,1)
        body.addWidget(dock)

        QShortcut(QKeySequence(Qt.Key.Key_Return),self,activated=self.connect_proxy)

    def theme_mode(self):
        if self.cfg["theme"]=="auto":
            return"dark" if is_system_dark() else"light"
        return self.cfg["theme"]

    def current_accent(self):
        if self.cfg["accent"]=="auto":
            return QColor(system_accent())
        return QColor(self.cfg["accent"])

    def open_settings(self):
        dlg=SettingsDialog(self,self.cfg)
        dlg.applied.connect(self.on_settings)
        dlg.exec()

    def on_settings(self,cfg):
        self.cfg=cfg
        save_config(self.cfg)
        self._apply_style()

    def _bar_pressed(self,e):
        if e.button()==Qt.MouseButton.LeftButton:
            if self.windowHandle() and self.windowHandle().startSystemMove():
                return
            self._drag_pos=e.globalPosition().toPoint()-self.frameGeometry().topLeft()

    def _bar_moved(self,e):
        if self._drag_pos and e.buttons()&Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint()-self._drag_pos)

    def resizeEvent(self,e):
        super().resizeEvent(e)
        QTimer.singleShot(50,self._relayout_cards)

    def _apply_style(self):
        dark=(self.theme_mode()=="dark")
        a=self.current_accent()
        a_name=a.name()
        sel_border="rgba({}, {}, {}, 235)".format(a.red(),a.green(),a.blue()) if self.cfg["accent"]!="auto" else"rgba(255,255,255,230)"
        if dark:
            bg="qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #6F5C71,stop:0.55 #5F4F65,stop:1 #524659)"
            fg="#ffffff"
            fg2="rgba(255,255,255,185)"
            fg3="rgba(255,255,255,135)"
            chip_bg="rgba(255,255,255,24)"
            soft="rgba(255,255,255,22)"
            soft_hover="rgba(255,255,255,34)"
            line="rgba(255,255,255,42)"
            card_border="rgba(255,255,255,38)"
            on_accent="#453a4b"
            solid="#4e4254"
            solid_line="rgba(255,255,255,50)"
        else:
            bg="qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #d3c3da,stop:0.55 #c4b4cc,stop:1 #b3a5bd)"
            fg="#372d3d"
            fg2="rgba(55,45,61,160)"
            fg3="rgba(55,45,61,120)"
            chip_bg="rgba(255,255,255,120)"
            soft="rgba(255,255,255,110)"
            soft_hover="rgba(255,255,255,160)"
            line="rgba(255,255,255,170)"
            card_border="rgba(255,255,255,150)"
            on_accent="#453a4b"
            solid="#efe9f2"
            solid_line="rgba(55,45,61,60)"
        qss=f"""
        QMainWindow{{background:transparent}}
        #central{{background:{bg};border-radius:26px}}
        #glass{{background:transparent}}
        #bar,#gridw{{background:transparent}}
        #chip{{background:{chip_bg};border-radius:18px}}
        #logo{{border-radius:10px}}
        #title{{font-size:16px;font-weight:800;color:{fg}}}
        #ver{{font-size:11px;font-weight:600;color:{fg2}}}
        #empty{{color:{fg2};font-size:14px;font-weight:600;padding:40px}}
        #status{{color:{fg3};font-size:11px;font-weight:600;padding:0 4px}}
        QPushButton{{background:transparent;border:none;color:{fg};font-size:13px;font-weight:700;border-radius:14px;padding:8px 14px}}
        QPushButton:disabled{{color:{fg3}}}
        QPushButton#round{{background:{soft};border-radius:22px;font-size:16px;font-weight:700;padding:0}}
        QPushButton#round:hover{{background:{soft_hover}}}
        QPushButton#win{{background:{soft};border-radius:22px;font-size:14px;color:{fg2};padding:0}}
        QPushButton#win:hover{{background:{soft_hover};color:{fg}}}
        QPushButton#seg{{background:{soft};border:none;border-radius:19px;padding:9px 24px;font-size:13px;font-weight:700;color:{fg}}}
        QPushButton#seg:checked{{background:#ffffff;color:{on_accent}}}
        #pcard{{background:{soft};border:2px solid {card_border};border-radius:22px}}
        #pcard:hover{{background:{soft_hover}}}
        #pcard[sel="true"]{{background:{soft_hover};border:2px solid {sel_border}}}
        #phost{{color:{fg};font-size:13px;font-weight:700;background:transparent}}
        #badge{{border-radius:13px;padding:3px 10px;font-size:12px;font-weight:800;color:{fg2};background:{soft_hover}}}
        #badge[st="good"]{{background:#8fe392;color:#123b18}}
        #badge[st="mid"]{{background:#ecd35b;color:#4a3d0b}}
        #badge[st="bad"]{{background:#e25a5a;color:#fff3f3}}
        #badge[st="dead"]{{background:{soft_hover};color:{fg3}}}
        #dock{{background:{soft};border-radius:26px}}
        #primary{{background:#ffffff;color:{on_accent};border-radius:19px;padding:11px 16px;font-size:13px;font-weight:800}}
        #primary:hover{{background:#f4eef6}}
        #primary:disabled{{background:{soft_hover};color:{fg3}}}
        #pill{{background:{soft_hover};border:none;border-radius:19px;padding:11px 16px;font-size:13px;font-weight:700;color:{fg}}}
        #pill:hover{{background:{line}}}
        #pill:checked{{background:#ffffff;color:{on_accent}}}
        QLabel{{color:{fg};background:transparent}}
        QToolTip{{background:{solid};color:{fg};border:1px solid {solid_line};padding:6px 10px;border-radius:8px;font-size:12px}}
        QMenu{{background:{solid};color:{fg};border:1px solid {solid_line};border-radius:10px;padding:6px}}
        QMenu::item{{padding:8px 26px;border-radius:6px}}
        QMenu::item:selected{{background:{fg};color:{on_accent}}}
        QDialog,QMessageBox,QColorDialog,QInputDialog{{background:{solid};color:{fg}}}
        QMessageBox QLabel,QInputDialog QLabel,QFormLayout QLabel{{color:{fg}}}
        QComboBox{{background:{soft_hover};color:{fg};border:1px solid {line};border-radius:10px;padding:8px 12px;font-size:13px}}
        QComboBox::drop-down{{border:none;width:24px}}
        QComboBox::down-arrow{{image:none;border-left:5px solid transparent;border-right:5px solid transparent;border-top:6px solid {fg2};margin-right:8px}}
        QComboBox QAbstractItemView{{background:{solid};color:{fg};border:1px solid {solid_line};selection-background-color:{fg};selection-color:{on_accent};outline:none}}
        QRadioButton{{color:{fg};font-size:13px;spacing:8px}}
        QRadioButton::indicator{{width:18px;height:18px;border:2px solid {fg2};border-radius:9px;background:transparent}}
        QRadioButton::indicator:checked{{border:5px solid {fg};}}
        QSpinBox,QLineEdit{{background:{soft_hover};color:{fg};border:1px solid {line};border-radius:8px;padding:6px 10px;font-size:13px}}
        QGroupBox{{color:{fg}}}
        QDialogButtonBox QPushButton{{min-width:90px;background:{soft_hover};border-radius:10px}}
        QScrollArea#list{{background:transparent;border:none}}
        QScrollArea#list>QWidget>QWidget{{background:transparent}}
        QScrollBar:vertical{{background:transparent;width:8px;margin:2px}}
        QScrollBar::handle:vertical{{background:{soft_hover};border-radius:4px;min-height:30px}}
        QScrollBar::handle:vertical:hover{{background:{line}}}
        QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;background:transparent}}
        QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{{background:transparent}}
        """
        self.setStyleSheet(qss)
        for w in QApplication.topLevelWidgets():
            if w is not self:
                w.setStyleSheet(qss)

    def show_info(self):
        QMessageBox.information(self,"О пинге",self.INFO_TEXT)

    def open_author(self):
        subprocess.Popen(["xdg-open",AUTHOR_URL])

    def pool(self):
        if self.mode=="socks5":
            return[p for p in self.all_proxies if p.proto=="socks5"]
        return[p for p in self.all_proxies if p.proto=="mtproto"]

    def set_mode(self,mode):
        if self.manual_mode:
            self.ping_btn.setChecked(False)
            self.toggle_manual_ping()
        self.mode=mode
        self.btn_mtproto.setChecked(mode=="mtproto")
        self.btn_socks.setChecked(mode=="socks5")
        self.selected=None
        self.connect_btn.setEnabled(False)
        self.top=self._ordered(self.pool())[:MAX_SERVERS]
        self._rebuild_grid()
        self._update_status()
        if self.all_proxies and not self.ping_thread_running():
            self.start_ping()

    def select(self,p):
        self.selected=p
        for c in self.cards.values():
            c.refresh()
        self.connect_btn.setEnabled(p is not None)

    def ping_thread_running(self):
        return self.ping_thread and self.ping_thread.isRunning()

    def start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.retry_timer.stop()
        self._set_status("🔍 Ищу прокси в интернете…")
        self.scan_thread=ScanThread(self)
        self.scan_thread.finished_scan.connect(self.on_scan_done)
        self.scan_thread.failed.connect(self.on_scan_failed)
        self.scan_thread.start()

    def on_scan_done(self,proxies):
        if self.ping_thread_running():
            self.ping_thread.requestInterruption()
        self._rescan_scheduled=False
        self.all_proxies=proxies
        self.no_internet=False
        self.ping_timer.start()
        self.scan_timer.start()
        self.selected=None
        self.connect_btn.setEnabled(False)
        self.top=self._ordered(self.pool())[:MAX_SERVERS]
        self._rebuild_grid()
        self._set_status(f"Найдено {len(proxies)} прокси — измеряю пинг…")
        self.start_ping()

    def on_scan_failed(self,msg):
        self.no_internet=True
        self._set_status("⚠ Нет интернета — повтор через 15 секунд…")
        if not self.top:
            QMessageBox.warning(self,APP_NAME,msg)
        self.retry_timer.start()

    def start_ping(self):
        if not self.all_proxies or self.ping_thread_running() or self.manual_mode:
            return
        pool=self.pool()
        untested=[p for p in pool if p.ping==-1.0]
        targets=untested if untested else(self.top or pool)
        if not targets:
            return
        self.ping_thread=PingThread(targets)
        self.ping_thread.one_done.connect(self.on_one_pinged)
        self.ping_thread.finished.connect(self._round_done)
        self.ping_thread.start()

    def toggle_manual_ping(self):
        self.manual_mode=self.ping_btn.isChecked()
        if self.manual_mode:
            self.ping_timer.stop()
            if self.ping_thread_running():
                self.ping_thread.requestInterruption()
            self._manual_step()
        else:
            self.ping_timer.start()

    def _manual_step(self):
        if not self.manual_mode:
            return
        p=self.selected
        if p is None:
            self._set_status("Выберите сервер — пингую только его")
            QTimer.singleShot(1500,self._manual_step)
            return
        self._set_status(f"🎯 Пингую только {p.host}:{p.port}")
        self.ping_thread=PingThread([p],timeout=2.5)
        self.ping_thread.one_done.connect(self.on_one_pinged)
        self.ping_thread.finished.connect(lambda:QTimer.singleShot(1500,self._manual_step))
        self.ping_thread.start()

    def on_one_pinged(self,proxy,ms):
        c=self.cards.get(id(proxy))
        if c:
            c.refresh()
        if not self.manual_mode:
            pool=self.pool()
            tested=sum(1 for p in pool if p.ping!=-1.0)
            alive=sum(1 for p in pool if p.valid and p.ping>0)
            self._set_status(f"📶 Проверено {tested} из {len(pool)} · рабочих: {alive}")

    def _round_done(self):
        if self.manual_mode:
            return
        pool=self.pool()
        newtop=self._ordered(pool)[:MAX_SERVERS]
        if[id(p)for p in newtop]!=[id(p)for p in self.top]:
            self.top=newtop
            self._rebuild_grid()
        self._update_status()

    def _ordered(self,pool):
        valid=sorted([p for p in pool if p.valid and p.ping>0],key=lambda p:p.ping)
        untested=[p for p in pool if p.ping==-1.0]
        dead=sorted([p for p in pool if p.ping!=-1.0 and not p.valid],key=lambda p:p.ping if p.ping>0 else 1e9)
        return valid+untested+dead

    def _update_status(self):
        pool=self.pool()
        if not pool:
            self._set_status("Прокси этого типа не найдено")
            return
        tested=sum(1 for p in pool if p.ping!=-1.0)
        alive=sum(1 for p in pool if p.valid and p.ping>0)
        if tested<len(pool):
            self._set_status(f"📶 Проверено {tested} из {len(pool)} · рабочих: {alive}")
        elif alive:
            self._set_status(f"✅ Рабочих прокси: {alive} · обновление каждые {REPING_INTERVAL} с")
        else:
            self._set_status("⚠ Рабочих прокси не найдено — пересканирую через 30 секунд…")
            if not self._rescan_scheduled:
                self._rescan_scheduled=True
                QTimer.singleShot(30000,self._rescan_reset)
                self.start_scan()

    def _rescan_reset(self):
        self._rescan_scheduled=False

    def _set_status(self,text):
        self.status_lbl.setText(text)

    def _rebuild_grid(self):
        while self.grid_lay.count():
            it=self.grid_lay.takeAt(0)
            w=it.widget()
            if w:
                w.hide()
                w.deleteLater()
        self.cards={}
        for i,p in enumerate(self.top):
            c=ProxyCard(self,p)
            self.cards[id(p)]=c
            self.grid_lay.addWidget(c,i//2,i%2)
        if not self.top:
            self.grid_lay.addWidget(self.empty_lbl,0,0,1,2)
            self.empty_lbl.show()
        self._relayout_cards()

    def _relayout_cards(self):
        if not self.cards:
            return
        w=self.list.viewport().width()
        colw=max(180,(w-14)//2)
        avail=max(90,colw-116)
        for c in self.cards.values():
            c.set_avail(avail)

    def current_proxy(self):
        return self.selected

    def connect_proxy(self):
        p=self.selected
        if not p:
            return
        self._set_status(f"🔗 Открываю {p.host}:{p.port} в Telegram…")
        subprocess.Popen(["xdg-open",p.tg_link])

    def toggle_local(self):
        if self.local_btn.isChecked():
            cand=[p for p in self.all_proxies if p.proto=="mtproto" and not p.secret.lower().startswith("ee") and p.valid and p.ping>0]
            cand.sort(key=lambda p:p.ping)
            p=cand[0] if cand else None
            if p is None:
                self.local_btn.setChecked(False)
                QMessageBox.warning(self,APP_NAME,"Нет рабочего MTProto-прокси для моста — подождите проверки.")
                return
            self.bridge.pick=lambda pp=p:pp
            try:
                self.bridge.start()
            except OSError as e:
                self.local_btn.setChecked(False)
                QMessageBox.warning(self,APP_NAME,"Не удалось запустить локальный прокси: {}".format(e))
                return
            self._bridge_pick=p
            self.local_btn.setText(f"Локальный :{self.bridge.port}")
            self._set_status(f"🔌 Локальный MTProto на 127.0.0.1:{self.bridge.port} через {p.host}")
            subprocess.Popen(["xdg-open","tg://proxy?server=127.0.0.1&port={}&secret={}".format(self.bridge.port,LOCAL_SECRET.hex())])
        else:
            self.bridge.stop()
            self.local_btn.setText("Локальный прокси")
            self._set_status("Локальный прокси остановлен")

class SettingsDialog(QDialog):
    applied=pyqtSignal(dict)

    def __init__(self,parent,cfg):
        super().__init__(parent)
        self.setWindowTitle("Настройки оформления")
        self.setMinimumWidth(380)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self._cfg=dict(cfg)
        root=QVBoxLayout(self)
        root.setContentsMargins(22,20,22,20)
        root.setSpacing(14)
        title=QLabel("Оформление")
        title.setObjectName("dlgTitle")
        root.addWidget(title)

        form=QFormLayout()
        form.setSpacing(12)
        self.theme_box=QComboBox()
        self.theme_box.addItem("Авто (по системе)","auto")
        self.theme_box.addItem("Тёмная (фиолет)","dark")
        self.theme_box.addItem("Светлая (лаванда)","light")
        self.theme_box.setCurrentIndex(max(0,self.theme_box.findData(cfg["theme"])))
        form.addRow("Тема",self.theme_box)

        self.accent_auto=QRadioButton("Авто (системный акцент)")
        self.accent_manual=QRadioButton("Свой цвет (RGB)")
        grp=QButtonGroup(self)
        grp.addButton(self.accent_auto)
        grp.addButton(self.accent_manual)
        self.accent_auto.setChecked(cfg["accent"]=="auto")
        self.accent_manual.setChecked(cfg["accent"]!="auto")
        self.color_btn=QPushButton()
        self.color_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.color_btn.clicked.connect(self.pick)
        self._manual=QColor(cfg["accent"]) if cfg["accent"]!="auto" else system_accent()
        self._update()
        self.accent_manual.toggled.connect(lambda on:self.color_btn.setEnabled(on))
        self.color_btn.setEnabled(self.accent_manual.isChecked())
        form.addRow("Акцент",self.accent_auto)
        form.addRow("",self.accent_manual)
        form.addRow("",self.color_btn)
        root.addLayout(form)

        btns=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._ok)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def _update(self):
        c=self._manual
        on="#ffffff" if c.lightness()<150 else"#1c2128"
        self.color_btn.setText(f"  {c.name()}")
        self.color_btn.setStyleSheet(f"QPushButton{{background:{c.name()};color:{on};border-radius:12px;padding:8px 12px;font-weight:700}}")

    def pick(self):
        c=QColorDialog.getColor(self._manual,self,"Цвет акцента")
        if c.isValid():
            self._manual=c
            self._update()

    def _ok(self):
        cfg=dict(self._cfg)
        cfg["theme"]=self.theme_box.currentData()
        cfg["accent"]="auto" if self.accent_auto.isChecked() else self._manual.name()
        self.applied.emit(cfg)
        self.accept()

def main():
    if not os.environ.get("QT_QPA_PLATFORM")and os.environ.get("DISPLAY"):
        os.environ["QT_QPA_PLATFORM"]="xcb"
    app=QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(LOGO))
    win=MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()
