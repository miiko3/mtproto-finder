#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json,os,re,socket,ssl,struct,subprocess,sys,time,urllib.parse,urllib.request
from localproxy import handshake_ping,LocalBridge

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
from PyQt6.QtWidgets import QApplication,QFrame,QHBoxLayout,QHeaderView,QLabel,QMainWindow,QAbstractItemView,QDialog,QMessageBox,QPushButton,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget,QColorDialog,QComboBox,QRadioButton,QButtonGroup,QDialogButtonBox,QFormLayout

APP_NAME="MTProto Finder"
APP_VERSION="1.2.2.0"
AUTHOR_URL="https://t.me/yetilov"
SOURCES=[
"https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json",
"https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt",
"https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt",
]
MAX_SERVERS=30
REPING_INTERVAL=5
RESCAN_INTERVAL=600
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
    def ptype(self):
        return self.proto

    @property
    def type_label(self):
        return"SOCKS5" if self.proto=="socks5" else("Fake TLS" if self.ptype2=="faketls" else"MTProto")

    @property
    def ptype2(self):
        return"faketls" if self.secret.lower().startswith("ee") else"mtproto"

    @property
    def tg_link(self):
        if self.proto=="socks5":
            user,_,pwd=self.secret.partition(":")
            link="tg://socks?server={}&port={}".format(self.host,self.port)
            if user:
                link+="&user={}&pass={}".format(urllib.parse.quote(user,safe=""),urllib.parse.quote(pwd,safe=""))
            return link
        return"tg://proxy?server={}&port={}&secret={}".format(self.host,self.port,urllib.parse.quote(self.secret,safe=""))

SOCKS_RE=re.compile(r"^(socks5|socks)://([^:@\s]+):([^@\s]+)@([\w.\-]+):(\d+)$")

def parse_socks_line(line):
    m=SOCKS_RE.match(line.strip())
    if not m:
        return None
    user,pwd,host,port=m.group(1),m.group(2),m.group(3),int(m.group(4))
    return Proxy(host,port,user+":"+pwd,proto="socks5")

def parse_proxy_link(link):
    if"server="not in link or"port="not in link:
        return None
    params=dict(LINK_RE.findall(link))
    try:
        host=urllib.parse.unquote(params["server"]).rstrip(".")
        port=int(params["port"])
        secret=urllib.parse.unquote(params.get("secret",""))
        if not host or not secret:
            return None
        return Proxy(host,port,secret)
    except(KeyError,ValueError):
        return None

def _fetch_source(url):
    parsed=urllib.parse.urlparse(url)
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

SOCKS_SOURCES=[
"https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
"https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
]

def fetch_proxies():
    found,seen=[],set()
    pool=ThreadPoolExecutor(max_workers=len(SOURCES)+len(SOCKS_SOURCES))
    urls=list(SOURCES)+list(SOCKS_SOURCES)
    try:
        futures=[pool.submit(_fetch_source,url)for url in urls]
        for fut in as_completed(futures):
            url,text=fut.result()
            if not text:
                continue
            if url in SOCKS_SOURCES:
                for line in text.splitlines():
                    line=line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "://" in line:
                        p=parse_socks_line(line)
                    else:
                        parts=line.replace("|",":").replace(" ",":").split(":")
                        p=None
                        if len(parts)>=2:
                            try:
                                p=Proxy(parts[-2],int(parts[-1]),"",proto="socks5")
                            except ValueError:
                                p=None
                    if p and(p.host,p.port)not in seen:
                        seen.add((p.host,p.port));found.append(p)
                continue
            for p in _parse_source(url,text):
                if(p.host,p.port)not in seen:
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
    raw=secret
    if not raw.lower().startswith("ee") or len(raw)<4:
        return"www.cloudflare.com"
    try:
        out=""
        i=2
        while i+1<len(raw):
            ch=bytes.fromhex(raw[i:i+2]).decode("ascii","ignore")
            if not(ch.isalnum() or ch in".-"):
                break
            out+=ch
            i+=2
        out=out.strip(".")
        if out and"." in out:
            return out
    except Exception:
        pass
    return"www.cloudflare.com"

def _tls_client_hello(proxy):
    host=_extract_domain(proxy.secret).encode()
    name_entry=struct.pack("!B",0x00)+struct.pack("!H",len(host))+host
    sni_list=struct.pack("!H",len(name_entry))+name_entry
    sni_ext=struct.pack("!H",0x0000)+struct.pack("!H",len(sni_list))+sni_list
    ciphers=struct.pack("!H",0x1301)+struct.pack("!H",0x1302)+struct.pack("!H",0x1303)+struct.pack("!H",0x009c)+struct.pack("!H",0x0035)
    cipher_list=struct.pack("!H",len(ciphers))+ciphers
    body=struct.pack("!H",0x0303)+b"\x00"*32
    body+=struct.pack("!B",0)
    body+=cipher_list
    body+=struct.pack("!B",0x01)+b"\x00"
    body+=struct.pack("!H",len(sni_ext))+sni_ext
    handshake=struct.pack("!B",0x01)+struct.pack("!I",len(body))[1:]+body
    return struct.pack("!B",0x16)+struct.pack("!H",0x0301)+struct.pack("!H",len(handshake))+handshake

def validate_mtproto(proxy,timeout=1.5):
    if proxy.ptype=="faketls":
        try:
            ip=_resolve(proxy.host)
            if not ip:
                return False
            s=socket.create_connection((ip,proxy.port),timeout=timeout)
            s.settimeout(timeout)
            s.sendall(_tls_client_hello(proxy))
            d=s.recv(6)
            s.close()
            return len(d)>=2 and d[0]==0x16
        except(ConnectionRefusedError,OSError):
            return False
        except Exception:
            return True
    else:
        try:
            secret=bytes.fromhex(proxy.secret)
        except Exception:
            return False
        try:
            ip=_resolve(proxy.host)
            if not ip:
                return False
            s=socket.create_connection((ip,proxy.port),timeout=timeout)
            s.settimeout(timeout)
            s.sendall(b"\xee"+secret)
            d=s.recv(4)
            s.close()
            return len(d)>=1 and d[0]==0xee
        except(ConnectionRefusedError,OSError):
            return False
        except Exception:
            return True

def probe_proxy(proxy,ping_timeout=2.0,validate_timeout=1.5):
    if proxy.proto=="socks5":
        ping,ok=handshake_ping(proxy,timeout=ping_timeout)
        if ping<0:
            ping=tcp_ping_one(proxy,1.0)
            ok=False
        proxy.ping=ping
        proxy.valid=ok
        return
    if proxy.ping!=-1.0 and proxy.valid:
        ping=tcp_ping_one(proxy,1.0)
        proxy.ping=ping if ping>0 else ping
        proxy.valid=ping>0
        return
    ping,ok=handshake_ping(proxy,timeout=ping_timeout)
    if ping<0:
        ping=tcp_ping_one(proxy,1.0)
        ok=ping>0
    proxy.ping=ping
    proxy.valid=ok

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

    def __init__(self,proxies,timeout=1.0):
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
        return QColor("#1f6feb")

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

def muted_color(mode):
    return"#8b949e" if mode=="dark" else"#57606a"

class MainWindow(QMainWindow):
    INFO_TEXT=("Пинг в приложении отличается от пинга в Telegram? Все из за разности подхода к проверки его доступности.\n\n"
"MTProto Finder предоставляет пинг (число) путем подключение мобильной/WiFi сети к серверу.\n\n"
"А Telegram обрабатывает прокси сервер через HTTPS, то есть, чтобы установить соединение, нужно выполнить «рукопожатие» (3 пакета TCP + обмен ключами шифрования) - это занимает время и требует больше ресурсов.")

    def __init__(self):
        super().__init__()
        self.cfg=load_config()
        self.bridge=LocalBridge()
        self._bridge_pick=None
        self.all_proxies=[]
        self.top=[]
        self.scan_thread=None
        self.ping_thread=None
        self.no_internet=False
        self._refresh_pending=False
        self._rescan_scheduled=False
        self.mode="mtproto"
        self.manual_mode=False
        self._drag_pos=None
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(QIcon(LOGO))
        self.resize(780,600)
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
        outer.setContentsMargins(0,0,0,0)

        card=QFrame()
        card.setObjectName("glass")
        body=QVBoxLayout(card)
        body.setContentsMargins(20,12,20,16)
        body.setSpacing(12)
        outer.addWidget(card)

        bar=QHBoxLayout()
        bar.setSpacing(10)
        icon=QLabel()
        icon.setObjectName("logo")
        icon.setPixmap(QPixmap(LOGO).scaled(34,34,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        bar.addWidget(icon)
        title=QLabel(APP_NAME)
        title.setObjectName("title")
        bar.addWidget(title)
        ver=QLabel(f"v{APP_VERSION}")
        ver.setObjectName("ver")
        bar.addWidget(ver)
        bar.addStretch()
        self.info_btn=QPushButton("ⓘ")
        self.info_btn.setObjectName("round")
        self.info_btn.setFixedSize(34,34)
        self.info_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.info_btn.clicked.connect(self.show_info)
        bar.addWidget(self.info_btn)
        self.theme_btn=QPushButton("◐")
        self.theme_btn.setObjectName("round")
        self.theme_btn.setFixedSize(34,34)
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.clicked.connect(self.cycle_theme)
        bar.addWidget(self.theme_btn)
        self.settings_btn=QPushButton("⚙")
        self.settings_btn.setObjectName("round")
        self.settings_btn.setFixedSize(34,34)
        self.settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_btn.clicked.connect(self.open_settings)
        bar.addWidget(self.settings_btn)
        self.author_btn=QPushButton("@yetilov")
        self.author_btn.setObjectName("link")
        self.author_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.author_btn.clicked.connect(self.open_author)
        bar.addWidget(self.author_btn)
        self.min_btn=QPushButton("—")
        self.min_btn.setObjectName("win")
        self.min_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.min_btn.clicked.connect(self.showMinimized)
        bar.addWidget(self.min_btn)
        self.close_btn=QPushButton("✕")
        self.close_btn.setObjectName("win")
        self.close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_btn.clicked.connect(self.close)
        bar.addWidget(self.close_btn)
        bar_widget=QWidget()
        bar_widget.setObjectName("bar")
        bar_widget.setLayout(bar)
        bar_widget.mousePressEvent=self._bar_pressed
        bar_widget.mouseMoveEvent=self._bar_moved
        bar_widget.mouseDoubleClickEvent=lambda e:self.showMaximized() if not self.isMaximized()else self.showNormal()
        body.addWidget(bar_widget)

        seg=QHBoxLayout()
        seg.setSpacing(8)
        lbl=QLabel("ТИП")
        lbl.setObjectName("cap")
        seg.addWidget(lbl)
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
        seg.addWidget(self.btn_socks)
        seg.addStretch()
        self.hint=QLabel("")
        self.hint.setObjectName("cap")
        seg.addWidget(self.hint)
        seg_wrap=QWidget()
        seg_wrap.setLayout(seg)
        body.addWidget(seg_wrap)

        self.table=QTableWidget(0,4)
        self.table.setObjectName("table")
        self.table.setHorizontalHeaderLabels(["#","Сервер","Порт","Пинг"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(2,90)
        self.table.setColumnWidth(3,120)
        self.table.doubleClicked.connect(self.connect_proxy)
        self.table.itemSelectionChanged.connect(lambda:self.connect_btn.setEnabled(self.table.currentRow()>=0))
        QShortcut(QKeySequence(Qt.Key.Key_Return),self.table,activated=self.connect_selected)
        body.addWidget(self.table,1)

        bottom=QHBoxLayout()
        bottom.setSpacing(10)
        self.connect_btn=QPushButton("🚀 Подключиться к Telegram")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.setEnabled(False)
        self.connect_btn.clicked.connect(self.connect_selected)
        self.ping_btn=QPushButton("🎯 Пинг выбранного")
        self.ping_btn.setObjectName("ghost")
        self.ping_btn.setCheckable(True)
        self.ping_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ping_btn.clicked.connect(self.toggle_manual_ping)
        bottom.addWidget(self.connect_btn)
        bottom.addWidget(self.ping_btn)
        self.local_btn=QPushButton("🔌 Локальный прокси")
        self.local_btn.setObjectName("ghost")
        self.local_btn.setCheckable(True)
        self.local_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.local_btn.clicked.connect(self.toggle_local)
        bottom.addWidget(self.local_btn)
        bottom.addStretch()
        bottom_wrap=QWidget()
        bottom_wrap.setLayout(bottom)
        body.addWidget(bottom_wrap)

        self.status_lbl=QLabel("Готов")
        self.status_lbl.setObjectName("status")
        body.addWidget(self.status_lbl)

    def theme_mode(self):
        if self.cfg["theme"]=="auto":
            return"dark" if is_system_dark() else"light"
        return self.cfg["theme"]

    def current_accent(self):
        if self.cfg["accent"]=="auto":
            return QColor(system_accent())
        return QColor(self.cfg["accent"])

    def cycle_theme(self):
        order=["auto","dark","light"]
        self.cfg["theme"]=order[(order.index(self.cfg["theme"])+1)%3]
        save_config(self.cfg)
        self._apply_style()
        self.refresh_table()

    def open_settings(self):
        dlg=SettingsDialog(self,self.cfg)
        dlg.applied.connect(self.on_settings)
        dlg.exec()

    def on_settings(self,cfg):
        self.cfg=cfg
        save_config(self.cfg)
        self._apply_style()
        self.refresh_table()

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

    def _apply_style(self):
        dark=(self.theme_mode()=="dark")
        a=self.current_accent()
        a_name=a.name()
        a_hover=a.lighter(118).name()
        a_press=a.darker(115).name()
        a_border=f"rgba({a.red()},{a.green()},{a.blue()},130)"
        if dark:
            fg="#eef2f7"; muted="#9aa6b2"; line="rgba(255,255,255,40)"
            glass="#141821"
            solid="#161b22"
            border=a_border
            hover="rgba(255,255,255,28)"
            sel=a_border
            on_accent="#ffffff"
            head=f"rgba(255,255,255,90)"
            host_c="#79c0ff"; tls_c="#a371f7"
        else:
            fg="#1c2128"; muted="#57606a"; line="rgba(0,0,0,40)"
            glass="#f5f7fa"
            solid="#f6f8fa"
            border=a_border
            hover="rgba(0,0,0,28)"
            sel=a_border
            on_accent="#ffffff" if a.lightness()<150 else"#1c2128"
            head=f"rgba(0,0,0,110)"
            host_c="#0969da"; tls_c="#8250df"

        theme_icons={"auto":"◐","dark":"🌙","light":"☀️"}
        self.theme_btn.setText(theme_icons[self.cfg["theme"]])
        self.theme_btn.setToolTip({"auto":"Тема: авто","dark":"Тема: тёмная","light":"Тема: светлая"}[self.cfg["theme"]])

        qss=f"""
        QMainWindow{{background:transparent}}
        #central{{background:transparent}}
        #glass{{background:{glass};border:1.5px solid {border};border-radius:24px}}
        #bar{{background:transparent}}
        #logo{{border-radius:10px}}
        #title{{font-size:19px;font-weight:800;color:{fg}}}
        #ver{{font-size:11px;font-weight:700;color:{muted};background:{hover};border-radius:9px;padding:2px 8px}}
        #cap{{color:{muted};font-size:12px;font-weight:700;letter-spacing:1px}}
        #table{{background:transparent;border:none;color:{fg};font-size:14px;gridline-color:transparent;selection-background-color:transparent}}
        #table::item{{padding:6px 6px;border:none;background:transparent;border-radius:9px}}
        #table::item:hover{{background:{hover}}}
        #table::item:selected{{background:{sel};color:{fg}}}
        QHeaderView::section{{background:transparent;color:{muted};border:none;padding:8px 6px;font-weight:700;font-size:12px;letter-spacing:1px}}
        QPushButton{{background:transparent;border:none;color:{fg};font-size:13px;font-weight:700;border-radius:12px;padding:8px 14px}}
        QPushButton:hover{{background:{hover}}}
        QPushButton:disabled{{color:{muted}}}
        #primary{{background:{a_name};color:{on_accent};border-radius:14px;padding:10px 18px;font-size:14px}}
        #primary:hover{{background:{a_hover}}}
        #primary:disabled{{background:{hover};color:{muted}}}
        #ghost{{border:1px solid {line};border-radius:14px}}
        #ghost:checked{{background:{a_name};color:{on_accent};border-color:{a_name}}}
        #link{{color:{a_name};font-weight:600}}
        #link:hover{{background:{hover};border-radius:10px}}
        QPushButton#seg{{border:1px solid {line};border-radius:16px;padding:6px 16px;font-size:12px;letter-spacing:1px}}
        QPushButton#seg:checked{{background:{a_name};color:{on_accent};border-color:{a_name};font-weight:800}}
        QPushButton#round{{border-radius:17px;font-size:15px}}
        QPushButton#round:hover{{background:{hover}}}
        QPushButton#win{{border-radius:12px;color:{muted};padding:2px 8px}}
        #win:hover{{background:{hover};color:{fg}}}
        #close:hover{{background:#e5484d;color:#ffffff}}
        #status{{color:{muted};font-size:12px;padding:1px 4px}}
        QLabel{{color:{fg}}}
        QToolTip{{background:{solid};color:{fg};border:1px solid {line};padding:6px 10px;border-radius:8px;font-size:12px}}
        QMenu{{background:{solid};color:{fg};border:1px solid {line};border-radius:10px;padding:6px}}
        QMenu::item{{padding:8px 26px;border-radius:6px}}
        QMenu::item:selected{{background:{a_name};color:{on_accent}}}
        QDialog,QMessageBox,QColorDialog,QInputDialog{{background:{solid};color:{fg}}}
        QMessageBox QLabel,QInputDialog QLabel,QFormLayout QLabel{{color:{fg}}}
        QComboBox{{background:{hover};color:{fg};border:1px solid {line};border-radius:10px;padding:8px 12px;font-size:13px}}
        QComboBox:hover{{border-color:{a_border}}}
        QComboBox::drop-down{{border:none;width:24px}}
        QComboBox::down-arrow{{image:none;border-left:5px solid transparent;border-right:5px solid transparent;border-top:6px solid {muted};margin-right:8px}}
        QComboBox QAbstractItemView{{background:{solid};color:{fg};border:1px solid {line};selection-background-color:{a_name};selection-color:{on_accent};outline:none}}
        QRadioButton{{color:{fg};font-size:13px;spacing:8px}}
        QRadioButton::indicator{{width:18px;height:18px;border:2px solid {muted};border-radius:9px;background:transparent}}
        QRadioButton::indicator:checked{{border:5px solid {a_name}}}
        QSpinBox,QLineEdit{{background:{hover};color:{fg};border:1px solid {line};border-radius:8px;padding:6px 10px;font-size:13px}}
        QGroupBox{{color:{fg}}}
        QTableCornerButton::section{{background:transparent;border:none}}
        QScrollBar:vertical{{background:transparent;width:10px;margin:4px}}
        QScrollBar::handle:vertical{{background:{hover};border-radius:5px;min-height:30px}}
        QScrollBar::handle:vertical:hover{{background:{a_border}}}
        QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;background:transparent}}
        QScrollBar:horizontal{{background:transparent;height:10px;margin:4px}}
        QScrollBar::handle:horizontal{{background:{hover};border-radius:5px;min-width:30px}}
        QScrollBar::handle:horizontal:hover{{background:{a_border}}}
        QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;background:transparent}}
        QDialogButtonBox QPushButton{{min-width:90px}}
        """
        self.setStyleSheet(qss)
        for w in QApplication.topLevelWidgets():
            w.setStyleSheet(qss)
        self._host_color=host_c
        self._tls_color=tls_c

    def show_info(self):
        QMessageBox.information(self,"О пинге",self.INFO_TEXT)

    def toggle_local(self):
        if self.local_btn.isChecked():
            cand=[p for p in self.all_proxies if p.proto=="mtproto" and p.ping>0]
            cand.sort(key=lambda p:p.ping)
            p=cand[0] if cand else None
            if p is None:
                self.local_btn.setChecked(False)
                QMessageBox.warning(self,APP_NAME,"Нет рабочего MTProto-прокси для моста — подождите проверки.")
                return
            self.bridge.pick=lambda pp=p:pp
            self.bridge.start()
            self._bridge_pick=p
            self.local_btn.setText(f"🔌 Локальный прокси :{self.bridge.port}")
            self.set_status(f"🔌 Локальный SOCKS5 на 127.0.0.1:{self.bridge.port} через {p.host}")
        else:
            self.bridge.stop()
            self.local_btn.setText("🔌 Локальный прокси")
            self.set_status("Локальный прокси остановлен")

    def open_author(self):
        subprocess.Popen(["xdg-open",AUTHOR_URL])

    def pool(self):
        if self.mode=="socks5":
            return[p for p in self.all_proxies if p.proto=="socks5"]
        return[p for p in self.all_proxies if p.ptype==self.mode]

    def set_mode(self,mode):
        if self.manual_mode:
            self.ping_btn.setChecked(False)
            self.toggle_manual_ping()
        self.mode=mode
        self.btn_mtproto.setChecked(mode=="mtproto")
        self.btn_socks.setChecked(mode=="socks5")
        self._refresh_now()
        if self.all_proxies and not self.ping_thread_running():
            self.start_ping()

    def ping_thread_running(self):
        return self.ping_thread and self.ping_thread.isRunning()

    def start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.retry_timer.stop()
        self.set_status("🔍 Поиск MTProto-прокси в интернете…")
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
        self.set_status(f"Найдено {len(proxies)} прокси, измеряю пинг…")
        self.ping_timer.start()
        self.scan_timer.start()
        self.top=self.pool()[:MAX_SERVERS]
        self.refresh_table()
        self.start_ping()

    def on_scan_failed(self,msg):
        self.no_internet=True
        self.set_status("⚠ Нет интернета — повтор через 15 секунд…")
        if not self.top:
            QMessageBox.warning(self,APP_NAME,msg)
        self.retry_timer.start()

    def start_ping(self):
        if not self.all_proxies or self.ping_thread_running():
            return
        untested=[p for p in self.pool() if p.ping==-1.0]
        targets=untested if untested else(self.top or self.pool())
        if not targets:
            return
        self.ping_thread=PingThread(targets)
        self.ping_thread.one_done.connect(self.on_one_pinged)
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
        p=self.current_proxy()
        if p is None:
            self.set_status("Выберите сервер в таблице — пингую только его")
            QTimer.singleShot(1500,self._manual_step)
            return
        self.set_status(f"🎯 Пингую только {p.host}:{p.port} · остальные остановлены")
        self.ping_thread=PingThread([p],timeout=1.0)
        self.ping_thread.one_done.connect(self.on_one_pinged)
        self.ping_thread.finished.connect(lambda:QTimer.singleShot(1500,self._manual_step))
        self.ping_thread.start()

    def on_one_pinged(self,proxy,ms):
        proxy.ping=ms
        self._schedule_refresh()

    def _ping_status(self):
        tested=sum(1 for p in self.pool() if p.ping!=-1.0)
        alive=sum(1 for p in self.pool() if p.ping>0)
        return tested,alive

    def _schedule_refresh(self):
        if self._refresh_pending:
            return
        self._refresh_pending=True
        QTimer.singleShot(400,self._refresh_now)

    def _refresh_now(self):
        self._refresh_pending=False
        pool=self.pool()
        alive=sorted([p for p in pool if p.ping>0],key=lambda p:p.ping)
        untested=[p for p in pool if p.ping==-1.0]
        dead=[p for p in pool if p.ping==-2.0]
        self.top=(alive+untested+dead)[:MAX_SERVERS]
        self.refresh_table()
        if self.manual_mode:
            return
        n_alive=len(alive)
        tested,total=self._ping_status()
        if total and tested<total:
            self.set_status(f"📶 Проверено {tested} из {total} серверов · рабочих: {n_alive}")
        elif n_alive:
            self.set_status(f"✅ Рабочих прокси: {n_alive} · показаны лучшие {min(n_alive,MAX_SERVERS)} · обновление каждые {REPING_INTERVAL} с")
        else:
            self.set_status("⚠ Рабочих прокси не найдено — повторный поиск через 30 секунд…")
            if not self._rescan_scheduled:
                self._rescan_scheduled=True
                QTimer.singleShot(30000,self._rescan_reset)
                self.start_scan()

    def _rescan_reset(self):
        self._rescan_scheduled=False

    def refresh_table(self):
        prev=self.current_proxy()
        self.table.setRowCount(len(self.top))
        for i,p in enumerate(self.top):
            num=QTableWidgetItem(str(i+1))
            num.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i,0,num)
            mark=""
            if p.ping!=-1.0:
                mark="✅ " if p.valid else "⚠ "
            self.table.setItem(i,1,QTableWidgetItem(mark+p.host))
            port=QTableWidgetItem(str(p.port))
            port.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i,2,port)
            if p.ping>0:
                text,color=f"{p.ping:.0f} мс",self._ping_color(p.ping)
            elif p.ping==-2.0:
                text,color="✖",QColor("#8b949e")
            else:
                text,color="…",QColor(muted_color(self.theme_mode()))
            ping_item=QTableWidgetItem(text)
            ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ping_item.setForeground(color)
            self.table.setItem(i,3,ping_item)
        if prev:
            for i,p in enumerate(self.top):
                if p is prev:
                    self.table.selectRow(i)
                    break

    @staticmethod
    def _ping_color(ms):
        if ms<150:
            return QColor("#3fb950")
        if ms<400:
            return QColor("#d29922")
        return QColor("#f85149")

    def set_status(self,text):
        self.status_lbl.setText(text)

    def current_proxy(self):
        row=self.table.currentRow()
        return self.top[row]if 0<=row<len(self.top)else None

    def connect_selected(self):
        self.connect_proxy(self.table.currentIndex())

    def connect_proxy(self,index):
        p=self.current_proxy()
        if not p:
            return
        self.set_status(f"🔗 Открываю {p.host}:{p.port} в Telegram…")
        subprocess.Popen(["xdg-open",p.tg_link])

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
        self.theme_box.addItem("Тёмная","dark")
        self.theme_box.addItem("Светлая","light")
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

def apply_blur(win,radius=24):
    try:
        wid=int(win.winId())
        w=win.width(); h=win.height()
        r=radius
        if r*2>h: r=h//2
        if r*2>w: r=w//2
        if r<0: r=0
        rects=[
            "0,0,{},{}".format(w,r),
            "0,{},{},{}".format(r,w,h-2*r),
            "0,{},{},{}".format(h-r,w,r),
        ]
        region=" ".join(rects)
        subprocess.Popen([
            "xprop","-id",str(wid),
            "-f","_KDE_NET_WM_BLUR_BEHIND_REGION","32c",
            "-set","_KDE_NET_WM_BLUR_BEHIND_REGION",region,
        ],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except Exception:
        pass

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
