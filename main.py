#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json,os,re,socket,subprocess,sys,time,urllib.parse,urllib.request
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import dataclass
from PyQt6.QtCore import Qt,QThread,pyqtSignal,QTimer
from PyQt6.QtGui import QColor,QIcon,QPixmap,QKeySequence,QShortcut
from PyQt6.QtWidgets import QApplication,QFrame,QHBoxLayout,QHeaderView,QLabel,QMainWindow,QAbstractItemView,QMessageBox,QPushButton,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget

APP_NAME="MTProto Finder"
APP_VERSION="1.2.0"
AUTHOR_URL="https://t.me/yetilov"
SOURCES=["https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/proxies.json","https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt"]
MAX_SERVERS=10
REPING_INTERVAL=5
RESCAN_INTERVAL=600
LINK_RE=re.compile(r"(server|port|secret)=([^&\s]+)")

def resource_path(name):
    base=getattr(sys,"_MEIPASS",os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base,name)

LOGO=resource_path("logo.png")

@dataclass
class Proxy:
    host:str
    port:int
    secret:str
    ping:float=-1.0

    @property
    def ptype(self):
        return"faketls"if self.secret.lower().startswith("ee")else"mtproto"

    @property
    def type_label(self):
        return"Fake TLS"if self.ptype=="faketls"else"MTProto"

    @property
    def tg_link(self):
        return"tg://proxy?server={}&port={}&secret={}".format(self.host,self.port,urllib.parse.quote(self.secret,safe=""))

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

def fetch_proxies():
    found,seen=[],set()
    for url in SOURCES:
        try:
            req=urllib.request.Request(url,headers={"User-Agent":APP_NAME})
            with urllib.request.urlopen(req,timeout=15)as r:
                text=r.read().decode("utf-8","replace")
        except Exception:
            continue
        if url.endswith(".json"):
            try:
                for item in json.loads(text):
                    link=item.get("connect_url")or"tg://proxy?server={}&port={}&secret={}".format(item.get("host",""),item.get("port",""),item.get("secret",""))
                    p=parse_proxy_link(link)
                    if p and(p.host,p.port)not in seen:
                        seen.add((p.host,p.port));found.append(p)
            except(json.JSONDecodeError,AttributeError):
                pass
        else:
            for line in text.splitlines():
                p=parse_proxy_link(line.strip())
                if p and(p.host,p.port)not in seen:
                    seen.add((p.host,p.port));found.append(p)
    return found

def tcp_ping_one(proxy,timeout=2.0):
    start=time.perf_counter()
    try:
        with socket.create_connection((proxy.host,proxy.port),timeout=timeout):
            return(time.perf_counter()-start)*1000
    except OSError:
        return-2.0

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

    def __init__(self,proxies,timeout=2):
        super().__init__()
        self.proxies=proxies
        self.timeout=timeout

    def run(self):
        with ThreadPoolExecutor(max_workers=100)as pool:
            futures={pool.submit(tcp_ping_one,p,self.timeout):p for p in self.proxies}
            for fut in as_completed(futures):
                if self.isInterruptionRequested():
                    for f in futures:
                        f.cancel()
                    break
                p=futures[fut]
                try:
                    ms=fut.result()
                except OSError:
                    ms=-2.0
                self.one_done.emit(p,ms)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.all_proxies=[]
        self.top=[]
        self.scan_thread=None
        self.ping_thread=None
        self.no_internet=False
        self._refresh_pending=False
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
        shadow=QWidget(self)
        self.setCentralWidget(shadow)
        outer=QVBoxLayout(shadow)
        outer.setContentsMargins(14,14,14,14)
        card=QFrame()
        card.setObjectName("card")
        root=QVBoxLayout(card)
        root.setContentsMargins(18,12,18,14)
        root.setSpacing(10)
        outer.addWidget(card)

        bar=QHBoxLayout()
        bar.setSpacing(8)
        icon_lbl=QLabel()
        icon_lbl.setPixmap(QPixmap(LOGO).scaled(28,28,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        bar.addWidget(icon_lbl)
        title=QLabel(APP_NAME)
        title.setObjectName("title")
        bar.addWidget(title)
        subtitle=QLabel("· MTProto с реальным пингом")
        subtitle.setObjectName("subtitle")
        bar.addWidget(subtitle)
        bar.addStretch()
        self.author_btn=QPushButton("👤 @yetilov")
        self.author_btn.setObjectName("authorBtn")
        self.author_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.author_btn.clicked.connect(self.open_author)
        bar.addWidget(self.author_btn)
        self.min_btn=QPushButton("—")
        self.min_btn.setObjectName("winBtn")
        self.min_btn.clicked.connect(self.showMinimized)
        bar.addWidget(self.min_btn)
        self.close_btn=QPushButton("✕")
        self.close_btn.setObjectName("closeBtn")
        self.close_btn.clicked.connect(self.close)
        bar.addWidget(self.close_btn)
        bar_widget=QWidget()
        bar_widget.setObjectName("titleBar")
        bar_widget.setLayout(bar)
        bar_widget.mousePressEvent=self._bar_pressed
        bar_widget.mouseMoveEvent=self._bar_moved
        bar_widget.mouseDoubleClickEvent=lambda e:self.showMaximized() if not self.isMaximized()else self.showNormal()
        root.addWidget(bar_widget)

        filter_row=QHBoxLayout()
        type_label=QLabel("ТИП:")
        type_label.setObjectName("typeLabel")
        filter_row.addWidget(type_label)
        self.btn_mtproto=QPushButton("MTPROTO")
        self.btn_faketls=QPushButton("FAKE TLS")
        for b in(self.btn_mtproto,self.btn_faketls):
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setObjectName("filterBtn")
        self.btn_mtproto.setChecked(True)
        self.btn_mtproto.clicked.connect(lambda:self.set_mode("mtproto"))
        self.btn_faketls.clicked.connect(lambda:self.set_mode("faketls"))
        filter_row.addWidget(self.btn_mtproto)
        filter_row.addWidget(self.btn_faketls)
        filter_row.addStretch()
        self.search_lbl=QLabel("")
        self.search_lbl.setObjectName("typeLabel")
        filter_row.addWidget(self.search_lbl)
        filter_wrap=QWidget()
        filter_wrap.setLayout(filter_row)
        root.addWidget(filter_wrap)

        self.table=QTableWidget(0,5)
        self.table.setHorizontalHeaderLabels(["#","Сервер","Порт","Тип","Пинг"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(3,90)
        self.table.setColumnWidth(4,110)
        self.table.doubleClicked.connect(self.connect_proxy)
        self.table.itemSelectionChanged.connect(lambda:self.connect_btn.setEnabled(self.table.currentRow()>=0))
        QShortcut(QKeySequence(Qt.Key.Key_Return),self.table,activated=self.connect_selected)
        root.addWidget(self.table,1)

        bottom=QHBoxLayout()
        self.connect_btn=QPushButton("🚀 Подключиться к Telegram")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.setEnabled(False)
        self.connect_btn.clicked.connect(self.connect_selected)
        self.ping_btn=QPushButton("🎯 Пинг выбранного")
        self.ping_btn.setObjectName("pingBtn")
        self.ping_btn.setCheckable(True)
        self.ping_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ping_btn.clicked.connect(self.toggle_manual_ping)
        bottom.addWidget(self.connect_btn)
        bottom.addWidget(self.ping_btn)
        bottom.addStretch()
        bottom_wrap=QWidget()
        bottom_wrap.setLayout(bottom)
        root.addWidget(bottom_wrap)

        self.status_lbl=QLabel("Готов")
        self.status_lbl.setObjectName("status")
        root.addWidget(self.status_lbl)

    def _bar_pressed(self,e):
        if e.button()==Qt.MouseButton.LeftButton:
            self._drag_pos=e.globalPosition().toPoint()-self.frameGeometry().topLeft()

    def _bar_moved(self,e):
        if self._drag_pos and e.buttons()&Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint()-self._drag_pos)

    def _apply_style(self):
        self.setStyleSheet("""
        QMainWindow{background:transparent}
        #card{background:rgba(22,27,34,215);border-radius:18px;border:1px solid rgba(48,54,61,220)}
        #titleBar{background:transparent}
        #title{font-size:19px;font-weight:800;color:#e6edf3}
        #subtitle{color:#8b949e;font-size:13px}
        #typeLabel{color:#8b949e;font-size:12px;font-weight:700;letter-spacing:1px}
        QTableWidget{background:rgba(13,17,23,190);border:1px solid rgba(48,54,61,200);border-radius:12px;gridline-color:rgba(33,38,45,180);font-size:14px;color:#e6edf3;selection-background-color:#1f6feb}
        QTableWidget::item{padding:8px 6px}
        QTableWidget::item:hover{background:rgba(31,111,235,40)}
        QTableWidget::item:selected{background:#1f6feb;color:white}
        QHeaderView::section{background:transparent;color:#8b949e;border:none;border-bottom:1px solid rgba(48,54,61,220);padding:9px;font-weight:700;font-size:12px;letter-spacing:1px}
        QPushButton{background:rgba(33,38,45,200);border:1px solid rgba(48,54,61,220);border-radius:10px;padding:9px 16px;font-weight:700;color:#e6edf3;font-size:13px}
        QPushButton:hover{background:rgba(48,54,61,230)}
        QPushButton:disabled{color:#484f58}
        #connectBtn{background:#238636;border:none;color:white;font-size:14px;padding:11px 20px}
        #connectBtn:hover{background:#2ea043}
        #connectBtn:disabled{background:rgba(35,134,54,70);color:rgba(255,255,255,70)}
        #pingBtn:checked{background:#d29922;border-color:#d29922;color:#161b22}
        #authorBtn{color:#58a6ff;background:transparent;border:1px solid rgba(88,166,255,80)}
        #authorBtn:hover{background:rgba(88,166,255,30)}
        QPushButton#filterBtn{padding:7px 18px;font-size:12px;letter-spacing:1px}
        QPushButton#filterBtn:checked{background:#1f6feb;border-color:#1f6feb;color:white}
        #winBtn,#closeBtn{background:transparent;border:none;color:#8b949e;font-size:14px;padding:6px 10px}
        #winBtn:hover{background:rgba(48,54,61,230);color:white;border-radius:8px}
        #closeBtn:hover{background:#da3633;color:white;border-radius:8px}
        #status{color:#8b949e;font-size:12px;padding:2px 4px}
        """)

    def open_author(self):
        subprocess.Popen(["xdg-open",AUTHOR_URL])

    def pool(self):
        return[p for p in self.all_proxies if p.ptype==self.mode]

    def set_mode(self,mode):
        if self.manual_mode:
            self.ping_btn.setChecked(False)
            self.toggle_manual_ping()
        self.mode=mode
        if mode=="mtproto":
            self.btn_faketls.setChecked(False)
        else:
            self.btn_mtproto.setChecked(False)
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
        self.ping_thread=PingThread([p],timeout=2)
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
        self.top=(alive+untested)[:MAX_SERVERS]
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
            self.set_status("⚠ Рабочих прокси не найдено — повторный поиск…")
            self.start_scan()

    def refresh_table(self):
        prev=self.current_proxy()
        self.table.setRowCount(len(self.top))
        for i,p in enumerate(self.top):
            num=QTableWidgetItem(str(i+1))
            num.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i,0,num)
            self.table.setItem(i,1,QTableWidgetItem(p.host))
            port=QTableWidgetItem(str(p.port))
            port.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i,2,port)
            ptype=QTableWidgetItem(p.type_label)
            ptype.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ptype.setForeground(QColor("#a371f7")if p.ptype=="faketls"else QColor("#79c0ff"))
            self.table.setItem(i,3,ptype)
            if p.ping>0:
                text,color=f"{p.ping:.0f} мс",self._ping_color(p.ping)
            elif p.ping==-2.0:
                text,color="✖",QColor("#484f58")
            else:
                text,color="…",QColor("#8b949e")
            ping_item=QTableWidgetItem(text)
            ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ping_item.setForeground(color)
            self.table.setItem(i,4,ping_item)
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

def main():
    app=QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(LOGO))
    win=MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()
