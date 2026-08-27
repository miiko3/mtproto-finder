#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MTProto Finder — поиск рабочих MTProto-прокси для Telegram с реальным пингом.

Автор: https://t.me/yetilov
Лицензия: MIT
"""

import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow, QPushButton,
    QStatusBar, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QHeaderView, QAbstractItemView, QMessageBox,
)

import os

APP_NAME = "MTProto Finder"
APP_VERSION = "1.0.0"
AUTHOR_URL = "https://t.me/yetilov"


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


LOGO = resource_path("logo.png")

# Источники прокси (публичные, авто-обновляемые списки)
SOURCES = [
    # JSON-список: [{host, port, connect_url}, ...]
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/proxies.json",
    # Текстовый список tg://proxy?server=..&port=..&secret=..
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
]

MAX_SERVERS = 10          # сколько серверов показывать
PING_ATTEMPTS = 3         # замеров на один сервер
PING_TIMEOUT = 3          # сек на TCP-подключение
REPING_INTERVAL = 5       # сек между обновлениями пинга
RESCAN_INTERVAL = 10 * 60 # сек между повторными поисками прокси

LINK_RE = re.compile(r"(server|port|secret)=([^&\s]+)")


@dataclass
class Proxy:
    host: str
    port: int
    secret: str
    ping: float = -1.0          # мс; -1 = не проверен, -2 = недоступен
    history: list = field(default_factory=list)

    @property
    def tg_link(self) -> str:
        return "tg://proxy?server={}&port={}&secret={}".format(
            self.host, self.port, urllib.parse.quote(self.secret, safe="")
        )


def parse_proxy_link(link: str):
    """Извлекает (host, port, secret) из tg:// или https://t.me/proxy ссылки."""
    if "server=" not in link or "port=" not in link:
        return None
    params = dict(LINK_RE.findall(link))
    try:
        host = urllib.parse.unquote(params["server"]).rstrip(".")
        port = int(params["port"])
        secret = urllib.parse.unquote(params.get("secret", ""))
        if not host or not secret:
            return None
        return Proxy(host, port, secret)
    except (KeyError, ValueError):
        return None


def fetch_proxies():
    """Скачивает и парсит все источники, возвращает список Proxy без дублей."""
    found, seen = [], set()
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception:
            continue
        if url.endswith(".json"):
            try:
                for item in json.loads(text):
                    link = item.get("connect_url") or "tg://proxy?server={}&port={}&secret={}".format(
                        item.get("host", ""), item.get("port", ""), item.get("secret", ""))
                    p = parse_proxy_link(link)
                    if p and (p.host, p.port) not in seen:
                        seen.add((p.host, p.port))
                        found.append(p)
            except (json.JSONDecodeError, AttributeError):
                pass
        else:
            for line in text.splitlines():
                p = parse_proxy_link(line.strip())
                if p and (p.host, p.port) not in seen:
                    seen.add((p.host, p.port))
                    found.append(p)
    return found


def tcp_ping(proxy: Proxy) -> float:
    """TCP-пинг: время подключения к host:port, минимум из PING_ATTEMPTS попыток."""
    results = []
    for _ in range(PING_ATTEMPTS):
        start = time.perf_counter()
        try:
            with socket.create_connection((proxy.host, proxy.port), timeout=PING_TIMEOUT):
                results.append((time.perf_counter() - start) * 1000)
        except OSError:
            return -2.0
    return min(results) if results else -2.0


class ScanThread(QThread):
    """Фоновый поиск прокси в интернете."""
    finished_scan = pyqtSignal(list)   # list[Proxy]
    failed = pyqtSignal(str)

    def run(self):
        proxies = fetch_proxies()
        if proxies:
            self.finished_scan.emit(proxies)
        else:
            self.failed.emit(
                "Не удалось получить список прокси.\n"
                "Проверьте подключение к интернету — повтор будет выполнен автоматически."
            )


class PingThread(QThread):
    """Параллельный пинг списка серверов: по одному результату на каждый сервер."""
    one_done = pyqtSignal(object, float)  # (Proxy, ping_ms)

    def __init__(self, proxies, attempts=1, timeout=2):
        super().__init__()
        self.proxies = proxies
        self.attempts = attempts
        self.timeout = timeout

    def run(self):
        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = {pool.submit(self._ping, p): p for p in self.proxies}
            for fut in as_completed(futures):
                if self.isInterruptionRequested():
                    for f in futures:
                        f.cancel()
                    break
                p, ms = futures[fut], -2.0
                try:
                    ms = fut.result()
                except OSError:
                    pass
                self.one_done.emit(p, ms)

    def _ping(self, p):
        best = -2.0
        for _ in range(self.attempts):
            start = time.perf_counter()
            with socket.create_connection((p.host, p.port), timeout=self.timeout):
                ms = (time.perf_counter() - start) * 1000
            best = ms if best < 0 else min(best, ms)
        return best


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.all_proxies: list[Proxy] = []
        self.top: list[Proxy] = []
        self.scan_thread = None
        self.ping_thread = None
        self.no_internet = False
        self._refresh_pending = False

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(QIcon(LOGO))
        self.resize(760, 560)
        self._build_ui()
        self._apply_style()

        # Таймеры: постоянный ре-пинг и периодический поиск новых прокси
        self.ping_timer = QTimer(self, interval=REPING_INTERVAL * 1000, timeout=self.start_ping)
        self.scan_timer = QTimer(self, interval=RESCAN_INTERVAL * 1000, timeout=self.start_scan)
        self.retry_timer = QTimer(self, interval=15000, timeout=self.start_scan)

        self.start_scan()

    # ---------- UI ----------

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 8)
        root.setSpacing(10)

        header = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(QPixmap(LOGO).scaled(
            96, 96, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation))
        header.addWidget(logo)
        text_col = QVBoxLayout()
        text_col.setSpacing(0)
        title = QLabel(f"⚡ {APP_NAME}")
        title.setObjectName("title")
        subtitle = QLabel("рабочие MTProto-прокси с пингом от вашей сети")
        subtitle.setObjectName("subtitle")
        text_col.addWidget(title)
        text_col.addWidget(subtitle)
        header.addLayout(text_col)
        header.addStretch()

        self.author_btn = QPushButton("👤 Автор: @yetilov")
        self.author_btn.setObjectName("authorBtn")
        self.author_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.author_btn.clicked.connect(self.open_author)
        header.addWidget(self.author_btn)
        root.addLayout(header)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["#", "Сервер", "Порт", "Пинг"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(3, 110)
        self.table.setRowCount(MAX_SERVERS)
        self.table.doubleClicked.connect(self.connect_proxy)
        self.table.itemSelectionChanged.connect(
            lambda: self.connect_btn.setEnabled(self.table.currentRow() >= 0))
        root.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        self.connect_btn = QPushButton("🚀 Подключиться к Telegram")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.setEnabled(False)
        self.connect_btn.clicked.connect(self.connect_selected)
        self.copy_btn = QPushButton("📋 Копировать ссылку")
        self.copy_btn.clicked.connect(self.copy_selected)
        bottom.addWidget(self.connect_btn)
        bottom.addWidget(self.copy_btn)
        bottom.addStretch()
        root.addLayout(bottom)

        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов")

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #161b22; color: #e6edf3; font-size: 14px; }
            #title { font-size: 22px; font-weight: bold; }
            #subtitle { color: #8b949e; padding-top: 6px; }
            QTableWidget {
                background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
                gridline-color: #21262d; font-size: 15px;
            }
            QHeaderView::section {
                background: #161b22; color: #8b949e; border: none;
                border-bottom: 1px solid #30363d; padding: 8px; font-weight: bold;
            }
            QTableWidget::item { padding: 6px; }
            QTableWidget::item:selected { background: #1f6feb; color: white; }
            QPushButton {
                background: #21262d; border: 1px solid #30363d; border-radius: 8px;
                padding: 9px 16px; font-weight: bold;
            }
            QPushButton:hover { background: #30363d; }
            QPushButton:disabled { color: #484f58; }
            #connectBtn { background: #2ea043; border: none; }
            #connectBtn:hover { background: #3fb950; }
            #connectBtn:disabled { background: #1c2a20; color: #3d5245; }
            #authorBtn { color: #58a6ff; }
            QStatusBar { color: #8b949e; }
        """)

    # ---------- логика ----------

    def open_author(self):
        import subprocess
        subprocess.Popen(["xdg-open", AUTHOR_URL])

    def start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.retry_timer.stop()
        self.statusBar().showMessage("🔍 Поиск MTProto-прокси в интернете…")
        self.scan_thread = ScanThread(self)
        self.scan_thread.finished_scan.connect(self.on_scan_done)
        self.scan_thread.failed.connect(self.on_scan_failed)
        self.scan_thread.start()

    def on_scan_done(self, proxies):
        self.all_proxies = proxies
        self.no_internet = False
        self.statusBar().showMessage(f"Найдено {len(proxies)} прокси, измеряю пинг…")
        self.ping_timer.start()
        self.scan_timer.start()
        self.top = proxies[:MAX_SERVERS]
        self.refresh_table()
        self.start_ping()

    def on_scan_failed(self, msg):
        self.no_internet = True
        self.statusBar().showMessage("⚠ Нет интернета — повтор через 15 секунд…")
        if not self.top:
            QMessageBox.warning(self, APP_NAME, msg)
        self.retry_timer.start()

    def start_ping(self):
        if not self.all_proxies or (self.ping_thread and self.ping_thread.isRunning()):
            return
        untested = [p for p in self.all_proxies if p.ping == -1.0]
        targets = untested if untested else self.top
        self.ping_thread = PingThread(targets)
        self.ping_thread.one_done.connect(self.on_one_pinged)
        self.ping_thread.start()

    def on_one_pinged(self, proxy, ms):
        proxy.ping = ms
        self._schedule_refresh()

    def _ping_status(self):
        tested = sum(1 for p in self.all_proxies if p.ping != -1.0)
        alive = sum(1 for p in self.all_proxies if p.ping > 0)
        return tested, alive

    def _schedule_refresh(self):
        if self._refresh_pending:
            return
        self._refresh_pending = True
        QTimer.singleShot(400, self._refresh_now)

    def _schedule_refresh(self):
        if self._refresh_pending:
            return
        self._refresh_pending = True
        QTimer.singleShot(400, self._refresh_now)

    def _refresh_now(self):
        self._refresh_pending = False
        alive = [p for p in self.all_proxies if p.ping > 0]
        alive.sort(key=lambda p: p.ping)
        untested = [p for p in self.all_proxies if p.ping == -1.0]
        self.top = (alive + untested)[:MAX_SERVERS]
        self.refresh_table()
        n_alive = len(alive)
        tested, total = self._ping_status()
        if tested < total:
            self.statusBar().showMessage(
                f"📶 Проверено {tested} из {total} серверов · рабочих: {n_alive}")
        elif n_alive:
            self.statusBar().showMessage(
                f"✅ Рабочих прокси: {n_alive} · показаны лучшие {min(n_alive, MAX_SERVERS)}"
                f" · пинг обновляется каждые {REPING_INTERVAL} с")
        else:
            self.statusBar().showMessage("⚠ Рабочих прокси не найдено — повторный поиск…")
            self.start_scan()

    def refresh_table(self):
        prev = self.current_proxy()
        self.table.setRowCount(len(self.top))
        for i, p in enumerate(self.top):
            num = QTableWidgetItem(str(i + 1))
            num.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 0, num)
            self.table.setItem(i, 1, QTableWidgetItem(p.host))
            port = QTableWidgetItem(str(p.port))
            port.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 2, port)

            if p.ping > 0:
                text, color = f"{p.ping:.0f} мс", self._ping_color(p.ping)
            elif p.ping == -2.0:
                text, color = "✖", QColor("#484f58")
            else:
                text, color = "…", QColor("#8b949e")
            ping_item = QTableWidgetItem(text)
            ping_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ping_item.setForeground(color)
            self.table.setItem(i, 3, ping_item)
        if prev:
            for i, p in enumerate(self.top):
                if p is prev:
                    self.table.selectRow(i)
                    break

    @staticmethod
    def _ping_color(ms):
        if ms < 150:
            return QColor("#3fb950")   # зелёный
        if ms < 400:
            return QColor("#d29922")   # жёлтый
        return QColor("#f85149")       # красный

    # ---------- подключение ----------

    def current_proxy(self):
        row = self.table.currentRow()
        return self.top[row] if 0 <= row < len(self.top) else None

    def connect_selected(self):
        self.connect_proxy(self.table.currentIndex())

    def connect_proxy(self, index):
        p = self.current_proxy()
        if not p:
            return
        import subprocess
        self.statusBar().showMessage(f"🔗 Открываю {p.host}:{p.port} в Telegram…")
        subprocess.Popen(["xdg-open", p.tg_link])

    def copy_selected(self):
        p = self.current_proxy()
        if p:
            QApplication.clipboard().setText(p.tg_link)
            self.statusBar().showMessage("📋 Ссылка скопирована")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(LOGO))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
