# ⚡ MTProto Finder

[![Author](https://img.shields.io/badge/author-%40yetilov-blue)](https://t.me/yetilov)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Графическое приложение для **Arch Linux**, которое автоматически находит рабочие
MTProto-прокси для Telegram в интернете и показывает их **реальный пинг от вашей сети**
в режиме реального времени.

![logo](logo.png)

## Возможности

- 🔍 **Автоматический поиск** MTProto-прокси в интернете (несколько публичных источников, обновление каждые 10 минут)
- 📶 **Реальный TCP-пинг** каждого сервера от сети пользователя (обновляется каждые 5 секунд)
- 🏆 Топ **5–10 самых быстрых серверов** в красивом тёмном GUI (PyQt6)
- 🚀 **Подключение в один клик**: двойной клик по серверу или кнопка — прокси автоматически подставляется в Telegram (через `tg://proxy` ссылку)
- 📋 Копирование прокси-ссылки в буфер обмена
- 📦 Поставляется как **AppImage** — не требует установки

## Установка и запуск

```bash
chmod +x MTProto-Finder-x86_64.AppImage
./MTProto-Finder-x86_64.AppImage
```

Требования: Linux x86_64 с FUSE2 (`sudo pacman -S fuse2` на Arch Linux).

Приложение само следит за интернетом: если связи нет, поиск повторяется каждые 15 секунд
до появления соединения.

## Сборка из исходников

```bash
./build.sh
```

Скрипт соберёт бинарник через PyInstaller и упакует его в AppImage
(нужны `python-pyqt6`, `fuse2` и `appimagetool`).

## Источники прокси

Списки берутся из открытых авто-обновляемых репозиториев:
[ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy) и
[Argh94/Proxy-List](https://github.com/Argh94/Proxy-List).

## Автор

**@yetilov** — [https://t.me/yetilov](https://t.me/yetilov)

## Лицензия

[MIT](LICENSE)
