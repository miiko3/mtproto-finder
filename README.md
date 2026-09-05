# ⚡ MTProto Finder

[![Author](https://img.shields.io/badge/author-%40yetilov-blue)](https://t.me/yetilov)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.4.0-orange)](.)

Графическое приложение для **Linux**, которое автоматически находит рабочие
MTProto-прокси для Telegram в интернете и показывает их **реальный пинг от вашей сети**
в режиме реального времени. Полупрозрачный интерфейс без рамки окна с фоном-блюром
(эффект стекла через KWin).

![screenshot](docs/screenshot.png)

## Возможности

- 🔍 **Автопоиск** из 15 публичных источников (7 MTProto + 8 SOCKS5), обновление каждые 10 минут
- ⚡ **Оптимизированный поиск** — источники грузятся параллельно, недоступные списки быстро отсекаются (поиск занимает ~4 сек)
- 📶 **Честная валидация**: MTProto — реальный req_pq_multi до Telegram-DC (внутри TLS для FakeTLS), SOCKS5 — полный CONNECT, FakeTLS — TLS ClientHello с SNI из секрета; цветной бейдж получают только прокси, реально говорящие с Telegram
- 🏆 Карточки в две колонки: рабочие сверху по пингу, мёртвые внизу серым; бейджи зелёный <300 мс / жёлтый <1000 мс / красный выше
- 🔀 Вкладки **MTPROTO | SOCKS5** — два типа прокси для Telegram
- 🖥 До **32 серверов** в списке, пинг пересчитывается каждые 6 секунд
- 🎯 **«Пинг выбранного»** — пингует только выбранный сервер, останавливая остальные
- 🚀 Подключение в один клик (двойной клик или Enter) — прокси подставляется в Telegram
- 🌙 Фиолетовый glass-интерфейс в стиле macOS/macOS-виджета: безрамочное окно, две темы (фиолет/лаванда), акцент настраивается
- 📦 Поставляется как **AppImage** — без установки
- 🚀 **Автозапуск** при входе в систему (настраивается скриптом)

## Установка и запуск

```bash
chmod +x MTProto-Finder-x86_64.AppImage
./MTProto-Finder-x86_64.AppImage
```

Требования: Linux x86_64 с FUSE2 (`sudo pacman -S fuse2` на Arch Linux).
Для блюра нужен композитор с поддержкой blur (KDE Plasma: Эффекты → «Размытие»).

Приложение само следит за интернетом: если связи нет, поиск повторяется каждые 15 секунд.

### Автозапуск при запуске системы

```bash
./install_autostart.sh
```

Скрипт создаёт файл `~/.config/autostart/mtproto-finder.desktop`, чтобы приложение
запускалось автоматически при входе в систему.

## Сборка из исходников

```bash
./build.sh
```

Нужны: `python-pyqt6`, `fuse2`, `appimagetool` (или путь к нему в `$APPIMAGETOOL`).
Также есть автосборка через GitHub Actions — AppImage прикладывается к релизу.

## Источники прокси

Открытые авто-обновляемые списки, часть — через CDN-зеркала jsdelivr (работают даже
при блокировке raw.githubusercontent):
- [ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy) (proxies.json, README)
- [Argh94/Proxy-List](https://github.com/Argh94/Proxy-List) (MTProto.txt)

## Автор

**@yetilov** — [https://t.me/yetilov](https://t.me/yetilov)

## Лицензия

[MIT](LICENSE)

## Платформы

| Платформа | Версия | Статус |
|---|---|---|
| Linux (AppImage) | 1.2.1.5 | ✅ стабильная |
| Android (APK) | 0.1.1.4 | 🧪 альфа |
| iOS (SwiftUI) | v0.pa1t | 🚧 пре-альфа, сборка на Mac |

Android и iOS: при первом запуске показывается напоминание — если пинг не отображается, пушьте баг на GitHub или пишите [@yetilov](https://t.me/yetilov).
