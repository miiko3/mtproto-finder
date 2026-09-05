# ⚡ MTProto Finder

[![Author](https://img.shields.io/badge/author-%40yetilov-blue)](https://t.me/yetilov)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.4.0-orange)](../../releases/latest)
[![Boosty](https://img.shields.io/badge/%F0%9F%9A%80-Boosty-ff4d8b)](https://boosty.to/miilo3)

Приложение, которое само находит в интернете **рабочие прокси для Telegram** —
MTProto и SOCKS5 — и показывает их **настоящий пинг из вашей сети**.
Никаких фейковых «1 мс»: сервер получает цветной бейдж только после успешного
рукопожатия с ним.

| Тёмная тема | Светлая тема |
|---|---|
| ![dark](docs/screenshot.png) | ![light](docs/screenshot-light.png) |

## Скачать

Готовые сборки — в разделе [Releases](../../releases/latest):

| Файл | Для |
|---|---|
| `MTProto-Finder-x86_64.AppImage` | Linux x86_64, запуск без установки |
| `MTProto-Finder-v0.1.3.2b.apk` | Android 8+ |

```bash
chmod +x MTProto-Finder-x86_64.AppImage
./MTProto-Finder-x86_64.AppImage
```

Нужен только FUSE2 (`sudo pacman -S fuse2` на Arch / `sudo apt install libfuse2` на Debian/Ubuntu).

## Как это работает

- **Поиск** — приложение тянет 15 открытых авто-обновляемых списков прокси
  (7 MTProto + 8 SOCKS5), всё параллельно, через CDN-зеркала jsDelivr.
- **Проверка** — по каждому серверу делается полноценное рукопожатие:
  - MTProto: реальный запрос `req_pq_multi` и ответ от Telegram-DC;
  - FakeTLS: TLS ClientHello с SNI, зашитым в секрет;
  - SOCKS5: полный CONNECT-запрос через прокси.
- **Бейджи пинга**: 🟢 до 300 мс · 🟡 до 1000 мс · 🔴 выше.
  Серый `✖` — TCP отвечает, но MTProto не работает: в Telegram такой
  прокси не подключится. Серый `—` — сервер мёртв. Рабочие всегда сверху.

## Возможности

- 🔀 Два типа прокси: **MTProto | SOCKS5**
- 🃏 Карточки в две колонки, до 32 серверов, пинг пересчитывается каждые 6 секунд
- 🎯 Режим «Пинг» — пингует только выбранный сервер
- 🚀 Подключение в один клик: двойной клик по карточке, Enter или кнопка «Подключиться» — прокси открывается в Telegram
- 🌸 Фиолетовый glass-интерфейс: безрамочное окно, тёмная и светлая темы, свой цвет акцента
- 🔌 **Локальный прокси** — поднимает MTProto-мост на `127.0.0.1:10811` через лучший найденный сервер
- 🚙 Автозапуск при входе в систему (`./install_autostart.sh`)
- 📴 Сам следит за интернетом: пропала сеть — пересканирует через 15 секунд

## Сборка из исходников

```bash
./build.sh
```

Нужны: `python-pyqt6`, `pycryptodome`, `fuse2`, `appimagetool`
(путь к нему можно передать через `$APPIMAGETOOL`).

Android-сборка: `android/build_android.sh`, iOS-проект лежит в `ios/`.

## Источники прокси

Открытые GitHub-списки, обновляются их владельцами круглосуточно
(в приложении грузятся через зеркала `cdn.jsdelivr.net`):

MTProto: [ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy),
[Argh94/Proxy-List](https://github.com/Argh94/Proxy-List),
[MhdiTaheri/ProxyCollector](https://github.com/MhdiTaheri/ProxyCollector),
[SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto),
[Chumbayoumba/free-telegram-proxy-russia-2026](https://github.com/Chumbayoumba/free-telegram-proxy-russia-2026),
[horizonpaz-create/mtproto-live](https://github.com/horizonpaz-create/mtproto-live)

SOCKS5: [monosans/proxy-list](https://github.com/monosans/proxy-list),
[TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List),
[proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list),
[roosterkid/openproxylist](https://github.com/roosterkid/openproxylist),
[zloi-user/hideip.me](https://github.com/zloi-user/hideip.me),
[casals-ar/proxy-list](https://github.com/casals-ar/proxy-list),
[ShiftyTR/Proxy-List](https://github.com/ShiftyTR/Proxy-List),
[Argh94/Proxy-List](https://github.com/Argh94/Proxy-List)

Бесплатные списки живут своей жизнью: часть серверов умирает за часы,
поэтому приложение перепроверяет всё само и показывает только то,
что отвечает прямо сейчас.

## Платформы

| Платформа | Версия | Статус |
|---|---|---|
| Linux (AppImage) | 1.4.0 | ✅ стабильная |
| Android (APK) | 0.1.3.2b | 🧪 бета |
| iOS (SwiftUI) | v0.pa1t | 🚧 пре-альфа, сборка на Mac |

## Поддержать

Если приложение помогло — можно поддержать разработку на Boosty:
**[boosty.to/miilo3](https://boosty.to/miilo3)**

## Автор

**@yetilov** — [t.me/yetilov](https://t.me/yetilov)

## Лицензия

[MIT](LICENSE)
