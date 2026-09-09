# ⚡ MTProto Finder

[![Author](https://img.shields.io/badge/author-%40yetilov-blue)](https://t.me/yetilov)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.4.3-orange)](../../releases/latest)
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
| `MTProto-Finder-v0.1.3.5b.apk` | Android 8+ |
| `MTProtoFinder.ipa` | iPhone (iOS 26+), unsigned — для Sideloadly/AltStore |

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
- 📋 Контекстное меню карточки: подключиться, скопировать ссылку или адрес; на Android — долгий тап
- ⌨ Менюбар с горячими клавишами: `Ctrl+1/2` — тип прокси, `F5` — обновить, `Ctrl+,` — настройки, `F1` — справка
- 🌸 Фиолетовый glass-интерфейс: безрамочное окно, тёмная и светлая темы, свой цвет акцента
- 🔌 **Локальный прокси** — поднимает MTProto-мост на `127.0.0.1:10811` через лучший найденный сервер; работает и с FakeTLS-прокси (нативный TLS или record-обёртка), на Android то же самое
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
| Linux (AppImage) | 1.4.3 | ✅ стабильная |
| Android (APK) | 0.1.3.5b | 🧪 бета |
| iOS (SwiftUI, Liquid Glass) | 1.0.0 | 🚧 пре-альфа, сборка unsigned через GitHub Actions |

## Что нового в 1.4.3

- 🛠 **Честный пинг MTProto**: обычные (не FakeTLS) прокси теперь проверяются
  реальным рукопожатием `req_pq_multi` → `ResPQ` (obfuscated2, AES-CTR),
  а не «верой» в ответ TCP. Раньше такие серверы могли показываться
  рабочими, но не подключаться в Telegram.
- 🔍 **Исправлен пинг FakeTLS**: рабочим считается только прокси, который
  ответил настоящим MTProto-ответом внутри TLS-туннеля; убран shortcut,
  из-за которого «живыми» числились любые TLS-серверы.
- 🤝 **Локальный прокси стал надёжнее**: мост на `127.0.0.1:10811` теперь
  на каждое подключение сам подбирает лучший проверенный MTProto-сервер,
  а не замораживает первый на момент запуска; переживает смерть лучшего.
- 🌊 **iOS 26 (Liquid Glass)**: `glassEffect(.regular)`, `buttonStyle(.glass/.glassProminent)`,
  живой aurora-фон, морфинг переключателя MTProto|SOCKS5, плавающий
  стеклянный док. Deployment target поднят до iOS 26, версия приложения — 1.0.0.
- 🏭 **Готовые `.ipa` через GitHub Actions**: пуш тега `v*` автоматически
  собирает unsigned `.ipa` (Xcode 26, macOS runner) и крепит его к Release —
  подпишите локально через Sideloadly/AltStore и ставьте на iPhone.
- 📄 Подробный ревью изменений — в описании коммита `v1.4.3`.

## Поддержать

Если приложение помогло — можно поддержать разработку на Boosty:
**[boosty.to/miilo3](https://boosty.to/miilo3)**

## Автор

**@yetilov** — [t.me/yetilov](https://t.me/yetilov)

## Лицензия

[MIT](LICENSE)
