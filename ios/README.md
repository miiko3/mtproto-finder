# MTProto Finder — iOS 26 (Liquid Glass)

SwiftUI-приложение: поиск MTProto/SOCKS5 прокси для Telegram с настоящей проверкой пинга.

## Особенности
- **Liquid Glass (iOS 26)**: `glassEffect(.regular)`, максимальные скругления-пиллы, усиленный blur, стеклянный док, кастомные `GlassButtonStyle`/`AccentButtonStyle` с пружинной анимацией нажатия.
- **Палитра из иконки**: графитовый монохром извлечён из `Frame 30.png` (AppIcon), UI — серое стекло с синим акцентом `#0A84FF`.
- **Адаптивный макет**: на iPad — центрированная колонка и сетка в 3 колонки, на iPhone — 2.
- **Честный MTProto-пинг**: обычные MTProto-прокси проверяются реальным obfuscated2-хендшейком `req_pq_multi` → `ResPQ` (`MTProtoPing.swift`, AES-CTR через CommonCrypto/CryptoKit).
- **FakeTLS** (секреты `ee…`): полный MTProto-пинг (`req_pq_multi` → `ResPQ`) **внутри** TLS-туннеля по SNI, извлечённому из секрета (+ хост + fallback `www.cloudflare.com`).
- **SOCKS5**: полный CONNECT-хендшейк, живым считается только сервер, подтвердивший `05 00` на оба этапа.
- **Подключение/копирование** через `tg://proxy` / `tg://socks`, тёмная тема.
- MTProto и SOCKS5 — отдельные кнопки переключения с анимацией нажатия.
- **Локальный туннель** (`BridgeTunnel.swift`): настоящий MTProto-прокси на
  `127.0.0.1:10811` с секретом `dd…dd` — в Telegram добавляется
  `tg://proxy?server=127.0.0.1&port=10811&secret=dd…dd`. Реле через лучший
  проверенный сервер тремя режимами: обычный MTProto, FakeTLS (полный TLS
  по SNI), fallback `ClientHello` + запись-TLS-records.
- **WebSocket-режим**: без рабочих серверов туннель ходит напрямую в Telegram
  через `kws1-3.web.telegram.org:443` (WSS, собственный WS-клиент на
  Network.framework).
- **Самопроверка шифра** (`CryptoVectors.swift`): AES-CTR/derive/framing/
  wrap-strip сверяются с эталонными векторами PyCryptodome — щит в шапке.
- Карточка туннеля в стиле UI: PowerButton, LiveBadge, адрес/секрет,
  кнопки «Ссылка tg://» и «В Telegram».

## Статус
Сборка .ipa возможна только на macOS с Xcode 26. На iOS 25 и ниже интерфейс Liquid Glass недоступен (deployment target — iOS 26).

## Сборка
1. Открыть `MTProtoFinder.xcodeproj` в Xcode 26 на любом Mac
2. Выбрать свой Signing Team в настройках таргета
3. Product → Run (симулятор/устройство) или Product → Archive для .ipa

Требования: iOS 26+, Xcode 26. Иконка — `logo.png` в Assets.