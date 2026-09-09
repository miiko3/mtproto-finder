# MTProto Finder — iOS 26 (Liquid Glass)

SwiftUI-приложение: поиск MTProto/SOCKS5 прокси для Telegram с настоящей проверкой пинга.

## Особенности
- **Liquid Glass (iOS 26)**: `glassEffect(.regular)`, `buttonStyle(.glass/.glassProminent)`, живой aurora-фон, морфинг переключателя, плавающий стеклянный док.
- **Честный MTProto-пинг**: обычные MTProto-прокси проверяются реальным obfuscated2-хендшейком `req_pq_multi` → `ResPQ` (`MTProtoPing.swift`, AES-CTR через CommonCrypto/CryptoKit).
- **FakeTLS** (секреты `ee…`): TLS-пинг по SNI, извлечённому из секрета (+ хост + fallback `www.cloudflare.com`).
- **SOCKS5**: полный CONNECT-хендшейк, живым считается только сервер, подтвердивший `05 00` на оба этапа.
- Подключение/копирование через `tg://proxy` / `tg://socks`, тёмная тема.

## Статус
Сборка .ipa возможна только на macOS с Xcode 26. На iOS 25 и ниже интерфейс Liquid Glass недоступен (deployment target — iOS 26).

## Сборка
1. Открыть `MTProtoFinder.xcodeproj` в Xcode 26 на любом Mac
2. Выбрать свой Signing Team в настройках таргета
3. Product → Run (симулятор/устройство) или Product → Archive для .ipa

Требования: iOS 26+, Xcode 26. Иконка — `logo.png` в Assets.