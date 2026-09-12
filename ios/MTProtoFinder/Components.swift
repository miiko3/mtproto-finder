import SwiftUI
import UIKit

// MARK: - Palette (графит из AppIcon Frame 30.png) + акцент

enum AppPalette {
    static let baseMid       = Color(red: 0.16, green: 0.16, blue: 0.17)   // #29292C
    static let baseDeep      = Color(red: 0.12, green: 0.12, blue: 0.13)   // #1F1F21
    static let graphite      = Color(red: 0.36, green: 0.36, blue: 0.36)   // #5C5C5C (avg иконки)
    static let graphiteSoft  = Color(red: 0.44, green: 0.44, blue: 0.44)   // #707070
    static let graphiteLight = Color(red: 0.60, green: 0.60, blue: 0.61)
    static let graphiteFaint = Color(red: 0.74, green: 0.74, blue: 0.75)
    static let accent        = Color(red: 0.04, green: 0.52, blue: 1.00)   // #0A84FF
    static let accentSoft    = Color(red: 0.04, green: 0.52, blue: 1.00).opacity(0.30)
    static let violet        = Color(red: 0.39, green: 0.37, blue: 0.88)   // #6360E0
    static let good          = Color(red: 0.30, green: 0.90, blue: 0.55)
    static let mid           = Color(red: 0.98, green: 0.83, blue: 0.22)
    static let bad           = Color(red: 1.00, green: 0.36, blue: 0.40)
}

extension View {
    @ViewBuilder
    func `if`<Content: View>(_ condition: Bool, transform: (Self) -> Content) -> some View {
        if condition { transform(self) } else { self }
    }
}

// MARK: - Flat primitives (плоские поверхности).
// Весь UI плоский: лёгкий градиент + тонкая обводка, без материалов и блюра.
// Стеклянный «меню-стиль» из 1.0.3 остаётся только у кнопок меню
// (MenuPillStyle: активная капсула — прозрачный акцент + свечение, как в 1.0.3).

extension View {
    @ViewBuilder
    func flatSurface(_ shape: some InsettableShape) -> some View {
        self.background {
            shape
                .fill(
                    LinearGradient(colors: [Color.white.opacity(0.085), Color.white.opacity(0.035)],
                                   startPoint: .top, endPoint: .bottom)
                )
                .overlay(shape.strokeBorder(Color.white.opacity(0.08), lineWidth: 0.6))
        }
    }

    /// Карточка: плоская поверхность с закруглениями + клип контента.
    @ViewBuilder
    func flatCard(_ radius: CGFloat) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        self
            .flatSurface(shape)
            .clipShape(shape)
    }

    /// Капсула для кнопок/чипов.
    @ViewBuilder
    func flatCapsule() -> some View {
        self.flatSurface(Capsule())
    }
}

struct GlassCard: ViewModifier {
    var cornerRadius: CGFloat = 28
    func body(content: Content) -> some View {
        content.flatCard(cornerRadius)
    }
}

struct SqueezeButtonStyle: ButtonStyle {
    var scale: CGFloat = 0.95
    var dim: Double = 0.85
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? scale : 1)
            .opacity(configuration.isPressed ? dim : 1)
            .animation(.spring(response: 0.30, dampingFraction: 0.58), value: configuration.isPressed)
    }
}

struct GlassButtonStyle: ButtonStyle {
    var prominent = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .brightness(configuration.isPressed ? -0.06 : (prominent ? 0.05 : 0))
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(.spring(response: 0.30, dampingFraction: 0.58), value: configuration.isPressed)
            .flatCapsule()
    }
}

struct GlassButton: ViewModifier {
    var prominent = false
    func body(content: Content) -> some View {
        content.buttonStyle(GlassButtonStyle(prominent: prominent))
    }
}

struct AccentButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        let shape = Capsule()
        configuration.label
            .foregroundColor(.white)
            .background {
                shape
                    .fill(AppPalette.accent.opacity(0.42))
                    .overlay(
                        shape.fill(
                            LinearGradient(colors: [Color.white.opacity(0.18), .clear],
                                           startPoint: .top, endPoint: .center)
                        )
                    )
                    .overlay(shape.strokeBorder(AppPalette.accent.opacity(0.6), lineWidth: 0.6))
                    .shadow(color: AppPalette.accent.opacity(configuration.isPressed ? 0.15 : 0.45),
                            radius: configuration.isPressed ? 4 : 12,
                            y: configuration.isPressed ? 1 : 3)
            }
            .scaleEffect(configuration.isPressed ? 0.95 : 1)
            .animation(.spring(response: 0.30, dampingFraction: 0.58), value: configuration.isPressed)
    }
}

// MARK: - Graphite background (цвета иконки + лёгкий акцент)

struct LiquidBackground: View {
    var body: some View {
        LinearGradient(colors: [Color(red: 0.27, green: 0.27, blue: 0.29),
                                Color(red: 0.20, green: 0.20, blue: 0.22),
                                Color(red: 0.14, green: 0.14, blue: 0.15)],
                       startPoint: .top, endPoint: .bottom)
            .ignoresSafeArea()
    }
}

// MARK: - Ping badge

struct PingBadge: View {
    let proxy: Proxy

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(indicatorColor)
                .frame(width: 7, height: 7)
                .shadow(color: indicatorColor, radius: 3)
            if proxy.ping == -1 && !proxy.valid && !proxy.reachable {
                ProgressView()
                    .controlSize(.mini)
                    .tint(indicatorColor)
                    .scaleEffect(0.8)
            } else {
                Text(proxy.pingText)
                    .font(.caption.weight(.heavy))
                    .monospacedDigit()
                    .foregroundColor(indicatorColor)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 6)
        .flatCapsule()
    }

    private var indicatorColor: Color {
        if proxy.isGood { return AppPalette.good }
        if proxy.isMid { return AppPalette.mid }
        if proxy.isBad { return AppPalette.bad }
        if proxy.isReachOnly { return AppPalette.graphiteLight }
        if proxy.ping == -1 { return Color.white.opacity(0.45) }
        return AppPalette.graphiteFaint.opacity(0.6)
    }
}

// MARK: - Proxy card

struct ProxyCard: View {
    let proxy: Proxy
    var action: (() -> Void)? = nil

    var body: some View {
        Button {
            action?()
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(proxy.endpoint)
                        .font(.system(size: 14, weight: .bold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .foregroundColor(.primary)
                    Spacer(minLength: 4)
                    PingBadge(proxy: proxy)
                }
                if !proxy.note.isEmpty && (proxy.valid || proxy.reachable) {
                    Text(proxy.note)
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(AppPalette.graphiteFaint.opacity(0.85))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.leading, 16)
            .padding(.trailing, 9)
            .padding(.vertical, 10)
            .frame(minHeight: 54)
            .modifier(GlassCard(cornerRadius: 26))
        }
        .buttonStyle(SqueezeButtonStyle(scale: 0.96))
    }
}

// MARK: - Menu buttons (стиль 1.0.3: полупрозрачная акцентная капсула + свечение)

struct MenuPillContainer: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(5)
            .modifier(GlassCard(cornerRadius: 999))
    }
}

struct MenuPillStyle: ButtonStyle {
    let on: Bool
    let accentColor: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(on ? .white : AppPalette.graphiteFaint)
            .frame(maxWidth: .infinity)
            .frame(height: 44)
            .background {
                if on {
                    Capsule()
                        .fill(accentColor.opacity(0.42))
                        .overlay(
                            Capsule().fill(
                                LinearGradient(colors: [Color.white.opacity(0.18), .clear],
                                               startPoint: .top, endPoint: .center)
                            )
                        )
                        .overlay(Capsule().strokeBorder(accentColor.opacity(0.55), lineWidth: 0.6))
                        .shadow(color: accentColor.opacity(0.4), radius: 12, y: 3)
                }
            }
            .scaleEffect(configuration.isPressed ? 0.94 : 1)
            .brightness(configuration.isPressed ? -0.06 : 0)
            .animation(.spring(response: 0.30, dampingFraction: 0.58), value: configuration.isPressed)
    }
}

struct MenuPillButton: View {
    let isOn: Bool
    let icon: String
    let label: String
    var accentColor: Color = AppPalette.accent
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 7) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .bold))
                Text(label)
                    .font(.system(size: 13, weight: .heavy))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
        }
        .buttonStyle(MenuPillStyle(on: isOn, accentColor: accentColor))
    }
}

// MARK: - Плавающий таб-бар (Прокси | Локальный) — общая пилюля как в 1.0.3

struct GlassTabBar: View {
    @Binding var selection: MainTab

    var body: some View {
        HStack(spacing: 5) {
            ForEach(MainTab.allCases) { tab in
                MenuPillButton(isOn: selection == tab,
                               icon: tab.icon,
                               label: tab.label) {
                    withAnimation(.snappy(duration: 0.26)) { selection = tab }
                }
            }
        }
        .modifier(MenuPillContainer())
        .frame(maxWidth: 340)
    }
}

// MARK: - Mode switch (две отдельные кнопки MTProto / SOCKS5)

struct ModeSwitch: View {
    @Binding var mode: String

    var body: some View {
        HStack(spacing: 12) {
            MenuPillButton(isOn: mode == "mtproto", icon: "bolt.fill", label: "MTProto",
                           accentColor: AppPalette.accent) {
                withAnimation(.snappy(duration: 0.26)) { mode = "mtproto" }
            }
            MenuPillButton(isOn: mode == "socks5", icon: "network", label: "SOCKS5",
                           accentColor: AppPalette.violet) {
                withAnimation(.snappy(duration: 0.26)) { mode = "socks5" }
            }
        }
        .frame(maxWidth: 340)
    }
}

// MARK: - Status chip

struct StatusChip: View {
    let text: String
    var busy = false

    var body: some View {
        HStack(spacing: 7) {
            if busy {
                ProgressView()
                    .controlSize(.mini)
                    .tint(.secondary)
            }
            Text(text)
                .font(.caption2.weight(.semibold))
                .foregroundColor(AppPalette.graphiteFaint.opacity(0.9))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .flatCapsule()
    }
}

// MARK: - Floating dock

struct DockBar: View {
    let proxy: Proxy
    var copied: Bool
    var onCopy: () -> Void
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Image(systemName: proxy.proto == "socks5" ? "network" : "bolt.fill")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(proxy.valid ? AppPalette.accent : AppPalette.graphiteFaint.opacity(0.7))
                Text(proxy.endpoint)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                Spacer()
                if proxy.valid {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(AppPalette.good)
                } else if proxy.reachable {
                    Text("жив · без MTProto")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(AppPalette.graphiteLight)
                } else {
                    Text("нет ответа")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.secondary)
                }
            }
            HStack(spacing: 10) {
                Button {
                    if let url = proxy.tgURL { openURL(url) }
                } label: {
                    Label("Подключиться", systemImage: "link")
                        .font(.system(size: 14, weight: .heavy))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                }
                .buttonStyle(AccentButtonStyle())

                Button {
                    onCopy()
                } label: {
                    Label(copied ? "Скопировано" : "Ссылка", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                }
                .buttonStyle(GlassButtonStyle())
            }
        }
        .padding(12)
        .modifier(GlassCard(cornerRadius: 30))
        .padding(.horizontal, 4)
    }
}

// MARK: - LiveBadge (пульсирующий статус, как в референсе)

struct LiveBadge: View {
    let isLive: Bool
    @State private var pulse = false

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(isLive ? AppPalette.good : Color.secondary.opacity(0.5))
                .frame(width: 7, height: 7)
                .scaleEffect(pulse ? 1.4 : 0.85)
                .opacity(pulse ? 0.55 : 1)
            Text(isLive ? "LIVE" : "OFF")
                .font(.caption2.weight(.heavy))
                .kerning(0.6)
                .foregroundColor(isLive ? AppPalette.good : Color.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(isLive ? AppPalette.good.opacity(0.14) : Color.primary.opacity(0.05)))
        .overlay(Capsule().strokeBorder(isLive ? AppPalette.good.opacity(0.4) : Color.primary.opacity(0.08),
                                        lineWidth: 0.5))
        .onAppear {
            withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }
}

// MARK: - PowerButton (с пульсирующим ореолом вкл/выкл)

struct PowerButton: View {
    let isOn: Bool
    var size: CGFloat = 58
    var action: () -> Void

    @State private var boost = false

    var body: some View {
        Button {
            boost = true
            withAnimation(.spring(response: 0.45, dampingFraction: 0.55)) { boost = false }
            action()
        } label: {
            ZStack {
                if isOn {
                    Circle()
                        .fill(AppPalette.good.opacity(0.35))
                        .frame(width: size * 0.75, height: size * 0.75)
                        .blur(radius: 8)
                        .scaleEffect(boost ? 1.8 : 1)
                        .animation(.easeOut(duration: 0.5), value: boost)
                }
                Circle()
                    .fill(isOn
                          ? AnyShapeStyle(LinearGradient(colors: [AppPalette.good, AppPalette.accent],
                                                          startPoint: .top, endPoint: .bottom))
                          : AnyShapeStyle(LinearGradient(colors: [AppPalette.baseMid, AppPalette.graphite],
                                                          startPoint: .top, endPoint: .bottom)))
                    .overlay(Circle().strokeBorder(isOn ? Color.white.opacity(0.3) : Color.primary.opacity(0.08),
                                                   lineWidth: 1))
                    .shadow(color: isOn ? AppPalette.good.opacity(0.55) : Color.clear,
                            radius: isOn ? 16 : 0, y: 2)
                    .shadow(color: Color.black.opacity(0.35), radius: 6, y: 3)
                Image(systemName: "power")
                    .font(.system(size: size * 0.30, weight: .bold))
                    .foregroundColor(isOn ? .white : AppPalette.graphiteFaint)
            }
            .frame(width: size, height: size)
        }
        .buttonStyle(SqueezeButtonStyle(scale: 0.9))
    }
}

// MARK: - InfoRow (строка настроек, как card() в референсе)

struct InfoRow: View {
    var icon: String
    var title: String
    var value: String
    var mono = false
    var accent = false
    var tint: Color? = nil

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(AppPalette.graphiteFaint)
                .frame(width: 22)
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.primary)
            Spacer()
            Text(value)
                .font(mono
                      ? .system(size: 12, weight: .semibold).monospaced()
                      : .system(size: 12, weight: .semibold))
                .foregroundColor(tint ?? (accent ? AppPalette.accent : AppPalette.graphiteFaint.opacity(0.92)))
                .lineLimit(1)
                .minimumScaleFactor(0.55)
        }
        .padding(.vertical, 9)
        .overlay(Divider().opacity(0.35), alignment: .bottom)
    }
}

// MARK: - AppHeader (лого + название + версия + бейдж шифра)

struct AppHeader: View {
    var cryptoOK: Bool?
    var title = "MTProto Finder"
    var showAuthor = true
    @Environment(\.openURL) private var openURL

    var body: some View {
        HStack(spacing: 12) {
            Image("AppLogo")
                .resizable()
                .scaledToFit()
                .frame(width: 46, height: 46)
                .clipShape(Circle())
                .overlay(Circle().strokeBorder(AppPalette.accent.opacity(0.45), lineWidth: 1.5))
                .shadow(color: AppPalette.accent.opacity(0.35), radius: 8)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 17, weight: .heavy))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                HStack(spacing: 6) {
                    Text(APP_VERSION)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                    if let ok = cryptoOK {
                        Label(ok ? "шифр OK" : "шифр: сбой",
                              systemImage: ok ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(ok ? AppPalette.good : AppPalette.bad)
                            .labelStyle(.titleAndIcon)
                    } else {
                        ProgressView().controlSize(.mini).tint(.secondary)
                    }
                }
            }

            Spacer(minLength: 0)

            if showAuthor {
                Link(destination: URL(string: AUTHOR_URL)!) {
                    Image(systemName: "paperplane.fill")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(.white)
                        .frame(width: 46, height: 46)
                        .modifier(GlassCard(cornerRadius: 23))
                }
            }
        }
        .padding(.leading, 10)
        .padding(.trailing, 14)
        .padding(.vertical, 10)
        .modifier(GlassCard(cornerRadius: 30))
        .padding(.horizontal, 4)
    }
}

// MARK: - GuideCard (инструкция для локального прокси)

struct GuideCard: View {
    @ObservedObject var tunnel: BridgeTunnel
    @State private var copied = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "info.circle.fill")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(AppPalette.accent)
                Text("Как подключить в Telegram")
                    .font(.system(size: 14, weight: .heavy))
                    .foregroundColor(.primary)
            }
            step(1, "Включи «Локальный прокси» кнопкой питания выше.")
            step(2, "Используй ссылку tg:// или добавь вручную: 127.0.0.1, порт \(tunnel.port), секрет dd…dd.")
            step(3, "Telegram → Настройки → Данные и память → Прокси → добавить MTProto.")
            step(4, tunnel.wsFallbackActive
                 ? "Сейчас реле — WebSocket (kws): серверы недоступны, трафик идёт напрямую."
                 : "Серверы проверяются автоматически: туннель релеит через лучший MTProto / FakeTLS.")

            HStack(spacing: 10) {
                Button {
                    UIPasteboard.general.string = tunnel.tgURL?.absoluteString ?? ""
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Скопировано" : "Ссылка tg://",
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 13, weight: .heavy))
                        .foregroundColor(.primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(GlassButtonStyle())

                Button {
                    if let url = tunnel.tgURL { openURL(url) }
                } label: {
                    Label("В Telegram", systemImage: "paperplane.fill")
                        .font(.system(size: 13, weight: .heavy))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(AccentButtonStyle())
            }
        }
        .padding(16)
        .modifier(GlassCard(cornerRadius: 28))
        .padding(.horizontal, 4)
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                Circle()
                    .fill(AppPalette.accent.opacity(0.30))
                Text("\(n)")
                    .font(.system(size: 11, weight: .heavy))
                    .foregroundColor(.white)
            }
            .frame(width: 22, height: 22)
            Text(text)
                .font(.system(size: 12.5, weight: .medium))
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Карточка «Локальный туннель»

struct TunnelCard: View {
    @ObservedObject var tunnel: BridgeTunnel
    @Environment(\.openURL) private var openURL
    @State private var copied = false
    @State private var revealSecret = false

    private var fullSecret: String { BridgeTunnel.localSecretHex }

    private var pingTint: Color {
        if tunnel.wsFallbackActive { return AppPalette.mid }
        if tunnel.relayPing > 0 { return AppPalette.good }
        if tunnel.relayPing == -2 { return AppPalette.bad }
        return AppPalette.graphiteFaint.opacity(0.8)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                PowerButton(isOn: tunnel.isRunning) {
                    if tunnel.isRunning { tunnel.stop() } else { tunnel.start() }
                }
                VStack(alignment: .leading, spacing: 5) {
                    Text("Локальный туннель")
                        .font(.system(size: 15, weight: .heavy))
                        .foregroundColor(.primary)
                    LiveBadge(isLive: tunnel.isRunning)
                    Text(tunnel.detail)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
            }
            .padding(14)

            VStack(spacing: 0) {
                InfoRow(icon: "location.fill", title: "Адрес",
                        value: "127.0.0.1:\(tunnel.port)", mono: true)
                Button {
                    revealSecret.toggle()
                } label: {
                    InfoRow(icon: "key.fill", title: "Секрет",
                            value: revealSecret ? fullSecret : "dd…dd",
                            mono: true, accent: revealSecret)
                }
                .buttonStyle(SqueezeButtonStyle(scale: 0.99))
                if tunnel.isRunning {
                    InfoRow(icon: "gauge", title: "Пинг реле",
                            value: tunnel.relayPingText,
                            mono: true,
                            tint: pingTint)
                }
                if tunnel.wsFallbackActive {
                    InfoRow(icon: "globe", title: "Транспорт",
                            value: "WebSocket · kws Telegram DC", accent: true)
                } else if !tunnel.isRunning {
                    InfoRow(icon: "bolt.badge.clock", title: "Реле",
                            value: "лучший MTProto / FakeTLS")
                }
            }
            .padding(.horizontal, 14)

            HStack(spacing: 10) {
                Button {
                    UIPasteboard.general.string = tunnel.tgURL?.absoluteString ?? ""
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Скопировано" : "Ссылка tg://",
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 13, weight: .heavy))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(AccentButtonStyle())

                Button {
                    if let url = tunnel.tgURL { openURL(url) }
                } label: {
                    Label("В Telegram", systemImage: "paperplane.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(tunnel.isRunning ? AppPalette.accent : .primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(GlassButtonStyle())
            }
            .padding(12)
        }
        .modifier(GlassCard(cornerRadius: 30))
        .padding(.horizontal, 4)
    }
}