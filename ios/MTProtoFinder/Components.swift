import SwiftUI
import UIKit

// MARK: - Palette (графит из AppIcon Frame 30.png) + акцент

enum AppPalette {
    static let baseDeep      = Color(red: 0.08, green: 0.08, blue: 0.09)   // #151517
    static let baseMid       = Color(red: 0.12, green: 0.12, blue: 0.13)   // #1F1F21
    static let graphite      = Color(red: 0.36, green: 0.36, blue: 0.36)   // #5C5C5C (avg иконки)
    static let graphiteSoft  = Color(red: 0.44, green: 0.44, blue: 0.44)   // #707070
    static let graphiteLight = Color(red: 0.55, green: 0.55, blue: 0.55)   // #8C8C8C
    static let graphiteFaint = Color(red: 0.72, green: 0.72, blue: 0.72)   // #B8B8B8
    static let accent        = Color(red: 0.04, green: 0.52, blue: 1.00)   // #0A84FF
    static let accentSoft    = Color(red: 0.04, green: 0.52, blue: 1.00).opacity(0.30)
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

// MARK: - Glass primitives

struct GlassCard: ViewModifier {
    var cornerRadius: CGFloat = 28
    func body(content: Content) -> some View {
        content.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
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
            .glassEffect(.regular, in: .capsule)
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
        configuration.label
            .background(
                Capsule().fill(
                    LinearGradient(colors: [AppPalette.accent, AppPalette.accent.opacity(0.80)],
                                   startPoint: .top, endPoint: .bottom)
                )
            )
            .shadow(color: AppPalette.accent.opacity(configuration.isPressed ? 0.12 : 0.45),
                    radius: configuration.isPressed ? 4 : 14, y: configuration.isPressed ? 1 : 4)
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.spring(response: 0.30, dampingFraction: 0.58), value: configuration.isPressed)
    }
}

// MARK: - Graphite background (цвета иконки + лёгкий акцент)

struct LiquidBackground: View {
    @State private var animating = false

    var body: some View {
        ZStack {
            LinearGradient(colors: [AppPalette.baseMid, AppPalette.baseDeep,
                                    Color(red: 0.06, green: 0.06, blue: 0.07)],
                           startPoint: .top, endPoint: .bottom)
            orbs
        }
        .ignoresSafeArea()
        .onAppear {
            withAnimation(.easeInOut(duration: 16).repeatForever(autoreverses: true)) {
                animating = true
            }
        }
    }

    private var orbs: some View {
        ZStack {
            orb(AppPalette.graphiteSoft.opacity(0.32), radius: 210,
                offset: animating ? CGSize(width: 160, height: -210) : CGSize(width: -140, height: 150))
            orb(AppPalette.graphiteLight.opacity(0.16), radius: 250,
                offset: animating ? CGSize(width: -190, height: 190) : CGSize(width: 160, height: -170))
            orb(AppPalette.accent.opacity(0.13), radius: 220,
                offset: animating ? CGSize(width: 90, height: 130) : CGSize(width: -120, height: -90))
            orb(AppPalette.graphite.opacity(0.20), radius: 180,
                offset: animating ? CGSize(width: -70, height: -130) : CGSize(width: 70, height: 90))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func orb(_ color: Color, radius: CGFloat, offset: CGSize) -> some View {
        Circle()
            .fill(color)
            .frame(width: radius * 2, height: radius * 2)
            .blur(radius: radius * 0.95)
            .offset(offset)
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
            Text(proxy.pingText)
                .font(.caption.weight(.heavy))
                .monospacedDigit()
                .foregroundColor(indicatorColor)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 6)
        .glassEffect(.regular, in: .capsule)
    }

    private var indicatorColor: Color {
        if proxy.isGood { return AppPalette.good }
        if proxy.isMid { return AppPalette.mid }
        if proxy.isBad { return AppPalette.bad }
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
                if !proxy.note.isEmpty && proxy.valid {
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

// MARK: - Mode switch (две отдельные кнопки MTProto / SOCKS5)

struct ModeSwitch: View {
    @Binding var mode: String

    private let items: [(key: String, label: String, icon: String)] = [
        ("mtproto", "MTProto", "bolt.fill"),
        ("socks5", "SOCKS5", "network")
    ]

    var body: some View {
        HStack(spacing: 5) {
            ForEach(items, id: \.key) { item in
                Button {
                    withAnimation(.snappy(duration: 0.26)) { mode = item.key }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: item.icon)
                            .font(.system(size: 12, weight: .bold))
                        Text(item.label)
                            .font(.system(size: 13, weight: .heavy))
                    }
                    .foregroundColor(mode == item.key ? .white : AppPalette.graphiteFaint)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(mode == item.key ? Capsule().fill(AppPalette.accent) : nil)
                }
                .buttonStyle(SqueezeButtonStyle(scale: 0.94))
                .if(mode != item.key) { view in
                    view.glassEffect(.regular, in: .capsule)
                }
            }
        }
        .padding(5)
        .modifier(GlassCard(cornerRadius: 999))
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
        .glassEffect(.regular, in: .capsule)
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