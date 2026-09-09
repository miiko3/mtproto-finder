import SwiftUI
import UIKit

// MARK: - Glass primitives

struct GlassCard: ViewModifier {
    var cornerRadius: CGFloat = 27
    func body(content: Content) -> some View {
        content.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
    }
}

struct GlassButton: ViewModifier {
    var prominent = false
    func body(content: Content) -> some View {
        content.buttonStyle(prominent ? .glassProminent : .glass)
    }
}

// MARK: - Aurora background

struct LiquidBackground: View {
    @State private var animating = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.14, green: 0.12, blue: 0.19),
                         Color(red: 0.09, green: 0.11, blue: 0.17),
                         Color(red: 0.08, green: 0.09, blue: 0.14)],
                startPoint: .top, endPoint: .bottom
            )
            orbs
        }
        .ignoresSafeArea()
        .onAppear {
            withAnimation(.easeInOut(duration: 14).repeatForever(autoreverses: true)) {
                animating = true
            }
        }
    }

    private var orbs: some View {
        ZStack {
            orb(Color(red: 0.62, green: 0.30, blue: 0.85).opacity(0.45), radius: 190,
                offset: animating ? CGSize(width: 150, height: -180) : CGSize(width: -130, height: 130))
            orb(Color(red: 0.18, green: 0.75, blue: 0.78).opacity(0.30), radius: 220,
                offset: animating ? CGSize(width: -170, height: 160) : CGSize(width: 150, height: -150))
            orb(Color(red: 0.95, green: 0.40, blue: 0.55).opacity(0.28), radius: 170,
                offset: animating ? CGSize(width: 60, height: 100) : CGSize(width: -90, height: -70))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func orb(_ color: Color, radius: CGFloat, offset: CGSize) -> some View {
        Circle()
            .fill(color)
            .frame(width: radius * 2, height: radius * 2)
            .blur(radius: radius * 0.85)
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
        if proxy.isGood { return Color(red: 0.22, green: 0.92, blue: 0.48) }
        if proxy.isMid { return Color(red: 0.98, green: 0.85, blue: 0.12) }
        if proxy.isBad { return Color(red: 1.0, green: 0.34, blue: 0.40) }
        if proxy.ping == -1 { return Color.white.opacity(0.45) }
        return Color.secondary.opacity(0.6)
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
                        .foregroundColor(.secondary)
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
        .buttonStyle(.plain)
    }
}

// MARK: - Mode picker

struct ProxyModePicker: View {
    @Binding var mode: String
    @Namespace private var pill

    private let items = [("mtproto", "MTProto"), ("socks5", "SOCKS5")]

    var body: some View {
        HStack(spacing: 4) {
            ForEach(items, id: \.0) { key, label in
                Button {
                    withAnimation(.snappy(duration: 0.28)) { mode = key }
                } label: {
                    Text(label)
                        .font(.system(size: 13, weight: .heavy))
                        .foregroundColor(mode == key ? .primary : Color.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background {
                            if mode == key {
                                Capsule()
                                    .fill(.white.opacity(0.16))
                                    .matchedGeometryEffect(id: "pill", in: pill)
                            }
                        }
                }
                .buttonStyle(.plain)
            }
        }
        .padding(4)
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
                .foregroundColor(.secondary)
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
                Label(proxy.endpoint, systemImage: proxy.proto == "socks5" ? "network" : "bolt.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                Spacer()
                if !proxy.valid {
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
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                }
                .modifier(GlassButton(prominent: true))

                Button {
                    onCopy()
                } label: {
                    Label(copied ? "Скопировано" : "Ссылка", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 14, weight: .bold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                }
                .modifier(GlassButton())
            }
            .foregroundColor(.primary)
        }
        .padding(12)
        .modifier(GlassCard(cornerRadius: 30))
        .padding(.horizontal, 4)
    }
}