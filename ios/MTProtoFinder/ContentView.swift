import SwiftUI
import UIKit

struct GlassCard: ViewModifier {
    var cornerRadius: CGFloat = 27
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            content.background(.ultraThinMaterial, in: .rect(cornerRadius: cornerRadius))
        }
    }
}

struct GlassButton: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.buttonStyle(.glass)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}

struct ProxyBadge: View {
    let proxy: Proxy
    var body: some View {
        Text(proxy.pingText)
            .font(.caption.weight(.heavy))
            .monospacedDigit()
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(badgeColor.opacity(0.85))
            .foregroundColor(badgeText)
            .clipShape(Capsule())
    }

    private var badgeColor: Color {
        if proxy.isGood { return Color(red: 0.43, green: 0.56, blue: 0.49) }
        if proxy.isMid { return Color(red: 0.60, green: 0.48, blue: 0.36) }
        if proxy.isBad { return Color(red: 0.60, green: 0.31, blue: 0.38) }
        return Color.white.opacity(0.14)
    }

    private var badgeText: Color {
        if proxy.isGood { return Color(red: 0.17, green: 0.88, blue: 0.37) }
        if proxy.isMid { return Color(red: 0.96, green: 0.85, blue: 0.03) }
        if proxy.isBad { return Color(red: 1.0, green: 0.26, blue: 0.32) }
        return Color.white.opacity(0.55)
    }
}

struct ProxyCard: View {
    let proxy: Proxy
    @Environment(\.openURL) private var openURL

    var body: some View {
        Button {
            if let url = proxy.tgURL { openURL(url) }
        } label: {
            HStack {
                Text(proxy.endpoint)
                    .font(.system(size: 15, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                    .foregroundColor(.primary)
                Spacer()
                ProxyBadge(proxy: proxy)
            }
            .padding(.leading, 18)
            .padding(.trailing, 10)
            .frame(height: 54)
            .modifier(GlassCard(cornerRadius: 27))
        }
        .buttonStyle(.plain)
    }
}

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @Environment(\.openURL) private var openURL
    @State private var copied = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.48, green: 0.37, blue: 0.49),
                         Color(red: 0.41, green: 0.29, blue: 0.42),
                         Color(red: 0.36, green: 0.22, blue: 0.36)],
                startPoint: .top, endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 12) {
                header
                Picker("Тип", selection: $model.mode) {
                    Text("MTProto").tag("mtproto")
                    Text("SOCKS5").tag("socks5")
                }
                .pickerStyle(.segmented)
                .frame(width: 260)
                .tint(.white)

                ScrollView {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                        ForEach(model.top) { proxy in
                            ProxyCard(proxy: proxy)
                        }
                    }
                    .padding(.horizontal, 2)
                }

                Text(model.status)
                    .font(.caption2.weight(.semibold))
                    .foregroundColor(.white.opacity(0.55))

                if let selected = model.top.first {
                    dock(selected)
                }
            }
            .padding(.horizontal, 14)
            .padding(.top, 8)
            .padding(.bottom, 6)
        }
        .preferredColorScheme(.dark)
        .task { await model.start() }
    }

    private var header: some View {
        HStack {
            HStack(spacing: 12) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 22, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 56, height: 56)
                    .background(LinearGradient(colors: [Color(red: 0.88, green: 0.33, blue: 0.62), Color(red: 0.56, green: 0.18, blue: 0.38)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .clipShape(Circle())
                VStack(alignment: .leading, spacing: 0) {
                    Text("MTProto Finder")
                        .font(.system(size: 18, weight: .heavy))
                        .foregroundColor(.primary)
                    Text(APP_VERSION)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.leading, 10)
            .padding(.trailing, 20)
            .padding(.vertical, 9)
            .modifier(GlassCard(cornerRadius: 32))
            Spacer()
            Link(destination: URL(string: AUTHOR_URL)!) {
                Image(systemName: "paperplane.fill")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 48, height: 48)
                    .modifier(GlassCard(cornerRadius: 24))
            }
        }
    }

    private func dock(_ proxy: Proxy) -> some View {
        HStack(spacing: 10) {
            Button {
                if let url = proxy.tgURL { openURL(url) }
            } label: {
                Text("Подключиться")
                    .font(.system(size: 14, weight: .heavy))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
            }
            .modifier(GlassButton())

            Button {
                UIPasteboard.general.string = proxy.tgURL?.absoluteString ?? ""
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Text(copied ? "Скопировано" : "Ссылка")
                    .font(.system(size: 14, weight: .bold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
            }
            .modifier(GlassButton())
        }
        .modifier(GlassCard(cornerRadius: 28))
        .padding(8)
        .foregroundColor(.primary)
    }
}
