import SwiftUI
import UIKit

enum MainTab: String, CaseIterable, Identifiable, Hashable {
    case proxies
    case local

    var id: String { rawValue }

    var label: String {
        switch self {
        case .proxies: return "Прокси"
        case .local: return "Локальный"
        }
    }

    var icon: String {
        switch self {
        case .proxies: return "antenna.radiowaves.left.and.right"
        case .local: return "bolt.horizontal.circle"
        }
    }
}

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @State private var tab = MainTab.proxies
    @State private var copied = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        ZStack {
            LiquidBackground()
            switch tab {
            case .proxies: ProxiesTab(model: model)
            case .local: LocalProxyTab(model: model)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            bottomBar
        }
        .preferredColorScheme(.dark)
        .task { await model.start() }
    }

    private var bottomBar: some View {
        VStack(spacing: 10) {
            if tab == .proxies, let sel = model.top.first {
                DockBar(proxy: sel, copied: copied) { copyLink(sel) }
                    .frame(maxWidth: 680)
            }
            GlassTabBar(selection: $tab)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }

    private func copyLink(_ proxy: Proxy) {
        UIPasteboard.general.string = proxy.tgURL?.absoluteString ?? ""
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    }
}

// MARK: - Адаптивная раскладка (общая для вкладок)

private enum Layout {
    static func columns(_ width: CGFloat) -> Int {
        if width >= 700 { return 3 }
        if width >= 390 { return 2 }
        return 1
    }

    static func insets(_ width: CGFloat) -> CGFloat {
        width >= 700 ? 26 : 14
    }
}

// MARK: - Вкладка «Прокси»

struct ProxiesTab: View {
    @ObservedObject var model: ProxyModel
    @Environment(\.openURL) private var openURL

    var body: some View {
        GeometryReader { geo in
            ScrollView {
                VStack(spacing: 13) {
                    AppHeader(cryptoOK: model.cryptoOK)
                    ModeSwitch(mode: $model.mode)
                    proxyList(columns: Layout.columns(geo.size.width))
                    StatusChip(text: model.status, busy: model.isSearching)
                }
                .padding(.horizontal, Layout.insets(geo.size.width))
                .padding(.top, 8)
                .padding(.bottom, 24)
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
        }
    }

    private func proxyList(columns: Int) -> some View {
        Group {
            if model.top.isEmpty {
                ContentUnavailableView(
                    "Загрузка…",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text("Получение списков и проверка пинга")
                )
                .frame(minHeight: 240)
            } else {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12),
                                         count: max(1, columns)), spacing: 12) {
                    ForEach(model.top) { proxy in
                        ProxyCard(proxy: proxy) {
                            if let url = proxy.tgURL { openURL(url) }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Вкладка «Локальный прокси»

struct LocalProxyTab: View {
    @ObservedObject var model: ProxyModel

    var body: some View {
        GeometryReader { geo in
            ScrollView {
                VStack(spacing: 14) {
                    AppHeader(cryptoOK: model.cryptoOK,
                              title: "Локальный прокси",
                              showAuthor: false)
                    TunnelCard(tunnel: model.tunnel)
                    GuideCard(tunnel: model.tunnel)
                    tunnelStatus(tunnel: model.tunnel)
                }
                .padding(.horizontal, Layout.insets(geo.size.width))
                .padding(.top, 8)
                .padding(.bottom, 24)
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
        }
    }

    private func tunnelStatus(tunnel: BridgeTunnel) -> some View {
        VStack(spacing: 0) {
            InfoRow(icon: "arrow.triangle.2.circlepath", title: "Реле",
                    value: tunnel.wsFallbackActive
                        ? "WebSocket · kws Telegram DC"
                        : (tunnel.isRunning && !tunnel.relayEndpoint.isEmpty
                            ? tunnel.relayEndpoint
                            : (tunnel.isRunning ? "выбор лучшего сервера…" : tunnel.detail)),
                    mono: true, accent: tunnel.isRunning || tunnel.wsFallbackActive)
        }
        .padding(.horizontal, 14)
        .modifier(GlassCard(cornerRadius: 26))
        .padding(.horizontal, 2)
    }
}