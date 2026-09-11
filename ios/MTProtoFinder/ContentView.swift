import SwiftUI
import UIKit

enum MainTab: String, CaseIterable, Identifiable {
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

    var iconActive: String {
        switch self {
        case .proxies: return "antenna.radiowaves.left.and.right.fill"
        case .local: return "bolt.horizontal.circle.fill"
        }
    }
}

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @State private var tab = MainTab.proxies

    var body: some View {
        ZStack {
            LiquidBackground()
            TabView(selection: $tab) {
                ProxiesTab(model: model)
                    .tabItem { Label(MainTab.proxies.label, systemImage: MainTab.proxies.icon) }
                    .tag(MainTab.proxies)
                LocalProxyTab(model: model)
                    .tabItem { Label(MainTab.local.label, systemImage: MainTab.local.icon) }
                    .tag(MainTab.local)
            }
            .tint(AppPalette.accent)
        }
        .preferredColorScheme(.dark)
        .task { await model.start() }
    }
}

// MARK: - Вкладка «Прокси»

struct ProxiesTab: View {
    @ObservedObject var model: ProxyModel
    @Environment(\.openURL) private var openURL
    @State private var copied = false

    var body: some View {
        GeometryReader { geo in
            ScrollView {
                VStack(spacing: 12) {
                    AppHeader(cryptoOK: model.cryptoOK)
                    ModeSwitch(mode: $model.mode)
                    proxyList(columns: gridColumns(geo.size.width))
                    StatusChip(text: model.status, busy: model.isSearching)
                }
                .padding(.horizontal, 14)
                .padding(.top, 8)
                .padding(.bottom, 12)
                .frame(maxWidth: 720)
                .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if let sel = model.top.first {
                    DockBar(proxy: sel, copied: copied) {
                        copyLink(sel)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
            }
        }
    }

    private func gridColumns(_ width: CGFloat) -> Int {
        if width >= 760 { return 3 }
        if width >= 400 { return 2 }
        return 1
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
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10),
                                         count: max(1, columns)), spacing: 10) {
                    ForEach(model.top) { proxy in
                        ProxyCard(proxy: proxy) {
                            if let url = proxy.tgURL { openURL(url) }
                        }
                    }
                }
                .padding(.horizontal, 2)
            }
        }
    }

    private func copyLink(_ proxy: Proxy) {
        UIPasteboard.general.string = proxy.tgURL?.absoluteString ?? ""
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
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
                .padding(.horizontal, 14)
                .padding(.top, 8)
                .padding(.bottom, 16)
                .frame(maxWidth: 720)
                .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
        }
    }

    private func tunnelStatus(tunnel: BridgeTunnel) -> some View {
        VStack(spacing: 0) {
            InfoRow(icon: "arrow.triangle.2.circlepath", title: "Реле",
                    value: tunnel.wsFallbackActive ? "WebSocket · kws" : tunnel.detail,
                    mono: false, accent: tunnel.isRunning)
        }
        .padding(.horizontal, 14)
        .modifier(GlassCard(cornerRadius: 26))
        .padding(.horizontal, 4)
    }
}