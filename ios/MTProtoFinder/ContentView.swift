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

    var body: some View {
        ZStack {
            LiquidBackground()
            Group {
                switch tab {
                case .proxies: ProxiesTab(model: model)
                case .local: LocalProxyTab(model: model)
                }
            }
            .safeAreaInset(edge: .bottom, spacing: 6) {
                GlassTabBar(selection: $tab)
                    .padding(.horizontal, 24)
                    .padding(.top, 6)
                    .padding(.bottom, 2)
            }
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

    private let columns = [GridItem(.adaptive(minimum: 170, maximum: 300), spacing: 12)]

    var body: some View {
        GeometryReader { geo in
            ScrollView {
                VStack(spacing: 13) {
                    AppHeader(cryptoOK: model.cryptoOK)
                    ModeSwitch(mode: $model.mode)
                    proxyList
                    StatusChip(text: model.status, busy: model.isSearching)
                }
                .padding(.horizontal, 14)
                .padding(.top, 8)
                .padding(.bottom, 12)
                .frame(maxWidth: 660)
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

    private var proxyList: some View {
        Group {
            if model.top.isEmpty {
                ContentUnavailableView(
                    "Загрузка…",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text("Получение списков и проверка пинга")
                )
                .frame(minHeight: 240)
            } else {
                LazyVGrid(columns: columns, spacing: 12) {
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
                .frame(maxWidth: 660)
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
        .padding(.horizontal, 4)
    }
}