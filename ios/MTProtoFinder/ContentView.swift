import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @Environment(\.openURL) private var openURL
    @Environment(\.horizontalSizeClass) private var hSize
    @State private var copied = false

    var body: some View {
        ZStack {
            LiquidBackground()
            VStack(spacing: 14) {
                header
                ModeSwitch(mode: $model.mode)
                proxyList
                StatusChip(text: model.status, busy: model.isSearching)
                if let sel = model.top.first {
                    DockBar(proxy: sel, copied: copied) {
                        copyLink(sel)
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.top, 8)
            .padding(.bottom, 6)
            .frame(maxWidth: 640)
            .frame(maxWidth: .infinity)
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
                    .background(
                        LinearGradient(colors: [AppPalette.graphiteLight,
                                                 AppPalette.graphite],
                                       startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .clipShape(Circle())
                    .overlay(Circle().strokeBorder(AppPalette.accent.opacity(0.55), lineWidth: 1.5))
                VStack(alignment: .leading, spacing: 0) {
                    Text("MTProto Finder").font(.system(size: 18, weight: .heavy))
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

    private var columns: [GridItem] {
        let count = hSize == .regular ? 3 : 2
        return Array(repeating: GridItem(.flexible(), spacing: 10), count: count)
    }

    private var proxyList: some View {
        ScrollView {
            if model.top.isEmpty {
                ContentUnavailableView(
                    "Загрузка…",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text("Получение списков и проверка пинга")
                )
                .frame(minHeight: 300)
            } else {
                LazyVGrid(columns: columns, spacing: 10) {
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