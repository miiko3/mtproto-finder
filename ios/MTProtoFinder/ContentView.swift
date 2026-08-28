import SwiftUI

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("⚡ MTProto Finder").font(.title3.bold())
                Text("v0.pa1t").font(.caption2.bold()).padding(.horizontal, 8).padding(.vertical, 3).background(Color.white.opacity(0.08)).cornerRadius(8)
                Spacer()
                Link(destination: URL(string: AUTHOR_URL)!) {
                    Text("👤 @yetilov").font(.footnote.bold())
                }
            }.padding()
            Picker("Тип", selection: $model.mode) {
                Text("MTPROTO").tag("mtproto")
                Text("SOCKS5").tag("socks5")
            }.pickerStyle(.segmented).padding(.horizontal)
            List(model.top) { p in
                HStack {
                    Text(p.host).font(.subheadline.bold()).lineLimit(1)
                    Spacer()
                    Text(p.pingText).font(.subheadline.bold()).foregroundColor(p.pingColor)
                }
            }.listStyle(.plain)
            Text(model.status).font(.caption).foregroundColor(.secondary).padding(.vertical, 4)
            Text("Уважаемые (будущие/нынешние) пользователи (тестировщики).\nЕсли приложение не отдает пинг (не показывает его) на GitHub пуште баг с подробным описанием проблемы, или пишите в Телеграм указанный в правом углу приложения.")
                .font(.caption2).foregroundColor(.secondary)
                .padding(12).background(Color.white.opacity(0.05)).cornerRadius(12).padding(.horizontal).padding(.bottom, 8)
        }
        .preferredColorScheme(.dark)
        .onTapGesture {}
        .task { await model.start() }
    }
}
