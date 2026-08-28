import Foundation

let AUTHOR_URL = "https://t.me/yetilov"
let MAX_SERVERS = 30
let SOURCES = ["https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json", "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt"]
let SOCKS_SOURCES = ["https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt", "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt"]

struct Proxy: Identifiable {
    let id = UUID()
    let host: String
    let port: Int
    let secret: String
    let proto: String
    var ping: Double = -1
    var tgURL: URL? {
        if proto == "socks5" { return URL(string: "tg://socks?server=\(host)&port=\(port)") }
        return URL(string: "tg://proxy?server=\(host)&port=\(port)&secret=\(secret)")
    }
    var pingText: String {
        if ping > 0 { return String(format: "%.0f мс", ping) }
        if ping == -2 { return "✖" }
        return "…"
    }
    var pingColor: Color {
        if ping > 0 && ping < 150 { return .green }
        if ping >= 150 && ping < 400 { return .yellow }
        if ping >= 400 { return .red }
        return .secondary
    }
}

@MainActor
final class ProxyModel: ObservableObject {
    @Published var top: [Proxy] = []
    @Published var status = "Готов"
    @Published var mode = "mtproto"
    private var all: [Proxy] = []
    private var pingTask: Task<Void, Never>?

    func start() async {
        status = "🔍 Поиск прокси…"
        all = await Self.fetchAll()
        status = "Найдено \(all.count) прокси, измеряю пинг…"
        refresh()
        pingTask = Task { await pingLoop() }
    }

    private func pingLoop() async {
        while !Task.isCancelled {
            let targets = Array(pool().prefix(120))
            await withTaskGroup(of: Void.self) { group in
                for p in targets {
                    group.addTask {
                        let ms = await Self.tcpPing(host: p.host, port: p.port)
                        await MainActor.run {
                            if let i = self.all.firstIndex(where: { $0.id == p.id }) {
                                self.all[i].ping = ms
                            }
                        }
                    }
                }
            }
            refresh()
            try? await Task.sleep(nanoseconds: 5_000_000_000)
        }
    }

    func pool() -> [Proxy] {
        all.filter { $0.proto == mode }
    }

    func refresh() {
        let pl = pool()
        let alive = pl.filter { $0.ping > 0 }.sorted { $0.ping < $1.ping }
        let un = pl.filter { $0.ping == -1 }
        let dead = pl.filter { $0.ping == -2 }
        top = Array((alive + un + dead).prefix(MAX_SERVERS))
        let live = alive.count
        status = live > 0 ? "✅ Рабочих: \(live) · топ \(min(live, MAX_SERVERS))" : "📶 Измеряю пинг…"
    }

    static func fetchAll() async -> [Proxy] {
        var result: [Proxy] = []
        var seen = Set<String>()
        let linkRegex = try! NSRegularExpression(pattern: "(server|port|secret)=([^&\\s]+)")
        for url in SOURCES {
            guard let (data, _) = try? await URLSession.shared.data(from: URL(string: url)!) else { continue }
            let text = String(decoding: data, as: UTF8.self)
            for lineRaw in text.split(separator: "\n") {
                let line = String(lineRaw)
                var d: [String: String] = [:]
                for m in linkRegex.matches(in: line, range: NSRange(line.startIndex..., in: line)) {
                    if let k = Range(m.range(at: 1), in: line), let v = Range(m.range(at: 2), in: line) {
                        d[String(line[k])] = String(line[v]).removingPercentEncoding ?? ""
                    }
                }
                if let h = d["server"], let p = d["port"], let sec = d["secret"], let port = Int(p), !h.isEmpty, !sec.isEmpty {
                    let host = h.hasSuffix(".") ? String(h.dropLast()) : h
                    if seen.insert("\(host):\(port)").inserted {
                        result.append(Proxy(host: host, port: port, secret: sec, proto: "mtproto"))
                    }
                }
            }
        }
        for url in SOCKS_SOURCES {
            guard let (data, _) = try? await URLSession.shared.data(from: URL(string: url)!) else { continue }
            let text = String(decoding: data, as: UTF8.self)
            for lineRaw in text.split(separator: "\n").prefix(800) {
                let parts = lineRaw.split(separator: ":")
                if parts.count == 2, let port = Int(parts[1]), !parts[0].isEmpty {
                    let host = String(parts[0])
                    if seen.insert("\(host):\(port)").inserted {
                        result.append(Proxy(host: host, port: port, secret: "", proto: "socks5"))
                    }
                }
            }
        }
        return result
    }

    static func tcpPing(host: String, port: Int) async -> Double {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                let start = Date()
                let sock = socket(AF_INET, SOCK_STREAM, 0)
                guard sock >= 0 else { cont.resume(returning: -2); return }
                var addr = sockaddr_in()
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = UInt16(port).bigEndian
                if inet_pton(AF_INET, host, &addr.sin_addr) != 1 {
                    var hints = addrinfo()
                    hints.ai_family = AF_INET
                    hints.ai_socktype = SOCK_STREAM
                    var list: UnsafeMutablePointer<addrinfo>? = nil
                    guard getaddrinfo(host, nil, &hints, &list) == 0, let first = list else {
                        close(sock); cont.resume(returning: -2); return
                    }
                    first.pointee.ai_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                        addr.sin_addr = p.pointee.sin_addr
                    }
                    freeaddrinfo(list)
                }
                _ = fcntl(sock, F_SETFL, O_NONBLOCK)
                let connectResult = withUnsafePointer(to: addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if connectResult == 0 {
                    close(sock)
                    cont.resume(returning: Date().timeIntervalSince(start) * 1000)
                    return
                }
                var fds = fd_set()
                fds.fds_bits.0 = Int32(1 << (sock % 32))
                var tv = timeval(tv_sec: 2, tv_usec: 0)
                let sel = withUnsafeMutablePointer(to: &fds) {
                    select(sock + 1, nil, $0, nil, &tv)
                }
                close(sock)
                cont.resume(returning: sel > 0 ? Date().timeIntervalSince(start) * 1000 : -2)
            }
        }
    }                }
                let nonblocking = fcntl(sock, F_SETFL, O_NONBLOCK)
                _ = nonblocking
                let connectResult = withUnsafePointer(to: addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if connectResult == 0 {
                    close(sock)
                    cont.resume(returning: Date().timeIntervalSince(start) * 1000)
                    return
                }
                var fdset = fd_set()
                withUnsafeMutablePointer(to: &fdset) { $0.pointee.__fds_bits.0 = 0 }
                fdset.__fds_bits.0 = Int(clamping: 1 << sock % 32)
                _ = fdset
                var fds = fd_set()
                fds.fds_bits.0 = Int32(1 << (sock % 32))
                var tv = timeval(tv_sec: 2, tv_usec: 0)
                let sel = withUnsafeMutablePointer(to: &fds) {
                    select(sock + 1, nil, $0, nil, &tv)
                }
                close(sock)
                if sel > 0 {
                    cont.resume(returning: Date().timeIntervalSince(start) * 1000)
                } else {
                    cont.resume(returning: -2)
                }
            }
        }
    }
}
