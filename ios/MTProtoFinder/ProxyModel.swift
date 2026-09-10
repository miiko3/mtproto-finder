import Foundation
import Network

let AUTHOR_URL = "https://t.me/miiko3"
let APP_VERSION = "1.0.2"
let MAX_SERVERS = 32
let MT_SOURCES = [
    "https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/proxies.json",
    "https://cdn.jsdelivr.net/gh/ALIILAPRO/MTProtoProxy@main/mtproto.txt",
    "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/MTProto.txt",
    "https://cdn.jsdelivr.net/gh/MhdiTaheri/ProxyCollector@main/proxy.txt",
    "https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt",
    "https://cdn.jsdelivr.net/gh/Chumbayoumba/free-telegram-proxy-russia-2026@main/proxy-list.txt",
    "https://cdn.jsdelivr.net/gh/horizonpaz-create/mtproto-live@main/mtproto.txt"
]
let SOCKS_SOURCES = [
    "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
    "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/SOCKS5_RAW.txt",
    "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/socks5.txt",
    "https://cdn.jsdelivr.net/gh/casals-ar/proxy-list@main/socks5",
    "https://cdn.jsdelivr.net/gh/ShiftyTR/Proxy-List@master/socks5.txt",
    "https://cdn.jsdelivr.net/gh/Argh94/Proxy-List@main/SOCKS5.txt"
]

struct Proxy: Identifiable {
    let id = UUID()
    let host: String
    let port: Int
    let secret: String
    let proto: String
    var ping: Double = -1    // -1 in progress, -2 failed, >0 elapsed ms
    var valid: Bool = false
    var note: String = ""

    var endpoint: String { "\(host):\(port)" }

    var tgURL: URL? {
        if proto == "socks5" { return URL(string: "tg://socks?server=\(host)&port=\(port)") }
        return URL(string: "tg://proxy?server=\(host)&port=\(port)&secret=\(secret)")
    }

    var pingText: String {
        if valid && ping > 0 { return String(format: "%.0f ms", ping) }
        if ping == -2 { return "—" }
        if ping > 0 { return "✖" }
        return "…"
    }

    var isGood: Bool { valid && ping > 0 && ping < 300 }
    var isMid: Bool { valid && ping >= 300 && ping < 1000 }
    var isBad: Bool { valid && ping >= 1000 }
}

@MainActor
final class ProxyModel: ObservableObject {
    @Published var top: [Proxy] = []
    @Published var status = "Готов"
    @Published var mode = "mtproto"
    @Published var isSearching = false
    @Published var cryptoOK: Bool?
    let tunnel = BridgeTunnel(pick: { nil })
    private var all: [Proxy] = []
    private var pingTask: Task<Void, Never>?

    func start() async {
        let check = CipherCheck.run()
        cryptoOK = check.ok
        if !check.ok {
            status = "Шифр: сбой — туннель не включится"
        }
        tunnel.setPicker { [weak self] in self?.bestBridgeServer() }
        status = "Поиск прокси…"
        isSearching = true
        all = await Self.fetchAll()
        status = "Найдено \(all.count) прокси, проверяю пинг…"
        refresh()
        pingTask = Task { await pingLoop() }
    }

    func restart() {
        pingTask?.cancel()
        pingTask = nil
        all = []
        top = []
        status = "Поиск прокси…"
        isSearching = true
        Task { await start() }
    }

    func pool() -> [Proxy] {
        all.filter { $0.proto == mode }
    }

    /// Лучший рабочий MTProto-сервер для реле туннеля (пул не зависит от mode).
    func bestBridgeServer() -> Proxy? {
        all.filter { $0.proto == "mtproto" && $0.valid && $0.ping > 0 }
            .min { $0.ping < $1.ping }
    }

    private func pingLoop() async {
        while !Task.isCancelled {
            let pl = pool()
            let untested = pl.filter { $0.ping == -1 }
            let alive = pl.filter { $0.valid && $0.ping > 0 }
            let targets: [Proxy]
            if alive.count >= 10 || untested.isEmpty {
                targets = Array((alive + pl.filter { $0.ping != -1 }).prefix(MAX_SERVERS))
            } else {
                targets = Array(untested.prefix(48))
            }
            await MainActor.run { self.isSearching = !untested.isEmpty }
            await withTaskGroup(of: Void.self) { group in
                for p in targets {
                    group.addTask {
                        let r = await Self.probe(p)
                        await MainActor.run {
                            if let i = self.all.firstIndex(where: { $0.id == p.id }) {
                                self.all[i].ping = r.0
                                self.all[i].valid = r.1
                                self.all[i].note = r.2
                            }
                        }
                    }
                }
            }
            refresh()
            try? await Task.sleep(nanoseconds: 6_000_000_000)
        }
    }

    func refresh() {
        let pl = pool()
        let valid = pl.filter { $0.valid && $0.ping > 0 }.sorted { $0.ping < $1.ping }
        let un = pl.filter { $0.ping == -1 }
        let dead = pl.filter { !($0.valid && $0.ping > 0) && $0.ping != -1 }
        top = Array((valid + un + dead).prefix(MAX_SERVERS))
        let live = valid.count
        if live > 0 {
            status = "Рабочих прокси: \(live) · проверено \(top.count)"
        } else if un.isEmpty {
            status = "Живых прокси не найдено"
        } else {
            status = "Проверяю пинг… осталось \(un.count)"
        }
    }

    // MARK: - Parsing

    static func normalize(_ sec: String) -> String? {
        let s = sec.trimmingCharacters(in: .whitespaces)
        if s.count >= 32, s.allSatisfy({ $0.isHexDigit }) { return s.lowercased() }
        return nil
    }

    static func fetchAll() async -> [Proxy] {
        var result: [Proxy] = []
        var seen = Set<String>()
        let linkRegex = try! NSRegularExpression(pattern: "(server|port|secret)=([^&\\s]+)")
        for url in MT_SOURCES {
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
                if let h = d["server"], let p = d["port"], let port = Int(p),
                   let sec = normalize(d["secret"] ?? "") {
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
            for lineRaw in text.split(separator: "\n").prefix(2000) {
                var s = String(lineRaw).trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("#") { continue }
                if let rng = s.range(of: "socks5://") { s = String(s[rng.upperBound...]) }
                if let rng = s.range(of: "socks://") { s = String(s[rng.upperBound...]) }
                let parts = s.split(separator: ":")
                if parts.count >= 2, let port = Int(parts[1]) {
                    let host = String(parts[0])
                    if seen.insert("\(host):\(port)").inserted {
                        result.append(Proxy(host: host, port: port, secret: "", proto: "socks5"))
                    }
                }
            }
        }
        return result
    }

    // MARK: - Pings

    static func probe(_ p: Proxy) async -> (Double, Bool, String) {
        if p.proto == "socks5" {
            let (ms, ok) = await socksProbe(host: p.host, port: p.port)
            return (ms, ok, ok ? "SOCKS5 · CONNECT ok" : "")
        }
        let lower = p.secret.lowercased()
        if lower.hasPrefix("ee") {
            for sni in sniCandidates(secret: p.secret, host: p.host) {
                switch await fakeTLSPing(host: p.host, port: p.port, secret: p.secret, sni: sni) {
                case .success(let ms):
                    return (ms, true, "FakeTLS · \(sni) · ResPQ ok")
                case .notMTProto:
                    return (-2.0, false, "")
                case .tlsFailed:
                    continue
                }
            }
            return (-2.0, false, "")
        }
        let (ms, ok) = await deepMTProtoPing(host: p.host, port: p.port, secret: p.secret)
        return (ms, ok, ok ? "MTProto · ResPQ ok" : "")
    }

    static func domainFromSecret(_ sec: String) -> String {
        let h = sec.lowercased()
        guard h.hasPrefix("ee"), h.count >= 36 else { return "www.cloudflare.com" }
        var bytes = [UInt8]()
        let chars = Array(h)
        var i = 34
        while i + 1 < chars.count {
            guard let b = UInt8(String(chars[i...i+1]), radix: 16) else { break }
            bytes.append(b)
            i += 2
        }
        let domain = String(bytes: bytes, encoding: .ascii)?.filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" } ?? ""
        return domain.contains(".") && domain.count >= 4 ? domain : "www.cloudflare.com"
    }

    static func tlsPing(host: String, port: Int, sni: String, timeout: Double = 4.0) async -> Double {
        await withCheckedContinuation { cont in
            let start = Date()
            guard let portV = NWEndpoint.Port(rawValue: UInt16(port)) else {
                cont.resume(returning: -2); return
            }
            let tlsOpts = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tlsOpts.securityProtocolOptions, sni)
            let params = NWParameters(tls: tlsOpts)
            let conn = NWConnection(to: NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: portV), using: params)
            let once = Once()
            let queue = DispatchQueue(label: "mtprotofinder.tls")
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler { [weak conn] in
                once.fire {
                    timer.cancel()
                    cont.resume(returning: -2)
                    conn?.cancel()
                }
            }
            timer.resume()
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    once.fire {
                        timer.cancel()
                        cont.resume(returning: Date().timeIntervalSince(start) * 1000)
                        conn.cancel()
                    }
                case .failed, .cancelled:
                    once.fire {
                        timer.cancel()
                        cont.resume(returning: -2)
                    }
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
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
                var addrCopy = addr
                let connectResult = withUnsafePointer(to: &addrCopy) {
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
                withUnsafeMutablePointer(to: &fds) { $0.pointee.fds_bits.0 = 0 }
                fds.fds_bits.0 = Int32(1 << (sock % 32))
                var tv = timeval(tv_sec: 2, tv_usec: 0)
                let sel = select(sock + 1, nil, &fds, nil, &tv)
                close(sock)
                cont.resume(returning: sel > 0 ? Date().timeIntervalSince(start) * 1000 : -2)
            }
        }
    }

    /// Real SOCKS5 probe: greeting (05 01 00) + CONNECT to the proxy's own
    /// endpoint. Valid only when the server replies 05 00 to both.
    static func socksProbe(host: String, port: Int, timeout: Double = 5.0) async -> (Double, Bool) {
        await withCheckedContinuation { cont in
            guard let portV = NWEndpoint.Port(rawValue: UInt16(port)), portV.rawValue <= 65535 else {
                cont.resume(returning: (-2.0, false)); return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: portV, using: .tcp)
            let queue = DispatchQueue(label: "mtprotofinder.socks")
            let once = Once()
            let start = Date()

            let name = Array(host.utf8)
            guard name.count >= 1, name.count <= 255 else {
                cont.resume(returning: (-2.0, false)); return
            }
            var req = Data([0x05, 0x01, 0x00, 0x03, UInt8(name.count)])
            req.append(contentsOf: name)
            req.append(contentsOf: [UInt8(port >> 8), UInt8(port & 0xFF)])

            func done(_ ms: Double, _ ok: Bool) {
                once.fire {
                    conn.cancel()
                    cont.resume(returning: (ms, ok))
                }
            }

            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler { done(-2.0, false) }
            timer.resume()

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: Data([0x05, 0x01, 0x00]), completion: .contentProcessed { _ in
                        conn.receive(minimumIncompleteLength: 2, maximumLength: 2048) { data, _, _, error in
                            guard let d = data, error == nil, d.count >= 2, d[0] == 0x05, d[1] == 0x00 else {
                                done(-2.0, false); return
                            }
                            conn.send(content: req, completion: .contentProcessed { _ in
                                conn.receive(minimumIncompleteLength: 2, maximumLength: 4096) { data2, _, _, err2 in
                                    guard let d2 = data2, err2 == nil, d2.count >= 2, d2[0] == 0x05, d2[1] == 0x00 else {
                                        done(-2.0, false); return
                                    }
                                    done(Date().timeIntervalSince(start) * 1000, true)
                                }
                            })
                        }
                    })
                case .failed, .cancelled:
                    done(-2.0, false)
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
    }
}

final class Once {
    private let lock = NSLock()
    private var done = false
    func fire(_ f: () -> Void) {
        lock.lock()
        if !done { done = true; lock.unlock(); f() }
        else { lock.unlock() }
    }
}