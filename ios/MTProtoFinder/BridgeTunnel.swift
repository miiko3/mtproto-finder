import Foundation
import Network

// MARK: - Локальный MTProto-туннель (порт localproxy.py LocalBridge)
//
// Приложение поднимает обычный MTProto-прокси на 127.0.0.1:<port> с секретом
// dd…dd. В Telegram достаточно добавить tg://proxy?server=127.0.0.1&port=…
// &secret=dd…dd — каждый клиентский коннект релеится на выбранный рабочий
// MTProto/FakeTLS сервер, а если рабочих серверов нет — напрямую в Telegram
// по WebSocket (kws*.web.telegram.org:443).

enum BridgeUpstreamMode {
    case plainTCP        // обычный MTProto без TLS-обёртки
    case nativeTLS       // FakeTLS: полный TLS по SNI из секрета
    case wrappedRecord   // FakeTLS: ClientHello + обёртка TLS-records
    case webSocket       // напрямую в Telegram через WSS
}

@MainActor
final class BridgeTunnel: ObservableObject {
    static let localSecret = Data(repeating: 0xdd, count: 16)
    static let localSecretHex = "dd" + String(repeating: "d", count: 32)

    @Published var isRunning = false
    @Published var connCount = 0
    @Published var detail = "Локальный туннель выключен"
    @Published var port: UInt16 = 10811
    @Published var wsFallbackActive = false
    @Published var relayPing: Double = -1      // -1 проверка, -2 нет ответа, >0 мс
    @Published var relayEndpoint = ""

    private var relayPinger: Task<Void, Never>?

    var relayPingText: String {
        if wsFallbackActive { return "WebSocket · kws" }
        if relayPing > 0 { return String(format: "%.0f ms", relayPing) }
        if relayPing == -2 { return "нет ответа" }
        return "проверка…"
    }

    /// Вызывается при выборе сервера-реле для каждой новой клиентской сессии.
    func noteBridge(_ proxy: Proxy) {
        relayEndpoint = proxy.endpoint
        relayPing = -1
        startRelayPinger(proxy)
    }

    func resetRelay() {
        relayPinger?.cancel()
        relayPinger = nil
        relayPing = -2
        relayEndpoint = "kws.web.telegram.org:443"
    }

    private func startRelayPinger(_ proxy: Proxy) {
        relayPinger?.cancel()
        relayPinger = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                if self.isRunning {
                    let r = await ProxyModel.probe(proxy)
                    if Task.isCancelled { break }
                    self.relayPing = r.1 ? r.0 : -2
                }
                try? await Task.sleep(nanoseconds: 12_000_000_000)
            }
        }
    }

    private var listener: NWListener?
    nonisolated(unsafe) private var pick: () -> Proxy?
    private var sessions = Set<BridgeSession>()
    nonisolated(unsafe) private static let wsHosts = ["kws1.web.telegram.org", "kws2.web.telegram.org", "kws3.web.telegram.org"]
    nonisolated(unsafe) private static var wsIndex = 0

    var tgURL: URL? {
        URL(string: "tg://proxy?server=127.0.0.1&port=\(port)&secret=\(Self.localSecretHex)")
    }

    init(pick: @escaping () -> Proxy?) {
        self.pick = pick
    }

    func setPicker(_ pick: @escaping () -> Proxy?) {
        self.pick = pick
    }

    nonisolated var currentPicker: () -> Proxy? { pick }

    func start() {
        guard !isRunning else { return }
        if let proxy = currentPicker(), proxy.proto == "mtproto" {
            noteBridge(proxy)
        }
        let portValue = port
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        do {
            guard let portNW = NWEndpoint.Port(rawValue: portValue) else {
                detail = "Некорректный порт \(portValue)"
                return
            }
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: NWEndpoint.Host("127.0.0.1"),
                                                                 port: portNW)
            let nw = try NWListener(using: params, on: portNW)
            listener = nw
            nw.newConnectionHandler = { [weak self] conn in
                DispatchQueue.main.async { self?.accept(conn) }
            }
            nw.stateUpdateHandler = { [weak self] state in
                DispatchQueue.main.async {
                    guard let self else { return }
                    switch state {
                    case .ready:
                        self.isRunning = true
                        self.connCount = 0
                        self.detail = "Готов · 127.0.0.1:\(portValue)"
                    case .failed(let error):
                        self.isRunning = false
                        self.detail = "Ошибка: \(error.localizedDescription)"
                        self.listener = nil
                    case .cancelled:
                        self.isRunning = false
                    default:
                        break
                    }
                }
            }
            nw.start(queue: .global(qos: .utility))
        } catch {
            detail = "Не удалось открыть порт \(portValue): \(error.localizedDescription)"
        }
    }

    func stop() {
        relayPinger?.cancel()
        relayPinger = nil
        relayPing = -1
        listener?.cancel()
        listener = nil
        isRunning = false
        connCount = 0
        detail = "Локальный туннель выключен"
        for s in sessions { s.stop() }
        sessions.removeAll()
    }

    nonisolated static func nextWSHost() -> String {
        let h = wsHosts[wsIndex % wsHosts.count]
        wsIndex += 1
        return h
    }

    private func accept(_ conn: NWConnection) {
        let queue = DispatchQueue(label: "mtprotofinder.bridge-\(UUID().uuidString.prefix(6))")
        let session = BridgeSession(client: conn, tunnel: self, queue: queue)
        sessions.insert(session)
        connCount = sessions.count
        session.run()
    }

    func sessionEnded(_ session: BridgeSession) {
        sessions.remove(session)
        connCount = sessions.count
    }

    // MARK: - TLS record wrap/strip (как localproxy._wrap_records/_strip_records)

    nonisolated static func wrapRecords(_ data: Data) -> Data {
        var out = Data()
        var rest = data
        while !rest.isEmpty {
            let chunk = rest.prefix(16384)
            rest.removeFirst(chunk.count)
            out.append(0x17); out.append(0x03); out.append(0x03)
            out.append(UInt8((chunk.count >> 8) & 0xFF))
            out.append(UInt8(chunk.count & 0xFF))
            out.append(chunk)
        }
        return out
    }

    nonisolated static func stripRecords(_ buf: Data) -> (payload: Data, rest: Data) {
        var out = Data()
        var rest = buf
        while rest.count >= 5 {
            let len = Int(rest[rest.startIndex + 3]) << 8 | Int(rest[rest.startIndex + 4])
            if len <= 0 || len > 18432 {
                return (out, buf)
            }
            if rest.count < 5 + len { break }
            out.append(rest[rest.startIndex + 5 ..< rest.startIndex + 5 + len])
            rest.removeFirst(5 + len)
        }
        return (out, rest)
    }
}

/// Одна клиентская сессия: клиент (Telegram) <-> реле <-> выбранный сервер/WSS.
final class BridgeSession: Hashable {
    static func == (lhs: BridgeSession, rhs: BridgeSession) -> Bool { lhs === rhs }
    func hash(into hasher: inout Hasher) { hasher.combine(ObjectIdentifier(self)) }

    private let client: NWConnection
    private weak var tunnel: BridgeTunnel?
    private let queue: DispatchQueue

    private var upstream: NWConnection?
    private var mode: BridgeUpstreamMode = .plainTCP
    private var nativeReady = false

    private var recvC: ObfCipher!
    private var sendC: ObfCipher!
    private var encU: ObfCipher!
    private var decU: ObfCipher!
    private var pendingHead: Data?

    private var bufFromClient = Data()
    private var bufFromUpstream = Data()
    private var wsPlainBuf = Data()
    private var kwsDecBuf = Data()
    private var wsHeader: Data?
    private var wsAttempts = 0
    private var lastActivity = Date()
    private var idleTimer: DispatchSourceTimer?
    private var stopped = false

    private var tag: [UInt8] = []
    private var dc: UInt16 = 2
    private var framing: ObfFraming = .abridged

    private let tagABRIDGED: [UInt8] = [0xEF, 0xEF, 0xEF, 0xEF]
    private let tagINTERMEDIATE: [UInt8] = [0xEE, 0xEE, 0xEE, 0xEE]
    private let tagSECURE_DD: [UInt8] = [0xDD, 0xDD, 0xDD, 0xDD]
    private static let MAX_WS_BUFFER = 16 << 20

    init(client: NWConnection, tunnel: BridgeTunnel, queue: DispatchQueue) {
        self.client = client
        self.tunnel = tunnel
        self.queue = queue
    }

    func run() {
        self.startIdleWatcher()
        client.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.lastActivity = Date()
                self.receiveFromClient()
            case .failed, .cancelled:
                self.stop()
            default:
                break
            }
        }
        client.start(queue: queue)
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        idleTimer?.cancel()
        idleTimer = nil
        upstream?.cancel()
        upstream = nil
        client.cancel()
        if let tunnel {
            DispatchQueue.main.async { tunnel.sessionEnded(self) }
        }
    }

    private func startIdleWatcher() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 5, repeating: 5)
        t.setEventHandler { [weak self] in
            guard let self, !self.stopped else { return }
            if Date().timeIntervalSince(self.lastActivity) > 25 {
                self.stop()
            }
        }
        idleTimer = t
        t.resume()
    }

    private func touch() {
        lastActivity = Date()
    }

    private func setTunnel(_ body: @escaping @MainActor (BridgeTunnel) -> Void) {
        guard let tunnel else { return }
        Task { @MainActor in body(tunnel) }
    }

    // MARK: - клиент -> заголовок

    private func receiveFromClient() {
        guard !stopped else { return }
        client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self, !self.stopped else { return }
            if let data, !data.isEmpty {
                self.bufFromClient.append(data)
                self.touch()
            }
            if let error { self.stop(); return }
            if self.recvC == nil {
                guard self.bufFromClient.count >= 64 else {
                    self.receiveFromClient()
                    return
                }
                self.headerReady()
            } else {
                if self.mode == .webSocket {
                    self.pumpClientWS()
                } else {
                    self.pumpClient()
                }
                self.receiveFromClient()
            }
        }
    }

    private func headerReady() {
        let head = Data(bufFromClient.prefix(64))
        bufFromClient.removeFirst(64)

        let regionArr = [UInt8](head[head.startIndex + 8 ..< head.startIndex + 56])
        let keys = deriveKeys(region: regionArr, secret: BridgeTunnel.localSecret)
        recvC = ObfCipher(key: keys.fk, iv: keys.fkIV)
        sendC = ObfCipher(key: keys.rk, iv: keys.rkIV)

        let plain = recvC.update(head)
        let plainArr = [UInt8](plain)
        tag = Array(plainArr[56..<60])
        dc = UInt16(plainArr[60]) | UInt16(plainArr[61]) << 8

        guard tag == tagABRIDGED || tag == tagINTERMEDIATE || tag == tagSECURE_DD else {
            stop()
            return
        }
        framing = (tag == tagABRIDGED) ? .abridged : .intermediate

        guard let proxy = tunnel?.currentPicker(), proxy.proto == "mtproto" else {
            fallbackToWS()
            receiveFromClient()
            return
        }
        setTunnel { t in
            t.wsFallbackActive = false
            t.noteBridge(proxy)
            let kind = proxy.secret.lowercased().hasPrefix("ee") ? "FakeTLS" : "MTProto"
            t.detail = "Туннель через \(proxy.endpoint) · \(kind)"
        }
        startUpstream(proxy)
        receiveFromClient()
    }

    private func fallbackToWS() {
        setTunnel { t in
            t.wsFallbackActive = true
            t.resetRelay()
            t.detail = "Рабочих серверов нет — WebSocket-режим (Telegram DC)"
        }
        startWS()
    }

    // MARK: - upstream

    private func makeObf(secretData: Data, dc: UInt16) -> (ObfCipher, ObfCipher, Data)? {
        let dcID = (dc == 0) ? UInt16(2) : dc
        guard var initBytes = obfuscatedInit(tag: tag, dcID: dcID) else { return nil }
        let region = [UInt8](initBytes[8..<56])
        let keys = deriveKeys(region: region, secret: secretData)
        let enc = ObfCipher(key: keys.fk, iv: keys.fkIV)
        let full = enc.update(Data(initBytes))
        let head = Data(initBytes.prefix(56)) + full.dropFirst(56)
        let dec = ObfCipher(key: keys.rk, iv: keys.rkIV)
        return (enc, dec, head)
    }

    private func startUpstream(_ proxy: Proxy) {
        let lower = proxy.secret.lowercased()
        guard let secretData = mtprotoSecretBytes(proxy.secret) else { stop(); return }
        guard let obf = makeObf(secretData: secretData, dc: dc) else { stop(); return }
        encU = obf.0
        decU = obf.1
        pendingHead = obf.2

        if !lower.hasPrefix("ee") {
            mode = .plainTCP
            connect(host: proxy.host, port: proxy.port, tls: false, sni: nil)
        } else {
            let snis = sniCandidates(secret: proxy.secret, host: proxy.host)
            guard let firstSNI = snis.first else { stop(); return }
            mode = .nativeTLS
            connect(host: proxy.host, port: proxy.port, tls: true, sni: firstSNI) { [weak self] rest in
                self?.fallbackWrapped(proxy: proxy,
                                      snis: rest.isEmpty ? Array(snis.dropFirst()) : Array(rest.dropFirst()))
            }
        }
    }

    private func connect(host: String, port: Int, tls: Bool, sni: String?,
                         onFail: (([String]) -> Void)? = nil) {
        guard let portV = NWEndpoint.Port(rawValue: UInt16(port)) else { stop(); return }
        let params: NWParameters
        if tls, let sni {
            let tlsOpts = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tlsOpts.securityProtocolOptions, sni)
            sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, queue)
            params = NWParameters(tls: tlsOpts)
        } else {
            params = .tcp
        }
        let conn = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: portV), using: params)
        upstream = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.touch()
                self.nativeReady = true
                self.upstreamReady()
            case .failed, .cancelled:
                if !self.nativeReady {
                    onFail?([])
                } else {
                    self.stop()
                }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func upstreamReady() {
        guard let head = pendingHead, let up = upstream else { stop(); return }
        pendingHead = nil
        up.send(content: head, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil {
                self.stop()
                return
            }
            self.startRelay(leftover: Data())
        })
    }

    // Fallback для ee-серверов, не умеющих полный TLS: ClientHello + TLS-records
    private func fallbackWrapped(proxy: Proxy, snis: [String]) {
        guard !snis.isEmpty, !stopped else {
            if snis.isEmpty { stop() }
            return
        }
        let sni = snis.first!
        let rest = Array(snis.dropFirst())
        mode = .wrappedRecord
        guard let portV = NWEndpoint.Port(rawValue: UInt16(proxy.port)) else { stop(); return }
        let conn = NWConnection(host: NWEndpoint.Host(proxy.host), port: portV, using: .tcp)
        upstream?.cancel()
        upstream = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.sendClientHello(conn, sni: sni, rest: rest)
            case .failed, .cancelled:
                self.fallbackWrapped(proxy: proxy, snis: rest)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func sendClientHello(_ conn: NWConnection, sni: String, rest: [String]) {
        touch()
        let hello = tlsClientHello(host: sni)
        conn.send(content: hello, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil {
                self.retryWrapped(conn, sni: sni, rest: rest)
                return
            }
            self.drainClientHelloReply(conn, sni: sni, rest: rest, buf: Data())
        })
    }

    private func retryWrapped(_ conn: NWConnection, sni: String, rest: [String]) {
        conn.cancel()
        if let p = tunnel?.currentPicker(), !p.secret.isEmpty, !rest.isEmpty {
            fallbackWrapped(proxy: p, snis: rest)
        } else {
            stop()
        }
    }

    private func drainClientHelloReply(_ conn: NWConnection, sni: String, rest: [String], buf: Data) {
        guard !stopped else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.touch()
                var b = buf
                b.append(data)
                if b.count >= 5, b[b.startIndex] == 0x16 {
                    let recLen = Int(b[b.startIndex + 3]) << 8 | Int(b[b.startIndex + 4])
                    if recLen > 0, recLen <= 18432, b.count >= 5 + recLen {
                        let stripped = BridgeTunnel.stripRecords(b)
                        self.wrappedRelayReady(conn: conn, leftover: stripped.rest)
                        return
                    }
                }
                if b.count > 4096 || b.first != 0x16 {
                    self.retryWrapped(conn, sni: sni, rest: rest)
                    return
                }
                self.drainClientHelloReply(conn, sni: sni, rest: rest, buf: b)
            } else if let error {
                self.retryWrapped(conn, sni: sni, rest: rest)
            } else {
                self.stop()
            }
        }
    }

    private func wrappedRelayReady(conn: NWConnection, leftover: Data) {
        guard let head = pendingHead else { stop(); return }
        pendingHead = nil
        let wrapped = BridgeTunnel.wrapRecords(head)
        conn.send(content: wrapped, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil {
                self.stop()
                return
            }
            self.bufFromUpstream = leftover
            self.startRelay(leftover: leftover)
        })
    }

    // MARK: - WebSocket (Telegram DC напрямую)

    private func startWS() {
        wsAttempts += 1
        guard !stopped, wsAttempts <= 6 else { stop(); return }
        let host = BridgeTunnel.nextWSHost()
        // Новое обф-сессии к kws: обычный MTProto-транспорт (abridged, без секрета),
        // как у прямых подключений к DC. Потоки re-encrypt'ятся отдельно от клиента.
        guard let initK = obfuscatedInit(tag: tagABRIDGED, dcID: 2) else { stop(); return }
        let regionK = [UInt8](initK[8..<56])
        let keysK = deriveKeys(region: regionK, secret: Data())
        encU = ObfCipher(key: keysK.fk, iv: keysK.fkIV)
        decU = ObfCipher(key: keysK.rk, iv: keysK.rkIV)
        var initData = Data(initK)
        let encHeader = encU.update(initData)
        wsHeader = Data(initData.prefix(56)) + encHeader.dropFirst(56)

        mode = .webSocket
        kwsDecBuf = Data()
        let portV = NWEndpoint.Port(rawValue: 443)!
        let tlsOpts = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOpts.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
            complete(true)
        }, queue)
        let conn = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: portV),
                                using: NWParameters(tls: tlsOpts))
        upstream = conn
        conn.stateUpdateHandler = { [weak self] (state: NWConnection.State) in
            guard let self else { return }
            switch state {
            case .ready:
                self.sendWSUpgrade(conn, host: host)
            case .failed, .cancelled:
                if !self.stopped && self.mode == .webSocket {
                    self.startWS()
                }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func sendWSUpgrade(_ conn: NWConnection, host: String) {
        touch()
        let keyData = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let key = Data(keyData).base64EncodedString()
        let req = """
        GET /telegram HTTP/1.1\r
        Host: \(host)\r
        Upgrade: websocket\r
        Connection: Upgrade\r
        Sec-WebSocket-Key: \(key)\r
        Sec-WebSocket-Version: 13\r
        \r
        """
        conn.send(content: Data(req.utf8), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil { self.startWS(); return }
            self.readWSUpgradeReply(conn, host: host, buf: Data())
        })
    }

    private func readWSUpgradeReply(_ conn: NWConnection, host: String, buf: Data) {
        guard !stopped else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self else { return }
            guard let data, !data.isEmpty else {
                if error != nil { self.startWS() } else { self.stop() }
                return
            }
            var b = buf
            b.append(data)
            if let crlf = b.range(of: Data("\r\n\r\n".utf8)) {
                let statusLine = String(data: b[b.startIndex ..< b.startIndex + min(64, b.count)], encoding: .utf8) ?? ""
                guard statusLine.contains(" 101") else {
                    self.startWS()
                    return
                }
                let afterStart = crlf.lowerBound + 4
                if afterStart < b.endIndex {
                    self.bufFromUpstream = Data(b[afterStart...])
                } else {
                    self.bufFromUpstream = Data()
                }
                self.afterUpgrade(conn)
                return
            }
            self.readWSUpgradeReply(conn, host: host, buf: b)
        }
    }

    /// Первое WS-сообщение — заголовок obfuscated2; дальше — фреймы.
    private func afterUpgrade(_ conn: NWConnection) {
        wsAttempts = 0
        if let header = wsHeader {
            wsHeader = nil
            conn.send(content: header, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if error != nil {
                    self.stop()
                    return
                }
                self.startRelay(leftover: self.bufFromUpstream)
            })
        } else {
            startRelay(leftover: bufFromUpstream)
        }
    }

    // MARK: - реле

    private func startRelay(leftover: Data) {
        if mode == .webSocket {
            pumpClientWS()
        } else {
            pumpClient()
        }
        receiveFromUpstream()
    }

    private func receiveFromUpstream() {
        guard !stopped, let up = upstream else { return }
        up.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self, !self.stopped else { return }
            if let data, !data.isEmpty {
                self.bufFromUpstream.append(data)
                self.touch()
                self.pumpUpstream()
            }
            if error == nil {
                self.receiveFromUpstream()
            } else {
                self.stop()
            }
        }
    }

    private func pumpClient() {
        guard !stopped, !bufFromClient.isEmpty, let up = upstream else { return }
        var plain = recvC.update(bufFromClient)
        bufFromClient = Data()
        plain = encU.update(plain)
        if mode == .wrappedRecord {
            plain = BridgeTunnel.wrapRecords(plain)
        }
        up.send(content: plain, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.stop() }
        })
    }

    private func pumpClientWS() {
        guard !stopped, !bufFromClient.isEmpty, let up = upstream else { return }
        var plain = recvC.update(bufFromClient)
        bufFromClient = Data()
        wsPlainBuf.append(plain)
        guard wsPlainBuf.count <= Self.MAX_WS_BUFFER else { stop(); return }
        var out = Data()
        while wsPlainBuf.count >= 4 {
            guard let (used, offset) = consumeFrame(wsPlainBuf, framing: framing),
                  used >= offset, used <= wsPlainBuf.count else { break }
            out.append(abridgedFrame(Data(wsPlainBuf[wsPlainBuf.startIndex + offset ..< wsPlainBuf.startIndex + used])))
            wsPlainBuf.removeFirst(used)
        }
        guard !out.isEmpty else { return }
        let wire = encU.update(out)
        up.send(content: wsFrame(wire), completion: .contentProcessed { [weak self] error in
            if error != nil { self?.stop() }
        })
    }

    private func pumpUpstream() {
        guard !stopped else { return }
        if mode == .webSocket {
            pumpUpstreamWS()
            return
        }
        var plain = Data()
        if mode == .wrappedRecord {
            let (payload, rest) = BridgeTunnel.stripRecords(bufFromUpstream)
            bufFromUpstream = rest
            plain = payload
        } else {
            plain = bufFromUpstream
            bufFromUpstream = Data()
        }
        guard !plain.isEmpty else { return }
        sendToClient(plain)
    }

    private func sendToClient(_ plainFromUpstream: Data) {
        var p = decU.update(plainFromUpstream)
        p = sendC.update(p)
        client.send(content: p, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.stop() }
        })
    }

    /// kws → клиент: abridged-фреймы (обф) → intermediate-фреймы (dd-секрет).
    private func pumpUpstreamWS() {
        let (messages, rest) = dequeueWS(bufFromUpstream)
        bufFromUpstream = rest
        guard !messages.isEmpty else { return }
        kwsDecBuf.append(decU.update(messages))
        var wire = Data()
        while kwsDecBuf.count >= 4 {
            guard let (used, offset) = consumeFrame(kwsDecBuf, framing: .abridged),
                  used >= offset, used <= kwsDecBuf.count else { break }
            let payload = Data(kwsDecBuf[kwsDecBuf.startIndex + offset ..< kwsDecBuf.startIndex + used])
            kwsDecBuf.removeFirst(used)
            wire.append(intermediateFrame(payload))
        }
        guard !wire.isEmpty else { return }
        let out = sendC.update(wire)
        client.send(content: out, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.stop() }
        })
    }

    /// MTProto abridged transport: 1 байт len (в четвертях) или 0x7F + len/4 (3 bytes LE).
    private func abridgedFrame(_ payload: Data) -> Data {
        var out = Data()
        let n = payload.count
        if n / 4 < 127 {
            out.append(UInt8(n / 4))
        } else {
            out.append(0x7F)
            let ln = n / 4
            out.append(UInt8(ln & 0xFF))
            out.append(UInt8((ln >> 8) & 0xFF))
            out.append(UInt8((ln >> 16) & 0xFF))
        }
        out.append(payload)
        return out
    }

    /// MTProto intermediate transport: 4 байта длины LE + payload.
    private func intermediateFrame(_ payload: Data) -> Data {
        var out = Data()
        let n = payload.count
        out.append(UInt8(n & 0xFF))
        out.append(UInt8((n >> 8) & 0xFF))
        out.append(UInt8((n >> 16) & 0xFF))
        out.append(UInt8((n >> 24) & 0xFF))
        out.append(payload)
        return out
    }

    // MARK: - WebSocket фреймы

    private func wsFrame(_ payload: Data) -> Data {
        let mask = (0..<4).map { _ in UInt8.random(in: 0...255) }
        var out = Data()
        out.append(0x82) // FIN + binary
        let len = payload.count
        if len < 126 {
            out.append(0x80 | UInt8(len))
        } else if len <= 0xFFFF {
            out.append(0x80 | 126)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        } else {
            out.append(0x80 | 127)
            var l = UInt64(len)
            var lenBytes = [UInt8]()
            for _ in 0..<8 {
                lenBytes.insert(UInt8(l & 0xFF), at: 0)
                l >>= 8
            }
            out.append(contentsOf: lenBytes)
        }
        out.append(contentsOf: mask)
        for i in 0..<payload.count {
            out.append(payload[payload.startIndex + i] ^ mask[i % 4])
        }
        return out
    }

    private func dequeueWS(_ buf: Data) -> (payload: Data, rest: Data) {
        var payloads = Data()
        var b = buf
        while true {
            guard b.count >= 2 else { break }
            let op = b[b.startIndex] & 0x0F
            let masked = (b[b.startIndex + 1] & 0x80) != 0
            var len = UInt64(b[b.startIndex + 1] & 0x7F)
            var off = b.startIndex + 2
            if len == 126 {
                guard b.count >= off + 2 else { break }
                len = UInt64(b[off]) << 8 | UInt64(b[off + 1])
                off += 2
            } else if len == 127 {
                guard b.count >= off + 8 else { break }
                var v: UInt64 = 0
                for i in 0..<8 { v = v << 8 | UInt64(b[off + i]) }
                off += 8
                len = v
            }
            var maskStart = off
            if masked {
                guard b.count >= off + 4 else { break }
                off += 4
            }
            guard len <= 16 << 20, b.count >= off + Int(len) else { break }
            var payload = Data(b[b.startIndex + off ..< b.startIndex + off + Int(len)])
            if masked {
                let maskBytes = [UInt8](b[maskStart ..< maskStart + 4])
                for i in 0..<payload.count {
                    payload[payload.startIndex + i] ^= maskBytes[i % 4]
                }
            }
            let skip = off + Int(len)
            if op == 0x8 {
                return (payloads, Data())
            }
            if op == 0x1 || op == 0x2 {
                payloads.append(payload)
            }
            b = b.dropFirst(skip)
        }
        return (payloads, b)
    }
}

// MARK: - TLS ClientHello (порт main.py _tls_client_hello)

func tlsClientHello(host: String) -> Data {
    let hostBytes = Array(host.utf8)
    var d = Data()

    func len2(_ data: Data) -> Data {
        var out = Data()
        out.append(UInt8((data.count >> 8) & 0xFF))
        out.append(UInt8(data.count & 0xFF))
        out.append(data)
        return out
    }

    var nameEntry = Data()
    nameEntry.append(0x00)
    nameEntry.append(len2(Data(hostBytes)))
    let sniList = len2(nameEntry)
    let extSNI = len2(Data([0x00, 0x00]) + len2(sniList))

    let groups = Data([0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19])
    let extGroups = len2(Data([0x00, 0x0A]) + len2(groups))
    let extEPF = len2(Data([0x00, 0x0B]) + Data([0x02, 0x01, 0x00]))

    var sigalgs = Data()
    for s in [UInt16]([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]) {
        sigalgs.append(UInt8((s >> 8) & 0xFF)); sigalgs.append(UInt8(s & 0xFF))
    }
    let extSig = len2(Data([0x00, 0x0D]) + len2(sigalgs))

    let vers = Data([0x03, 0x04, 0x03, 0x03])
    let extVers = len2(Data([0x00, 0x2B]) + Data([UInt8(vers.count)]) + vers)

    let xkey = (0..<32).map { _ in UInt8.random(in: 0...255) }
    var ksEntry = Data()
    ksEntry.append(0x00); ksEntry.append(0x1D)
    ksEntry.append(0x00); ksEntry.append(0x20)
    ksEntry.append(contentsOf: xkey)
    let extKS = len2(Data([0x00, 0x33]) + len2(ksEntry))

    let extTicket = len2(Data([0x00, 0x23]) + Data([0x00, 0x00]))

    var ciphers = Data()
    for c in [UInt16]([0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                       0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A]) {
        ciphers.append(UInt8((c >> 8) & 0xFF)); ciphers.append(UInt8(c & 0xFF))
    }
    let cipherList = len2(ciphers)

    var exts = Data()
    exts.append(extSNI)
    exts.append(extGroups)
    exts.append(extEPF)
    exts.append(extSig)
    exts.append(extVers)
    exts.append(extKS)
    exts.append(extTicket)

    var body = Data()
    body.append(0x03); body.append(0x03)
    body.append(contentsOf: (0..<32).map { _ in UInt8.random(in: 0...255) })
    body.append(0x20)
    body.append(contentsOf: (0..<32).map { _ in UInt8.random(in: 0...255) })
    body.append(cipherList)
    body.append(0x01); body.append(0x00)
    body.append(len2(exts))

    var handshake = Data()
    handshake.append(0x01)
    handshake.append(UInt8((body.count >> 16) & 0xFF))
    handshake.append(UInt8((body.count >> 8) & 0xFF))
    handshake.append(UInt8(body.count & 0xFF))
    handshake.append(body)

    var record = Data()
    record.append(0x16)
    record.append(0x03); record.append(0x01)
    record.append(UInt8((handshake.count >> 8) & 0xFF))
    record.append(UInt8(handshake.count & 0xFF))
    record.append(handshake)
    return record
}