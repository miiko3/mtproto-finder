import Foundation
import CommonCrypto
import CryptoKit
import Network

// MARK: - MTProto obfuscated2 (AES-CTR) + real req_pq_multi probe
//
// Ported from localproxy.py: a real checker for plain MTProto (non-FakeTLS)
// proxies. Sends an obfuscated2 header, then req_pq_multi, and treats the
// proxy as alive only when a valid ResPQ echoing our nonce comes back.

enum ObfFraming {
    case abridged
    case intermediate
}

private let reservedInitPrefixes: [[UInt8]] = [
    Array("HEAD".utf8), Array("POST".utf8), Array("GET ".utf8), Array("OPTI".utf8),
    [0xEE, 0xEE, 0xEE, 0xEE], [0xDD, 0xDD, 0xDD, 0xDD], [0x16, 0x03, 0x01, 0x02]
]

private func aesECBEncrypt(key: Data, block: [UInt8]) -> [UInt8] {
    guard block.count == 16 else { return [] }
    var out = [UInt8](repeating: 0, count: 16)
    let outCount = out.count
    var moved = 0
    let status: CCCryptorStatus = key.withUnsafeBytes { kp in
        block.withUnsafeBytes { ins -> CCCryptorStatus in
            out.withUnsafeMutableBytes { oo in
                CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                        kp.baseAddress, key.count, nil,
                        ins.baseAddress, block.count, oo.baseAddress, outCount, &moved)
            }
        }
    }
    return status == kCCSuccess ? out : []
}

/// AES-CTR stream compatible with PyCryptodome's `AES.MODE_CTR` (128-bit
/// big-endian counter starting at `initial_value`, advanced per 16-byte block).
private final class ObfCipher: @unchecked Sendable {
    private let key: Data
    private let iv: [UInt8]
    private var counter: UInt64

    init(key: Data, iv: [UInt8], blockOffset: UInt64 = 0) {
        self.key = key
        self.iv = iv
        self.counter = blockOffset
    }

    func update(_ input: Data) -> Data {
        var out = Data(count: input.count)
        var idx = 0
        while idx < input.count {
            let n = min(16, input.count - idx)
            var cb = iv
            var carry: UInt64 = counter
            var bi = 15
            while carry > 0 && bi >= 0 {
                let sum = UInt32(cb[bi]) + UInt32(carry & 0xFF)
                cb[bi] = UInt8(sum & 0xFF)
                carry = (carry >> 8) + UInt64(sum >> 8)
                bi -= 1
            }
            let ks = aesECBEncrypt(key: key, block: cb)
            for i in 0..<n where i < ks.count {
                out[idx + i] = input[input.startIndex + idx + i] ^ ks[i]
            }
            idx += n
            counter += 1
        }
        return out
    }
}

private final class DeepProbeFinisher: @unchecked Sendable {
    private let once: Once
    private let timer: DispatchSourceTimer
    private let conn: NWConnection
    private let cont: CheckedContinuation<(Double, Bool), Never>

    init(once: Once, timer: DispatchSourceTimer, conn: NWConnection,
         cont: CheckedContinuation<(Double, Bool), Never>) {
        self.once = once
        self.timer = timer
        self.conn = conn
        self.cont = cont
    }

    func call(_ ms: Double, _ ok: Bool) {
        once.fire {
            self.timer.cancel()
            self.conn.cancel()
            self.cont.resume(returning: (ms, ok))
        }
    }
}

private func obfuscatedInit(tag: [UInt8], dcID: UInt16) -> [UInt8]? {
    for _ in 0..<128 {
        var r = (0..<64).map { _ in UInt8.random(in: 0...255) }
        if r[0] == 0xEF { continue }
        if reservedInitPrefixes.contains(Array(r[0..<4])) { continue }
        if Array(r[4..<8]) == [0, 0, 0, 0] { continue }
        r.replaceSubrange(56..<60, with: tag)
        r[60] = UInt8(dcID & 0xFF)
        r[61] = UInt8((dcID >> 8) & 0xFF)
        r[62] = 0
        r[63] = 0
        return r
    }
    return nil
}

private func decodeHex(_ s: String) -> [UInt8]? {
    var out = [UInt8]()
    var i = s.startIndex
    while i < s.index(before: s.endIndex) {
        let next = s.index(after: i)
        guard let b = UInt8(String(s[i...next]), radix: 16) else { return nil }
        out.append(b)
        i = s.index(after: next)
    }
    return out
}

/// Same as localproxy.py `_secret_bytes`: FakeTLS secrets start with a 0xEE
/// marker byte, so the crypto key is the 16 bytes *after* it.
private func mtprotoSecretBytes(_ secret: String) -> Data? {
    var h = secret.lowercased()
    if h.hasPrefix("dd"), h.count == 34 { h = String(h.dropFirst(2)) }
    guard h.count % 2 == 0, h.count >= 2, var bytes = decodeHex(h) else { return nil }
    if bytes.count >= 17, bytes[0] == 0xEE {
        bytes = Array(bytes.dropFirst(1).prefix(16))
    }
    guard bytes.count >= 16 else { return nil }
    return Data(bytes.prefix(16))
}

private func consumeFrame(_ data: Data, framing: ObfFraming) -> (used: Int, offset: Int)? {
    let b = [UInt8](data)
    switch framing {
    case .abridged:
        guard let b0 = b.first else { return nil }
        if b0 == 0x7F {
            guard b.count >= 4 else { return nil }
            let ln = Int(b[1]) | Int(b[2]) << 8 | Int(b[3]) << 16
            let total = 4 + ln * 4
            guard total > 0, b.count >= total else { return nil }
            return (total, 4)
        }
        let total = 1 + Int(b0) * 4
        guard total > 0, b.count >= total else { return nil }
        return (total, 1)
    case .intermediate:
        guard b.count >= 4 else { return nil }
        var ln = Int(b[0]) | Int(b[1]) << 8 | Int(b[2]) << 16 | Int(b[3]) << 24
        ln &= 0x7FFFFFFF
        let total = 4 + ln
        guard total > 0, b.count >= total else { return nil }
        return (total, 4)
    }
}

/// Returns true when a full ResPQ echoing `nonce` was found, false when the
/// current buffer can't be a valid MTProto reply, nil when more data is needed.
private func parseResPQ(_ data: Data, framing: ObfFraming, nonce: Data) -> Bool? {
    var buf = data
    while let (used, offset) = consumeFrame(buf, framing: framing) {
        guard offset >= 0, used <= buf.count, offset <= used else {
            return false
        }
        let payload = Array(buf[buf.startIndex + offset ..< buf.startIndex + used])
        buf.removeFirst(used)
        guard payload.count >= 20 else { continue }
        var ctor: UInt32 = 0
        for i in 0..<4 { ctor |= UInt32(payload[i]) << (8 * UInt32(i)) }
        if ctor == 0x05162463, Data(payload[4..<20]) == nonce {
            return true
        }
    }
    return nil
}

/// Full MTProto round-trip ping: obfuscated2 handshake + req_pq_multi == ResPQ.
/// Returns (elapsed ms, validated). -2.0/"dead" on failure, positive ms + true
/// only when the proxy really answered with the correct ResPQ.
func deepMTProtoPing(host: String, port: Int, secret: String, timeout: Double = 2.5) async -> (Double, Bool) {
    await withCheckedContinuation { cont in
        guard let portV = NWEndpoint.Port(rawValue: UInt16(port)) else {
            cont.resume(returning: (-2.0, false)); return
        }
        let lower = secret.lowercased()
        let isIntermediate = lower.hasPrefix("dd") && lower.count == 34
        let framing: ObfFraming = isIntermediate ? .intermediate : .abridged
        let tag: [UInt8] = isIntermediate ? [0xDD, 0xDD, 0xDD, 0xDD] : [0xEF, 0xEF, 0xEF, 0xEF]

        guard let initBytes = obfuscatedInit(tag: tag, dcID: 2),
              let secretData = mtprotoSecretBytes(secret) else {
            cont.resume(returning: (-2.0, false)); return
        }

        let region = Data(initBytes[8..<56])
        let regionArr = [UInt8](region)
        let rev = Array(regionArr.reversed())

        let fk = Data(SHA256.hash(data: Data(regionArr[0..<32]) + secretData))
        let fiv = [UInt8](region[32..<48])
        let rk = Data(SHA256.hash(data: Data(rev[0..<32]) + secretData))
        let riv = [UInt8](rev[32..<48])

        let enc = ObfCipher(key: fk, iv: fiv)
        let full = enc.update(Data(initBytes))
        let head = Data(initBytes.prefix(56)) + full.dropFirst(56)

        let nonce = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let nonceData = Data(nonce)

        var body = Data()
        withUnsafeBytes(of: UInt32(0xBE7E8EF1).littleEndian) { body.append(contentsOf: $0) }
        body.append(contentsOf: nonce)
        body.append(Data(count: 160))

        var frame = Data()
        if isIntermediate {
            var len = UInt32(body.count).littleEndian
            frame = withUnsafeBytes(of: &len) { Data($0) }
            frame.append(body)
        } else {
            frame = Data([UInt8(body.count / 4)])
            frame.append(body)
        }

        let packet = head + enc.update(frame)

        let conn = NWConnection(host: NWEndpoint.Host(host), port: portV, using: .tcp)
        let queue = DispatchQueue(label: "mtprotofinder.deep")
        let once = Once()
        let start = Date()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + max(1.0, timeout))

        var recvBuf = Data()
        let dec = ObfCipher(key: rk, iv: riv)

        let finish = DeepProbeFinisher(once: once, timer: timer, conn: conn, cont: cont)
        timer.setEventHandler { finish.call(-2.0, false) }
        timer.resume()

        func receiveMore() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                guard let data, !data.isEmpty, error == nil else {
                    finish.call(-2.0, false); return
                }
                recvBuf.append(dec.update(data))
                if let ok = parseResPQ(recvBuf, framing: framing, nonce: nonceData) {
                    let ms = Date().timeIntervalSince(start) * 1000
                    finish.call(ok ? ms : -2.0, ok)
                } else {
                    receiveMore()
                }
            }
        }

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: packet, completion: .contentProcessed { error in
                    if error != nil {
                        finish.call(-2.0, false)
                    } else {
                        receiveMore()
                    }
                })
            case .failed, .cancelled:
                finish.call(-2.0, false)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }
}

// MARK: - FakeTLS (ee...) SNI candidates

/// Extracts the SNI domain embedded in a FakeTLS secret (same algorithm as
/// localproxy.py `_extract_domain`).
func extractDomain(fromSecret secret: String) -> String {
    let h = secret.lowercased()
    let chars = Array(h)
    guard h.hasPrefix("ee"), chars.count >= 36 else { return "www.cloudflare.com" }

    var offsets = [34]
    offsets.append(contentsOf: (2..<min(64, chars.count - 6)).filter { $0 % 2 == 0 && $0 != 34 })

    for off in offsets {
        var out = ""
        var i = off
        var clean = true
        while i + 1 < chars.count {
            guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { clean = false; break }
            let ch = Character(UnicodeScalar(b))
            if !("a"..."z" ~= ch.lowercased().first ?? "#".first!),
               !("0"..."9" ~= ch),
               ch != ".", ch != "-" { break }
            out.append(ch)
            i += 2
        }
        let nonDotAllDigits = out.filter { $0 != "." }.allSatisfy { $0.isNumber }
        if clean, out.count >= 4, out.contains("."), !nonDotAllDigits {
            return out
        }
    }
    return "www.cloudflare.com"
}

func sniCandidates(secret: String, host: String) -> [String] {
    var out: [String] = []
    let candidates = [extractDomain(fromSecret: secret), host, "www.cloudflare.com"]
    for raw in candidates {
        let d = raw.trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if !d.isEmpty, d.contains("."), !out.contains(d) {
            out.append(d)
        }
    }
    return out
}

// MARK: - FakeTLS (ee...) real MTProto probe inside TLS

enum FakeTLSProbeResult {
    case success(Double)
    case tlsFailed
    case notMTProto
}

/// Ported from localproxy.py `_ssl_obf_ping`: establishes a real TLS tunnel to
/// the SNI embedded in the secret, then performs the full obfuscated2 MTProto
/// handshake (obf2 header + req_pq_multi) and validates the ResPQ nonce.
/// A plain TLS handshake is NOT enough to certify a FakeTLS proxy.
func fakeTLSPing(host: String, port: Int, secret: String, sni: String, timeout: Double = 4.0) async -> FakeTLSProbeResult {
    await withCheckedContinuation { cont in
        guard let portV = NWEndpoint.Port(rawValue: UInt16(port)),
              let secretData = mtprotoSecretBytes(secret),
              let initBytes = obfuscatedInit(tag: [0xEF, 0xEF, 0xEF, 0xEF], dcID: 2) else {
            cont.resume(returning: .tlsFailed); return
        }
        let framing: ObfFraming = .abridged

        let region = Data(initBytes[8..<56])
        let regionArr = [UInt8](region)
        let rev = Array(regionArr.reversed())
        let fk = Data(SHA256.hash(data: Data(regionArr[0..<32]) + secretData))
        let fiv = [UInt8](region[32..<48])
        let rk = Data(SHA256.hash(data: Data(rev[0..<32]) + secretData))
        let riv = [UInt8](rev[32..<48])

        let enc = ObfCipher(key: fk, iv: fiv)
        let full = enc.update(Data(initBytes))
        let head = Data(initBytes.prefix(56)) + full.dropFirst(56)

        let nonce = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let nonceData = Data(nonce)

        var body = Data()
        withUnsafeBytes(of: UInt32(0xBE7E8EF1).littleEndian) { body.append(contentsOf: $0) }
        body.append(contentsOf: nonce)
        body.append(Data(count: 160))

        var frame = Data([UInt8(body.count / 4)])
        frame.append(body)

        let packet = head + enc.update(frame)

        let queue = DispatchQueue(label: "mtprotofinder.faketls")
        let tlsOpts = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOpts.securityProtocolOptions, sni)
        sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
            complete(true)
        }, queue)
        let params = NWParameters(tls: tlsOpts)
        let conn = NWConnection(to: NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: portV), using: params)
        let once = Once()
        let start = Date()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + max(1.5, timeout))

        var recvBuf = Data()
        let dec = ObfCipher(key: rk, iv: riv)
        var readyReached = false

        let finish: (Double, Bool) -> Void = { ms, ok in
            once.fire {
                timer.cancel()
                conn.cancel()
                if ok {
                    cont.resume(returning: .success(ms))
                } else if readyReached {
                    cont.resume(returning: .notMTProto)
                } else {
                    cont.resume(returning: .tlsFailed)
                }
            }
        }
        timer.setEventHandler { finish(-2.0, false) }
        timer.resume()

        func receiveMore() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                guard let data, !data.isEmpty, error == nil else {
                    finish(-2.0, false); return
                }
                recvBuf.append(dec.update(data))
                if let ok = parseResPQ(recvBuf, framing: framing, nonce: nonceData) {
                    let ms = Date().timeIntervalSince(start) * 1000
                    finish(ok ? ms : -2.0, ok)
                } else {
                    receiveMore()
                }
            }
        }

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                readyReached = true
                conn.send(content: packet, completion: .contentProcessed { error in
                    if error != nil {
                        finish(-2.0, false)
                    } else {
                        receiveMore()
                    }
                })
            case .failed, .cancelled:
                finish(-2.0, false)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }
}