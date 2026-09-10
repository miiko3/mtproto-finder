import Foundation

// MARK: - Самопроверка криптографии против эталонных векторов
//
// Векторы сгенерированы PyCryptodome (тем же, что использует localproxy.py):
// AES-CTR с nonce=b'"" и initial_value=16 байт — keystream идентичен нашей
// реализации ObfCipher (128-бит big-endian счётчик). Если тест падает —
// шифрование несовместимо с реальными MTProto-прокси и туннель не заработает.

enum CipherCheck {
    static let LS_FK = "492879ebc3f6e4cd83690c01b4400bbf631218a9caefe2643726b9b08f90d093"
    static let LS_FIV = "202122232425262728292a2b2c2d2e2f"
    static let LS_RK = "832c3d30ec77994b2275d3fe9407d29a33ef3c22c1f446d1480008353de7575f"
    static let LS_RIV = "0f0e0d0c0b0a09080706050403020100"

    static let INIT_HEX = "0001020304050607" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f" + "efefefef02000000"
    static let HEAD_HEX = "0001020304050607" +
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f" + "e5bf979751ce3ba6"

    static let CTR_FK_HEX = "c1dcba544f1c8840af97fa5bc85f1afa95222b439af6cc99a0ff0c6c3e55e101" +
        "66f9f69634fb4a87b1286a9f9fbd0c36b84608ae891244200a50787853ce3ba68bda96a5241b0cb3" +
        "30e41c54798536e6c229c02aabae82e76483e4be7c41c175c54c6c7ed76f21651498c9fd118cb3a" +
        "59ce5e299cc699a42044ceac3d45bd0da399eb2c9e2c488c8402a411ef743182a7a0d3096280e73" +
        "60d84291b331dd4f0130fc9d22d759cb9d78c544db801d917a794511c2f25121af1ec9bce686e6b9" +
        "38cf11331df2406f8767b0bda2fb1960a0f5c2e71adc6d7d808f0954ae0286c544ad2153360b2de" +
        "286f9b2c116d3ed9b83512b13c0103cb1e554960c76606b2c9a"
    static let CTR_RK_HEX = "7e263223dc1ca3cf760962641aaa032cf3dbe60d0888542529c33b00061f6f30" +
        "39cd293d5d6ab18e65b388f53cf83e777b58ce8d49f0311310773e0d35759b4f742ee057f310d3fe" +
        "0f08d39ec6e365b053f4cfb4dfcdb498ddd68d124783b46b26a9b425c00b0d46e92ebb36164a67ba" +
        "e07d950f59ff184713c07499be6a1a7ea0dcc19e8cdcfc2a8b4102fba8b16b9d1d5f73acb7e758e0" +
        "deffd5a66cb857b905d92b646d9d7aa80073563c7b22a174c0f73d91d14216b53930c634ef458a02" +
        "41eddad7dbc528e582e1334cfb60f24077d46d32bd7e2ae37fcc38d91da0155f31ad6d9233b18da7" +
        "9776c9ab9a50cbbc5c728adc715027312154952d38f80deb"

    static func run() -> (ok: Bool, message: String) {
        let region = (0..<48).map { UInt8($0) }
        let keys = deriveKeys(region: region, secret: BridgeTunnel.localSecret)

        let fk = Data(Self.LS_FK.hexBytes)
        let rk = Data(Self.LS_RK.hexBytes)
        let fiv = [UInt8](Self.LS_FIV.hexBytes)
        let riv = [UInt8](Self.LS_RIV.hexBytes)
        guard keys.fk == fk, keys.fkIV == fiv, keys.rk == rk, keys.rkIV == riv else {
            return (false, "deriveKeys не совпал с эталоном")
        }

        // Заголовок клиента (фикс. nonce 0..7) -> HEAD
        var initBytes = Data(count: 8)
        for i in 0..<8 { initBytes[i] = UInt8(i) }
        var fullInit = initBytes
        fullInit.append(region)
        fullInit.append(contentsOf: [0xEF, 0xEF, 0xEF, 0xEF, 0x02, 0x00, 0x00, 0x00])
        guard fullInit.hexString.lowercased() == Self.INIT_HEX else {
            return (false, "init собран неверно")
        }
        let enc = ObfCipher(key: fk, iv: fiv)
        let full = enc.update(fullInit)
        let head = Data(fullInit.prefix(56)) + full.dropFirst(56)
        guard head.hexString.lowercased() == Self.HEAD_HEX else {
            return (false, "HEAD не совпал с эталоном")
        }

        // Серверная сторона декодирует заголовок (dd-секрет) -> tag/dc
        let serverKeys = deriveKeys(region: [UInt8](head[8..<56]), secret: BridgeTunnel.localSecret)
        guard serverKeys.fk == fk, serverKeys.rkIV == riv else {
            return (false, "серверная derive не дала те же ключи")
        }
        let recvC = ObfCipher(key: serverKeys.fk, iv: serverKeys.fkIV)
        let plain = recvC.update(head)
        let pArr = [UInt8](plain)
        guard Array(pArr[56..<60]) == [0xEF, 0xEF, 0xEF, 0xEF],
              pArr[60] == 0x02, pArr[61] == 0x00 else {
            return (false, "tag/dc не восстановлены")
        }

        // Keystream CTR
        let ksFK = ObfCipher(key: fk, iv: fiv).update(Data(count: 256))
        guard ksFK.hexString.lowercased() == Self.CTR_FK_HEX else {
            return (false, "AES-CTR(fk) не совпал с pycryptodome")
        }
        let ksRK = ObfCipher(key: rk, iv: riv).update(Data(count: 256))
        guard ksRK.hexString.lowercased() == Self.CTR_RK_HEX else {
            return (false, "AES-CTR(rk) не совпал с pycryptodome")
        }

        // TLS record wrap/strip round-trip
        var dump = Data()
        for i in 0..<40000 { dump.append(UInt8(i % 256)) }
        let wrapped = BridgeTunnel.wrapRecords(dump)
        let (back, rest) = BridgeTunnel.stripRecords(wrapped)
        guard back == dump, rest.isEmpty, !wrapped.isEmpty else {
            return (false, "wrap/strip records не round-trip")
        }

        // framing
        let ab = Data([0x04]) + Data(count: 16)
        guard let f1 = consumeFrame(ab, framing: .abridged), f1.used == 17, f1.offset == 1 else {
            return (false, "abridged framing неверный")
        }
        var long = Data([0x7F, 0x20, 0x00, 0x00]) + Data(count: 128)
        guard let f2 = consumeFrame(long, framing: .abridged), f2.offset == 4, f2.used == 132 else {
            return (false, "abridged long framing неверный")
        }
        var int = Data()
        withUnsafeBytes(of: UInt32(64).littleEndian) { int.append(contentsOf: $0) }
        int.append(Data(count: 64))
        guard let f3 = consumeFrame(int, framing: .intermediate), f3.offset == 4, f3.used == 68 else {
            return (false, "intermediate framing неверный")
        }

        return (true, "")
    }

}

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private extension String {
    var hexBytes: Data {
        var out = Data()
        var iter = self[...]
        while iter.count >= 2 {
            let sub = iter.prefix(2)
            if let b = UInt8(String(sub), radix: 16) {
                out.append(b)
            }
            iter = iter.dropFirst(2)
        }
        return out
    }
}