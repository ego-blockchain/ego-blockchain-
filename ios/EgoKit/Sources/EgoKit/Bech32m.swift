public enum Bech32m {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let constant: UInt32 = 0x2BC8_30A3
    private static let generator: [UInt32] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]

    public static func encode(hrp: String, payload: [UInt8]) -> String {
        let words = convert(payload, from: 8, to: 5, pad: true) ?? []
        let values = expand(hrp) + words + [UInt8](repeating: 0, count: 6)
        let mod = polymod(values) ^ constant
        let checksum = (0..<6).map { UInt8((mod >> (5 * (5 - UInt32($0)))) & 31) }
        let body = (words + checksum).map { charset[Int($0)] }
        return hrp + "1" + String(decoding: body, as: UTF8.self)
    }

    public static func decode(_ text: String) -> (hrp: String, payload: [UInt8])? {
        let lower = text.lowercased()
        guard lower == text || text.uppercased() == text, text.count <= 90 else { return nil }
        guard let separator = lower.lastIndex(of: "1") else { return nil }
        let hrp = String(lower[lower.startIndex..<separator])
        let rest = Array(lower[lower.index(after: separator)...].utf8)
        guard !hrp.isEmpty, rest.count >= 6 else { return nil }
        var values = [UInt8]()
        for c in rest {
            guard let index = charset.firstIndex(of: c) else { return nil }
            values.append(UInt8(index))
        }
        guard polymod(expand(hrp) + values) == constant else { return nil }
        guard let payload = convert(Array(values.dropLast(6)), from: 5, to: 8, pad: false) else { return nil }
        return (hrp, payload)
    }

    private static func expand(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        return bytes.map { $0 >> 5 } + [0] + bytes.map { $0 & 31 }
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1FF_FFFF) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 {
                chk ^= generator[i]
            }
        }
        return chk
    }

    private static func convert(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        let maxValue = (1 << to) - 1
        var out = [UInt8]()
        for value in data {
            guard Int(value) >> from == 0 else { return nil }
            acc = (acc << from) | Int(value)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxValue))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxValue)) }
        } else if bits >= from || (acc << (to - bits)) & maxValue != 0 {
            return nil
        }
        return out
    }
}
