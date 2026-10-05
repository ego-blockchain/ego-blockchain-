public enum Blake2s {
    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    public static func hash<S: Sequence>(_ input: S) -> [UInt8] where S.Element == UInt8 {
        let data = Array(input)
        var h = iv
        h[0] ^= 0x0101_0000 ^ 32
        if data.isEmpty {
            compress(&h, block: [UInt8](repeating: 0, count: 64), counter: 0, last: true)
        } else {
            var offset = 0
            var counter: UInt64 = 0
            while offset < data.count {
                let take = min(64, data.count - offset)
                var block = [UInt8](repeating: 0, count: 64)
                block.replaceSubrange(0..<take, with: data[offset..<(offset + take)])
                counter += UInt64(take)
                offset += take
                compress(&h, block: block, counter: counter, last: offset == data.count)
            }
        }
        var out = [UInt8]()
        out.reserveCapacity(32)
        for word in h {
            out.append(contentsOf: word.littleEndianBytes)
        }
        return out
    }

    private static func compress(_ h: inout [UInt32], block: [UInt8], counter: UInt64, last: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[i * 4])
                | UInt32(block[i * 4 + 1]) << 8
                | UInt32(block[i * 4 + 2]) << 16
                | UInt32(block[i * 4 + 3]) << 24
        }
        var v = h + iv
        v[12] ^= UInt32(truncatingIfNeeded: counter)
        v[13] ^= UInt32(truncatingIfNeeded: counter >> 32)
        if last { v[14] = ~v[14] }
        for round in 0..<10 {
            let s = sigma[round]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    private static func mix(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotate(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotate(v[b] ^ v[c], 12)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotate(v[d] ^ v[a], 8)
        v[c] = v[c] &+ v[d]
        v[b] = rotate(v[b] ^ v[c], 7)
    }

    private static func rotate(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x >> n) | (x << (32 - n))
    }
}
