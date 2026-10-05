public enum Mnemonic {
    public static let wordCount = 24
    private static let maxCombinations = 256

    public static func words(for seed: [UInt8]) -> [String] {
        precondition(seed.count == 32, "seed must be 32 bytes")
        let list = Wordlist.words
        var data = seed
        data.append(Blake2s.hash(seed)[0])
        var words = [String]()
        for i in 0..<wordCount {
            let bitOffset = i * 11
            let byteIndex = bitOffset / 8
            let shift = bitOffset % 8
            let b0 = Int(data[byteIndex])
            let b1 = byteIndex + 1 < data.count ? Int(data[byteIndex + 1]) : 0
            let b2 = byteIndex + 2 < data.count ? Int(data[byteIndex + 2]) : 0
            let raw = (b0 << 16) | (b1 << 8) | b2
            let index = ((raw >> (13 - shift)) & 0x7FF) % list.count
            words.append(list[index])
        }
        return words
    }

    public static func seed(from phrase: String) -> [UInt8]? {
        let words = phrase
            .split(whereSeparator: { $0.isWhitespace })
            .map { $0.lowercased() }
        return seed(from: words)
    }

    public static func seed(from words: [String]) -> [UInt8]? {
        guard words.count == wordCount else { return nil }
        var positions = [String: [Int]]()
        for (i, w) in Wordlist.words.enumerated() {
            positions[w, default: []].append(i)
        }
        var candidates = [[Int]]()
        for word in words {
            guard let found = positions[word.lowercased()] else { return nil }
            candidates.append(found)
        }
        guard candidates.reduce(1, { $0 * $1.count }) <= maxCombinations else { return nil }
        var combo = [Int](repeating: 0, count: wordCount)
        return search(0, candidates: candidates, combo: &combo)
    }

    public static func isWord(_ word: String) -> Bool {
        Wordlist.words.contains(word.lowercased())
    }

    private static func search(_ position: Int, candidates: [[Int]], combo: inout [Int]) -> [UInt8]? {
        if position == wordCount { return attempt(combo) }
        for index in candidates[position] {
            combo[position] = index
            if let seed = search(position + 1, candidates: candidates, combo: &combo) { return seed }
        }
        return nil
    }

    private static func attempt(_ indices: [Int]) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: 33)
        for i in 0..<wordCount {
            let bitOffset = i * 11
            let byteIndex = bitOffset / 8
            let shift = bitOffset % 8
            let raw = (indices[i] & 0x7FF) << (13 - shift)
            buffer[byteIndex] |= UInt8((raw >> 16) & 0xFF)
            if byteIndex + 1 < 33 { buffer[byteIndex + 1] |= UInt8((raw >> 8) & 0xFF) }
            if byteIndex + 2 < 33 { buffer[byteIndex + 2] |= UInt8(raw & 0xFF) }
        }
        let seed = Array(buffer[0..<32])
        return Blake2s.hash(seed)[0] == buffer[32] ? seed : nil
    }
}
