import Foundation

public enum TransactionError: Error, Equatable {
    case memoTooLong
    case badRecipient
    case zeroAmount
}

public struct SignedTransaction: Codable, Equatable {
    public let hash: String
    public let from: String
    public let to: String
    public let amount: UInt64
    public let memo: String?
    public let timestamp: Int64
    public let signature: String
    public let status: String
    public let nonce: UInt64
    public let publicKeyEd25519: String
    public let feeUegoc: UInt64
    public let txType: String
    public let txVersion: Int
    public let chainId: Int

    enum CodingKeys: String, CodingKey {
        case hash, from, to, amount, memo, timestamp, signature, status, nonce
        case publicKeyEd25519 = "public_key_ed25519"
        case feeUegoc = "fee_uegoc"
        case txType = "tx_type"
        case txVersion = "tx_version"
        case chainId = "chain_id"
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(hash, forKey: .hash)
        try c.encode(from, forKey: .from)
        try c.encode(to, forKey: .to)
        try c.encode(amount, forKey: .amount)
        if let memo { try c.encode(memo, forKey: .memo) } else { try c.encodeNil(forKey: .memo) }
        try c.encode(timestamp, forKey: .timestamp)
        try c.encode(signature, forKey: .signature)
        try c.encode(status, forKey: .status)
        try c.encode(nonce, forKey: .nonce)
        try c.encode(publicKeyEd25519, forKey: .publicKeyEd25519)
        try c.encode(feeUegoc, forKey: .feeUegoc)
        try c.encode(txType, forKey: .txType)
        try c.encode(txVersion, forKey: .txVersion)
        try c.encode(chainId, forKey: .chainId)
    }
}

public enum Transactions {
    public static let maxMemoBytes = 256

    public static func signingBytesV2(
        from: String,
        to: String,
        amount: UInt64,
        nonce: UInt64,
        timestamp: Int64,
        chainId: UInt8,
        memo: String
    ) -> [UInt8] {
        let memoBytes = Array(memo.utf8.prefix(maxMemoBytes))
        let colon = UInt8(ascii: ":")
        var out = Array("ego/tx/v2:".utf8)
        out.append(chainId)
        out.append(colon)
        out.append(contentsOf: from.utf8)
        out.append(colon)
        out.append(contentsOf: to.utf8)
        out.append(colon)
        out.append(contentsOf: amount.littleEndianBytes)
        out.append(colon)
        out.append(contentsOf: nonce.littleEndianBytes)
        out.append(colon)
        out.append(contentsOf: UInt64(bitPattern: timestamp).littleEndianBytes)
        out.append(colon)
        out.append(contentsOf: UInt32(memoBytes.count).littleEndianBytes)
        out.append(contentsOf: memoBytes)
        return out
    }

    public static func transfer(
        key: EgoKey,
        to: String,
        amount: UInt64,
        nonce: UInt64,
        fee: UInt64,
        memo: String = "",
        timestamp: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> SignedTransaction {
        guard memo.utf8.count <= maxMemoBytes else { throw TransactionError.memoTooLong }
        guard EgoAddress.isValid(to) else { throw TransactionError.badRecipient }
        guard amount > 0 else { throw TransactionError.zeroAmount }
        return try sign(key: key, to: to, amount: amount, nonce: nonce, fee: fee, memo: memo, txType: "transfer", timestamp: timestamp)
    }

    public static func sign(
        key: EgoKey,
        to: String,
        amount: UInt64,
        nonce: UInt64,
        fee: UInt64,
        memo: String,
        txType: String,
        timestamp: Int64
    ) throws -> SignedTransaction {
        let from = key.address
        let bytes = signingBytesV2(from: from, to: to, amount: amount, nonce: nonce, timestamp: timestamp, chainId: EgoNetwork.chainId, memo: memo)
        let signature = try key.sign(bytes)
        return SignedTransaction(
            hash: "0x" + Hex.encode(Blake2s.hash(bytes)),
            from: from,
            to: to,
            amount: amount,
            memo: memo.isEmpty ? nil : memo,
            timestamp: timestamp,
            signature: Hex.encode(signature),
            status: "Pending",
            nonce: nonce,
            publicKeyEd25519: Hex.encode(key.publicKey),
            feeUegoc: fee,
            txType: txType,
            txVersion: 2,
            chainId: Int(EgoNetwork.chainId)
        )
    }
}

public enum Amount {
    public static let unitsPerEgoc: UInt64 = 1_000_000

    public static func parse(_ text: String) -> UInt64? {
        let trimmed = text.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ",", with: ".")
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        let whole = parts[0].isEmpty ? "0" : String(parts[0])
        let fraction = parts.count == 2 ? String(parts[1]) : ""
        guard whole.allSatisfy(\.isASCII), whole.allSatisfy(\.isNumber),
              fraction.allSatisfy(\.isASCII), fraction.allSatisfy(\.isNumber),
              fraction.count <= 6,
              let w = UInt64(whole) else { return nil }
        let f = UInt64(fraction.padding(toLength: 6, withPad: "0", startingAt: 0)) ?? 0
        let (scaled, overflow) = w.multipliedReportingOverflow(by: unitsPerEgoc)
        guard !overflow else { return nil }
        let (total, overflow2) = scaled.addingReportingOverflow(f)
        return overflow2 ? nil : total
    }

    public static func format(_ units: UInt64, maxDecimals: Int = 6) -> String {
        let whole = units / unitsPerEgoc
        var fraction = String(units % unitsPerEgoc)
        fraction = String(repeating: "0", count: 6 - fraction.count) + fraction
        fraction = String(fraction.prefix(maxDecimals))
        while fraction.hasSuffix("0") { fraction.removeLast() }
        let grouped = groupThousands(whole)
        return fraction.isEmpty ? grouped : "\(grouped).\(fraction)"
    }

    private static func groupThousands(_ value: UInt64) -> String {
        let digits = Array(String(value))
        var out = [Character]()
        for (i, d) in digits.enumerated() {
            if i > 0 && (digits.count - i) % 3 == 0 { out.append(",") }
            out.append(d)
        }
        return String(out)
    }
}
