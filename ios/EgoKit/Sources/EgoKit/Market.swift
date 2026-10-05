import Foundation

public enum MarketSide: String, Codable, CaseIterable, Sendable {
    case sell
    case buy
}

public enum MarketPrice: Decodable, Equatable, Sendable {
    case fixed(UInt64)
    case marginBps(Int)

    private enum Keys: String, CodingKey {
        case fixed
        case marginBps = "margin_bps"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        if let v = try c.decodeIfPresent(UInt64.self, forKey: .fixed) {
            self = .fixed(v)
        } else if let v = try c.decodeIfPresent(Int.self, forKey: .marginBps) {
            self = .marginBps(v)
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown price"))
        }
    }

    public func unitMicro(fiat: String, egocUsd: Double) -> UInt64? {
        switch self {
        case .fixed(let micro):
            return micro
        case .marginBps(let bps):
            guard fiat == "USD" else { return nil }
            let micro = egocUsd * 1_000_000 * (1 + Double(bps) / 10_000)
            guard micro.isFinite, micro >= 1, micro < Double(UInt64.max) else { return nil }
            return UInt64(micro.rounded())
        }
    }

    public var marginLabel: String? {
        guard case .marginBps(let bps) = self else { return nil }
        if bps == 0 { return "Market price" }
        let pct = Double(bps) / 100
        let text = String(format: "%.2f", pct).replacingOccurrences(of: #"\.?0+$"#, with: "", options: .regularExpression)
        return "Market \(pct > 0 ? "+" : "")\(text)%"
    }
}

public struct MarketOffer: Decodable, Identifiable, Equatable, Sendable {
    public let id: String
    public let maker: String
    public let side: MarketSide
    public let asset: String
    public let fiat: String
    public let price: MarketPrice
    public let minMicro: UInt64
    public let maxMicro: UInt64
    public let methods: [String]
    public let country: String?
    public let terms: String
    public let paymentWindowSecs: Int64
    public let createdAt: Int64
    public let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case id, maker, side, asset, fiat, price, methods, country, terms
        case minMicro = "min_micro"
        case maxMicro = "max_micro"
        case paymentWindowSecs = "payment_window_secs"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }
}

public struct MakerProfile: Decodable, Equatable, Sendable {
    public let completed: UInt64
    public let partners: UInt64
    public let positive: UInt64
    public let neutral: UInt64
    public let negative: UInt64
    public let volumeUegoc: UInt64
    public let disputesLost: UInt64
    public let firstTradeAt: Int64?

    enum CodingKeys: String, CodingKey {
        case completed, partners, positive, neutral, negative
        case volumeUegoc = "volume_uegoc"
        case disputesLost = "disputes_lost"
        case firstTradeAt = "first_trade_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        completed = try c.decodeIfPresent(UInt64.self, forKey: .completed) ?? 0
        partners = try c.decodeIfPresent(UInt64.self, forKey: .partners) ?? 0
        positive = try c.decodeIfPresent(UInt64.self, forKey: .positive) ?? 0
        neutral = try c.decodeIfPresent(UInt64.self, forKey: .neutral) ?? 0
        negative = try c.decodeIfPresent(UInt64.self, forKey: .negative) ?? 0
        volumeUegoc = try c.decodeIfPresent(UInt64.self, forKey: .volumeUegoc) ?? 0
        disputesLost = try c.decodeIfPresent(UInt64.self, forKey: .disputesLost) ?? 0
        firstTradeAt = try c.decodeIfPresent(Int64.self, forKey: .firstTradeAt)
    }

    public var positivePercent: Int? {
        let rated = positive + neutral + negative
        guard rated > 0 else { return nil }
        return Int((Double(positive) / Double(rated) * 100).rounded())
    }

    public var summary: String {
        guard completed > 0 else { return "New trader" }
        var parts = ["\(completed) trade\(completed == 1 ? "" : "s")"]
        if let pct = positivePercent { parts.append("\(pct)% positive") }
        if partners > 1 { parts.append("\(partners) partners") }
        return parts.joined(separator: " · ")
    }
}

public struct PaymentMethod: Identifiable, Hashable, Sendable {
    public let id: String
    public let label: String
}

public enum PaymentMethods {
    public static let all: [PaymentMethod] = [
        .init(id: "bank_transfer", label: "Bank transfer"),
        .init(id: "sepa", label: "SEPA"),
        .init(id: "sepa_instant", label: "SEPA Instant"),
        .init(id: "wise", label: "Wise"),
        .init(id: "revolut", label: "Revolut"),
        .init(id: "paypal", label: "PayPal"),
        .init(id: "zelle", label: "Zelle"),
        .init(id: "venmo", label: "Venmo"),
        .init(id: "cash_app", label: "Cash App"),
        .init(id: "interac", label: "Interac e-Transfer"),
        .init(id: "pix", label: "Pix"),
        .init(id: "upi", label: "UPI"),
        .init(id: "mpesa", label: "M-Pesa"),
        .init(id: "alipay", label: "Alipay"),
        .init(id: "cash_in_person", label: "Cash in person"),
    ]

    public static func label(_ id: String) -> String {
        if let known = all.first(where: { $0.id == id }) { return known.label }
        return id.split(whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

public func paymentWindowLabel(seconds: Int64) -> String {
    let minutes = Int64((Double(seconds) / 60).rounded())
    if minutes >= 60 && minutes % 60 == 0 { return "\(minutes / 60) h" }
    return "\(minutes) min"
}

public struct OfferListing: Decodable, Identifiable, Equatable, Sendable {
    public let offer: MarketOffer
    public let open: Bool
    public let makerProfile: MakerProfile

    public var id: String { offer.id }

    enum CodingKeys: String, CodingKey {
        case offer, open
        case makerProfile = "maker_profile"
    }
}

public struct OfferPage: Decodable, Equatable, Sendable {
    public let offers: [OfferListing]
    public let next: String?
}

public struct FiatCurrency: Identifiable, Hashable, Sendable {
    public let code: String
    public let name: String

    public var id: String { code }
}

public enum Fiat {
    public static let all: [FiatCurrency] = [
        .init(code: "USD", name: "US dollar"),
        .init(code: "EUR", name: "Euro"),
        .init(code: "GBP", name: "British pound"),
        .init(code: "CHF", name: "Swiss franc"),
        .init(code: "CAD", name: "Canadian dollar"),
        .init(code: "AUD", name: "Australian dollar"),
        .init(code: "JPY", name: "Japanese yen"),
        .init(code: "INR", name: "Indian rupee"),
        .init(code: "BRL", name: "Brazilian real"),
        .init(code: "MXN", name: "Mexican peso"),
        .init(code: "TRY", name: "Turkish lira"),
        .init(code: "NGN", name: "Nigerian naira"),
        .init(code: "KES", name: "Kenyan shilling"),
        .init(code: "ZAR", name: "South African rand"),
        .init(code: "AED", name: "UAE dirham"),
        .init(code: "PLN", name: "Polish zloty"),
        .init(code: "SEK", name: "Swedish krona"),
        .init(code: "ALL", name: "Albanian lek"),
    ]

    public static func decimals(_ code: String) -> Int {
        ["JPY", "KRW", "VND", "IDR", "CLP", "HUF", "ISK"].contains(code.uppercased()) ? 0 : 2
    }

    public static func format(micro: UInt64, code: String) -> String {
        let value = Double(micro) / 1_000_000
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.minimumFractionDigits = decimals(code)
        formatter.maximumFractionDigits = decimals(code)
        return "\(formatter.string(from: NSNumber(value: value)) ?? String(value)) \(code)"
    }

    public static func formatUnitPrice(micro: UInt64, code: String) -> String {
        let value = Double(micro) / 1_000_000
        let digits = value >= 100 ? 2 : value >= 1 ? 4 : value >= 0.01 ? 5 : 6
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.minimumFractionDigits = digits
        formatter.maximumFractionDigits = digits
        return "\(formatter.string(from: NSNumber(value: value)) ?? String(value)) \(code)"
    }
}

extension GatewayClient {
    public func marketOffers(asset: String = "EGOC", fiat: String = "USD", side: MarketSide, limit: Int = 50, cursor: String? = nil) async throws -> OfferPage {
        struct Params: Encodable { let asset: String; let fiat: String; let side: String; let limit: Int; let cursor: String? }
        return try await call("market.offers", Params(asset: asset, fiat: fiat, side: side.rawValue, limit: limit, cursor: cursor))
    }

    public func egocPriceUsd() async throws -> Double {
        struct Price: Decodable { let usd: Double }
        let p: Price = try await call("chain.getEgocPrice", Empty())
        return p.usd
    }
}
