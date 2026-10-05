import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public struct Gateway: Codable, Equatable, Hashable {
    public let endpoint: URL
    public let certSha256: String?
    public let node: String

    public init(endpoint: URL, certSha256: String?, node: String) {
        self.endpoint = endpoint
        self.certSha256 = certSha256
        self.node = node
    }

    enum CodingKeys: String, CodingKey {
        case endpoint, node
        case certSha256 = "cert_sha256"
    }
}

public enum GatewayError: Error, Equatable, LocalizedError {
    case unreachable(String)
    case http(Int)
    case rpc(Int, String)
    case badResponse

    public var errorDescription: String? {
        switch self {
        case .unreachable(let why): return "Couldn't reach the Ego network: \(why)"
        case .http(let code): return "The gateway answered with HTTP \(code)."
        case .rpc(_, let message): return message
        case .badResponse: return "The gateway sent an answer the app doesn't understand."
        }
    }
}

public struct Balance: Decodable, Equatable {
    public let uegoc: UInt64
}

public struct NonceInfo: Decodable, Equatable {
    public let lastConfirmed: UInt64
    public let next: UInt64
    public let feeUegoc: UInt64

    enum CodingKeys: String, CodingKey {
        case next
        case lastConfirmed = "last_confirmed"
        case feeUegoc = "fee_uegoc"
    }
}

public struct SubmitResult: Decodable, Equatable {
    public let txHash: String

    enum CodingKeys: String, CodingKey { case txHash = "tx_hash" }
}

public struct HistoryItem: Decodable, Equatable, Identifiable {
    public let hash: String
    public let from: String
    public let to: String
    public let amount: UInt64
    public let timestamp: Int64
    public let memo: String?
    public let txType: String?
    public let blockHeight: UInt64?
    public let feeUegoc: UInt64?

    public var id: String { hash }

    enum CodingKeys: String, CodingKey {
        case hash, from, to, amount, timestamp, memo
        case txType = "tx_type"
        case blockHeight = "block_height"
        case feeUegoc = "fee_uegoc"
    }
}

public struct ChatPostView: Decodable, Equatable, Identifiable {
    public let id: String
    public let from: String
    public let name: String
    public let body: String
    public let ts: Int64
    public let mine: Bool
    public let edited: Bool
    public let changeUntil: Int64?
    public let removalVotes: Int
    public let myVote: Bool
    public let removedUntil: Int64?

    enum CodingKeys: String, CodingKey {
        case id, from, name, body, ts, mine, edited
        case changeUntil = "change_until"
        case removalVotes = "removal_votes"
        case myVote = "my_vote"
        case removedUntil = "removed_until"
    }
}

public struct ChatFeed: Decodable, Equatable {
    public let me: String
    public let myName: String
    public let myRemovedUntil: Int64?
    public let threshold: Int
    public let banDays: Int
    public let posts: [ChatPostView]
    public let oldest: Int64?

    enum CodingKeys: String, CodingKey {
        case me, threshold, posts, oldest
        case myName = "my_name"
        case myRemovedUntil = "my_removed_until"
        case banDays = "ban_days"
    }
}

public struct StorageCapacity: Decodable, Equatable {
    public let providers: Int
    public let freeBytes: UInt64
    public let updatedAt: Int64

    enum CodingKeys: String, CodingKey {
        case providers
        case freeBytes = "free_bytes"
        case updatedAt = "updated_at"
    }
}

struct RPCRequest<P: Encodable>: Encodable {
    let jsonrpc = "2.0"
    let id: Int
    let method: String
    let params: P
}

struct RPCErrorBody: Decodable {
    let code: Int
    let message: String
}

struct RPCEnvelope<R: Decodable>: Decodable {
    let result: R?
    let error: RPCErrorBody?
}

struct Empty: Codable {}

public final class GatewayClient {
    public let gateway: Gateway
    private let session: URLSession
    private var nextId = 1
    private let lock = NSLock()

    public init(gateway: Gateway, timeout: TimeInterval = 20) {
        self.gateway = gateway
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        #if canImport(Security)
        self.session = URLSession(configuration: config, delegate: PinningDelegate(pin: gateway.certSha256), delegateQueue: nil)
        #else
        self.session = URLSession(configuration: config)
        #endif
    }

    private func requestId() -> Int {
        lock.lock()
        defer { lock.unlock() }
        nextId += 1
        return nextId
    }

    public func call<P: Encodable, R: Decodable>(_ method: String, _ params: P, as: R.Type = R.self) async throws -> R {
        var request = URLRequest(url: gateway.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RPCRequest(id: requestId(), method: method, params: params))
        let (data, response) = try await send(request)
        guard let http = response as? HTTPURLResponse else { throw GatewayError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw GatewayError.http(http.statusCode) }
        guard let envelope = try? JSONDecoder().decode(RPCEnvelope<R>.self, from: data) else { throw GatewayError.badResponse }
        if let error = envelope.error { throw GatewayError.rpc(error.code, error.message) }
        if let result = envelope.result { return result }
        if let nothing = try? JSONDecoder().decode(R.self, from: Data("null".utf8)) { return nothing }
        throw GatewayError.badResponse
    }

    func get(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await send(request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw GatewayError.badResponse
        }
        return data
    }

    private func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: request) { data, response, error in
                if let error {
                    continuation.resume(throwing: GatewayError.unreachable(error.localizedDescription))
                } else if let data, let response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(throwing: GatewayError.badResponse)
                }
            }
            task.resume()
        }
    }

    public func balance(of address: String) async throws -> Balance {
        try await call("wallet.getBalance", ["address": address])
    }

    public func nonce(of address: String) async throws -> NonceInfo {
        try await call("wallet.getNonce", ["address": address])
    }

    public func history(of address: String, limit: Int = 50) async throws -> [HistoryItem] {
        struct Params: Encodable { let address: String; let limit: Int }
        let items: [HistoryItem]? = try await call("wallet.getTransactionHistory", Params(address: address, limit: limit))
        return items ?? []
    }

    public func submit(_ tx: SignedTransaction) async throws -> SubmitResult {
        try await call("tx.submit", ["tx": tx])
    }

    public func isConfirmed(hash: String) async throws -> Bool {
        struct Found: Decodable { let hash: String; let status: String? }
        let found: Found? = try await call("wallet.getTransaction", ["hash": hash])
        return found?.hash == hash
    }

    public func chatFeed(viewer: String, before: Int64? = nil) async throws -> ChatFeed {
        struct Params: Encodable { let viewer: String; let before: Int64? }
        return try await call("chat.feed", Params(viewer: viewer, before: before))
    }

    public func chatSubmit(_ wire: ChatWire) async throws {
        struct Accepted: Decodable { let accepted: Bool }
        let _: Accepted = try await call("chat.submit", ["wire": wire])
    }

    public func storageCapacity() async throws -> StorageCapacity {
        try await call("storage.capacity", Empty())
    }
}

public enum CertificatePin {
    public static func sha256(of der: [UInt8]) -> String {
        Hex.encode(Array(SHA256.hash(data: Data(der))))
    }
}

#if canImport(Security)
import Security

final class PinningDelegate: NSObject, URLSessionDelegate {
    private let pin: String?

    init(pin: String?) {
        self.pin = pin?.lowercased()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let pin
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first,
              CertificatePin.sha256(of: Array(SecCertificateCopyData(leaf) as Data)) == pin
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
#endif
