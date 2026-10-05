import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum EgoNetwork {
    public static let chainId: UInt8 = 1
    public static let hrp = "egot"
}

public enum EgoAddress {
    private static let domain = Array("ego/addr/v1".utf8)
    private static let version: UInt8 = 0b001
    private static let eoa: UInt8 = 0

    public static func from(publicKey: [UInt8]) -> String {
        var input = domain
        input.append(contentsOf: UInt32(EgoNetwork.chainId).littleEndianBytes)
        input.append(contentsOf: publicKey)
        let digest = Blake2s.hash(input)
        var payload = [UInt8]()
        payload.append(version << 5 | eoa)
        payload.append(contentsOf: digest[0..<20])
        return Bech32m.encode(hrp: EgoNetwork.hrp, payload: payload)
    }

    public static func isValid(_ address: String) -> Bool {
        guard let decoded = Bech32m.decode(address) else { return false }
        return decoded.hrp == EgoNetwork.hrp && decoded.payload.count == 21
    }
}

public enum EgoKeyError: Error, Equatable {
    case badSeed
}

public struct EgoKey {
    public let seed: [UInt8]
    private let signing: Curve25519.Signing.PrivateKey

    public init(seed: [UInt8]) throws {
        guard seed.count == 32 else { throw EgoKeyError.badSeed }
        self.seed = seed
        self.signing = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
    }

    public static func generate() -> EgoKey {
        try! EgoKey(seed: SecureRandom.bytes(32))
    }

    public var publicKey: [UInt8] {
        Array(signing.publicKey.rawRepresentation)
    }

    public var address: String {
        EgoAddress.from(publicKey: publicKey)
    }

    public var phrase: [String] {
        Mnemonic.words(for: seed)
    }

    public func sign(_ message: [UInt8]) throws -> [UInt8] {
        Array(try signing.signature(for: Data(message)))
    }

    public static func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKey)) else { return false }
        return key.isValidSignature(Data(signature), for: Data(message))
    }
}

public enum SignedMessage {
    public static let prefix = "\u{19}Ego Signed Message:\n"

    public static func bytes(for message: [UInt8]) -> [UInt8] {
        Array("\(prefix)\(message.count)\n".utf8) + message
    }

    public static func sign(_ message: [UInt8], with key: EgoKey) throws -> [UInt8] {
        try key.sign(bytes(for: message))
    }
}
