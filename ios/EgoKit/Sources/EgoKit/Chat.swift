import Foundation

public enum ChatRules {
    public static let maxBodyCharacters = 500
    public static let maxNameCharacters = 24
    public static let maxLines = 12
    public static let changeWindow: Int64 = 3_600

    public static func cleanBody(_ raw: String) -> String? {
        let body = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty,
              body.unicodeScalars.count <= maxBodyCharacters,
              !body.unicodeScalars.contains(where: { $0.properties.generalCategory == .control && $0 != "\n" }),
              body.split(separator: "\n", omittingEmptySubsequences: false).count <= maxLines
        else { return nil }
        return body
    }

    public static func cleanName(_ raw: String) -> String? {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard name.unicodeScalars.count <= maxNameCharacters,
              !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control })
        else { return nil }
        return name
    }

    public static func canChange(postTimestamp: Int64, now: Int64) -> Bool {
        now >= postTimestamp && now - postTimestamp < changeWindow
    }
}

public struct ChatPost: Codable, Equatable {
    public let from: String
    public let name: String
    public let body: String
    public let ts: Int64
    public var pubkey: String
    public var sig: String

    public var signingBytes: [UInt8] {
        Array("ego/dao-chat/post/v1\n\(from)\n\(ts)\n\(name)\n\(body)".utf8)
    }

    public var id: String {
        String(Hex.encode(Blake2s.hash(signingBytes)).prefix(32))
    }
}

public struct ChatVote: Codable, Equatable {
    public let voter: String
    public let target: String
    public let ts: Int64
    public var pubkey: String
    public var sig: String

    public var signingBytes: [UInt8] {
        Array("ego/dao-chat/vote/v1\n\(voter)\n\(target)\n\(ts)".utf8)
    }
}

public struct ChatName: Codable, Equatable {
    public let from: String
    public let name: String
    public let ts: Int64
    public var pubkey: String
    public var sig: String

    public var signingBytes: [UInt8] {
        Array("ego/dao-chat/name/v1\n\(from)\n\(ts)\n\(name)".utf8)
    }
}

public struct ChatEdit: Codable, Equatable {
    public let from: String
    public let postId: String
    public let postTs: Int64
    public let body: String
    public let ts: Int64
    public var pubkey: String
    public var sig: String

    enum CodingKeys: String, CodingKey {
        case from, body, ts, pubkey, sig
        case postId = "post_id"
        case postTs = "post_ts"
    }

    public var signingBytes: [UInt8] {
        Array("ego/dao-chat/edit/v1\n\(from)\n\(postId)\n\(postTs)\n\(ts)\n\(body)".utf8)
    }
}

public struct ChatDelete: Codable, Equatable {
    public let from: String
    public let postId: String
    public let postTs: Int64
    public let ts: Int64
    public var pubkey: String
    public var sig: String

    enum CodingKeys: String, CodingKey {
        case from, ts, pubkey, sig
        case postId = "post_id"
        case postTs = "post_ts"
    }

    public var signingBytes: [UInt8] {
        Array("ego/dao-chat/delete/v1\n\(from)\n\(postId)\n\(postTs)\n\(ts)".utf8)
    }
}

public enum ChatWire: Encodable, Equatable {
    case post(ChatPost)
    case vote(ChatVote)
    case name(ChatName)
    case edit(ChatEdit)
    case delete(ChatDelete)

    private enum KindKey: String, CodingKey { case kind }

    public func encode(to encoder: Encoder) throws {
        var kind = encoder.container(keyedBy: KindKey.self)
        switch self {
        case .post(let p): try kind.encode("post", forKey: .kind); try p.encode(to: encoder)
        case .vote(let v): try kind.encode("vote", forKey: .kind); try v.encode(to: encoder)
        case .name(let n): try kind.encode("name", forKey: .kind); try n.encode(to: encoder)
        case .edit(let e): try kind.encode("edit", forKey: .kind); try e.encode(to: encoder)
        case .delete(let d): try kind.encode("delete", forKey: .kind); try d.encode(to: encoder)
        }
    }
}

public enum ChatSigner {
    private static func sign(_ bytes: [UInt8], key: EgoKey) throws -> (String, String) {
        (Hex.encode(key.publicKey), Hex.encode(try key.sign(bytes)))
    }

    public static func post(key: EgoKey, name: String, body: String, ts: Int64) throws -> ChatPost {
        var p = ChatPost(from: key.address, name: name, body: body, ts: ts, pubkey: "", sig: "")
        (p.pubkey, p.sig) = try sign(p.signingBytes, key: key)
        return p
    }

    public static func vote(key: EgoKey, target: String, ts: Int64) throws -> ChatVote {
        var v = ChatVote(voter: key.address, target: target, ts: ts, pubkey: "", sig: "")
        (v.pubkey, v.sig) = try sign(v.signingBytes, key: key)
        return v
    }

    public static func name(key: EgoKey, name: String, ts: Int64) throws -> ChatName {
        var n = ChatName(from: key.address, name: name, ts: ts, pubkey: "", sig: "")
        (n.pubkey, n.sig) = try sign(n.signingBytes, key: key)
        return n
    }

    public static func edit(key: EgoKey, postId: String, postTs: Int64, body: String, ts: Int64) throws -> ChatEdit {
        var e = ChatEdit(from: key.address, postId: postId, postTs: postTs, body: body, ts: ts, pubkey: "", sig: "")
        (e.pubkey, e.sig) = try sign(e.signingBytes, key: key)
        return e
    }

    public static func delete(key: EgoKey, postId: String, postTs: Int64, ts: Int64) throws -> ChatDelete {
        var d = ChatDelete(from: key.address, postId: postId, postTs: postTs, ts: ts, pubkey: "", sig: "")
        (d.pubkey, d.sig) = try sign(d.signingBytes, key: key)
        return d
    }
}
