import Foundation
import XCTest
@testable import EgoKit

struct VectorFile: Decodable {
    struct WordlistInfo: Decodable { let count: Int; let blake2s: String; let duplicates: [String] }
    struct Key: Decodable { let seed: String; let publicKey: String; let address: String; let mnemonic: String; let roundtrip: String?; let signature: String }
    struct Tx: Decodable { let from: String; let to: String; let amount: String; let nonce: String; let timestamp: String; let chainId: Int; let memo: String; let signingBytes: String; let hash: String }
    struct Digest: Decodable { let input: String; let digest: String }
    struct Message: Decodable { let text: String; let bytes: String }
    let wordlist: WordlistInfo
    let keys: [Key]
    let tx: [Tx]
    let blake2s: [Digest]
    let message: Message
}

final class EgoKitTests: XCTestCase {
    let vectors = try! JSONDecoder().decode(VectorFile.self, from: Data(Vectors.json.utf8))

    func testBlake2sMatchesTheReference() {
        XCTAssertEqual(Hex.encode(Blake2s.hash(Array("abc".utf8))), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        for v in vectors.blake2s {
            XCTAssertEqual(Hex.encode(Blake2s.hash(Hex.decode(v.input)!)), v.digest, "input \(v.input.prefix(20))")
        }
    }

    func testWordlistIsTheDesktopList() {
        XCTAssertEqual(Wordlist.words.count, vectors.wordlist.count)
        XCTAssertEqual(Hex.encode(Blake2s.hash(Array(Wordlist.words.joined(separator: "\n").utf8))), vectors.wordlist.blake2s)
        let duplicates = Wordlist.words.enumerated().filter { Wordlist.words.firstIndex(of: $0.element) != $0.offset }.map(\.element)
        XCTAssertEqual(duplicates, vectors.wordlist.duplicates)
    }

    func testKeysAddressesAndPhrasesMatchTheExtension() throws {
        for v in vectors.keys {
            let key = try EgoKey(seed: Hex.decode(v.seed)!)
            XCTAssertEqual(Hex.encode(key.publicKey), v.publicKey)
            XCTAssertEqual(key.address, v.address)
            XCTAssertTrue(EgoAddress.isValid(key.address))
            XCTAssertEqual(key.phrase.joined(separator: " "), v.mnemonic)
            XCTAssertEqual(Mnemonic.seed(from: v.mnemonic).map { Hex.encode($0) }, v.seed)
            XCTAssertTrue(EgoKey.verify(signature: Hex.decode(v.signature)!, message: Array("ego vector".utf8), publicKey: key.publicKey))
            let mine = try key.sign(Array("ego vector".utf8))
            XCTAssertTrue(EgoKey.verify(signature: mine, message: Array("ego vector".utf8), publicKey: key.publicKey))
        }
    }

    func testAPhraseWithATypoIsRejected() {
        var words = vectors.keys[1].mnemonic.split(separator: " ").map(String.init)
        XCTAssertNil(Mnemonic.seed(from: Array(words.prefix(23))))
        words[3] = "notaword"
        XCTAssertNil(Mnemonic.seed(from: words))
        let first = vectors.keys[1].mnemonic.split(separator: " ").map(String.init)
        var swapped = first
        swapped.swapAt(0, 1)
        if swapped != first { XCTAssertNil(Mnemonic.seed(from: swapped)) }
    }

    func testSigningBytesAndHashesMatchTheNode() {
        for v in vectors.tx {
            let bytes = Transactions.signingBytesV2(
                from: v.from, to: v.to, amount: UInt64(v.amount)!, nonce: UInt64(v.nonce)!,
                timestamp: Int64(v.timestamp)!, chainId: UInt8(v.chainId), memo: v.memo)
            XCTAssertEqual(Hex.encode(bytes), v.signingBytes)
            XCTAssertEqual("0x" + Hex.encode(Blake2s.hash(bytes)), v.hash)
        }
    }

    func testATransferIsSignedTheWayTheNodeChecksIt() throws {
        let key = try EgoKey(seed: Hex.decode(vectors.keys[1].seed)!)
        let to = vectors.keys[2].address
        let tx = try Transactions.transfer(key: key, to: to, amount: 2_500_000, nonce: 7, fee: 1_000, memo: "lunch", timestamp: 1_800_000_000)
        let bytes = Transactions.signingBytesV2(from: key.address, to: to, amount: 2_500_000, nonce: 7, timestamp: 1_800_000_000, chainId: 1, memo: "lunch")
        XCTAssertEqual(tx.hash, "0x" + Hex.encode(Blake2s.hash(bytes)))
        XCTAssertTrue(EgoKey.verify(signature: Hex.decode(tx.signature)!, message: bytes, publicKey: key.publicKey))
        let json = String(decoding: try JSONEncoder().encode(tx), as: UTF8.self)
        for field in ["\"public_key_ed25519\"", "\"fee_uegoc\":1000", "\"tx_version\":2", "\"chain_id\":1", "\"tx_type\":\"transfer\"", "\"memo\":\"lunch\""] {
            XCTAssertTrue(json.contains(field), "missing \(field) in \(json)")
        }
        let empty = try Transactions.transfer(key: key, to: to, amount: 1, nonce: 8, fee: 1_000, timestamp: 1_800_000_000)
        XCTAssertTrue(String(decoding: try JSONEncoder().encode(empty), as: UTF8.self).contains("\"memo\":null"))
    }

    func testBadTransfersAreRefusedBeforeSigning() throws {
        let key = try EgoKey(seed: Hex.decode(vectors.keys[1].seed)!)
        XCTAssertThrowsError(try Transactions.transfer(key: key, to: "egot1notreal", amount: 1, nonce: 1, fee: 1))
        XCTAssertThrowsError(try Transactions.transfer(key: key, to: vectors.keys[2].address, amount: 0, nonce: 1, fee: 1))
        XCTAssertThrowsError(try Transactions.transfer(key: key, to: vectors.keys[2].address, amount: 1, nonce: 1, fee: 1, memo: String(repeating: "x", count: 257)))
    }

    func testSignedMessagesCarryThePrefix() {
        XCTAssertEqual(Hex.encode(SignedMessage.bytes(for: Array(vectors.message.text.utf8))), vectors.message.bytes)
    }

    func testAmountsParseExactly() {
        XCTAssertEqual(Amount.parse("1"), 1_000_000)
        XCTAssertEqual(Amount.parse("0.000001"), 1)
        XCTAssertEqual(Amount.parse("12.5"), 12_500_000)
        XCTAssertEqual(Amount.parse("12,5"), 12_500_000)
        XCTAssertEqual(Amount.parse(".5"), 500_000)
        XCTAssertNil(Amount.parse("0.0000001"))
        XCTAssertNil(Amount.parse("1.2.3"))
        XCTAssertNil(Amount.parse("abc"))
        XCTAssertNil(Amount.parse("-1"))
        XCTAssertNil(Amount.parse("99999999999999999999"))
        XCTAssertEqual(Amount.format(4_102_123_299), "4,102.123299")
        XCTAssertEqual(Amount.format(4_102_123_299, maxDecimals: 2), "4,102.12")
        XCTAssertEqual(Amount.format(1_000_000), "1")
    }

    func testChatBytesAndIdsMatchTheNode() throws {
        let from = "egot1yzwkx349luk82ksl0xe2tm6rfwj26t7pg5apncg2"
        let post = ChatPost(from: from, name: "Artit", body: "hello\nego", ts: 1_800_000_000, pubkey: "", sig: "")
        XCTAssertEqual(String(decoding: post.signingBytes, as: UTF8.self), "ego/dao-chat/post/v1\n\(from)\n1800000000\nArtit\nhello\nego")
        XCTAssertEqual(post.id, "cb73b6f6aed5d28c2e7546f860543c1e")
        let edit = ChatEdit(from: from, postId: post.id, postTs: post.ts, body: "hello again", ts: 1_800_000_003, pubkey: "", sig: "")
        XCTAssertEqual(String(decoding: edit.signingBytes, as: UTF8.self), "ego/dao-chat/edit/v1\n\(from)\ncb73b6f6aed5d28c2e7546f860543c1e\n1800000000\n1800000003\nhello again")
        let delete = ChatDelete(from: from, postId: post.id, postTs: post.ts, ts: 1_800_000_004, pubkey: "", sig: "")
        XCTAssertEqual(String(decoding: delete.signingBytes, as: UTF8.self), "ego/dao-chat/delete/v1\n\(from)\ncb73b6f6aed5d28c2e7546f860543c1e\n1800000000\n1800000004")
    }

    func testChatMessagesAreSignedAndTaggedForTheGateway() throws {
        let key = try EgoKey(seed: Hex.decode(vectors.keys[2].seed)!)
        let post = try ChatSigner.post(key: key, name: "Phone", body: "from my iPhone", ts: 1_800_000_000)
        XCTAssertEqual(post.from, key.address)
        XCTAssertTrue(EgoKey.verify(signature: Hex.decode(post.sig)!, message: post.signingBytes, publicKey: key.publicKey))
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(ChatWire.post(post))) as! [String: Any]
        XCTAssertEqual(json["kind"] as? String, "post")
        XCTAssertEqual(json["body"] as? String, "from my iPhone")
        let edit = try ChatSigner.edit(key: key, postId: post.id, postTs: post.ts, body: "edited", ts: 1_800_000_100)
        let editJson = try JSONSerialization.jsonObject(with: JSONEncoder().encode(ChatWire.edit(edit))) as! [String: Any]
        XCTAssertEqual(editJson["kind"] as? String, "edit")
        XCTAssertEqual(editJson["post_id"] as? String, post.id)
        XCTAssertEqual(editJson["post_ts"] as? Int, 1_800_000_000)
    }

    func testChatTextRulesMatchTheNode() {
        XCTAssertNil(ChatRules.cleanBody("   "))
        XCTAssertNil(ChatRules.cleanBody(String(repeating: "x", count: 501)))
        XCTAssertNil(ChatRules.cleanBody("bell\u{7}"))
        XCTAssertEqual(ChatRules.cleanBody("  two\nlines  "), "two\nlines")
        XCTAssertNil(ChatRules.cleanBody(Array(repeating: "l", count: 13).joined(separator: "\n")))
        XCTAssertEqual(ChatRules.cleanName("  Artit "), "Artit")
        XCTAssertNil(ChatRules.cleanName(String(repeating: "n", count: 25)))
        XCTAssertNil(ChatRules.cleanName("tab\there"))
        XCTAssertTrue(ChatRules.canChange(postTimestamp: 1_000, now: 1_000 + 3_599))
        XCTAssertFalse(ChatRules.canChange(postTimestamp: 1_000, now: 1_000 + 3_600))
    }

    func testANullResultMeansNothingOnlyWhereNothingIsAllowed() throws {
        struct Found: Decodable { let hash: String }
        let envelope = try JSONDecoder().decode(RPCEnvelope<Found?>.self, from: Data(#"{"jsonrpc":"2.0","id":3,"result":null}"#.utf8))
        XCTAssertNil(envelope.result ?? nil)
        XCTAssertNoThrow(try JSONDecoder().decode(Found?.self, from: Data("null".utf8)))
        XCTAssertThrowsError(try JSONDecoder().decode(Found.self, from: Data("null".utf8)))
    }

    func testBech32mRoundTripsAndRejectsTypos() {
        let address = vectors.keys[0].address
        XCTAssertNotNil(Bech32m.decode(address))
        var chars = Array(address)
        chars[10] = chars[10] == "q" ? "p" : "q"
        XCTAssertNil(Bech32m.decode(String(chars)))
        XCTAssertFalse(EgoAddress.isValid("ego1" + address.dropFirst(5)))
    }
}

final class MarketModelTests: XCTestCase {
    func testOffersDecodeTheNodeFormat() throws {
        let json = #"""
        {"offers":[{"offer":{"id":"o1","maker":"egot1abc","side":"sell","asset":"EGOC","fiat":"USD","price":{"fixed":1250000},"min_micro":10000000,"max_micro":500000000,"methods":["wise","revolut"],"country":null,"terms":"Fast","payment_window_secs":1800,"created_height":10,"created_at":1800000000,"expires_at":1800600000,"closed_height":null,"maker_key":"aa"},"open":true,"maker_profile":{"completed":12,"partners":9,"positive":11,"neutral":1,"negative":0,"volume_uegoc":5000000,"disputes_lost":0,"first_trade_at":1790000000}},
        {"offer":{"id":"o2","maker":"egot1def","side":"sell","asset":"EGOC","fiat":"EUR","price":{"margin_bps":-150},"min_micro":1,"max_micro":2,"methods":[],"terms":"","payment_window_secs":900,"created_height":11,"created_at":1800000001,"expires_at":1800600001},"open":false,"maker_profile":{}}],"next":null}
        """#
        let page = try JSONDecoder().decode(OfferPage.self, from: Data(json.utf8))
        XCTAssertEqual(page.offers.count, 2)
        XCTAssertEqual(page.offers[0].offer.price, .fixed(1_250_000))
        XCTAssertEqual(page.offers[0].makerProfile.positivePercent, 92)
        XCTAssertEqual(page.offers[1].offer.price, .marginBps(-150))
        XCTAssertNil(page.offers[1].makerProfile.positivePercent)
        XCTAssertEqual(MarketPrice.marginBps(-150).unitMicro(fiat: "USD", egocUsd: 2.0), 1_970_000)
        XCTAssertNil(MarketPrice.marginBps(-150).unitMicro(fiat: "EUR", egocUsd: 2.0))
        XCTAssertEqual(MarketPrice.marginBps(100).unitMicro(fiat: "USD", egocUsd: 0.008), 8_080)
        XCTAssertEqual(MarketPrice.marginBps(-150).marginLabel, "Market -1.5%")
        XCTAssertEqual(MarketPrice.marginBps(0).marginLabel, "Market price")
        XCTAssertEqual(MarketPrice.fixed(1).unitMicro(fiat: "EUR", egocUsd: 0), 1)
        XCTAssertNil(MarketPrice.marginBps(10).unitMicro(fiat: "USD", egocUsd: 0))
        XCTAssertNil(MarketPrice.marginBps(10).unitMicro(fiat: "USD", egocUsd: .nan))
        XCTAssertEqual(page.offers[0].makerProfile.summary, "12 trades · 92% positive · 9 partners")
        XCTAssertEqual(page.offers[1].makerProfile.summary, "New trader")
    }

    func testLabelsMatchTheDesktop() {
        XCTAssertEqual(PaymentMethods.label("sepa_instant"), "SEPA Instant")
        XCTAssertEqual(PaymentMethods.label("local_bank-x"), "Local Bank X")
        XCTAssertEqual(paymentWindowLabel(seconds: 1_800), "30 min")
        XCTAssertEqual(paymentWindowLabel(seconds: 7_200), "2 h")
        XCTAssertEqual(paymentWindowLabel(seconds: 5_400), "90 min")
        XCTAssertEqual(Fiat.all.count, 18)
        XCTAssertEqual(Set(Fiat.all.map(\.code)).count, 18)
    }
}
