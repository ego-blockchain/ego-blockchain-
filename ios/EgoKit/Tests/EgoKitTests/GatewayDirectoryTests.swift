import Foundation
import XCTest
@testable import EgoKit

final class MemoryStore: GatewayStore, @unchecked Sendable {
    private let lock = NSLock()
    private var saved: [CachedGateway] = []

    init(_ initial: [CachedGateway] = []) {
        saved = initial
    }

    func load() -> [CachedGateway] {
        lock.lock(); defer { lock.unlock() }
        return saved
    }

    func save(_ gateways: [CachedGateway]) {
        lock.lock(); defer { lock.unlock() }
        saved = gateways
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    private var stamp: Int64 = 1_800_000_000

    func bump() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
    var now: Int64 { lock.lock(); defer { lock.unlock() }; return stamp }
    func advance(_ seconds: Int64) { lock.lock(); stamp += seconds; lock.unlock() }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var state: Bool

    init(_ state: Bool) { self.state = state }
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return state }
        set { lock.lock(); state = newValue; lock.unlock() }
    }
}

final class GatewayDirectoryTests: XCTestCase {
    let cert = String(repeating: "ab", count: 32)

    func announcement(_ key: EgoKey, ip: String, ts: Int64) throws -> GatewayAnnouncement {
        let endpoint = "https://\(ip):47398/rpc"
        let unsigned = GatewayAnnouncement(endpoint: endpoint, certSha256: cert, node: key.address, ts: ts, pubkey: Hex.encode(key.publicKey), sig: "")
        let sig = try key.sign(unsigned.signingBytes)
        return GatewayAnnouncement(endpoint: endpoint, certSha256: cert, node: key.address, ts: ts, pubkey: Hex.encode(key.publicKey), sig: Hex.encode(sig))
    }

    func oracleCalls(_ directory: GatewayDirectory, _ counter: Counter, every step: Int64, for duration: Int64) async -> [Int64] {
        let start = counter.now
        var asked: [Int64] = []
        while counter.now - start <= duration {
            let before = counter.count
            _ = try? await directory.client()
            if counter.count > before { asked.append(counter.now - start) }
            counter.advance(step)
        }
        return asked
    }

    func testAnnouncementsMustBeSignedByTheNodeTheyName() throws {
        let key = EgoKey.generate()
        let good = try announcement(key, ip: "8.8.8.8", ts: 1_800_000_000)
        XCTAssertTrue(good.isAuthentic(now: 1_800_000_000))
        let moved = GatewayAnnouncement(endpoint: "https://1.1.1.1:47398/rpc", certSha256: cert, node: good.node, ts: good.ts, pubkey: good.pubkey, sig: good.sig)
        XCTAssertFalse(moved.isAuthentic(now: 1_800_000_000))
        let renamed = GatewayAnnouncement(endpoint: good.endpoint, certSha256: cert, node: EgoKey.generate().address, ts: good.ts, pubkey: good.pubkey, sig: good.sig)
        XCTAssertFalse(renamed.isAuthentic(now: 1_800_000_000))
        XCTAssertFalse(try announcement(key, ip: "192.168.1.4", ts: 1_800_000_000).isAuthentic(now: 1_800_000_000))
        XCTAssertFalse(try announcement(key, ip: "100.64.3.1", ts: 1_800_000_000).isAuthentic(now: 1_800_000_000))
        XCTAssertFalse(good.isAuthentic(now: 1_800_000_000 - 3_600), "announcements from the future are refused")
        XCTAssertTrue(good.isAuthentic(now: 1_800_000_000 + 86_400), "an old but genuine announcement is still worth trying")
        XCTAssertFalse(good.isAuthentic(now: 1_800_000_000 + 31 * 86_400), "a month-old announcement is refused")
        XCTAssertFalse(try announcement(key, ip: "8.8.8.8", ts: .min + 1).isAuthentic(now: 1_800_000_000))
    }

    func testSavedGatewaysAreUsedWithoutAskingTheOracle() async throws {
        let counter = Counter()
        let saved = try announcement(EgoKey.generate(), ip: "8.8.4.4", ts: 1_800_000_000)
        let store = MemoryStore([CachedGateway(announcement: saved, lastOK: 1_799_999_000, failures: 0)])
        let directory = GatewayDirectory(
            store: store,
            probe: { _ in true },
            fetchBootstrap: { counter.bump(); return [] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        let client = try await directory.client()
        XCTAssertEqual(client.gateway.endpoint.absoluteString, saved.endpoint)
        XCTAssertEqual(counter.count, 0)
    }

    func testTheOracleIsOnlyAskedWhenNothingAnswers() async throws {
        let counter = Counter()
        let dead = try announcement(EgoKey.generate(), ip: "9.9.9.9", ts: 1_800_000_000)
        let alive = try announcement(EgoKey.generate(), ip: "4.4.4.4", ts: 1_800_000_000)
        let directory = GatewayDirectory(
            store: MemoryStore([CachedGateway(announcement: dead, lastOK: nil, failures: 0)]),
            probe: { a in a.endpoint == alive.endpoint },
            fetchBootstrap: { counter.bump(); return [alive] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        let client = try await directory.client()
        XCTAssertEqual(client.gateway.endpoint.absoluteString, alive.endpoint)
        XCTAssertEqual(counter.count, 1)
        await directory.reportFailure()
        counter.advance(61)
        _ = try await directory.client()
        XCTAssertEqual(counter.count, 1, "a gateway that answers again needs no oracle")
    }

    func testTheOracleIsAskedLessAndLessWhileItCannotHelp() async throws {
        let counter = Counter()
        let dead = try announcement(EgoKey.generate(), ip: "9.9.9.9", ts: 1_800_000_000)
        let directory = GatewayDirectory(
            store: MemoryStore([CachedGateway(announcement: dead, lastOK: 1_799_000_000, failures: 0)]),
            probe: { _ in false },
            fetchBootstrap: { counter.bump(); return [] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        let asked = await oracleCalls(directory, counter, every: 60, for: 8 * 3_600)
        XCTAssertEqual(asked, [0, 1_200, 3_600, 8_400, 18_000])
    }

    func testAFreshInstallRetriesTheOracleQuicklyButStillBacksOff() async throws {
        let counter = Counter()
        let directory = GatewayDirectory(
            store: MemoryStore(),
            probe: { _ in false },
            fetchBootstrap: { counter.bump(); throw GatewayError.http(503) },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        let asked = await oracleCalls(directory, counter, every: 10, for: 1_800)
        XCTAssertEqual(asked, [0, 60, 180, 420, 900, 1_500])
    }

    func testBeingOfflineForgetsNothingAndANewNetworkStartsClean() async throws {
        let counter = Counter()
        let online = Flag(false)
        let saved = try (1...12).map { try announcement(EgoKey.generate(), ip: "5.5.5.\($0)", ts: 1_800_000_000) }
        let directory = GatewayDirectory(
            store: MemoryStore(saved.map { CachedGateway(announcement: $0, lastOK: 1_799_999_000, failures: 0) }),
            probe: { _ in online.value },
            fetchBootstrap: { counter.bump(); throw GatewayError.unreachable("offline") },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        _ = await oracleCalls(directory, counter, every: 60, for: 3_600)
        let known = await directory.known
        XCTAssertEqual(known.count, 12, "nothing is forgotten while offline")
        XCTAssertTrue(known.allSatisfy { $0.failures > 0 })

        online.value = true
        await directory.networkChanged()
        let before = counter.count
        let client = try await directory.client()
        XCTAssertTrue(saved.map(\.endpoint).contains(client.gateway.endpoint.absoluteString))
        XCTAssertEqual(counter.count, before, "saved gateways answer, so the oracle isn't asked")
    }

    func testFailedGatewaysCoolDownInsteadOfDisappearing() async throws {
        XCTAssertEqual(GatewayDirectory.cooldown(afterFailures: 0), 0)
        XCTAssertEqual(GatewayDirectory.cooldown(afterFailures: 1), 60)
        XCTAssertEqual(GatewayDirectory.cooldown(afterFailures: 2), 120)
        XCTAssertEqual(GatewayDirectory.cooldown(afterFailures: 10), 6 * 3_600)
        XCTAssertEqual(GatewayDirectory.cooldown(afterFailures: 500), 6 * 3_600)

        let counter = Counter()
        let flaky = try announcement(EgoKey.generate(), ip: "3.3.3.3", ts: 1_800_000_000)
        let up = Flag(false)
        let directory = GatewayDirectory(
            store: MemoryStore([CachedGateway(announcement: flaky, lastOK: 1_799_999_000, failures: 0)]),
            probe: { _ in up.value },
            fetchBootstrap: { counter.bump(); return [] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        _ = try? await directory.client()
        up.value = true
        do {
            _ = try await directory.client()
            XCTFail("a gateway that just failed waits out its cooldown")
        } catch {}
        counter.advance(61)
        _ = try await directory.client()
        let entry = await directory.known.first
        XCTAssertEqual(entry?.failures, 0)
        XCTAssertNil(entry?.lastFailure)
    }

    func testAFreshAnnouncementGivesAFailedGatewayAnotherChance() async throws {
        let counter = Counter()
        let key = EgoKey.generate()
        let old = try announcement(key, ip: "7.7.7.7", ts: counter.now - 3_600)
        let directory = GatewayDirectory(
            store: MemoryStore([CachedGateway(announcement: old, lastOK: nil, failures: 9, lastFailure: counter.now - 10)]),
            probe: { _ in true },
            fetchBootstrap: { [] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        await directory.merge([try announcement(key, ip: "7.7.7.7", ts: counter.now - 60)])
        let stale = await directory.known.first
        XCTAssertEqual(stale?.failures, 9, "an announcement older than the failure proves nothing")
        await directory.merge([try announcement(key, ip: "7.7.7.7", ts: counter.now)])
        let renewed = await directory.known.first
        XCTAssertEqual(renewed?.failures, 0)
        XCTAssertEqual(renewed?.announcement.ts, counter.now)
    }

    func testLongDeadGatewaysAreForgotten() async throws {
        let counter = Counter()
        let gone = try announcement(EgoKey.generate(), ip: "2.2.2.2", ts: counter.now - 20 * 86_400)
        let fine = try announcement(EgoKey.generate(), ip: "2.2.2.3", ts: counter.now - 20 * 86_400)
        let directory = GatewayDirectory(
            store: MemoryStore([
                CachedGateway(announcement: gone, lastOK: counter.now - 15 * 86_400, failures: 4, lastFailure: counter.now - 3_600),
                CachedGateway(announcement: fine, lastOK: counter.now - 15 * 86_400, failures: 0),
            ]),
            probe: { _ in true },
            fetchBootstrap: { [] },
            exchange: { _ in [] },
            clock: { counter.now }
        )
        await directory.merge([])
        let known = await directory.known.map(\.announcement.endpoint)
        XCTAssertEqual(known, [fine.endpoint])
    }

    func testGatewaysTeachThePhoneAboutMoreGateways() async throws {
        let counter = Counter()
        let first = try announcement(EgoKey.generate(), ip: "8.8.8.8", ts: 1_800_000_000)
        let more = try (1...3).map { try announcement(EgoKey.generate(), ip: "5.5.5.\($0)", ts: 1_800_000_000) }
        let forged = GatewayAnnouncement(endpoint: "https://6.6.6.6:47398/rpc", certSha256: cert, node: more[0].node, ts: more[0].ts, pubkey: more[0].pubkey, sig: more[0].sig)
        let store = MemoryStore([CachedGateway(announcement: first, lastOK: nil, failures: 0)])
        let directory = GatewayDirectory(
            store: store,
            probe: { _ in true },
            fetchBootstrap: { counter.bump(); return [] },
            exchange: { _ in more + [forged] },
            clock: { counter.now }
        )
        _ = try await directory.client()
        let known = await directory.known.map(\.announcement.endpoint)
        XCTAssertEqual(Set(known), Set([first.endpoint] + more.map(\.endpoint)), "forged entries are dropped")
        XCTAssertEqual(store.load().count, 4, "the list is saved for the next launch")
        XCTAssertEqual(counter.count, 0)
    }
}
