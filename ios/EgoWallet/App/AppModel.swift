import EgoKit
import Foundation
import Network
import SwiftUI

enum WalletError: LocalizedError {
    case locked
    case offline

    var errorDescription: String? {
        switch self {
        case .locked: return "Unlock your wallet first."
        case .offline: return "You're offline. Connect to the internet and try again."
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        case onboarding
        case locked
        case ready
    }

    @Published var phase: Phase
    @Published var address = ""
    @Published var balance: UInt64?
    @Published var history: [HistoryItem] = []
    @Published var gatewayHost: String?
    @Published var problem: String?
    @Published var refreshing = false
    @Published private(set) var online = true

    private(set) var key: EgoKey?
    let vault = SeedVault()
    let directory: GatewayDirectory
    private let pathMonitor = NWPathMonitor()
    private var pathSignature = ""

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        directory = GatewayDirectory(store: FileGatewayStore(url: support.appendingPathComponent("gateways.json")))
        if let stored = vault.storedAddress {
            address = stored
            phase = .locked
        } else {
            phase = .onboarding
        }
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let online = path.status == .satisfied
            let signature = "\(online)|" + path.availableInterfaces.map { "\($0.type):\($0.name)" }.joined(separator: ",")
            Task { @MainActor [weak self] in
                self?.pathChanged(online: online, signature: signature)
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "com.egoblockchain.wallet.path"))
    }

    private func pathChanged(online: Bool, signature: String) {
        let wasOnline = self.online
        let changed = signature != pathSignature
        pathSignature = signature
        self.online = online
        guard online, changed else { return }
        let directory = self.directory
        Task {
            await directory.networkChanged()
            if !wasOnline && phase == .ready {
                await refresh()
            }
        }
    }

    func gateway() async throws -> GatewayClient {
        let client = try await directory.client()
        gatewayHost = client.gateway.endpoint.host
        return client
    }

    func perform<T>(_ work: (GatewayClient) async throws -> T) async throws -> T {
        guard online else { throw WalletError.offline }
        do {
            return try await work(try await gateway())
        } catch GatewayError.rpc(let code, let message) {
            throw GatewayError.rpc(code, message)
        } catch {
            guard online else { throw WalletError.offline }
            await directory.reportFailure()
            return try await work(try await gateway())
        }
    }

    func finishSetup(with key: EgoKey) throws {
        try vault.store(seed: key.seed, address: key.address)
        self.key = key
        address = key.address
        phase = .ready
        Task { await refresh() }
    }

    func unlock() async {
        do {
            let seed = try await vault.readSeed(reason: "Unlock your Ego wallet")
            key = try EgoKey(seed: seed)
            phase = .ready
            problem = nil
            await refresh()
        } catch VaultError.cancelled {
            problem = nil
        } catch {
            problem = message(for: error)
        }
    }

    func revealPhrase() async throws -> [String] {
        let seed = try await vault.readSeed(reason: "Show your recovery phrase")
        return Mnemonic.words(for: seed)
    }

    func lock() {
        guard vault.storedAddress != nil else { return }
        key = nil
        phase = .locked
    }

    func refresh() async {
        guard !address.isEmpty else { return }
        refreshing = true
        defer { refreshing = false }
        let address = self.address
        do {
            balance = try await perform { try await $0.balance(of: address).uegoc }
            history = try await perform { try await $0.history(of: address, limit: 50) }
            problem = nil
        } catch {
            problem = message(for: error)
        }
    }

    func networkFee() async -> UInt64? {
        let address = self.address
        return try? await perform { try await $0.nonce(of: address).feeUegoc }
    }

    func send(to recipient: String, amount: UInt64, memo: String) async throws -> String {
        guard let key else { throw WalletError.locked }
        let address = key.address
        let info = try await perform { try await $0.nonce(of: address) }
        let tx = try Transactions.transfer(key: key, to: recipient, amount: amount, nonce: info.next, fee: info.feeUegoc, memo: memo)
        var hash = tx.hash
        do {
            hash = try await perform { try await $0.submit(tx) }.txHash
        } catch {
            let submitted = tx.hash
            let landed = try? await perform({ try await $0.isConfirmed(hash: submitted) })
            guard landed == true else { throw error }
        }
        Task { await refresh() }
        return hash
    }

    func deleteWallet() {
        vault.delete()
        key = nil
        address = ""
        balance = nil
        history = []
        problem = nil
        phase = .onboarding
    }

    func message(for error: Error) -> String {
        if let error = error as? LocalizedError, let text = error.errorDescription {
            return text
        }
        return error.localizedDescription
    }
}
