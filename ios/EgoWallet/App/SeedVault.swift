import Foundation
import LocalAuthentication
import Security

enum VaultError: LocalizedError {
    case keychain(OSStatus)
    case cancelled
    case noPasscode

    var errorDescription: String? {
        switch self {
        case .keychain(let status): return "The iPhone keychain refused the request (code \(status))."
        case .cancelled: return "Unlock was cancelled."
        case .noPasscode: return "Set a passcode on this iPhone first. Ego Wallet keeps your recovery key behind it."
        }
    }
}

struct SeedVault {
    private let service = "com.egoblockchain.wallet"
    private let account = "seed"
    private let addressKey = "ego.wallet.address"

    var storedAddress: String? {
        UserDefaults.standard.string(forKey: addressKey)
    }

    func store(seed: [UInt8], address: String) throws {
        delete()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            throw VaultError.noPasscode
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: Data(seed),
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecNotAvailable || status == errSecAuthFailed {
            throw VaultError.noPasscode
        }
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
        UserDefaults.standard.set(address, forKey: addressKey)
    }

    func readSeed(reason: String) async throws -> [UInt8] {
        let service = self.service
        let account = self.account
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let context = LAContext()
                context.localizedReason = reason
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context,
                ]
                var item: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &item)
                if status == errSecSuccess, let data = item as? Data, data.count == 32 {
                    continuation.resume(returning: [UInt8](data))
                } else if status == errSecUserCanceled {
                    continuation.resume(throwing: VaultError.cancelled)
                } else {
                    continuation.resume(throwing: VaultError.keychain(status))
                }
            }
        }
    }

    func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        UserDefaults.standard.removeObject(forKey: addressKey)
    }
}
