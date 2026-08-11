import Foundation
import LocalAuthentication
import Security

enum KeychainStore {
    private struct DeviceCredential: Codable {
        let schemaVersion: Int
        let audience: String
        let token: String
    }
    private static let service = "com.scopeproof.capture"
    private static let account = "capture-device-token"
    private static let packageSigningAccount = "assessor-package-signing-key-v2-user-presence"
    private static let updateSequenceAccount = "verified-update-highest-sequence-v1"

    private static func readCredential() -> DeviceCredential? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        guard let credential = try? JSONDecoder().decode(DeviceCredential.self, from: data), credential.schemaVersion == 1 else { return nil }
        return credential
    }

    static func readToken(for audience: URL) -> String? {
        guard let credential = readCredential(), credential.audience == audience.absoluteString else { return nil }
        return credential.token
    }

    static func tokenAudience() -> String? { readCredential()?.audience }

    static func saveToken(_ token: String, audience: URL) throws {
        let data = try JSONEncoder().encode(DeviceCredential(schemaVersion: 1, audience: audience.absoluteString, token: token))
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    static func deleteToken() { SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account] as CFDictionary) }

    static func highestUpdateSequence() -> Int {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: updateSequenceAccount, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data, let text = String(data: data, encoding: .utf8), let value = Int(text) else { return 0 }
        return value
    }

    static func saveHighestUpdateSequence(_ sequence: Int) throws {
        guard sequence >= highestUpdateSequence() else { return }
        let data = Data(String(sequence).utf8)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: updateSequenceAccount]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var create = query; attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        } else if status != errSecSuccess { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    static func readPackageSigningKey() -> Data? {
        let context = LAContext()
        context.localizedReason = "Approve use of the Scopeproof assessor-package signing identity"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: packageSigningAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    static func savePackageSigningKey(_ data: Data) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.userPresence], &error) else {
            throw error?.takeRetainedValue() ?? NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))
        }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: packageSigningAccount]
        SecItemDelete(query as CFDictionary)
        var create = query
        create[kSecValueData as String] = data
        create[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(create as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

}
