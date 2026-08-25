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
    private static let localAuditAccount = "local-console-audit-hmac-v1"
    private static let s3CredentialsAccount = "aws-s3-evidence-credentials-v1"
    private static let s3DestinationAccount = "aws-s3-verified-destination-v1"

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

    static func readS3Credentials() -> S3Credentials? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: s3CredentialsAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let credentials = try? JSONDecoder().decode(S3Credentials.self, from: data) else { return nil }
        if credentials.isExpired {
            deleteS3Credentials()
            return nil
        }
        return credentials
    }

    static func saveS3Credentials(_ credentials: S3Credentials) throws {
        let validated = try S3Credentials.validated(
            accessKeyID: credentials.accessKeyID, secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken, expiresAt: credentials.expiresAt
        )
        let data = try JSONEncoder().encode(validated)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: s3CredentialsAccount]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        deleteS3VerifiedDestination()
    }

    static func deleteS3Credentials() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: s3CredentialsAccount] as CFDictionary)
        deleteS3VerifiedDestination()
    }

    static func readS3VerifiedDestination() -> S3VerifiedDestination? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: s3DestinationAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let destination = try? JSONDecoder().decode(S3VerifiedDestination.self, from: data),
              destination.schemaVersion == 1 else { return nil }
        return destination
    }

    static func saveS3VerifiedDestination(_ destination: S3VerifiedDestination) throws {
        guard destination.schemaVersion == 1 else { throw S3StorageFailure.invalidResponse }
        let data = try JSONEncoder().encode(destination)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: s3DestinationAccount,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
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

    static func deleteS3VerifiedDestination() {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: s3DestinationAccount,
        ] as CFDictionary)
    }

    static func localAuditKey() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: localAuditAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let existingStatus = SecItemCopyMatching(query as CFDictionary, &item)
        if existingStatus == errSecSuccess, let data = item as? Data, data.count == 32 { return data }
        guard existingStatus == errSecItemNotFound else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(existingStatus)) }

        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard randomStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus)) }
        let create: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: localAuditAccount,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let createStatus = SecItemAdd(create as CFDictionary, nil)
        if createStatus == errSecDuplicateItem { return try localAuditKey() }
        guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        return bytes
    }

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
