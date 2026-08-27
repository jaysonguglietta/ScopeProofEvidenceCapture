import Foundation
import Security

/// The only long-lived hosted credential the public Mac client persists.
/// Access and ID tokens should remain in memory and be replaced frequently.
struct HostedRefreshCredential: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case schemaVersion, tenantID, issuer, clientID, refreshToken, storedAt
    }

    let schemaVersion: Int
    let tenantID: String
    let issuer: String
    let clientID: String
    let refreshToken: String
    let storedAt: Date

    init(configuration: HostedOAuthConfiguration, refreshToken: String, storedAt: Date = Date()) throws {
        guard Self.isValidToken(refreshToken) else { throw HostedOAuthFailure.invalidRefreshToken }
        self.schemaVersion = 1
        self.tenantID = configuration.tenant.tenantID
        self.issuer = configuration.issuerURL.absoluteString
        self.clientID = configuration.clientID
        self.refreshToken = refreshToken
        self.storedAt = storedAt
    }

    func isBound(to configuration: HostedOAuthConfiguration) -> Bool {
        schemaVersion == 1
            && tenantID == configuration.tenant.tenantID
            && issuer == configuration.issuerURL.absoluteString
            && clientID == configuration.clientID
            && Self.isValidToken(refreshToken)
    }

    static func isValidToken(_ value: String) -> Bool {
        (20...16_384).contains(value.utf8.count)
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.unicodeScalars.contains(where: {
                CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains($0)
            })
    }
}

/// Injectable boundary so tests and future UI code never need to touch Security
/// framework APIs directly. There is deliberately no client-secret or AWS-key API.
protocol HostedRefreshTokenStoring: Sendable {
    func load(for configuration: HostedOAuthConfiguration) throws -> HostedRefreshCredential?
    func save(refreshToken: String, for configuration: HostedOAuthConfiguration, storedAt: Date) throws
    func delete(for configuration: HostedOAuthConfiguration) throws
}

struct HostedKeychainRefreshTokenStore: HostedRefreshTokenStoring, Sendable {
    private let service: String

    init(service: String = "com.scopeproof.capture.hosted-oauth") {
        self.service = service
    }

    func load(for configuration: HostedOAuthConfiguration) throws -> HostedRefreshCredential? {
        let query = baseQuery(for: configuration).merging([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]) { _, new in new }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw HostedOAuthFailure.keychainFailure(Int32(status))
        }
        guard data.count <= 20_000,
              let credential = try? JSONDecoder().decode(HostedRefreshCredential.self, from: data),
              credential.isBound(to: configuration) else {
            throw HostedOAuthFailure.keychainDataInvalid
        }
        return credential
    }

    func save(refreshToken: String, for configuration: HostedOAuthConfiguration, storedAt: Date = Date()) throws {
        let credential = try HostedRefreshCredential(
            configuration: configuration, refreshToken: refreshToken, storedAt: storedAt
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(credential)
        guard data.count <= 20_000 else { throw HostedOAuthFailure.invalidRefreshToken }

        let query = baseQuery(for: configuration)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var create = query
            attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else {
                throw HostedOAuthFailure.keychainFailure(Int32(createStatus))
            }
        } else if updateStatus != errSecSuccess {
            throw HostedOAuthFailure.keychainFailure(Int32(updateStatus))
        }
    }

    func delete(for configuration: HostedOAuthConfiguration) throws {
        let status = SecItemDelete(baseQuery(for: configuration) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw HostedOAuthFailure.keychainFailure(Int32(status))
        }
    }

    private func baseQuery(for configuration: HostedOAuthConfiguration) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: configuration),
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func account(for configuration: HostedOAuthConfiguration) -> String {
        let binding = [
            "scopeproof-hosted-refresh-v1",
            configuration.tenant.tenantID,
            configuration.issuerURL.absoluteString,
            configuration.clientID,
        ].joined(separator: "\u{1f}")
        return "refresh-v1-\(HostedSHA256.hexDigest(Data(binding.utf8)).prefix(40))"
    }
}
