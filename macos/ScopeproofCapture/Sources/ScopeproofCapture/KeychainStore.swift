import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum KeychainStore {
    private struct DeviceCredential: Codable {
        let schemaVersion: Int
        let audience: String
        let tenantID: String
        let workspaceID: String
        let token: String

        var binding: TenantWorkspaceBinding? {
            TenantWorkspaceBinding.validated(tenantID: tenantID, workspaceID: workspaceID)
        }
    }
    private static let service = "com.scopeproof.capture"
    private static let account = "capture-device-token"
    private static let packageSigningAccount = "assessor-package-signing-key-v2-user-presence"
    private static let updateSequenceAccount = "verified-update-highest-sequence-v1"
    private static let updateReleaseAccount = "verified-update-release-v2"
    private static let localAuditAccount = "local-console-audit-hmac-v1"
    private static let localProvenanceAccount = "local-evidence-provenance-p256-v1"
    private static let localLifecycleAccount = "local-lifecycle-provenance-p256-v1"
    private static let localHoldAccount = "local-hold-provenance-p256-v1"
    private static let captureChainAnchorAccount = "local-capture-chain-anchor-v1"
    private static let captureCommitJournalAccount = "local-capture-commit-journal-v1"
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
        guard let credential = try? JSONDecoder().decode(DeviceCredential.self, from: data),
              credential.schemaVersion == 2, credential.binding != nil else { return nil }
        return credential
    }

    static func readToken(for audience: URL) -> String? {
        guard let credential = readCredential(), credential.audience == audience.absoluteString else { return nil }
        return credential.token
    }

    static func readToken(for audience: URL, binding: TenantWorkspaceBinding) -> String? {
        guard let credential = readCredential(), credential.audience == audience.absoluteString,
              credential.binding == binding else { return nil }
        return credential.token
    }

    static func tokenAudience() -> String? { readCredential()?.audience }
    static func tokenBinding() -> TenantWorkspaceBinding? { readCredential()?.binding }

    static func saveToken(
        _ token: String, audience: URL, binding: TenantWorkspaceBinding
    ) throws {
        let data = try JSONEncoder().encode(DeviceCredential(
            schemaVersion: 2, audience: audience.absoluteString,
            tenantID: binding.tenantID, workspaceID: binding.workspaceID, token: token
        ))
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
            sessionToken: credentials.sessionToken, expiresAt: credentials.expiresAt,
            tenantID: credentials.tenantID, workspaceID: credentials.workspaceID
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
              let data = item as? Data else { return nil }
        return decodeS3VerifiedDestination(data)
    }

    static func decodeS3VerifiedDestination(_ data: Data) -> S3VerifiedDestination? {
        guard let destination = try? JSONDecoder().decode(S3VerifiedDestination.self, from: data),
              destination.schemaVersion == S3VerifiedDestination.currentSchemaVersion else { return nil }
        return destination
    }

    static func saveS3VerifiedDestination(_ destination: S3VerifiedDestination) throws {
        guard destination.schemaVersion == S3VerifiedDestination.currentSchemaVersion else {
            throw S3StorageFailure.invalidResponse
        }
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

    static func localAuditKey(binding: TenantWorkspaceBinding = .localDefault) throws -> Data {
        let auditAccount = localAuditAccountForBinding(binding)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: auditAccount,
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
            kSecAttrAccount as String: auditAccount,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let createStatus = SecItemAdd(create as CFDictionary, nil)
        if createStatus == errSecDuplicateItem { return try localAuditKey(binding: binding) }
        guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        return bytes
    }

    private static func localAuditAccountForBinding(_ binding: TenantWorkspaceBinding) -> String {
        if binding == .localDefault { return localAuditAccount }
        let digest = SHA256.hash(data: Data("\(binding.tenantID)\u{001f}\(binding.workspaceID)".utf8))
            .map { String(format: "%02x", $0) }.joined()
        return "local-console-audit-hmac-v2-\(digest)"
    }

    static func localProvenancePrivateKey() throws -> Data {
        try localSigningPrivateKey(account: localProvenanceAccount)
    }

    static func localLifecyclePrivateKey() throws -> Data {
        try localSigningPrivateKey(account: localLifecycleAccount)
    }

    static func localHoldPrivateKey() throws -> Data {
        try localSigningPrivateKey(account: localHoldAccount)
    }

    private static func localSigningPrivateKey(account: String) throws -> Data {
        if let existing = keychainData(account: account),
           (try? P256.Signing.PrivateKey(rawRepresentation: existing)) != nil {
            return existing
        }
        let key = P256.Signing.PrivateKey().rawRepresentation
        try saveKeychainData(
            key, account: account,
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
        return key
    }

    static func localTrustHead(domain: LocalTrustDomain, scope: String) throws -> LocalTrustHead? {
        let digest = trustScopeDigest(domain: domain, scope: scope)
        guard let data = keychainData(account: trustHeadAccount(domain: domain, digest: digest)) else { return nil }
        guard let head = try? JSONDecoder().decode(LocalTrustHead.self, from: data),
              head.isValid, head.domain == domain, head.scopeDigest == digest else {
            throw LocalProvenanceFailure.invalidAnchor
        }
        return head
    }

    static func pendingLocalTrustAdvance(
        domain: LocalTrustDomain, scope: String
    ) throws -> LocalTrustAdvance? {
        let digest = trustScopeDigest(domain: domain, scope: scope)
        guard let data = keychainData(account: trustPendingAccount(domain: domain, digest: digest)) else { return nil }
        guard let advance = try? JSONDecoder().decode(LocalTrustAdvance.self, from: data),
              advance.isValid, advance.domain == domain, advance.scopeDigest == digest else {
            throw LocalProvenanceFailure.invalidAnchor
        }
        return advance
    }

    @discardableResult
    static func prepareLocalTrustAdvance(
        domain: LocalTrustDomain, scope: String, previousHash: String,
        sequence: Int, eventHash: String, signingKeyID: String, now: Date = Date()
    ) throws -> LocalTrustAdvance {
        let digest = trustScopeDigest(domain: domain, scope: scope)
        let head = LocalTrustHead(
            schemaVersion: LocalTrustHead.currentSchemaVersion, domain: domain,
            scopeDigest: digest, sequence: sequence, eventHash: eventHash,
            signingKeyID: signingKeyID, anchoredAt: ISO8601DateFormatter().string(from: now)
        )
        let advance = LocalTrustAdvance(
            schemaVersion: LocalTrustAdvance.currentSchemaVersion, domain: domain,
            scopeDigest: digest, previousHash: previousHash, head: head
        )
        guard advance.isValid else { throw LocalProvenanceFailure.invalidAnchor }
        if let pending = try pendingLocalTrustAdvance(domain: domain, scope: scope) {
            guard pending == advance else { throw LocalProvenanceFailure.rollbackDetected }
            return pending
        }
        if let existing = try localTrustHead(domain: domain, scope: scope) {
            guard sequence == existing.sequence + 1, previousHash == existing.eventHash,
                  signingKeyID == existing.signingKeyID else {
                throw LocalProvenanceFailure.rollbackDetected
            }
        } else {
            guard sequence == 1, previousHash == "GENESIS" else {
                throw LocalProvenanceFailure.rollbackDetected
            }
        }
        try saveKeychainData(
            JSONEncoder().encode(advance), account: trustPendingAccount(domain: domain, digest: digest),
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
        return advance
    }

    static func commitLocalTrustAdvance(
        _ advance: LocalTrustAdvance, scope: String
    ) throws {
        guard advance.isValid,
              advance.scopeDigest == trustScopeDigest(domain: advance.domain, scope: scope),
              try pendingLocalTrustAdvance(domain: advance.domain, scope: scope) == advance else {
            throw LocalProvenanceFailure.rollbackDetected
        }
        try saveKeychainData(
            JSONEncoder().encode(advance.head),
            account: trustHeadAccount(domain: advance.domain, digest: advance.scopeDigest),
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
        deleteKeychainData(account: trustPendingAccount(domain: advance.domain, digest: advance.scopeDigest))
    }

    static func cancelLocalTrustAdvance(_ advance: LocalTrustAdvance, scope: String) {
        guard advance.scopeDigest == trustScopeDigest(domain: advance.domain, scope: scope) else { return }
        deleteKeychainData(account: trustPendingAccount(domain: advance.domain, digest: advance.scopeDigest))
    }

    static func recoverLocalTrustAdvance(
        domain: LocalTrustDomain, scope: String, sequence: Int,
        eventHash: String, signingKeyID: String
    ) throws -> Bool {
        if let head = try localTrustHead(domain: domain, scope: scope),
           head.matches(sequence: sequence, eventHash: eventHash, signingKeyID: signingKeyID) {
            if let pending = try pendingLocalTrustAdvance(domain: domain, scope: scope) {
                guard pending.previousHash == head.eventHash,
                      pending.head.sequence == head.sequence + 1,
                      pending.head.signingKeyID == head.signingKeyID else {
                    throw LocalProvenanceFailure.rollbackDetected
                }
                deleteKeychainData(account: trustPendingAccount(domain: domain, digest: head.scopeDigest))
            }
            return true
        }
        guard let pending = try pendingLocalTrustAdvance(domain: domain, scope: scope),
              pending.head.matches(sequence: sequence, eventHash: eventHash, signingKeyID: signingKeyID) else {
            return false
        }
        try commitLocalTrustAdvance(pending, scope: scope)
        return true
    }

    static func adoptLocalTrustHeadForMigration(
        domain: LocalTrustDomain, scope: String, sequence: Int,
        eventHash: String, signingKeyID: String, now: Date = Date()
    ) throws {
        guard try localTrustHead(domain: domain, scope: scope) == nil,
              try pendingLocalTrustAdvance(domain: domain, scope: scope) == nil else { return }
        let digest = trustScopeDigest(domain: domain, scope: scope)
        let head = LocalTrustHead(
            schemaVersion: LocalTrustHead.currentSchemaVersion, domain: domain,
            scopeDigest: digest, sequence: sequence, eventHash: eventHash,
            signingKeyID: signingKeyID, anchoredAt: ISO8601DateFormatter().string(from: now)
        )
        guard head.isValid else { throw LocalProvenanceFailure.invalidAnchor }
        try saveKeychainData(
            JSONEncoder().encode(head), account: trustHeadAccount(domain: domain, digest: digest),
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    private static func trustScopeDigest(domain: LocalTrustDomain, scope: String) -> String {
        SHA256.hash(data: Data("\(domain.rawValue)\u{001f}\(scope)".utf8))
            .map { String(format: "%02x", $0) }.joined()
    }

    private static func trustHeadAccount(domain: LocalTrustDomain, digest: String) -> String {
        "trust-head-v1-\(domain.rawValue)-\(digest)"
    }

    private static func trustPendingAccount(domain: LocalTrustDomain, digest: String) -> String {
        "trust-pending-v1-\(domain.rawValue)-\(digest)"
    }

    static func captureChainAnchor(
        binding: TenantWorkspaceBinding = .localDefault
    ) throws -> LocalCaptureChainAnchor? {
        let scopedAccount = captureChainAccount(binding: binding)
        var data = keychainData(account: scopedAccount)
        if data == nil, binding == .localDefault,
           let legacy = keychainData(account: captureChainAnchorAccount) {
            try saveKeychainData(
                legacy, account: scopedAccount,
                accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
            data = legacy
        }
        guard let data else { return nil }
        guard let anchor = try? JSONDecoder().decode(LocalCaptureChainAnchor.self, from: data),
              anchor.schemaVersion == LocalCaptureChainAnchor.currentSchemaVersion,
              anchor.sequence > 0,
              anchor.eventHash.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              anchor.signingKeyID.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              ISO8601DateFormatter().date(from: anchor.anchoredAt) != nil else {
            throw LocalProvenanceFailure.invalidAnchor
        }
        return anchor
    }

    static func captureCommitJournal() throws -> LocalCaptureCommitJournal? {
        guard let data = keychainData(account: captureCommitJournalAccount) else { return nil }
        guard let journal = try? JSONDecoder().decode(LocalCaptureCommitJournal.self, from: data),
              journal.isValid else { throw CaptureCommitRecoveryFailure.invalidJournal }
        return journal
    }

    static func beginCaptureCommitJournal(_ journal: LocalCaptureCommitJournal) throws {
        guard journal.isValid else { throw CaptureCommitRecoveryFailure.invalidJournal }
        guard try captureCommitJournal() == nil else { throw CaptureCommitRecoveryFailure.conflictingCapture }
        try saveKeychainData(
            JSONEncoder().encode(journal), account: captureCommitJournalAccount,
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    static func updateCaptureCommitJournal(_ journal: LocalCaptureCommitJournal) throws {
        guard journal.isValid, let existing = try captureCommitJournal(),
              existing.evidenceID == journal.evidenceID,
              existing.evidenceRootPath == journal.evidenceRootPath else {
            throw CaptureCommitRecoveryFailure.conflictingCapture
        }
        try saveKeychainData(
            JSONEncoder().encode(journal), account: captureCommitJournalAccount,
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    static func clearCaptureCommitJournal(evidenceID: String) {
        guard (try? captureCommitJournal()?.evidenceID) == evidenceID else { return }
        deleteKeychainData(account: captureCommitJournalAccount)
    }

    static func advanceCaptureChain(
        previousHash: String, sequence: Int, eventHash: String,
        signingKeyID: String, binding: TenantWorkspaceBinding = .localDefault,
        now: Date = Date()
    ) throws -> LocalCaptureChainAnchor {
        guard sequence > 0,
              previousHash == "GENESIS" || previousHash.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              eventHash.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              signingKeyID.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil else {
            throw LocalProvenanceFailure.invalidAnchor
        }
        if let existing = try captureChainAnchor(binding: binding) {
            guard sequence == existing.sequence + 1, previousHash == existing.eventHash,
                  signingKeyID == existing.signingKeyID else {
                throw LocalProvenanceFailure.rollbackDetected
            }
        } else if sequence != 1 || previousHash != "GENESIS" {
            throw LocalProvenanceFailure.rollbackDetected
        }
        let anchor = LocalCaptureChainAnchor(
            schemaVersion: LocalCaptureChainAnchor.currentSchemaVersion,
            sequence: sequence, eventHash: eventHash,
            signingKeyID: signingKeyID,
            anchoredAt: ISO8601DateFormatter().string(from: now)
        )
        try saveKeychainData(
            try JSONEncoder().encode(anchor), account: captureChainAccount(binding: binding),
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
        return anchor
    }

    private static func captureChainAccount(binding: TenantWorkspaceBinding) -> String {
        let digest = SHA256.hash(data: Data("\(binding.tenantID)\u{001f}\(binding.workspaceID)".utf8))
            .map { String(format: "%02x", $0) }.joined()
        return "local-capture-chain-anchor-v2-\(digest)"
    }

    static func captureChainScopeIdentifier(binding: TenantWorkspaceBinding) -> String {
        captureChainAccount(binding: binding)
    }

    private static func keychainData(account: String) -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    private static func saveKeychainData(
        _ data: Data, account: String, accessible: CFString
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            if createStatus == errSecDuplicateItem {
                let retryStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
                guard retryStatus == errSecSuccess else {
                    throw NSError(domain: NSOSStatusErrorDomain, code: Int(retryStatus))
                }
            } else if createStatus != errSecSuccess {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus))
            }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private static func deleteKeychainData(account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
    }

    static func verifiedUpdateRelease() -> VerifiedUpdateRelease? {
        guard let data = keychainData(account: updateReleaseAccount),
              let release = try? JSONDecoder().decode(VerifiedUpdateRelease.self, from: data),
              release.schemaVersion == 1, release.sequence > 0,
              release.version.range(of: "^\\d+\\.\\d+\\.\\d+$", options: .regularExpression) != nil,
              release.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { return nil }
        return release
    }

    static func verifiedUpdateFloor() -> VerifiedUpdateRelease? {
        if let release = verifiedUpdateRelease() { return release }
        let legacySequence = legacyHighestUpdateSequence()
        return legacySequence > 0 ? VerifiedUpdateRelease(sequence: legacySequence, version: "", sha256: "") : nil
    }

    static func legacyHighestUpdateSequence() -> Int {
        guard let data = keychainData(account: updateSequenceAccount),
              let text = String(data: data, encoding: .utf8), let value = Int(text), value > 0 else { return 0 }
        return value
    }

    static func saveVerifiedUpdateRelease(_ release: VerifiedUpdateRelease) throws {
        guard release.schemaVersion == 1, release.sequence > 0,
              release.version.range(of: "^\\d+\\.\\d+\\.\\d+$", options: .regularExpression) != nil,
              release.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {
            throw UpdateFailure.invalidMetadata("the verified release tuple is malformed")
        }
        if release.sequence < legacyHighestUpdateSequence() { throw UpdateFailure.rollback }
        if let previous = verifiedUpdateRelease() {
            if release.sequence < previous.sequence { throw UpdateFailure.rollback }
            if release.sequence == previous.sequence {
                guard release == previous else { throw UpdateFailure.rollback }
                return
            }
        } else if release.sequence == legacyHighestUpdateSequence(), legacyHighestUpdateSequence() > 0 {
            // The v1 record has no artifact digest. Never let an equal sequence acquire a new identity.
            throw UpdateFailure.rollback
        }
        let data = try JSONEncoder().encode(release)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: updateReleaseAccount]
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var create = query; attributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        } else if status != errSecSuccess { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }

        // Preserve a sequence-only floor for downgrade protection across upgrades from older builds.
        let sequenceData = Data(String(release.sequence).utf8)
        let sequenceQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: updateSequenceAccount]
        let sequenceAttributes: [String: Any] = [kSecValueData as String: sequenceData, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let sequenceStatus = SecItemUpdate(sequenceQuery as CFDictionary, sequenceAttributes as CFDictionary)
        if sequenceStatus == errSecItemNotFound {
            var create = sequenceQuery; sequenceAttributes.forEach { create[$0.key] = $0.value }
            let createStatus = SecItemAdd(create as CFDictionary, nil)
            guard createStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)) }
        } else if sequenceStatus != errSecSuccess { throw NSError(domain: NSOSStatusErrorDomain, code: Int(sequenceStatus)) }
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
