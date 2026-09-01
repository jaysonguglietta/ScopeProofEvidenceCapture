import CryptoKit
import Foundation

struct LocalEvidenceHoldRecord: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let evidenceID: String
    let artifactSha256: String
    let active: Bool
    let updatedAt: String
    let actor: String
    let reason: String
    var sequence: Int? = nil
    var previousHash: String? = nil
    var eventHash: String? = nil
    var actorSubjectID: String? = nil
    var authenticationMethod: String? = nil
    var authenticatedAt: String? = nil
    var provenance: LocalProvenanceSignature?
}

enum LocalEvidenceHoldState: Equatable, Sendable {
    case none
    case active(LocalEvidenceHoldRecord)
    case released(LocalEvidenceHoldRecord)
    case invalid
}

enum LocalEvidenceHoldFailure: LocalizedError {
    case invalidEvidence
    case invalidRecord

    var errorDescription: String? {
        switch self {
        case .invalidEvidence:
            return "The evidence must pass local integrity validation before its legal-hold state can change."
        case .invalidRecord:
            return "The existing legal-hold marker failed signature or artifact-binding validation."
        }
    }
}

enum LocalEvidenceHoldStore {
    static func url(for manifestURL: URL) -> URL {
        manifestURL.deletingPathExtension().appendingPathExtension("hold.json")
    }

    static func state(for entry: CaptureHistoryEntry) -> LocalEvidenceHoldState {
        let markerURL = url(for: entry.manifestURL)
        let scope = trustScope(for: entry)
        guard FileManager.default.fileExists(atPath: markerURL.path) else {
            do {
                guard try KeychainStore.localTrustHead(domain: .legalHold, scope: scope) == nil,
                      try KeychainStore.pendingLocalTrustAdvance(
                        domain: .legalHold, scope: scope
                      ) == nil else { return .invalid }
                return .none
            } catch {
                return .invalid
            }
        }
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        guard let data = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: markerURL, within: root,
                maximumBytes: ValidatedEvidenceArtifact.maximumSidecarBytes
              ),
              let record = try? JSONDecoder().decode(LocalEvidenceHoldRecord.self, from: data),
              [1, LocalEvidenceHoldRecord.currentSchemaVersion].contains(record.schemaVersion),
              record.evidenceID == entry.manifest.evidenceID,
              record.artifactSha256 == entry.manifest.sha256,
              ISO8601DateFormatter().date(from: record.updatedAt) != nil,
              !record.actor.isEmpty, record.actor.count <= 160,
              !record.reason.isEmpty, record.reason.count <= 2_000,
              (record.schemaVersion != 1 || entry.manifest.schemaVersion < 7
                || record.provenance?.keyID == entry.manifest.provenance?.keyID),
              LocalProvenance.verifyHold(record),
              record.schemaVersion == 2
                ? verifyV2(record, entry: entry)
                : verifyAndAnchorLegacy(record, entry: entry) else { return .invalid }
        return record.active ? .active(record) : .released(record)
    }

    @discardableResult
    static func set(
        entry: CaptureHistoryEntry, active: Bool, actor: String = NSFullUserName(),
        reason: String, reviewerIdentity: LocalReviewerIdentity? = nil,
        privateKeyDataOverride: Data? = nil
    ) throws -> LocalEvidenceHoldRecord {
        _ = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
        if FileManager.default.fileExists(atPath: url(for: entry.manifestURL).path),
           state(for: entry) == .invalid {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let identity: LocalReviewerIdentity
        if let reviewerIdentity {
            identity = reviewerIdentity
        } else if privateKeyDataOverride != nil {
            identity = .testIdentity(actor)
        } else {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let cleanActor = String(identity.displayName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        let cleanReason = String(reason.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2_000))
        guard !cleanActor.isEmpty, !cleanReason.isEmpty, !identity.subjectID.isEmpty,
              ISO8601DateFormatter().date(from: identity.authenticatedAt) != nil else {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let existing = state(for: entry)
        let previousRecord: LocalEvidenceHoldRecord?
        switch existing {
        case .active(let record), .released(let record): previousRecord = record
        case .none: previousRecord = nil
        case .invalid: throw LocalEvidenceHoldFailure.invalidRecord
        }
        let scope = trustScope(for: entry)
        let previousHash: String
        let sequence: Int
        if let previousRecord, previousRecord.schemaVersion == 2 {
            previousHash = previousRecord.eventHash ?? ""
            sequence = (previousRecord.sequence ?? 0) + 1
        } else if previousRecord != nil {
            guard let migratedHead = try KeychainStore.localTrustHead(
                domain: .legalHold, scope: scope
            ) else { throw LocalEvidenceHoldFailure.invalidRecord }
            previousHash = migratedHead.eventHash
            sequence = migratedHead.sequence + 1
        } else {
            previousHash = "GENESIS"
            sequence = 1
        }
        let updatedAt = ISO8601DateFormatter().string(from: Date())
        let eventHash = digest([
            previousHash, entry.manifest.evidenceID, String(sequence),
            String(active), updatedAt, identity.subjectID, cleanActor, cleanReason
        ])
        var record = LocalEvidenceHoldRecord(
            schemaVersion: LocalEvidenceHoldRecord.currentSchemaVersion,
            evidenceID: entry.manifest.evidenceID, artifactSha256: entry.manifest.sha256,
            active: active, updatedAt: updatedAt,
            actor: cleanActor, reason: cleanReason,
            sequence: sequence, previousHash: previousHash, eventHash: eventHash,
            actorSubjectID: identity.subjectID,
            authenticationMethod: identity.authenticationMethod,
            authenticatedAt: identity.authenticatedAt,
            provenance: nil
        )
        record.provenance = try LocalProvenance.signHold(record, privateKeyData: privateKeyDataOverride)
        guard let keyID = record.provenance?.keyID else {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let advance = try KeychainStore.prepareLocalTrustAdvance(
            domain: .legalHold, scope: scope, previousHash: previousHash,
            sequence: sequence, eventHash: eventHash, signingKeyID: keyID
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let markerURL = url(for: entry.manifestURL)
        do {
            try encoder.encode(record).write(to: markerURL, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: markerURL.path)
        } catch {
            KeychainStore.cancelLocalTrustAdvance(advance, scope: scope)
            throw error
        }
        try KeychainStore.commitLocalTrustAdvance(advance, scope: scope)
        return record
    }

    private static func verifyV2(_ record: LocalEvidenceHoldRecord, entry: CaptureHistoryEntry) -> Bool {
        guard let sequence = record.sequence, sequence > 0,
              let previousHash = record.previousHash,
              let eventHash = record.eventHash,
              let subjectID = record.actorSubjectID, !subjectID.isEmpty,
              let method = record.authenticationMethod, !method.isEmpty,
              let authenticatedAt = record.authenticatedAt,
              ISO8601DateFormatter().date(from: authenticatedAt) != nil,
              digest([
                previousHash, record.evidenceID, String(sequence), String(record.active),
                record.updatedAt, subjectID, record.actor, record.reason
              ]) == eventHash,
              let keyID = record.provenance?.keyID else { return false }
        let scope = trustScope(for: entry)
        do {
            if try KeychainStore.recoverLocalTrustAdvance(
                domain: .legalHold, scope: scope, sequence: sequence,
                eventHash: eventHash, signingKeyID: keyID
            ) { return true }
            if try KeychainStore.localTrustHead(domain: .legalHold, scope: scope) == nil,
               try KeychainStore.pendingLocalTrustAdvance(domain: .legalHold, scope: scope) == nil {
                try KeychainStore.adoptLocalTrustHeadForMigration(
                    domain: .legalHold, scope: scope, sequence: sequence,
                    eventHash: eventHash, signingKeyID: keyID
                )
                return true
            }
        } catch { return false }
        return false
    }

    private static func verifyAndAnchorLegacy(
        _ record: LocalEvidenceHoldRecord, entry: CaptureHistoryEntry
    ) -> Bool {
        guard record.schemaVersion == 1, record.provenance != nil else { return false }
        let eventHash = digest([
            "legacy-v1", record.evidenceID, record.artifactSha256,
            String(record.active), record.updatedAt, record.actor, record.reason,
        ])
        let scope = trustScope(for: entry)
        do {
            let privateKey = try P256.Signing.PrivateKey(
                rawRepresentation: KeychainStore.localHoldPrivateKey()
            )
            let keyID = SHA256.hash(data: privateKey.publicKey.x963Representation)
                .map { String(format: "%02x", $0) }.joined()
            if let head = try KeychainStore.localTrustHead(domain: .legalHold, scope: scope) {
                return head.matches(sequence: 1, eventHash: eventHash, signingKeyID: keyID)
            }
            guard try KeychainStore.pendingLocalTrustAdvance(
                domain: .legalHold, scope: scope
            ) == nil else { return false }
            try KeychainStore.adoptLocalTrustHeadForMigration(
                domain: .legalHold, scope: scope, sequence: 1,
                eventHash: eventHash, signingKeyID: keyID
            )
            return try KeychainStore.localTrustHead(domain: .legalHold, scope: scope)?
                .matches(sequence: 1, eventHash: eventHash, signingKeyID: keyID) == true
        } catch {
            return false
        }
    }

    static func trustScope(for entry: CaptureHistoryEntry) -> String {
        let binding = entry.manifest.tenantBinding ?? .localDefault
        return [
            "legal-hold-v2", binding.tenantID, binding.workspaceID,
            entry.manifest.evidenceID, entry.manifest.sha256,
        ].map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
    }

    private static func digest(_ fields: [String]) -> String {
        let payload = fields.map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
        return SHA256.hash(data: Data(payload.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
