import Foundation

struct LocalEvidenceHoldRecord: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let evidenceID: String
    let artifactSha256: String
    let active: Bool
    let updatedAt: String
    let actor: String
    let reason: String
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
        guard FileManager.default.fileExists(atPath: markerURL.path) else { return .none }
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        guard let data = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: markerURL, within: root,
                maximumBytes: ValidatedEvidenceArtifact.maximumSidecarBytes
              ),
              let record = try? JSONDecoder().decode(LocalEvidenceHoldRecord.self, from: data),
              record.schemaVersion == LocalEvidenceHoldRecord.currentSchemaVersion,
              record.evidenceID == entry.manifest.evidenceID,
              record.artifactSha256 == entry.manifest.sha256,
              ISO8601DateFormatter().date(from: record.updatedAt) != nil,
              !record.actor.isEmpty, record.actor.count <= 160,
              !record.reason.isEmpty, record.reason.count <= 2_000,
              entry.manifest.schemaVersion < 7
                || record.provenance?.keyID == entry.manifest.provenance?.keyID,
              LocalProvenance.verifyHold(record) else { return .invalid }
        return record.active ? .active(record) : .released(record)
    }

    @discardableResult
    static func set(
        entry: CaptureHistoryEntry, active: Bool, actor: String = NSFullUserName(),
        reason: String
    ) throws -> LocalEvidenceHoldRecord {
        _ = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: false)
        if FileManager.default.fileExists(atPath: url(for: entry.manifestURL).path),
           state(for: entry) == .invalid {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let cleanActor = String(actor.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        let cleanReason = String(reason.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2_000))
        guard !cleanActor.isEmpty, !cleanReason.isEmpty else { throw LocalEvidenceHoldFailure.invalidRecord }
        var record = LocalEvidenceHoldRecord(
            schemaVersion: LocalEvidenceHoldRecord.currentSchemaVersion,
            evidenceID: entry.manifest.evidenceID, artifactSha256: entry.manifest.sha256,
            active: active, updatedAt: ISO8601DateFormatter().string(from: Date()),
            actor: cleanActor, reason: cleanReason, provenance: nil
        )
        record.provenance = try LocalProvenance.signHold(record)
        guard entry.manifest.schemaVersion < 7
                || record.provenance?.keyID == entry.manifest.provenance?.keyID else {
            throw LocalEvidenceHoldFailure.invalidRecord
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let markerURL = url(for: entry.manifestURL)
        try encoder.encode(record).write(to: markerURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: markerURL.path)
        return record
    }
}
