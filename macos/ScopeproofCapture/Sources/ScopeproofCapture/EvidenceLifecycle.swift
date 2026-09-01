import CryptoKit
import Foundation

enum EvidenceReviewStatus: String, Codable, CaseIterable, Sendable {
    case draft = "Draft"
    case inReview = "In Review"
    case approved = "Approved"
    case rejected = "Rejected"
    case superseded = "Superseded"

    var isPackageEligible: Bool { self == .approved }
}

struct EvidenceLifecycleEvent: Codable, Sendable {
    let sequence: Int
    let occurredAt: String
    let actor: String
    let action: String
    let status: EvidenceReviewStatus
    let owner: String
    let reviewer: String
    let reviewNotes: String
    let tags: [String]
    let supersedesEvidenceID: String?
    let artifactSha256: String
    let policyVersion: String
    let safetyScanPolicy: String
    let previousHash: String
    let eventHash: String
    var provenance: LocalProvenanceSignature?
}

struct EvidenceLifecycleRecord: Codable, Sendable {
    let schemaVersion: Int
    let evidenceID: String
    let events: [EvidenceLifecycleEvent]

    var status: EvidenceReviewStatus { events.last?.status ?? .draft }
    var owner: String { events.last?.owner ?? "" }
    var reviewer: String { events.last?.reviewer ?? "" }
    var reviewNotes: String { events.last?.reviewNotes ?? "" }
    var tags: [String] { events.last?.tags ?? [] }
    var supersedesEvidenceID: String? { events.last?.supersedesEvidenceID }
    var updatedAt: String { events.last?.occurredAt ?? "" }
}

enum EvidenceLifecycleFailure: LocalizedError {
    case integrityFailure

    var errorDescription: String? {
        "The existing review history is invalid or uses an obsolete unbound format. It cannot be changed or exported; recapture the evidence and review the new artifact."
    }
}

enum EvidenceLifecycleStore {
    static let policyVersion = "scopeproof-local-review-v2"

    static func url(for manifestURL: URL) -> URL {
        manifestURL.deletingPathExtension().appendingPathExtension("review.json")
    }

    static func load(for entry: CaptureHistoryEntry) -> EvidenceLifecycleRecord {
        let sidecar = url(for: entry.manifestURL)
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        guard let data = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: sidecar, within: root,
                maximumBytes: ValidatedEvidenceArtifact.maximumSidecarBytes
              ),
              let record = try? JSONDecoder().decode(EvidenceLifecycleRecord.self, from: data),
              record.evidenceID == entry.manifest.evidenceID,
              verify(
                record, artifactSha256: entry.manifest.sha256,
                provenanceKeyID: entry.manifest.provenance?.keyID
              ) else {
            return EvidenceLifecycleRecord(schemaVersion: 0, evidenceID: entry.manifest.evidenceID, events: [])
        }
        return record
    }

    @discardableResult
    static func update(
        entry: CaptureHistoryEntry, status: EvidenceReviewStatus, owner: String,
        reviewer: String, notes: String, tags: [String],
        supersedesEvidenceID: String? = nil,
        privateKeyDataOverride: Data? = nil,
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) throws -> EvidenceLifecycleRecord {
        // Lifecycle decisions are trust-bearing. Legacy schema-6 artifacts remain
        // browseable for migration, but cannot acquire a new review history.
        _ = try ValidatedEvidenceArtifact.load(
            entry, requireLifecycle: false, trustedAnchor: trustedAnchor
        )
        let sidecar = url(for: entry.manifestURL)
        let exists = FileManager.default.fileExists(atPath: sidecar.path)
        var record = load(for: entry)
        if exists && !verify(
            record, artifactSha256: entry.manifest.sha256,
            provenanceKeyID: entry.manifest.provenance?.keyID
        ) { throw EvidenceLifecycleFailure.integrityFailure }
        if !exists {
            record = EvidenceLifecycleRecord(
                schemaVersion: entry.manifest.schemaVersion >= 7 ? 3 : 2,
                evidenceID: entry.manifest.evidenceID, events: []
            )
        }
        let now = ISO8601DateFormatter().string(from: Date())
        let cleanOwner = String(owner.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        let cleanReviewer = String((reviewer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? NSFullUserName() : reviewer.trimmingCharacters(in: .whitespacesAndNewlines)).prefix(160))
        let cleanNotes = String(notes.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4_000))
        let cleanTags = Array(Set(tags.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty })).sorted().prefix(30)
        let cleanSupersedes = supersedesEvidenceID?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty
        let previousHash = record.events.last?.eventHash ?? "GENESIS"
        let sequence = record.events.count + 1
        let action = "status.\(status.rawValue.lowercased().replacingOccurrences(of: " ", with: "_"))"
        let safetyScanPolicy = entry.manifest.safetyScanPolicy ?? "legacy-unbound"
        let payload = eventPayload(
            evidenceID: entry.manifest.evidenceID, sequence: sequence, occurredAt: now, actor: cleanReviewer, action: action, status: status,
            owner: cleanOwner, reviewer: cleanReviewer, reviewNotes: cleanNotes, tags: Array(cleanTags), supersedesEvidenceID: cleanSupersedes,
            artifactSha256: entry.manifest.sha256, policyVersion: policyVersion, safetyScanPolicy: safetyScanPolicy, previousHash: previousHash
        )
        let eventHash = digest(payload)
        var event = EvidenceLifecycleEvent(
            sequence: sequence, occurredAt: now, actor: cleanReviewer, action: action, status: status, owner: cleanOwner, reviewer: cleanReviewer,
            reviewNotes: cleanNotes, tags: Array(cleanTags), supersedesEvidenceID: cleanSupersedes, artifactSha256: entry.manifest.sha256,
            policyVersion: policyVersion, safetyScanPolicy: safetyScanPolicy,
            previousHash: previousHash, eventHash: eventHash, provenance: nil
        )
        if record.schemaVersion == 3 {
            event.provenance = try LocalProvenance.signLifecycleEvent(
                event, evidenceID: record.evidenceID,
                privateKeyData: privateKeyDataOverride
            )
        }
        record = EvidenceLifecycleRecord(
            schemaVersion: record.schemaVersion, evidenceID: record.evidenceID,
            events: record.events + [event]
        )
        guard verify(
            record, artifactSha256: entry.manifest.sha256,
            provenanceKeyID: entry.manifest.provenance?.keyID
        ) else { throw EvidenceLifecycleFailure.integrityFailure }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(record).write(to: sidecar, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: sidecar.path)
        return record
    }

    static func verify(
        _ record: EvidenceLifecycleRecord, artifactSha256: String? = nil,
        provenanceKeyID expectedProvenanceKeyID: String? = nil
    ) -> Bool {
        guard [2, 3].contains(record.schemaVersion), !record.events.isEmpty else { return false }
        var previous = "GENESIS"
        var previousOccurredAt: Date?
        var seenHashes = Set<String>()
        var recordProvenanceKeyID: String?
        for (index, event) in record.events.enumerated() {
            guard event.sequence == index + 1, event.previousHash == previous, event.actor == event.reviewer,
                  event.action == "status.\(event.status.rawValue.lowercased().replacingOccurrences(of: " ", with: "_"))",
                  event.policyVersion == policyVersion, event.artifactSha256.count == 64,
                  event.artifactSha256.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
                  artifactSha256.map({ $0 == event.artifactSha256 }) ?? true,
                  !seenHashes.contains(event.eventHash), let occurredAt = ISO8601DateFormatter().date(from: event.occurredAt),
                  previousOccurredAt.map({ occurredAt >= $0 }) ?? true else { return false }
            let payload = eventPayload(
                evidenceID: record.evidenceID, sequence: event.sequence, occurredAt: event.occurredAt, actor: event.actor, action: event.action,
                status: event.status, owner: event.owner, reviewer: event.reviewer, reviewNotes: event.reviewNotes, tags: event.tags,
                supersedesEvidenceID: event.supersedesEvidenceID, artifactSha256: event.artifactSha256, policyVersion: event.policyVersion,
                safetyScanPolicy: event.safetyScanPolicy, previousHash: event.previousHash
            )
            guard digest(payload) == event.eventHash else { return false }
            if record.schemaVersion == 3 {
                guard let eventKeyID = event.provenance?.keyID,
                      expectedProvenanceKeyID.map({ $0 == eventKeyID }) ?? true,
                      recordProvenanceKeyID.map({ $0 == eventKeyID }) ?? true,
                      LocalProvenance.verifyLifecycleEvent(event, evidenceID: record.evidenceID) else { return false }
                recordProvenanceKeyID = eventKeyID
            } else if event.provenance != nil {
                return false
            }
            seenHashes.insert(event.eventHash)
            previous = event.eventHash
            previousOccurredAt = occurredAt
        }
        return true
    }

    private static func eventPayload(evidenceID: String, sequence: Int, occurredAt: String, actor: String, action: String, status: EvidenceReviewStatus, owner: String, reviewer: String, reviewNotes: String, tags: [String], supersedesEvidenceID: String?, artifactSha256: String, policyVersion: String, safetyScanPolicy: String, previousHash: String) -> Data {
        let values = [previousHash, evidenceID, String(sequence), occurredAt, actor, action, status.rawValue, owner, reviewer, reviewNotes, tags.joined(separator: "\u{001f}"), supersedesEvidenceID ?? "", artifactSha256, policyVersion, safetyScanPolicy]
        return Data(values.map { "\($0.utf8.count):\($0)" }.joined(separator: "|").utf8)
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
