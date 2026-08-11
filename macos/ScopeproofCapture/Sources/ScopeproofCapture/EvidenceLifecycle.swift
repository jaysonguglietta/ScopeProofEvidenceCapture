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
    let note: String
    let previousHash: String
    let eventHash: String
}

struct EvidenceLifecycleRecord: Codable, Sendable {
    let schemaVersion: Int
    let evidenceID: String
    var status: EvidenceReviewStatus
    var owner: String
    var reviewer: String
    var reviewNotes: String
    var tags: [String]
    var supersedesEvidenceID: String?
    var updatedAt: String
    var events: [EvidenceLifecycleEvent]
}

enum EvidenceLifecycleStore {
    static func url(for manifestURL: URL) -> URL {
        manifestURL.deletingPathExtension().appendingPathExtension("review.json")
    }

    static func load(for entry: CaptureHistoryEntry) -> EvidenceLifecycleRecord {
        let sidecar = url(for: entry.manifestURL)
        if let data = try? Data(contentsOf: sidecar), let record = try? JSONDecoder().decode(EvidenceLifecycleRecord.self, from: data), record.evidenceID == entry.manifest.evidenceID {
            return record
        }
        let contextOwner = entry.manifest.evidenceOwner ?? ""
        let contextTags = entry.manifest.tags ?? []
        return EvidenceLifecycleRecord(schemaVersion: 1, evidenceID: entry.manifest.evidenceID, status: .draft, owner: contextOwner, reviewer: "", reviewNotes: entry.manifest.reviewerNote ?? "", tags: contextTags, supersedesEvidenceID: nil, updatedAt: entry.manifest.capturedAt, events: [])
    }

    @discardableResult
    static func update(entry: CaptureHistoryEntry, status: EvidenceReviewStatus, owner: String, reviewer: String, notes: String, tags: [String], supersedesEvidenceID: String? = nil) throws -> EvidenceLifecycleRecord {
        var record = load(for: entry)
        let now = ISO8601DateFormatter().string(from: Date())
        let cleanTags = Array(Set(tags.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty })).sorted()
        let actor = reviewer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? NSFullUserName() : reviewer.trimmingCharacters(in: .whitespacesAndNewlines)
        let previousHash = record.events.last?.eventHash ?? "GENESIS"
        let sequence = record.events.count + 1
        let action = "status.\(status.rawValue.lowercased().replacingOccurrences(of: " ", with: "_"))"
        let canonical = "\(previousHash)|\(entry.manifest.evidenceID)|\(sequence)|\(now)|\(actor)|\(action)|\(notes)"
        let eventHash = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
        record.status = status
        record.owner = String(owner.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        record.reviewer = String(actor.prefix(160))
        record.reviewNotes = String(notes.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4_000))
        record.tags = Array(cleanTags.prefix(30))
        record.supersedesEvidenceID = supersedesEvidenceID?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty
        record.updatedAt = now
        record.events.append(EvidenceLifecycleEvent(sequence: sequence, occurredAt: now, actor: actor, action: action, note: record.reviewNotes, previousHash: previousHash, eventHash: eventHash))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let target = url(for: entry.manifestURL)
        try encoder.encode(record).write(to: target, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        return record
    }

    static func verify(_ record: EvidenceLifecycleRecord) -> Bool {
        var previous = "GENESIS"
        for (index, event) in record.events.enumerated() {
            guard event.sequence == index + 1, event.previousHash == previous else { return false }
            let canonical = "\(previous)|\(record.evidenceID)|\(event.sequence)|\(event.occurredAt)|\(event.actor)|\(event.action)|\(event.note)"
            let expected = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
            guard expected == event.eventHash else { return false }
            previous = event.eventHash
        }
        return true
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
