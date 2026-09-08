import CryptoKit
import Foundation

enum EvidenceArchiveFailure: LocalizedError {
    case invalidArchive, incompleteHistory, changedHistory, restoreRequired, destinationMismatch
    var errorDescription: String? {
        switch self {
        case .invalidArchive: return "The archive descriptor, exact object versions, or device trust could not be verified. No evidence was expired or replaced."
        case .incompleteHistory: return "A complete signed capture, review, and legal-hold history is required. Legacy missing decisions cannot be reconstructed or replaced with an unsigned marker."
        case .changedHistory: return "Evidence or protected decision history changed during archival. The local payload was preserved; retry after review activity finishes."
        case .restoreRequired: return "This payload is archived. Restore its verified exact S3 versions on this Mac before preview, review, upload, or export."
        case .destinationMismatch: return "Archive recovery requires the original verified S3 destination and this Mac's existing trust keys and decision anchors."
        }
    }
}

struct EvidenceArchiveObject: Codable, Equatable, Sendable {
    let filename: String
    let objectKey: String
    let versionID: String
    let eTag: String
    let sha256: String
    let checksumSHA256: String
    let byteCount: Int
    let retainUntil: String
}

/// Durable restore recipe: contains the exact original signed manifest, not a
/// regenerated evidence ID or unsigned tombstone. Public keys adjacent to this
/// file are insufficient; validation requires existing device Keychain trust.
struct EvidenceArchiveRecord: Codable, Sendable {
    static let domain = "scopeproof-exact-version-evidence-archive-v1"
    let schemaVersion: Int
    let evidenceID: String
    let tenantID: String
    let workspaceID: String
    let relativeManifestPath: String
    let manifestData: Data
    let manifestSHA256: String
    let destination: [String: String]
    let createdAt: String
    let lifecycleHead: LocalTrustHead
    let holdHead: LocalTrustHead?
    let objects: [EvidenceArchiveObject]
    var provenance: LocalProvenanceSignature?

    var manifest: CaptureManifest? { try? JSONDecoder().decode(CaptureManifest.self, from: manifestData) }
}

struct EvidenceArchiveSnapshot: Sendable {
    let entry: CaptureHistoryEntry
    let artifact: ValidatedEvidenceArtifact
    let files: [ValidatedEvidenceFile]
    let lifecycleHead: LocalTrustHead
    let holdHead: LocalTrustHead?
}

enum LocalEvidenceArchive {
    static let maximumDescriptorBytes = 4 * 1024 * 1024

    static func url(for manifestURL: URL) -> URL {
        manifestURL.deletingPathExtension().appendingPathExtension("archive.json")
    }

    static func snapshot(_ entry: CaptureHistoryEntry, expectedBinding: TenantWorkspaceBinding) throws -> EvidenceArchiveSnapshot {
        guard entry.manifest.schemaVersion == 8, entry.manifest.belongs(to: expectedBinding) else { throw EvidenceArchiveFailure.incompleteHistory }
        // Inspect pre-existing anchors BEFORE any compatibility loader could
        // adopt a legacy head. Archival never migrates or resets trust anchors.
        let heads = try protectedHeads(entry)
        let artifact = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: expectedBinding)
        guard let last = artifact.lifecycle?.events.last,
              heads.0.matches(sequence: last.sequence, eventHash: last.eventHash, signingKeyID: last.provenance?.keyID ?? ""),
              LocalEvidenceHoldStore.hasCompleteHistory(for: entry) else { throw EvidenceArchiveFailure.incompleteHistory }
        switch LocalEvidenceHoldStore.state(for: entry) {
        case .active, .invalid: throw EvidenceArchiveFailure.incompleteHistory
        case .none, .released: break
        }
        let files = try ValidatedEvidenceArtifact.exportFiles(for: entry, expectedBinding: expectedBinding)
        return EvidenceArchiveSnapshot(entry: entry, artifact: artifact, files: files, lifecycleHead: heads.0, holdHead: heads.1)
    }

    static func makeRecord(snapshot: EvidenceArchiveSnapshot, objects: [EvidenceArchiveObject], destination: [String: String]) throws -> EvidenceArchiveRecord {
        guard let root = snapshot.entry.evidenceRoot, let binding = snapshot.artifact.manifest.tenantBinding else { throw EvidenceArchiveFailure.invalidArchive }
        let manifestPath = snapshot.entry.manifestURL.standardizedFileURL.path
        let rootPath = root.standardizedFileURL.path + "/"
        guard manifestPath.hasPrefix(rootPath) else { throw EvidenceArchiveFailure.invalidArchive }
        var record = EvidenceArchiveRecord(schemaVersion: 1, evidenceID: snapshot.entry.manifest.evidenceID,
            tenantID: binding.tenantID, workspaceID: binding.workspaceID,
            relativeManifestPath: String(manifestPath.dropFirst(rootPath.count)),
            manifestData: snapshot.artifact.manifestData, manifestSHA256: digest(snapshot.artifact.manifestData),
            destination: destination, createdAt: ISO8601DateFormatter().string(from: Date()),
            lifecycleHead: snapshot.lifecycleHead, holdHead: snapshot.holdHead, objects: objects, provenance: nil)
        record.provenance = try LocalProvenance.sign(
            payload: LocalProvenance.canonicalJSON(record, removingTopLevelKeys: ["provenance"]),
            domain: EvidenceArchiveRecord.domain, privateKeyData: KeychainStore.localArchivePrivateKey())
        _ = try validate(record, evidenceRoot: root, expectedBinding: binding)
        guard sameFiles(snapshot.files, record: record) else { throw EvidenceArchiveFailure.changedHistory }
        return record
    }

    static func load(at archiveURL: URL, evidenceRoot: URL, expectedBinding: TenantWorkspaceBinding) throws -> (EvidenceArchiveRecord, CaptureHistoryEntry) {
        let data = try ValidatedEvidenceArtifact.readBoundedRegularFile(at: archiveURL, within: evidenceRoot, maximumBytes: maximumDescriptorBytes)
        let record = try JSONDecoder().decode(EvidenceArchiveRecord.self, from: data)
        guard let original = try JSONSerialization.jsonObject(with: data) as? NSDictionary,
              let typed = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record)) as? NSDictionary,
              original == typed else { throw EvidenceArchiveFailure.invalidArchive }
        let entry = try validate(record, evidenceRoot: evidenceRoot, expectedBinding: expectedBinding)
        guard archiveURL.standardizedFileURL.path == url(for: entry.manifestURL).standardizedFileURL.path else { throw EvidenceArchiveFailure.invalidArchive }
        return (record, entry)
    }

    static func load(for entry: CaptureHistoryEntry, expectedBinding: TenantWorkspaceBinding) throws -> EvidenceArchiveRecord {
        guard let root = entry.evidenceRoot else { throw EvidenceArchiveFailure.invalidArchive }
        let (record, restoredEntry) = try load(at: url(for: entry.manifestURL), evidenceRoot: root, expectedBinding: expectedBinding)
        guard restoredEntry.manifestURL.standardizedFileURL.path == entry.manifestURL.standardizedFileURL.path,
              record.manifestData == (try ValidatedEvidenceArtifact.readBoundedRegularFile(at: entry.manifestURL, within: root, maximumBytes: ValidatedEvidenceArtifact.maximumManifestBytes)) else {
            throw EvidenceArchiveFailure.invalidArchive
        }
        return record
    }

    static func validate(_ record: EvidenceArchiveRecord, evidenceRoot: URL, expectedBinding: TenantWorkspaceBinding) throws -> CaptureHistoryEntry {
        let parts = record.relativeManifestPath.split(separator: "/", omittingEmptySubsequences: false)
        guard record.schemaVersion == 1, !parts.isEmpty, parts.count <= 32,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\\") }),
              record.relativeManifestPath.utf8.count <= 2_048,
              record.manifestData.count <= ValidatedEvidenceArtifact.maximumManifestBytes,
              record.manifestSHA256 == digest(record.manifestData),
              record.tenantID == expectedBinding.tenantID, record.workspaceID == expectedBinding.workspaceID,
              let manifest = record.manifest, manifest.schemaVersion == 8, manifest.belongs(to: expectedBinding),
              manifest.evidenceID == record.evidenceID, LocalProvenance.verifyManifest(manifest),
              manifest.chainEventHash == digest(Data("\(manifest.chainPreviousHash)|\(manifest.sha256)|\(manifest.evidenceID)|\(manifest.capturedAt)|\(manifest.sessionID)".utf8)),
              manifest.screenshotFilename == (manifest.screenshotFilename as NSString).lastPathComponent,
              ISO8601DateFormatter().date(from: record.createdAt) != nil,
              record.objects.count >= 3, record.objects.count <= 7,
              Set(record.objects.map(\.filename)).count == record.objects.count,
              Set(record.objects.map(\.objectKey)).count == record.objects.count,
              let signature = record.provenance, signature.keyID == KeychainStore.localArchiveSigningKeyID(),
              LocalProvenance.verify(signature, payload: try LocalProvenance.canonicalJSON(record, removingTopLevelKeys: ["provenance"]), domain: EvidenceArchiveRecord.domain),
              let anchor = try KeychainStore.captureChainAnchor(binding: expectedBinding),
              manifest.provenance?.keyID == anchor.signingKeyID,
              let sequence = manifest.chainSequence, sequence > 0, sequence <= anchor.sequence,
              sequence != anchor.sequence || manifest.chainEventHash == anchor.eventHash else { throw EvidenceArchiveFailure.invalidArchive }
        let manifestURL = evidenceRoot.appendingPathComponent(record.relativeManifestPath)
        let entry = CaptureHistoryEntry(manifest: manifest, manifestURL: manifestURL,
            imageURL: manifestURL.deletingLastPathComponent().appendingPathComponent(manifest.screenshotFilename),
            receiptURL: manifestURL.deletingPathExtension().appendingPathExtension("receipt.json"), evidenceRoot: evidenceRoot)
        guard CaptureHistory.isWithinReadableRoots(manifestURL, primaryDirectory: evidenceRoot, expectedBinding: expectedBinding),
              manifestURL.pathExtension == "json" else { throw EvidenceArchiveFailure.invalidArchive }
        let names = Set([entry.imageURL.lastPathComponent, entry.manifestURL.lastPathComponent,
            EvidenceLifecycleStore.url(for: entry.manifestURL).lastPathComponent,
            LocalEvidenceHoldStore.url(for: entry.manifestURL).lastPathComponent,
            entry.receiptURL.lastPathComponent, entry.jiraReceiptURL.lastPathComponent, entry.s3ReceiptURL.lastPathComponent])
        guard let prefix = record.destination["prefix"], !prefix.isEmpty,
              record.destination["securityProfile"] == S3SecurityProfile.production.rawValue,
              record.destination["retentionMode"] == S3RetentionMode.compliance.rawValue,
              record.objects.allSatisfy({ item in
                names.contains(item.filename) && item.filename == (item.filename as NSString).lastPathComponent
                    && item.objectKey.hasPrefix(prefix + "/") && item.objectKey.hasSuffix("/\(record.evidenceID)/\(item.filename)")
                    && !item.versionID.isEmpty && item.versionID != "null" && !item.eTag.isEmpty
                    && item.byteCount > 0 && item.byteCount <= ValidatedEvidenceArtifact.maximumImageBytes
                    && item.sha256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil
                    && Data(base64Encoded: item.checksumSHA256)?.map({ String(format: "%02x", $0) }).joined() == item.sha256
                    && ISO8601DateFormatter().date(from: item.retainUntil) != nil
              }),
              record.objects.first(where: { $0.filename == entry.imageURL.lastPathComponent })?.sha256 == manifest.sha256,
              record.objects.first(where: { $0.filename == entry.manifestURL.lastPathComponent })?.sha256 == record.manifestSHA256,
              record.objects.contains(where: { $0.filename == EvidenceLifecycleStore.url(for: entry.manifestURL).lastPathComponent }) else { throw EvidenceArchiveFailure.invalidArchive }
        guard record.objects.contains(where: { $0.filename == LocalEvidenceHoldStore.url(for: entry.manifestURL).lastPathComponent }) == (record.holdHead != nil) else {
            throw EvidenceArchiveFailure.invalidArchive
        }
        let heads = try protectedHeads(entry, requireHoldFile: false)
        guard heads.0 == record.lifecycleHead, heads.1 == record.holdHead else { throw EvidenceArchiveFailure.changedHistory }
        return entry
    }

    static func persist(_ record: EvidenceArchiveRecord, for entry: CaptureHistoryEntry, expectedBinding: TenantWorkspaceBinding) throws {
        guard let root = entry.evidenceRoot else { throw EvidenceArchiveFailure.invalidArchive }
        _ = try validate(record, evidenceRoot: root, expectedBinding: expectedBinding)
        let fresh = try snapshot(entry, expectedBinding: expectedBinding)
        guard sameFiles(fresh.files, record: record) else { throw EvidenceArchiveFailure.changedHistory }
        let data = try encoded(record)
        let destination = url(for: entry.manifestURL)
        try data.write(to: destination, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }

    /// The caller provides the real remote exact-version revalidation and Trash
    /// action. Tests use synthetic files and an isolated test-only trash folder.
    @MainActor
    static func expirePayload(for entry: CaptureHistoryEntry, expectedBinding: TenantWorkspaceBinding,
        remoteRevalidator: (EvidenceArchiveRecord) async throws -> Bool,
        trashPayload: (URL) throws -> Void) async throws {
        let record = try load(for: entry, expectedBinding: expectedBinding)
        guard try await remoteRevalidator(record) else { throw EvidenceArchiveFailure.invalidArchive }
        let fresh = try snapshot(entry, expectedBinding: expectedBinding)
        guard fresh.lifecycleHead == record.lifecycleHead, fresh.holdHead == record.holdHead,
              sameFiles(fresh.files, record: record) else { throw EvidenceArchiveFailure.changedHistory }
        guard let root = entry.evidenceRoot,
              CaptureHistory.captureChainIntegrity(CaptureHistory.entries(in: root, expectedBinding: expectedBinding), expectedBinding: expectedBinding) else {
            throw EvidenceArchiveFailure.incompleteHistory
        }
        try trashPayload(entry.imageURL)
        // The full signed manifest, review/hold ledger, receipts and descriptor
        // remain local; capture-chain anchors are deliberately untouched.
    }

    /// Verify every staged byte before publishing anything. Existing differing
    /// files are never overwritten; metadata is restored first, PNG last, making
    /// an interrupted restore safely retryable without creating new evidence IDs.
    static func restoreStagedFiles(_ files: [ValidatedEvidenceFile], record: EvidenceArchiveRecord,
        evidenceRoot: URL, expectedBinding: TenantWorkspaceBinding) throws {
        let entry = try validate(record, evidenceRoot: evidenceRoot, expectedBinding: expectedBinding)
        guard sameFiles(files, record: record),
              let image = files.first(where: { $0.sourceURL.lastPathComponent == entry.imageURL.lastPathComponent }),
              let manifest = files.first(where: { $0.sourceURL.lastPathComponent == entry.manifestURL.lastPathComponent }),
              let lifecycle = files.first(where: { $0.sourceURL.lastPathComponent == EvidenceLifecycleStore.url(for: entry.manifestURL).lastPathComponent }),
              manifest.data == record.manifestData else { throw EvidenceArchiveFailure.invalidArchive }
        let artifact = try ValidatedEvidenceArtifact.validateDownloaded(manifestData: manifest.data, imageData: image.data,
            manifestURL: entry.manifestURL, imageURL: entry.imageURL, requireLocalAnchor: true)
        let review = try JSONDecoder().decode(EvidenceLifecycleRecord.self, from: lifecycle.data)
        guard review.evidenceID == entry.manifest.evidenceID, review.schemaVersion == 4,
              EvidenceLifecycleStore.verify(review, artifactSha256: entry.manifest.sha256),
              let last = review.events.last,
              record.lifecycleHead.matches(sequence: last.sequence, eventHash: last.eventHash, signingKeyID: last.provenance?.keyID ?? "") else {
            throw EvidenceArchiveFailure.invalidArchive
        }
        if let holdHead = record.holdHead {
            guard let file = files.first(where: { $0.sourceURL.lastPathComponent == LocalEvidenceHoldStore.url(for: entry.manifestURL).lastPathComponent }),
                  let hold = try? JSONDecoder().decode(LocalEvidenceHoldRecord.self, from: file.data),
                  !hold.active, hold.evidenceID == entry.manifest.evidenceID, hold.artifactSha256 == entry.manifest.sha256,
                  LocalProvenance.verifyHold(hold), LocalEvidenceHoldStore.recordHasCompleteHistory(hold, entry: entry),
                  holdHead.matches(sequence: hold.sequence ?? 0, eventHash: hold.eventHash ?? "", signingKeyID: hold.provenance?.keyID ?? "") else {
                throw EvidenceArchiveFailure.invalidArchive
            }
        } else if FileManager.default.fileExists(atPath: LocalEvidenceHoldStore.url(for: entry.manifestURL).path) {
            throw EvidenceArchiveFailure.changedHistory
        }
        let stagingEntry = CaptureHistoryEntry(manifest: entry.manifest, manifestURL: manifest.sourceURL,
            imageURL: image.sourceURL, receiptURL: manifest.sourceURL.deletingPathExtension().appendingPathExtension("receipt.json"),
            evidenceRoot: manifest.sourceURL.deletingLastPathComponent())
        for kind in TransferReceiptKind.allCases where files.contains(where: { $0.sourceURL.lastPathComponent == TransferReceipt.url(for: stagingEntry, kind: kind).lastPathComponent }) {
            _ = try TransferReceipt.verified(for: stagingEntry, kind: kind, artifact: artifact)
        }
        for file in files {
            let source = try ValidatedEvidenceArtifact.readBoundedRegularFile(at: file.sourceURL,
                within: file.sourceURL.deletingLastPathComponent(), maximumBytes: ValidatedEvidenceArtifact.maximumImageBytes)
            guard source == file.data else { throw EvidenceArchiveFailure.changedHistory }
            let destination = entry.manifestURL.deletingLastPathComponent().appendingPathComponent(file.sourceURL.lastPathComponent)
            if FileManager.default.fileExists(atPath: destination.path) {
                let existing = try ValidatedEvidenceArtifact.readBoundedRegularFile(at: destination, within: evidenceRoot,
                    maximumBytes: ValidatedEvidenceArtifact.maximumImageBytes)
                guard existing == file.data else { throw EvidenceArchiveFailure.changedHistory }
            }
        }
        // Recheck anchors immediately before publication; never adopt snapshot heads.
        _ = try validate(record, evidenceRoot: evidenceRoot, expectedBinding: expectedBinding)
        for file in files.sorted(by: { ($0.sourceURL.lastPathComponent == entry.imageURL.lastPathComponent ? 1 : 0) < ($1.sourceURL.lastPathComponent == entry.imageURL.lastPathComponent ? 1 : 0) }) {
            let destination = entry.manifestURL.deletingLastPathComponent().appendingPathComponent(file.sourceURL.lastPathComponent)
            if !FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.moveItem(at: file.sourceURL, to: destination)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            }
        }
        _ = try ValidatedEvidenceArtifact.load(entry, requireLifecycle: true, expectedBinding: expectedBinding)
    }

    static func encoded(_ record: EvidenceArchiveRecord) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(record)
        guard data.count <= maximumDescriptorBytes else { throw EvidenceArchiveFailure.invalidArchive }
        return data
    }

    static func sameFiles(_ files: [ValidatedEvidenceFile], record: EvidenceArchiveRecord) -> Bool {
        guard files.count == record.objects.count else { return false }
        return files.allSatisfy { file in record.objects.contains { $0.filename == file.sourceURL.lastPathComponent && $0.byteCount == file.data.count && $0.sha256 == digest(file.data) } }
    }

    private static func protectedHeads(_ entry: CaptureHistoryEntry, requireHoldFile: Bool = true) throws -> (LocalTrustHead, LocalTrustHead?) {
        let lifecycleScope = EvidenceLifecycleStore.trustScope(for: entry)
        let holdScope = LocalEvidenceHoldStore.trustScope(for: entry)
        guard try KeychainStore.pendingLocalTrustAdvance(domain: .lifecycle, scope: lifecycleScope) == nil,
              try KeychainStore.pendingLocalTrustAdvance(domain: .legalHold, scope: holdScope) == nil,
              let lifecycle = try KeychainStore.localTrustHead(domain: .lifecycle, scope: lifecycleScope) else {
            throw EvidenceArchiveFailure.incompleteHistory
        }
        let hold = try KeychainStore.localTrustHead(domain: .legalHold, scope: holdScope)
        if requireHoldFile, FileManager.default.fileExists(atPath: LocalEvidenceHoldStore.url(for: entry.manifestURL).path) != (hold != nil) { throw EvidenceArchiveFailure.incompleteHistory }
        return (lifecycle, hold)
    }

    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
