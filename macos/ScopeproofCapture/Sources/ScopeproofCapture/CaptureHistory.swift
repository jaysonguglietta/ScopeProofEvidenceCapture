import CryptoKit
import Foundation

enum LocalRetentionFailure: LocalizedError {
    case durableHistoryRequired

    var errorDescription: String? {
        "Legacy whole-record cleanup is disabled. Use Archive & Expire Old Payloads to preserve signed history and revalidate exact S3 versions before moving only PNGs to Trash. No local files were changed."
    }
}

struct LocalRetentionReport: Equatable, Sendable {
    var movedToTrash = 0
    var skippedLegalHold = 0
    var skippedWithoutDurableCopy = 0
    var skippedInvalidEvidence = 0
}

struct CaptureHistoryEntry: Sendable {
    let manifest: CaptureManifest
    let manifestURL: URL
    let imageURL: URL
    let receiptURL: URL
    let evidenceRoot: URL?

    init(
        manifest: CaptureManifest, manifestURL: URL, imageURL: URL,
        receiptURL: URL, evidenceRoot: URL? = nil
    ) {
        self.manifest = manifest
        self.manifestURL = manifestURL
        self.imageURL = imageURL
        self.receiptURL = receiptURL
        self.evidenceRoot = evidenceRoot
    }
    var jiraReceiptURL: URL { manifestURL.deletingPathExtension().appendingPathExtension("jira.json") }
    var s3ReceiptURL: URL { manifestURL.deletingPathExtension().appendingPathExtension("s3.json") }
    var isUploaded: Bool { TransferReceipt.isVerified(for: self, kind: .hosted) }
    var isStoredInS3: Bool { TransferReceipt.isVerified(for: self, kind: .s3) }
    var isPayloadArchived: Bool {
        guard !FileManager.default.fileExists(atPath: imageURL.path), let binding = manifest.tenantBinding else { return false }
        return (try? LocalEvidenceArchive.load(for: self, expectedBinding: binding)) != nil
    }
    var lifecycle: EvidenceLifecycleRecord { EvidenceLifecycleStore.load(for: self) }
}

enum CaptureHistory {
    static func defaultEvidenceRoot(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        homeDirectory
            .appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent("Scopeproof Evidence", isDirectory: true)
    }

    static func legacyEvidenceRoot(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        homeDirectory
            .appendingPathComponent("Pictures", isDirectory: true)
            .appendingPathComponent("Scopeproof Evidence", isDirectory: true)
    }

    static func readableRoots(
        for primaryDirectory: URL, expectedBinding: TenantWorkspaceBinding,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [URL] {
        // Preserve configured path spelling for path-bound trust heads. Resolve
        // symlinks for containment only, never to silently move evidence identity.
        let primary = primaryDirectory.standardizedFileURL
        guard expectedBinding == .localDefault, primary.resolvingSymlinksInPath() == defaultEvidenceRoot(homeDirectory: homeDirectory).standardizedFileURL.resolvingSymlinksInPath() else { return [primary] }
        return [primary, legacyEvidenceRoot(homeDirectory: homeDirectory).standardizedFileURL]
    }

    static func isWithinReadableRoots(
        _ url: URL,
        primaryDirectory: URL, expectedBinding: TenantWorkspaceBinding,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> Bool {
        let candidate = url.standardizedFileURL.resolvingSymlinksInPath().path
        return readableRoots(for: primaryDirectory, expectedBinding: expectedBinding, homeDirectory: homeDirectory).contains { root in
            let rootPath = root.resolvingSymlinksInPath().path
            return candidate.hasPrefix(rootPath + "/")
                && (expectedBinding != .localDefault || !candidate.hasPrefix(rootPath + "/tenants/"))
        }
    }

    static func entries(in directory: URL, expectedBinding: TenantWorkspaceBinding) -> [CaptureHistoryEntry] {
        let candidates = readableRoots(for: directory, expectedBinding: expectedBinding)
            .flatMap { entriesOnly(in: $0, expectedBinding: expectedBinding) }
        // Ambiguous IDs are not addressable capabilities. Omit every duplicate.
        let grouped = Dictionary(grouping: candidates, by: { $0.manifest.evidenceID })
        return candidates.filter { grouped[$0.manifest.evidenceID]?.count == 1 }.sorted { left, right in
            if left.manifest.capturedAt != right.manifest.capturedAt {
                return left.manifest.capturedAt > right.manifest.capturedAt
            }
            let leftSequence = left.manifest.chainSequence ?? 0
            let rightSequence = right.manifest.chainSequence ?? 0
            if leftSequence != rightSequence { return leftSequence > rightSequence }
            return left.manifest.evidenceID < right.manifest.evidenceID
        }
    }

    private static func entriesOnly(in directory: URL, expectedBinding: TenantWorkspaceBinding) -> [CaptureHistoryEntry] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return [] }
        var urls: [URL] = []
        for case let url as URL in enumerator {
            if expectedBinding == .localDefault,
               url.standardizedFileURL.path == directory.standardizedFileURL.appendingPathComponent("tenants").path {
                enumerator.skipDescendants()
                continue
            }
            guard urls.count < ValidatedEvidenceArtifact.maximumManifestCount else { break }
            if url.pathExtension == "json" && !url.lastPathComponent.hasSuffix(".receipt.json")
                && !url.lastPathComponent.hasSuffix(".review.json") && !url.lastPathComponent.hasSuffix(".s3.json")
                && !url.lastPathComponent.hasSuffix(".jira.json") && !url.lastPathComponent.hasSuffix(".hold.json")
                && !url.lastPathComponent.hasSuffix(".archive.json") {
                urls.append(url)
            }
        }
        return urls.compactMap { url in
            guard let data = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: url, within: directory, maximumBytes: ValidatedEvidenceArtifact.maximumManifestBytes
            ), let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data),
                  manifest.belongs(to: expectedBinding) else { return nil }
            let image = url.deletingLastPathComponent().appendingPathComponent(URL(fileURLWithPath: manifest.screenshotFilename).lastPathComponent)
            let receipt = url.deletingPathExtension().appendingPathExtension("receipt.json")
            let entry = CaptureHistoryEntry(
                manifest: manifest, manifestURL: url, imageURL: image,
                receiptURL: receipt, evidenceRoot: directory
            )
            if (try? ValidatedEvidenceArtifact.validateRegularFile(at: image, within: directory, maximumBytes: ValidatedEvidenceArtifact.maximumImageBytes)) != nil { return entry }
            return entry.isPayloadArchived ? entry : nil
        }
    }

    @MainActor
    static func removeExpired(
        in directory: URL, expectedBinding: TenantWorkspaceBinding,
        retentionDays: Int, now: Date = Date(),
        remoteDurabilityVerifier: (CaptureHistoryEntry) async throws -> Bool
    ) async throws -> LocalRetentionReport {
        // A PNG/manifest receipt cannot prove recoverability of lifecycle/hold
        // records or complete-chain continuity. Fail before network or mutation.
        throw LocalRetentionFailure.durableHistoryRequired
    }

    static func hasDurableLockedCopy(
        for entry: CaptureHistoryEntry, now: Date = Date(),
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) -> Bool {
        guard let artifact = try? ValidatedEvidenceArtifact.load(
                entry, requireLifecycle: false, trustedAnchor: trustedAnchor
              ),
              let receiptData = try? TransferReceipt.verified(for: entry, kind: .s3, artifact: artifact).receipt.payload,
              let receipt = try? JSONDecoder().decode(S3UploadReceipt.self, from: receiptData),
              receipt.schemaVersion == 3,
              receipt.evidenceID == artifact.manifest.evidenceID,
              receipt.screenshotSHA256 == artifact.manifest.sha256,
              receipt.manifestSHA256 == sha256(artifact.manifestData),
              receipt.securityProfile == S3SecurityProfile.production.rawValue,
              [S3RetentionMode.governance.rawValue, S3RetentionMode.compliance.rawValue].contains(receipt.retentionMode),
              receipt.retentionDays > 0,
              receipt.awsAccountID.range(of: #"^\d{12}$"#, options: .regularExpression) != nil,
              !receipt.principalARN.isEmpty,
              let uploadedAt = ISO8601DateFormatter().date(from: receipt.uploadedAt),
              uploadedAt <= now.addingTimeInterval(5 * 60),
              receipt.objectKeys.count == 2,
              Set(receipt.objectKeys).count == 2,
              let retainUntil = receipt.retainUntilByObjectKey else { return false }

        let imageChecksum = Data(SHA256.hash(data: artifact.imageData)).base64EncodedString()
        let manifestChecksum = Data(SHA256.hash(data: artifact.manifestData)).base64EncodedString()
        var sawImage = false
        var sawManifest = false
        for key in receipt.objectKeys {
            guard !key.isEmpty, key.utf8.count <= 1_024,
                  key.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }),
                  let versionID = receipt.versionIDs[key], !versionID.isEmpty, versionID != "null",
                  versionID.utf8.count <= 1_024,
                  let checksum = receipt.s3ChecksumsSHA256[key],
                  let retainedThrough = retainUntil[key].flatMap(parseISO8601),
                  retainedThrough > now else { return false }
            if key.lowercased().hasSuffix(".png") {
                guard !sawImage, checksum == imageChecksum else { return false }
                sawImage = true
            } else if key.lowercased().hasSuffix(".json") {
                guard !sawManifest, checksum == manifestChecksum else { return false }
                sawManifest = true
            } else {
                return false
            }
        }
        return sawImage && sawManifest
    }

    static func captureChainIntegrity(_ entries: [CaptureHistoryEntry], expectedBinding: TenantWorkspaceBinding) -> Bool {
        let anchor: LocalCaptureChainAnchor?
        let binding = expectedBinding
        guard entries.allSatisfy({ $0.manifest.belongs(to: expectedBinding) }) else {
            return false
        }
        do { anchor = try KeychainStore.captureChainAnchor(binding: binding) }
        catch { return false }
        return captureChainIntegrity(entries, anchor: anchor)
    }

    static func captureChainIntegrity(
        _ entries: [CaptureHistoryEntry], anchor: LocalCaptureChainAnchor?
    ) -> Bool {
        // CaptureHistory supplies complete local history newest-first. Verify the
        // signed epoch backwards from the Keychain anchor without sorting away
        // duplicated, missing, or reordered sequence claims.
        let signed = entries.compactMap { entry -> CaptureManifest? in
            entry.manifest.schemaVersion >= 7 ? entry.manifest : nil
        }
        guard let anchor else { return signed.isEmpty }
        guard anchor.schemaVersion == LocalCaptureChainAnchor.currentSchemaVersion,
              anchor.sequence > 0,
              anchor.eventHash.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              anchor.signingKeyID.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              ISO8601DateFormatter().date(from: anchor.anchoredAt) != nil,
              signed.count == anchor.sequence else { return false }

        var expectedSequence = anchor.sequence
        var expectedEventHash = anchor.eventHash
        for manifest in signed {
            guard let sequence = manifest.chainSequence, sequence > 0,
                  sequence == expectedSequence,
                  manifest.chainEventHash == expectedEventHash,
                  manifest.provenance?.keyID == anchor.signingKeyID,
                  LocalProvenance.verifyManifest(manifest) else { return false }
            if sequence == 1 {
                guard manifest.chainPreviousHash == "GENESIS" else { return false }
            } else {
                guard manifest.chainPreviousHash.range(
                    of: #"^[a-f0-9]{64}$"#, options: .regularExpression
                ) != nil else { return false }
            }
            expectedEventHash = manifest.chainPreviousHash
            expectedSequence -= 1
        }
        return expectedSequence == 0 && expectedEventHash == "GENESIS"
    }

    private static func parseISO8601(_ value: String) -> Date? {
        let standard = ISO8601DateFormatter()
        if let date = standard.date(from: value) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value)
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
