import CryptoKit
import Foundation

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
    var isUploaded: Bool { FileManager.default.fileExists(atPath: receiptURL.path) }
    var isStoredInS3: Bool { FileManager.default.fileExists(atPath: s3ReceiptURL.path) }
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
        for primaryDirectory: URL,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [URL] {
        let primary = primaryDirectory.standardizedFileURL.resolvingSymlinksInPath()
        guard primary == defaultEvidenceRoot(homeDirectory: homeDirectory).standardizedFileURL.resolvingSymlinksInPath() else { return [primary] }
        return [primary, legacyEvidenceRoot(homeDirectory: homeDirectory).standardizedFileURL.resolvingSymlinksInPath()]
    }

    static func isWithinReadableRoots(
        _ url: URL,
        primaryDirectory: URL,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> Bool {
        let candidate = url.standardizedFileURL.resolvingSymlinksInPath().path
        return readableRoots(for: primaryDirectory, homeDirectory: homeDirectory).contains { root in
            candidate.hasPrefix(root.path + "/")
        }
    }

    static func entries(in directory: URL) -> [CaptureHistoryEntry] {
        var seenEvidenceIDs = Set<String>()
        return readableRoots(for: directory).flatMap { entriesOnly(in: $0) }.filter { entry in
            seenEvidenceIDs.insert(entry.manifest.evidenceID).inserted
        }.sorted { left, right in
            if left.manifest.capturedAt != right.manifest.capturedAt {
                return left.manifest.capturedAt > right.manifest.capturedAt
            }
            let leftSequence = left.manifest.chainSequence ?? 0
            let rightSequence = right.manifest.chainSequence ?? 0
            if leftSequence != rightSequence { return leftSequence > rightSequence }
            return left.manifest.evidenceID < right.manifest.evidenceID
        }
    }

    private static func entriesOnly(in directory: URL) -> [CaptureHistoryEntry] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return [] }
        var urls: [URL] = []
        for case let url as URL in enumerator {
            guard urls.count < ValidatedEvidenceArtifact.maximumManifestCount else { break }
            if url.pathExtension == "json" && !url.lastPathComponent.hasSuffix(".receipt.json")
                && !url.lastPathComponent.hasSuffix(".review.json") && !url.lastPathComponent.hasSuffix(".s3.json")
                && !url.lastPathComponent.hasSuffix(".jira.json") && !url.lastPathComponent.hasSuffix(".hold.json") {
                urls.append(url)
            }
        }
        return urls.compactMap { url in
            guard let data = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: url, within: directory, maximumBytes: ValidatedEvidenceArtifact.maximumManifestBytes
            ), let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data) else { return nil }
            let image = url.deletingLastPathComponent().appendingPathComponent(URL(fileURLWithPath: manifest.screenshotFilename).lastPathComponent)
            let receipt = url.deletingPathExtension().appendingPathExtension("receipt.json")
            guard (try? ValidatedEvidenceArtifact.validateRegularFile(
                at: image, within: directory, maximumBytes: ValidatedEvidenceArtifact.maximumImageBytes
            )) != nil else { return nil }
            return CaptureHistoryEntry(
                manifest: manifest, manifestURL: url, imageURL: image,
                receiptURL: receipt, evidenceRoot: directory
            )
        }
    }

    static func removeExpired(
        in directory: URL, retentionDays: Int, now: Date = Date()
    ) throws -> LocalRetentionReport {
        let cutoff = now.addingTimeInterval(-Double(retentionDays) * 86_400)
        var report = LocalRetentionReport()
        for entry in entries(in: directory) {
            guard let date = ISO8601DateFormatter().date(from: entry.manifest.capturedAt), date < cutoff else { continue }
            switch LocalEvidenceHoldStore.state(for: entry) {
            case .active, .invalid:
                report.skippedLegalHold += 1
                continue
            case .none, .released:
                break
            }
            guard hasDurableLockedCopy(for: entry, now: now) else {
                report.skippedWithoutDurableCopy += 1
                continue
            }
            guard (try? ValidatedEvidenceArtifact.load(entry, requireLifecycle: true)) != nil else {
                report.skippedInvalidEvidence += 1
                continue
            }
            let lifecycleURL = EvidenceLifecycleStore.url(for: entry.manifestURL)
            let holdURL = LocalEvidenceHoldStore.url(for: entry.manifestURL)
            for url in [entry.imageURL, entry.manifestURL, entry.receiptURL, entry.jiraReceiptURL, entry.s3ReceiptURL, lifecycleURL, holdURL] where FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.trashItem(at: url, resultingItemURL: nil)
            }
            report.movedToTrash += 1
        }
        return report
    }

    static func hasDurableLockedCopy(
        for entry: CaptureHistoryEntry, now: Date = Date(),
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) -> Bool {
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        guard let artifact = try? ValidatedEvidenceArtifact.load(
                entry, requireLifecycle: false, trustedAnchor: trustedAnchor
              ),
              let receiptData = try? ValidatedEvidenceArtifact.readBoundedRegularFile(
                at: entry.s3ReceiptURL, within: root,
                maximumBytes: ValidatedEvidenceArtifact.maximumSidecarBytes
              ),
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

    static func captureChainIntegrity(_ entries: [CaptureHistoryEntry]) -> Bool {
        let anchor: LocalCaptureChainAnchor?
        do { anchor = try KeychainStore.captureChainAnchor() }
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
            entry.manifest.schemaVersion == 7 ? entry.manifest : nil
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
