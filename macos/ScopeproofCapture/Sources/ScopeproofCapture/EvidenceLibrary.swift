import CryptoKit
import Foundation

enum EvidenceStorageLocation: String, Codable, Sendable {
    case local = "Local"
    case s3 = "S3"
    case localAndS3 = "Local + S3"
}

struct EvidenceLibraryRecord: Codable, Sendable {
    let evidenceID: String
    let capturedAt: String
    let localTimestamp: String
    let complianceArea: String
    let controlID: String
    let controlTitle: String
    let title: String
    let system: String
    let environment: String
    let assessmentPeriod: String
    let owner: String
    let reviewer: String
    let reviewStatus: String
    let reviewNotes: String
    let tags: [String]
    let jiraIssueKey: String?
    let sourceURL: String?
    let safetyStatus: String
    let sha256: String
    let uploaded: Bool
    let lifecycleValid: Bool
    let storageLocation: EvidenceStorageLocation
    let localAvailable: Bool
    let s3Available: Bool
    let s3PreviewAvailable: Bool
    let s3IntegrityVerified: Bool
    let s3IntegrityStatus: String
    let reviewAvailable: Bool
    let s3VersionCount: Int
    let s3SizeBytes: Int64?
    let s3LastModified: String?
}

struct S3EvidenceReceiptBinding: Equatable, Sendable {
    let evidenceID: String
    let imageKey: String
    let imageVersionID: String
    let imageETag: String
    let imageSHA256: String
    let manifestKey: String
    let manifestVersionID: String
    let manifestETag: String
    let manifestSHA256: String
}

struct S3ScreenshotSummary: Equatable, Sendable {
    let evidenceID: String
    let controlFolder: String
    let assessmentPeriod: String
    let filename: String
    let size: Int64
    let lastModified: String
    let versionCount: Int
    let object: S3StoredObject
    let manifestObject: S3StoredObject
    let receiptBinding: S3EvidenceReceiptBinding?
}

enum EvidenceLibraryBuilder {
    private static let evidenceIDPattern = try! NSRegularExpression(pattern: #"^EV-[A-Z0-9]+$"#)

    static func verifiedReceiptBindings(
        entries: [CaptureHistoryEntry], settings: S3StorageSettings, destination: S3VerifiedDestination
    ) -> [String: S3EvidenceReceiptBinding] {
        guard settings.isConfigured, destination.matches(settings) else { return [:] }
        let candidates = entries.compactMap { entry -> S3EvidenceReceiptBinding? in
            guard let receiptData = try? Data(contentsOf: entry.s3ReceiptURL, options: [.mappedIfSafe]),
                  receiptData.count <= 2 * 1024 * 1024,
                  let manifestData = try? Data(contentsOf: entry.manifestURL, options: [.mappedIfSafe]),
                  manifestData.count <= 2 * 1024 * 1024,
                  let receipt = try? JSONDecoder().decode(S3UploadReceipt.self, from: receiptData),
                  receipt.schemaVersion == 2,
                  receipt.evidenceID == entry.manifest.evidenceID,
                  receipt.bucket == settings.bucket,
                  receipt.region == settings.region,
                  receipt.awsAccountID == destination.accountID,
                  receipt.securityProfile == settings.securityProfile.rawValue,
                  receipt.encryption == settings.encryptionMode.rawValue,
                  receipt.kmsKeyARN == settings.kmsKeyARN,
                  receipt.retentionMode == settings.retentionMode.rawValue,
                  receipt.retentionDays == settings.retentionDays,
                  receipt.screenshotSHA256 == entry.manifest.sha256,
                  receipt.manifestSHA256 == sha256(manifestData),
                  isSHA256(receipt.screenshotSHA256), isSHA256(receipt.manifestSHA256),
                  receipt.objectKeys.count == 2, Set(receipt.objectKeys).count == 2,
                  let imageKey = receipt.objectKeys.first(where: { lastPathComponent($0) == entry.manifest.screenshotFilename }),
                  let manifestKey = receipt.objectKeys.first(where: { lastPathComponent($0) == entry.manifestURL.lastPathComponent }),
                  imageKey != manifestKey,
                  parentKey(imageKey) == parentKey(manifestKey),
                  isExpectedLayout(imageKey, evidenceID: entry.manifest.evidenceID, prefix: settings.prefix),
                  isExpectedLayout(manifestKey, evidenceID: entry.manifest.evidenceID, prefix: settings.prefix),
                  let imageVersion = receipt.versionIDs[imageKey], !imageVersion.isEmpty, imageVersion != "null",
                  let manifestVersion = receipt.versionIDs[manifestKey], !manifestVersion.isEmpty, manifestVersion != "null",
                  let imageETag = receipt.etags[imageKey], !imageETag.isEmpty,
                  let manifestETag = receipt.etags[manifestKey], !manifestETag.isEmpty,
                  checksumHex(receipt.s3ChecksumsSHA256[imageKey]) == receipt.screenshotSHA256,
                  checksumHex(receipt.s3ChecksumsSHA256[manifestKey]) == receipt.manifestSHA256 else { return nil }
            return S3EvidenceReceiptBinding(
                evidenceID: receipt.evidenceID,
                imageKey: imageKey, imageVersionID: imageVersion, imageETag: imageETag,
                imageSHA256: receipt.screenshotSHA256,
                manifestKey: manifestKey, manifestVersionID: manifestVersion, manifestETag: manifestETag,
                manifestSHA256: receipt.manifestSHA256
            )
        }
        return Dictionary(grouping: candidates, by: \.evidenceID).compactMapValues { values in
            values.count == 1 ? values[0] : nil
        }
    }

    static func s3Screenshots(
        objects: [S3StoredObject], prefix: String,
        receiptBindings: [String: S3EvidenceReceiptBinding] = [:]
    ) -> [S3ScreenshotSummary] {
        let byKey = Dictionary(grouping: objects, by: \.key)
        let grouped = byKey.filter { $0.key.hasSuffix(".png") }
        let summaries: [S3ScreenshotSummary] = grouped.compactMap { key, versions -> S3ScreenshotSummary? in
            // If a delete marker or newer non-version state exists, ListObjectVersions
            // has no current Version. Never resurrect an older version as current.
            guard let selected = versions.first(where: \.isLatest) else { return nil }
            let relative = selected.relativeKey(prefix: prefix)
            let components = relative.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard components.count == 4,
                  components.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 }),
                  isEvidenceID(components[2]),
                  components[3].hasSuffix(".png") else { return nil }
            let manifestKey = String(key.dropLast(4)) + ".json"
            guard let manifest = byKey[manifestKey]?.first(where: \.isLatest),
                  manifest.size >= 0, manifest.size <= 2 * 1024 * 1024 else { return nil }
            let binding = receiptBindings[components[2]].flatMap { candidate -> S3EvidenceReceiptBinding? in
                candidate.imageKey == selected.key && candidate.imageVersionID == selected.versionID &&
                candidate.imageETag == selected.eTag && candidate.manifestKey == manifest.key &&
                candidate.manifestVersionID == manifest.versionID && candidate.manifestETag == manifest.eTag
                    ? candidate : nil
            }
            return S3ScreenshotSummary(
                evidenceID: components[2], controlFolder: components[0], assessmentPeriod: components[1],
                filename: components[3], size: selected.size, lastModified: selected.lastModified,
                versionCount: versions.count, object: selected, manifestObject: manifest,
                receiptBinding: binding
            )
        }
        // The browser API addresses previews by evidence ID, never by an S3 key.
        // Omit an ID entirely when more than one object key claims it so an
        // attacker or damaged archive cannot make that identifier ambiguous.
        let unique: [S3ScreenshotSummary] = Dictionary(grouping: summaries, by: \.evidenceID).values.compactMap { matches -> S3ScreenshotSummary? in
            matches.count == 1 ? matches[0] : nil
        }
        return unique.sorted { left, right in
            if left.lastModified == right.lastModified { return left.evidenceID < right.evidenceID }
            return left.lastModified > right.lastModified
        }
    }

    static func merge(local: [LocalEvidenceRecord], s3: [S3ScreenshotSummary], s3PreviewsAllowed: Bool = false) -> [EvidenceLibraryRecord] {
        let s3ByEvidenceID = Dictionary(grouping: s3, by: \.evidenceID)
        let localIDs = Set(local.map(\.evidenceID))
        var records = local.map { item -> EvidenceLibraryRecord in
            let candidate = s3ByEvidenceID[item.evidenceID]?.first
            let stored = candidate.flatMap { summary in
                summary.receiptBinding?.imageSHA256 == item.sha256 ? summary : nil
            }
            return record(
                from: item, s3: stored,
                unverifiedS3Detected: candidate != nil && stored == nil,
                s3PreviewsAllowed: s3PreviewsAllowed
            )
        }
        records.append(contentsOf: s3.filter { !localIDs.contains($0.evidenceID) }.map { s3OnlyRecord($0, previewsAllowed: s3PreviewsAllowed) })
        return records.sorted { left, right in
            if left.capturedAt == right.capturedAt { return left.evidenceID < right.evidenceID }
            return left.capturedAt > right.capturedAt
        }
    }

    private static func record(
        from item: LocalEvidenceRecord, s3: S3ScreenshotSummary?,
        unverifiedS3Detected: Bool, s3PreviewsAllowed: Bool
    ) -> EvidenceLibraryRecord {
        EvidenceLibraryRecord(
            evidenceID: item.evidenceID, capturedAt: item.capturedAt, localTimestamp: item.localTimestamp,
            complianceArea: item.complianceArea, controlID: item.controlID, controlTitle: item.controlTitle,
            title: item.title, system: item.system, environment: item.environment,
            assessmentPeriod: item.assessmentPeriod, owner: item.owner, reviewer: item.reviewer,
            reviewStatus: item.reviewStatus, reviewNotes: item.reviewNotes, tags: item.tags,
            jiraIssueKey: item.jiraIssueKey, sourceURL: item.sourceURL, safetyStatus: item.safetyStatus,
            sha256: item.sha256, uploaded: item.uploaded || s3 != nil, lifecycleValid: item.lifecycleValid,
            storageLocation: s3 == nil ? .local : .localAndS3, localAvailable: true,
            s3Available: s3 != nil,
            s3PreviewAvailable: s3 != nil && s3PreviewsAllowed && (s3?.size ?? 0) <= 40 * 1024 * 1024,
            s3IntegrityVerified: s3 != nil,
            s3IntegrityStatus: s3 != nil
                ? "Exact S3 version bound by local upload receipt"
                : (unverifiedS3Detected ? "S3 candidate is not bound to this local artifact" : ""),
            reviewAvailable: true, s3VersionCount: s3?.versionCount ?? 0,
            s3SizeBytes: s3?.size, s3LastModified: s3?.lastModified
        )
    }

    private static func s3OnlyRecord(_ item: S3ScreenshotSummary, previewsAllowed: Bool) -> EvidenceLibraryRecord {
        let (controlID, controlTitle) = controlParts(item.controlFolder)
        return EvidenceLibraryRecord(
            evidenceID: item.evidenceID, capturedAt: item.lastModified, localTimestamp: item.lastModified,
            complianceArea: "S3 archive", controlID: controlID, controlTitle: controlTitle,
            title: displayName(item.filename), system: "", environment: "",
            assessmentPeriod: item.assessmentPeriod.replacingOccurrences(of: "-", with: " "),
            owner: "", reviewer: "", reviewStatus: "S3 only", reviewNotes: "", tags: [],
            jiraIssueKey: nil, sourceURL: nil, safetyStatus: "Not available in inventory", sha256: "",
            uploaded: false, lifecycleValid: false, storageLocation: .s3, localAvailable: false,
            s3Available: true, s3PreviewAvailable: previewsAllowed && item.size <= 40 * 1024 * 1024,
            s3IntegrityVerified: false, s3IntegrityStatus: "Inventory only · provenance unverified",
            reviewAvailable: false,
            s3VersionCount: item.versionCount,
            s3SizeBytes: item.size, s3LastModified: item.lastModified
        )
    }

    private static func isEvidenceID(_ value: String) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return value.utf8.count <= 80 && evidenceIDPattern.firstMatch(in: value, range: range) != nil
    }

    private static func controlParts(_ folder: String) -> (String, String) {
        (folder.replacingOccurrences(of: "_", with: "."), "")
    }

    private static func displayName(_ filename: String) -> String {
        String(filename.dropLast(4)).replacingOccurrences(of: "_", with: " ")
    }

    private static func isExpectedLayout(_ key: String, evidenceID: String, prefix: String) -> Bool {
        let requiredPrefix = prefix.isEmpty ? "" : "\(prefix)/"
        guard requiredPrefix.isEmpty || key.hasPrefix(requiredPrefix) else { return false }
        let relative = S3StoredObject(key: key, size: 0, lastModified: "", eTag: "").relativeKey(prefix: prefix)
        let components = relative.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        return components.count == 4 && components[2] == evidenceID &&
            components.allSatisfy { !$0.isEmpty && $0.utf8.count <= 512 }
    }

    private static func lastPathComponent(_ key: String) -> String { key.split(separator: "/").last.map(String.init) ?? "" }
    private static func parentKey(_ key: String) -> String { key.split(separator: "/").dropLast().joined(separator: "/") }
    private static func isSHA256(_ value: String) -> Bool { value.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil }
    private static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func checksumHex(_ value: String?) -> String? {
        guard let value, let data = Data(base64Encoded: value), data.count == 32 else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }
}
