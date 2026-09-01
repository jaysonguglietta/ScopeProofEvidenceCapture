import CryptoKit
import Darwin
import Foundation
import ImageIO

enum EvidenceArtifactFailure: LocalizedError, Equatable {
    case outsideEvidenceRoot
    case unsafeFile(String)
    case fileTooLarge(String)
    case invalidManifest
    case invalidImage
    case invalidLifecycle
    case invalidHold

    var errorDescription: String? {
        switch self {
        case .outsideEvidenceRoot:
            return "An evidence file resolved outside the approved evidence directory."
        case .unsafeFile(let name):
            return "Evidence file \(name) is not a private regular file or changed while it was read."
        case .fileTooLarge(let name):
            return "Evidence file \(name) exceeds the local safety limit."
        case .invalidManifest:
            return "The evidence manifest is malformed or does not bind the selected screenshot."
        case .invalidImage:
            return "The evidence screenshot is not the exact bounded PNG bound by its manifest."
        case .invalidLifecycle:
            return "The evidence review lifecycle is missing or failed integrity validation."
        case .invalidHold:
            return "The evidence legal-hold marker failed signature or artifact-binding validation."
        }
    }
}

struct ValidatedEvidenceFile: Sendable {
    let sourceURL: URL
    let data: Data
}

struct ValidatedEvidenceArtifact: Sendable {
    static let maximumManifestBytes = 2 * 1024 * 1024
    static let maximumImageBytes = 50 * 1024 * 1024
    static let maximumSidecarBytes = 4 * 1024 * 1024
    static let maximumManifestCount = 5_000

    let manifest: CaptureManifest
    let manifestData: Data
    let imageData: Data
    let lifecycle: EvidenceLifecycleRecord?
    let lifecycleData: Data?
    let provenanceVerified: Bool

    static func load(_ capture: CaptureResult) throws -> ValidatedEvidenceArtifact {
        let root = capture.manifestURL.deletingLastPathComponent()
        let manifestData = try readBoundedRegularFile(
            at: capture.manifestURL, within: root, maximumBytes: maximumManifestBytes
        )
        let imageData = try readBoundedRegularFile(
            at: capture.imageURL, within: root, maximumBytes: maximumImageBytes
        )
        let artifact = try validate(
            manifestData: manifestData, imageData: imageData,
            expectedManifestURL: capture.manifestURL, expectedImageURL: capture.imageURL,
            allowUnsignedLegacy: false
        )
        guard artifact.manifest.evidenceID == capture.evidenceID,
              artifact.manifest.sha256 == capture.sha256 else {
            throw EvidenceArtifactFailure.invalidManifest
        }
        return artifact
    }

    static func load(
        _ entry: CaptureHistoryEntry, requireLifecycle: Bool = false,
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) throws -> ValidatedEvidenceArtifact {
        try load(
            entry, requireLifecycle: requireLifecycle, allowUnsignedLegacy: false,
            trustedAnchor: trustedAnchor
        )
    }

    /// Migration-only reader. It validates exact bytes and filesystem safety, but
    /// deliberately reports schema-6 artifacts as unverified and must not be used
    /// for upload, review, legal hold, retention, or assessor export decisions.
    static func loadForLegacyBrowsing(
        _ entry: CaptureHistoryEntry, requireLifecycle: Bool = false,
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) throws -> ValidatedEvidenceArtifact {
        try load(
            entry, requireLifecycle: requireLifecycle, allowUnsignedLegacy: true,
            trustedAnchor: trustedAnchor
        )
    }

    private static func load(
        _ entry: CaptureHistoryEntry, requireLifecycle: Bool,
        allowUnsignedLegacy: Bool, trustedAnchor: LocalCaptureChainAnchor?
    ) throws -> ValidatedEvidenceArtifact {
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        let manifestData = try readBoundedRegularFile(
            at: entry.manifestURL, within: root, maximumBytes: maximumManifestBytes
        )
        let imageData = try readBoundedRegularFile(
            at: entry.imageURL, within: root, maximumBytes: maximumImageBytes
        )
        var artifact = try validate(
            manifestData: manifestData, imageData: imageData,
            expectedManifestURL: entry.manifestURL, expectedImageURL: entry.imageURL,
            allowUnsignedLegacy: allowUnsignedLegacy, trustedAnchor: trustedAnchor
        )
        guard artifact.manifest.evidenceID == entry.manifest.evidenceID else {
            throw EvidenceArtifactFailure.invalidManifest
        }
        let lifecycleURL = EvidenceLifecycleStore.url(for: entry.manifestURL)
        if FileManager.default.fileExists(atPath: lifecycleURL.path) {
            let lifecycleData = try readBoundedRegularFile(
                at: lifecycleURL, within: root, maximumBytes: maximumSidecarBytes
            )
            guard let lifecycle = try? JSONDecoder().decode(EvidenceLifecycleRecord.self, from: lifecycleData),
                  lifecycle.evidenceID == artifact.manifest.evidenceID,
                  lifecycle.schemaVersion == (artifact.manifest.schemaVersion >= 7 ? 3 : 2),
                  EvidenceLifecycleStore.verify(
                    lifecycle, artifactSha256: artifact.manifest.sha256,
                    provenanceKeyID: artifact.manifest.provenance?.keyID
                  ) else {
                throw EvidenceArtifactFailure.invalidLifecycle
            }
            artifact = ValidatedEvidenceArtifact(
                manifest: artifact.manifest, manifestData: artifact.manifestData,
                imageData: artifact.imageData, lifecycle: lifecycle, lifecycleData: lifecycleData,
                provenanceVerified: artifact.provenanceVerified
            )
        } else if requireLifecycle {
            throw EvidenceArtifactFailure.invalidLifecycle
        }
        return artifact
    }

    static func exportFiles(
        for entry: CaptureHistoryEntry, trustedAnchor: LocalCaptureChainAnchor? = nil
    ) throws -> [ValidatedEvidenceFile] {
        let artifact = try load(entry, requireLifecycle: true, trustedAnchor: trustedAnchor)
        var files = [
            ValidatedEvidenceFile(sourceURL: entry.imageURL, data: artifact.imageData),
            ValidatedEvidenceFile(sourceURL: entry.manifestURL, data: artifact.manifestData),
        ]
        if let lifecycleData = artifact.lifecycleData {
            files.append(ValidatedEvidenceFile(
                sourceURL: EvidenceLifecycleStore.url(for: entry.manifestURL), data: lifecycleData
            ))
        }
        let root = entry.evidenceRoot ?? entry.manifestURL.deletingLastPathComponent()
        for url in [entry.receiptURL, entry.jiraReceiptURL, entry.s3ReceiptURL] where FileManager.default.fileExists(atPath: url.path) {
            files.append(ValidatedEvidenceFile(
                sourceURL: url,
                data: try readBoundedRegularFile(at: url, within: root, maximumBytes: maximumSidecarBytes)
            ))
        }
        let holdURL = LocalEvidenceHoldStore.url(for: entry.manifestURL)
        if FileManager.default.fileExists(atPath: holdURL.path) {
            guard LocalEvidenceHoldStore.state(for: entry) != .invalid else {
                throw EvidenceArtifactFailure.invalidHold
            }
            files.append(ValidatedEvidenceFile(
                sourceURL: holdURL,
                data: try readBoundedRegularFile(
                    at: holdURL, within: root, maximumBytes: maximumSidecarBytes
                )
            ))
        }
        return files
    }

    static func validateDownloaded(
        manifestData: Data, imageData: Data, manifestURL: URL, imageURL: URL,
        requireLocalAnchor: Bool
    ) throws -> ValidatedEvidenceArtifact {
        guard manifestData.count <= maximumManifestBytes else {
            throw EvidenceArtifactFailure.fileTooLarge(manifestURL.lastPathComponent)
        }
        guard imageData.count <= maximumImageBytes else {
            throw EvidenceArtifactFailure.fileTooLarge(imageURL.lastPathComponent)
        }
        return try validate(
            manifestData: manifestData, imageData: imageData,
            expectedManifestURL: manifestURL, expectedImageURL: imageURL,
            requireLocalAnchor: requireLocalAnchor, allowUnsignedLegacy: false
        )
    }

    static func validateDownloadedForLegacyBrowsing(
        manifestData: Data, imageData: Data, manifestURL: URL, imageURL: URL,
        requireLocalAnchor: Bool
    ) throws -> ValidatedEvidenceArtifact {
        guard manifestData.count <= maximumManifestBytes else {
            throw EvidenceArtifactFailure.fileTooLarge(manifestURL.lastPathComponent)
        }
        guard imageData.count <= maximumImageBytes else {
            throw EvidenceArtifactFailure.fileTooLarge(imageURL.lastPathComponent)
        }
        return try validate(
            manifestData: manifestData, imageData: imageData,
            expectedManifestURL: manifestURL, expectedImageURL: imageURL,
            requireLocalAnchor: requireLocalAnchor, allowUnsignedLegacy: true
        )
    }

    private static func validate(
        manifestData: Data, imageData: Data,
        expectedManifestURL: URL, expectedImageURL: URL,
        requireLocalAnchor: Bool = true, allowUnsignedLegacy: Bool,
        trustedAnchor: LocalCaptureChainAnchor? = nil
    ) throws -> ValidatedEvidenceArtifact {
        guard let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: manifestData),
              [6, 7].contains(manifest.schemaVersion),
              manifest.evidenceID.range(of: #"^EV-[A-Z0-9]{1,76}$"#, options: .regularExpression) != nil,
              manifest.screenshotFilename == expectedImageURL.lastPathComponent,
              URL(fileURLWithPath: manifest.screenshotFilename).lastPathComponent == manifest.screenshotFilename,
              expectedManifestURL.pathExtension.lowercased() == "json",
              manifest.sha256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              manifest.safetyScanSha256 == manifest.sha256 else {
            throw EvidenceArtifactFailure.invalidManifest
        }
        let chainPayload = Data("\(manifest.chainPreviousHash)|\(manifest.sha256)|\(manifest.evidenceID)|\(manifest.capturedAt)|\(manifest.sessionID)".utf8)
        let expectedChainHash = sha256(chainPayload)
        guard (manifest.chainPreviousHash == "GENESIS"
                || manifest.chainPreviousHash.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil),
              manifest.chainEventHash == expectedChainHash else {
            throw EvidenceArtifactFailure.invalidManifest
        }
        let provenanceVerified: Bool
        if manifest.schemaVersion == 7 {
            guard let chainSequence = manifest.chainSequence, chainSequence > 0,
                  LocalProvenance.verifyManifest(manifest) else {
                throw EvidenceArtifactFailure.invalidManifest
            }
            provenanceVerified = true
            if requireLocalAnchor {
                do {
                    guard let anchor = try trustedAnchor ?? KeychainStore.captureChainAnchor(),
                          chainSequence <= anchor.sequence,
                          manifest.provenance?.keyID == anchor.signingKeyID,
                          chainSequence != anchor.sequence || manifest.chainEventHash == anchor.eventHash else {
                        throw EvidenceArtifactFailure.invalidManifest
                    }
                } catch let failure as EvidenceArtifactFailure {
                    throw failure
                } catch {
                    throw EvidenceArtifactFailure.invalidManifest
                }
            }
        } else {
            guard allowUnsignedLegacy,
                  manifest.chainSequence == nil, manifest.provenance == nil else {
                throw EvidenceArtifactFailure.invalidManifest
            }
            provenanceVerified = false
        }
        guard imageData.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
              sha256(imageData) == manifest.sha256,
              validPNGDimensions(imageData, width: manifest.pixelWidth, height: manifest.pixelHeight) else {
            throw EvidenceArtifactFailure.invalidImage
        }
        return ValidatedEvidenceArtifact(
            manifest: manifest, manifestData: manifestData, imageData: imageData,
            lifecycle: nil, lifecycleData: nil, provenanceVerified: provenanceVerified
        )
    }

    @discardableResult
    static func validateRegularFile(at url: URL, within root: URL, maximumBytes: Int) throws -> Int {
        try withRegularFileDescriptor(at: url, within: root, maximumBytes: maximumBytes) { descriptor, size in
            _ = descriptor
            return size
        }
    }

    static func readBoundedRegularFile(at url: URL, within root: URL, maximumBytes: Int) throws -> Data {
        try withRegularFileDescriptor(at: url, within: root, maximumBytes: maximumBytes) { descriptor, expectedSize in
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            var data = Data()
            data.reserveCapacity(expectedSize)
            while true {
                let remaining = maximumBytes + 1 - data.count
                guard remaining > 0 else { throw EvidenceArtifactFailure.fileTooLarge(url.lastPathComponent) }
                let chunk = try handle.read(upToCount: min(64 * 1024, remaining)) ?? Data()
                if chunk.isEmpty { break }
                data.append(chunk)
                if data.count > maximumBytes { throw EvidenceArtifactFailure.fileTooLarge(url.lastPathComponent) }
            }
            guard data.count == expectedSize else { throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent) }
            return data
        }
    }

    private static func withRegularFileDescriptor<T>(
        at url: URL, within root: URL, maximumBytes: Int,
        _ operation: (Int32, Int) throws -> T
    ) throws -> T {
        guard maximumBytes > 0 else { throw EvidenceArtifactFailure.fileTooLarge(url.lastPathComponent) }
        let lexicalRoot = root.standardizedFileURL
        let lexicalCandidate = url.standardizedFileURL
        guard isContained(lexicalCandidate.path, in: lexicalRoot.path) else {
            throw EvidenceArtifactFailure.outsideEvidenceRoot
        }
        let resolvedRoot = lexicalRoot.resolvingSymlinksInPath()
        let resolvedCandidate = lexicalCandidate.resolvingSymlinksInPath()
        guard isContained(resolvedCandidate.path, in: resolvedRoot.path) else {
            throw EvidenceArtifactFailure.outsideEvidenceRoot
        }

        var before = stat()
        guard lstat(lexicalCandidate.path, &before) == 0 else {
            throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent)
        }
        guard
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_nlink == 1, before.st_size >= 0,
              before.st_size <= off_t(maximumBytes) else {
            if before.st_size > off_t(maximumBytes) { throw EvidenceArtifactFailure.fileTooLarge(url.lastPathComponent) }
            throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent)
        }
        let descriptor = Darwin.open(lexicalCandidate.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent) }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              opened.st_nlink == 1, opened.st_size >= 0,
              opened.st_size <= off_t(maximumBytes),
              opened.st_dev == before.st_dev, opened.st_ino == before.st_ino else {
            throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent)
        }
        let result = try operation(descriptor, Int(opened.st_size))
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              after.st_dev == opened.st_dev, after.st_ino == opened.st_ino,
              after.st_size == opened.st_size,
              lexicalCandidate.resolvingSymlinksInPath() == resolvedCandidate else {
            throw EvidenceArtifactFailure.unsafeFile(url.lastPathComponent)
        }
        return result
    }

    private static func isContained(_ candidate: String, in root: String) -> Bool {
        candidate == root || candidate.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    private static func validPNGDimensions(_ data: Data, width: Int, height: Int) -> Bool {
        guard width > 0, height > 0, width <= 32_768, height <= 32_768,
              width.multipliedReportingOverflow(by: height).overflow == false,
              width * height <= 100_000_000,
              let source = CGImageSourceCreateWithData(data as CFData, nil),
              CGImageSourceGetCount(source) == 1,
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue == width,
              (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue == height else { return false }
        return true
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
