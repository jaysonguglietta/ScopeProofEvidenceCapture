import Compression
import CryptoKit
import Darwin
import Foundation

struct ReleaseManifest: Codable, Sendable {
    let schemaVersion: Int
    let version: String
    let sequence: Int
    let downloadUrl: URL
    let sha256: String
    let byteSize: Int
    let publishedAt: String
    let expiresAt: String
    let minimumSystemVersion: String
    let teamIdentifier: String
    let designatedRequirement: String
    let keyId: String
    let notes: String

    var signingPayload: Data {
        let notesBase64 = Data(notes.utf8).base64EncodedString()
        return Data(["scopeproof-update-manifest-v1", String(schemaVersion), version, String(sequence), downloadUrl.absoluteString, sha256, String(byteSize), publishedAt, expiresAt, minimumSystemVersion, teamIdentifier, designatedRequirement, keyId, notesBase64].joined(separator: "\n").utf8)
    }
}

struct ReleaseEnvelope: Codable, Sendable {
    let manifest: ReleaseManifest
    let signatureDERBase64: String
}

struct TrustedUpdateKey: Sendable {
    let keyId: String
    let publicKeyX963Base64: String
    let notBefore: Date
    let notAfter: Date
}

struct VerifiedUpdateRelease: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let sequence: Int
    let version: String
    let sha256: String

    init(sequence: Int, version: String, sha256: String) {
        self.schemaVersion = 1
        self.sequence = sequence
        self.version = version
        self.sha256 = sha256
    }
}

enum UpdateFailure: LocalizedError {
    case invalidMetadata(String)
    case untrustedSignature
    case rollback
    case unapprovedDownload
    case invalidArtifact(String)

    var errorDescription: String? {
        switch self {
        case .invalidMetadata(let detail): return "Update metadata is invalid: \(detail)"
        case .untrustedSignature: return "The update was not signed by a currently trusted Scopeproof release key."
        case .rollback: return "The update was rejected because it is older than this Mac's installed or previously verified release."
        case .unapprovedDownload: return "The update download did not use an approved HTTPS origin or attempted a redirect."
        case .invalidArtifact(let detail): return "The downloaded update failed verification: \(detail)"
        }
    }
}

enum ReleaseVerifier {
    static func configuredIdentity(bundle: Bundle = .main) -> (teamIdentifier: String, designatedRequirement: String)? {
        guard let team = bundle.object(forInfoDictionaryKey: "ScopeproofUpdateTeamIdentifier") as? String,
              team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
              let requirement = bundle.object(forInfoDictionaryKey: "ScopeproofUpdateDesignatedRequirement") as? String,
              requirement.count >= 20, requirement.count <= 1_000 else { return nil }
        return (team, requirement)
    }

    static func trustedKeys(bundle: Bundle = .main) -> [TrustedUpdateKey] {
        guard let entries = bundle.object(forInfoDictionaryKey: "ScopeproofUpdatePublicKeys") as? [[String: String]] else { return [] }
        let formatter = ISO8601DateFormatter()
        return entries.compactMap { entry in
            guard let id = entry["keyId"], let key = entry["publicKeyX963Base64"], let start = entry["notBefore"].flatMap(formatter.date), let end = entry["notAfter"].flatMap(formatter.date) else { return nil }
            return TrustedUpdateKey(keyId: id, publicKeyX963Base64: key, notBefore: start, notAfter: end)
        }
    }

    static func configuredDownloadOrigin(bundle: Bundle = .main) -> URL? {
        guard let value = bundle.object(forInfoDictionaryKey: "ScopeproofUpdateDownloadOrigin") as? String,
              let url = URL(string: value), url.scheme == "https", url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.port == nil, url.path.isEmpty,
              let host = url.host, !host.isEmpty, value == "https://\(host)" else { return nil }
        return url
    }

    static func approvedDownloadURL(_ url: URL, version: String, origin: URL) -> Bool {
        url.absoluteString == "\(origin.absoluteString)/macos/\(version)/Scopeproof-Capture-\(version).zip"
    }

    static func approvedBundleMetadata(identifier: String, version: String, manifest: ReleaseManifest) -> Bool {
        identifier == "com.scopeproof.capture" && version == manifest.version
    }

    static func verify(_ envelope: ReleaseEnvelope, keys: [TrustedUpdateKey], expectedTeamIdentifier: String, expectedDesignatedRequirement: String, expectedDownloadOrigin: URL, installedVersion: String, previousRelease: VerifiedUpdateRelease?, now: Date = Date()) throws -> ReleaseManifest {
        let manifest = envelope.manifest
        let formatter = ISO8601DateFormatter()
        guard manifest.schemaVersion == 1, manifest.version.range(of: "^\\d+\\.\\d+\\.\\d+$", options: .regularExpression) != nil, manifest.sequence > 0, manifest.byteSize > 0, manifest.byteSize <= 500 * 1024 * 1024,
              manifest.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              manifest.teamIdentifier == expectedTeamIdentifier, manifest.designatedRequirement == expectedDesignatedRequirement,
              approvedDownloadURL(manifest.downloadUrl, version: manifest.version, origin: expectedDownloadOrigin),
              let published = formatter.date(from: manifest.publishedAt), let expires = formatter.date(from: manifest.expiresAt),
              published <= now.addingTimeInterval(300), expires > now, expires.timeIntervalSince(published) <= 45 * 86_400,
              compareVersions(currentSystemVersion(), manifest.minimumSystemVersion) != .orderedAscending else {
            throw UpdateFailure.invalidMetadata("version, sequence, digest, platform, or validity constraints failed")
        }
        guard let trusted = keys.first(where: { $0.keyId == manifest.keyId && $0.notBefore <= published && $0.notAfter >= expires }),
              let keyData = Data(base64Encoded: trusted.publicKeyX963Base64),
              let signatureData = Data(base64Encoded: envelope.signatureDERBase64),
              let publicKey = try? P256.Signing.PublicKey(x963Representation: keyData),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureData),
              publicKey.isValidSignature(signature, for: manifest.signingPayload) else { throw UpdateFailure.untrustedSignature }
        if let previousRelease {
            if manifest.sequence < previousRelease.sequence { throw UpdateFailure.rollback }
            if manifest.sequence == previousRelease.sequence,
               (manifest.version != previousRelease.version || manifest.sha256 != previousRelease.sha256) {
                throw UpdateFailure.rollback
            }
        }
        if compareVersions(manifest.version, installedVersion) == .orderedAscending { throw UpdateFailure.rollback }
        return manifest
    }

    static func compareVersions(_ left: String, _ right: String) -> ComparisonResult {
        let a = left.split(separator: ".").prefix(3).map { Int($0.split(separator: "-")[0]) ?? 0 }
        let b = right.split(separator: ".").prefix(3).map { Int($0.split(separator: "-")[0]) ?? 0 }
        for index in 0..<3 { let l = index < a.count ? a[index] : 0; let r = index < b.count ? b[index] : 0; if l != r { return l < r ? .orderedAscending : .orderedDescending } }
        return .orderedSame
    }

    private static func currentSystemVersion() -> String {
        let value = ProcessInfo.processInfo.operatingSystemVersion
        return "\(value.majorVersion).\(value.minorVersion).\(value.patchVersion)"
    }
}

struct UpdateArchivePolicy: Sendable {
    static let production = UpdateArchivePolicy(
        maximumEntries: 10_000,
        maximumPathBytes: 1_024,
        maximumEntryUncompressedBytes: 512 * 1_024 * 1_024,
        maximumTotalUncompressedBytes: 1_024 * 1_024 * 1_024,
        maximumCompressionRatio: 200,
        extractionSafetyMarginBytes: 256 * 1_024 * 1_024
    )

    let maximumEntries: Int
    let maximumPathBytes: Int
    let maximumEntryUncompressedBytes: UInt64
    let maximumTotalUncompressedBytes: UInt64
    let maximumCompressionRatio: UInt64
    let extractionSafetyMarginBytes: UInt64
}

struct UpdateArchiveMetadata: Equatable, Sendable {
    let entryCount: Int
    let totalCompressedBytes: UInt64
    let totalUncompressedBytes: UInt64
}

enum UpdateArchiveValidator {
    private static let endOfCentralDirectorySignature: UInt32 = 0x0605_4b50
    private static let centralDirectorySignature: UInt32 = 0x0201_4b50
    private static let localFileHeaderSignature: UInt32 = 0x0403_4b50
    private static let dataDescriptorSignature: UInt32 = 0x0807_4b50
    private static let regularFileMode: UInt16 = 0x8000
    private static let directoryMode: UInt16 = 0x4000
    private static let fileTypeMask: UInt16 = 0xf000
    private static let crc32Table: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 {
            crc = crc & 1 == 1 ? 0xedb8_8320 ^ (crc >> 1) : crc >> 1
        }
        return crc
    }

    private struct EntryRecord {
        let recordRange: Range<Int>
        let payloadRange: Range<Int>
        let method: UInt16
        let expectedCRC32: UInt32
        let expectedUncompressedSize: UInt64
    }

    static func validate(_ archive: Data, policy: UpdateArchivePolicy = .production) throws -> UpdateArchiveMetadata {
        guard policy.maximumEntries > 0, policy.maximumPathBytes > 0,
              policy.maximumEntryUncompressedBytes > 0, policy.maximumTotalUncompressedBytes > 0,
              policy.maximumCompressionRatio > 0,
              policy.extractionSafetyMarginBytes > 0,
              policy.extractionSafetyMarginBytes <= 1_024 * 1_024 * 1_024 else {
            throw UpdateFailure.invalidArtifact("The update archive validation policy is invalid.")
        }
        guard archive.count >= 22, let endOffset = endOfCentralDirectory(in: archive),
              archive.uint32LE(at: endOffset) == endOfCentralDirectorySignature,
              let diskNumber = archive.uint16LE(at: endOffset + 4),
              let centralDirectoryDisk = archive.uint16LE(at: endOffset + 6),
              let entriesOnDisk = archive.uint16LE(at: endOffset + 8),
              let totalEntries = archive.uint16LE(at: endOffset + 10),
              let centralDirectorySize = archive.uint32LE(at: endOffset + 12),
              let centralDirectoryOffset = archive.uint32LE(at: endOffset + 16),
              let commentLength = archive.uint16LE(at: endOffset + 20),
              checkedEnd(endOffset + 22, Int(commentLength), limit: archive.count) == archive.count else {
            throw UpdateFailure.invalidArtifact("The ZIP end-of-directory record is invalid.")
        }
        guard diskNumber == 0, centralDirectoryDisk == 0, entriesOnDisk == totalEntries else {
            throw UpdateFailure.invalidArtifact("Multi-disk ZIP archives are not supported.")
        }
        guard totalEntries != .max, centralDirectorySize != .max, centralDirectoryOffset != .max else {
            throw UpdateFailure.invalidArtifact("ZIP64 update archives are not supported.")
        }
        let entryCount = Int(totalEntries)
        guard entryCount > 0, entryCount <= policy.maximumEntries else {
            throw UpdateFailure.invalidArtifact("The archive contains an invalid number of entries.")
        }
        let centralStart = Int(centralDirectoryOffset)
        guard let centralEnd = checkedEnd(centralStart, Int(centralDirectorySize), limit: archive.count),
              centralEnd == endOffset else {
            throw UpdateFailure.invalidArtifact("The ZIP central directory is outside the signed archive boundary.")
        }

        var position = centralStart
        var totalCompressed: UInt64 = 0
        var totalUncompressed: UInt64 = 0
        var localOffsets = Set<UInt32>()
        var paths = Set<String>()
        var pathKinds = [String: Bool]()
        var records = [EntryRecord]()
        for _ in 0..<entryCount {
            guard checkedEnd(position, 46, limit: centralEnd) != nil,
                  archive.uint32LE(at: position) == centralDirectorySignature,
                  let flags = archive.uint16LE(at: position + 8),
                  let method = archive.uint16LE(at: position + 10),
                  let crc32 = archive.uint32LE(at: position + 16),
                  let compressedSize = archive.uint32LE(at: position + 20),
                  let uncompressedSize = archive.uint32LE(at: position + 24),
                  let nameLength = archive.uint16LE(at: position + 28),
                  let extraLength = archive.uint16LE(at: position + 30),
                  let fileCommentLength = archive.uint16LE(at: position + 32),
                  let diskStart = archive.uint16LE(at: position + 34),
                  let externalAttributes = archive.uint32LE(at: position + 38),
                  let localOffset = archive.uint32LE(at: position + 42) else {
                throw UpdateFailure.invalidArtifact("The ZIP central directory contains a malformed entry.")
            }
            guard compressedSize != .max, uncompressedSize != .max, localOffset != .max, diskStart == 0 else {
                throw UpdateFailure.invalidArtifact("ZIP64 or split update entries are not supported.")
            }
            guard flags & 0x0001 == 0, flags & 0x0040 == 0 else {
                throw UpdateFailure.invalidArtifact("Encrypted ZIP entries are not supported.")
            }
            guard method == 0 || method == 8 else {
                throw UpdateFailure.invalidArtifact("The archive uses an unsupported compression method.")
            }
            let variableLength = Int(nameLength) + Int(extraLength) + Int(fileCommentLength)
            guard nameLength > 0, let nextPosition = checkedEnd(position + 46, variableLength, limit: centralEnd) else {
                throw UpdateFailure.invalidArtifact("The ZIP central directory entry is truncated.")
            }
            let nameStart = position + 46
            let nameData = archive.subdata(in: nameStart..<(nameStart + Int(nameLength)))
            guard let path = String(data: nameData, encoding: .utf8),
                  isSafePath(path, maximumBytes: policy.maximumPathBytes) else {
                throw UpdateFailure.invalidArtifact("The archive contains an unsafe or ambiguous path.")
            }
            var canonicalPath = path.precomposedStringWithCanonicalMapping.lowercased()
            if canonicalPath.hasSuffix("/") { canonicalPath.removeLast() }
            guard paths.insert(canonicalPath).inserted else {
                throw UpdateFailure.invalidArtifact("The archive contains an unsafe or ambiguous path.")
            }

            let unixMode = UInt16(truncatingIfNeeded: externalAttributes >> 16)
            let unixType = unixMode & fileTypeMask
            let directoryByName = path.hasSuffix("/")
            let directoryByDOSAttribute = externalAttributes & 0x10 != 0
            let isDirectory: Bool
            if unixType != 0 {
                guard unixType == regularFileMode || unixType == directoryMode else {
                    throw UpdateFailure.invalidArtifact("The archive contains a symbolic link or special file.")
                }
                isDirectory = unixType == directoryMode
            } else {
                isDirectory = directoryByName || directoryByDOSAttribute
            }
            guard isDirectory == directoryByName else {
                throw UpdateFailure.invalidArtifact("The archive contains inconsistent file-type metadata.")
            }
            pathKinds[canonicalPath] = isDirectory

            let compressed = UInt64(compressedSize)
            let uncompressed = UInt64(uncompressedSize)
            if isDirectory {
                guard compressed == 0, uncompressed == 0 else {
                    throw UpdateFailure.invalidArtifact("A directory entry contains unexpected payload bytes.")
                }
            } else {
                guard uncompressed <= policy.maximumEntryUncompressedBytes else {
                    throw UpdateFailure.invalidArtifact("An archive entry exceeds the uncompressed file-size limit.")
                }
                guard withinCompressionRatio(uncompressed, compressed: compressed, maximumRatio: policy.maximumCompressionRatio) else {
                    throw UpdateFailure.invalidArtifact("An archive entry exceeds the compression-ratio limit.")
                }
            }
            guard let nextCompressed = adding(totalCompressed, compressed),
                  let nextUncompressed = adding(totalUncompressed, uncompressed),
                  nextUncompressed <= policy.maximumTotalUncompressedBytes else {
                throw UpdateFailure.invalidArtifact("The archive exceeds the total uncompressed-size limit.")
            }
            totalCompressed = nextCompressed
            totalUncompressed = nextUncompressed

            guard localOffsets.insert(localOffset).inserted else {
                throw UpdateFailure.invalidArtifact("Multiple ZIP entries reference the same local file record.")
            }
            records.append(try validateLocalHeader(
                archive,
                offset: Int(localOffset),
                expectedName: nameData,
                expectedFlags: flags,
                expectedMethod: method,
                expectedCRC32: crc32,
                expectedCompressedSize: compressedSize,
                expectedUncompressedSize: uncompressedSize,
                centralDirectoryOffset: centralStart
            ))
            position = nextPosition
        }
        guard position == centralEnd else {
            throw UpdateFailure.invalidArtifact("The ZIP central directory contains unsupported trailing records.")
        }
        for path in pathKinds.keys {
            let components = path.split(separator: "/")
            guard components.count > 1 else { continue }
            var ancestor = ""
            for component in components.dropLast() {
                ancestor = ancestor.isEmpty ? String(component) : "\(ancestor)/\(component)"
                if pathKinds[ancestor] == false {
                    throw UpdateFailure.invalidArtifact("A ZIP path traverses through a regular-file entry.")
                }
            }
        }
        guard withinCompressionRatio(totalUncompressed, compressed: totalCompressed, maximumRatio: policy.maximumCompressionRatio) else {
            throw UpdateFailure.invalidArtifact("The archive exceeds the aggregate compression-ratio limit.")
        }
        let orderedRecords = records.sorted { $0.recordRange.lowerBound < $1.recordRange.lowerBound }
        if orderedRecords.count > 1 {
            for index in 1..<orderedRecords.count where orderedRecords[index - 1].recordRange.upperBound > orderedRecords[index].recordRange.lowerBound {
                throw UpdateFailure.invalidArtifact("ZIP local file records overlap.")
            }
        }
        var actualTotalUncompressed: UInt64 = 0
        for record in orderedRecords {
            try validatePayload(
                archive,
                record: record,
                policy: policy,
                actualTotalUncompressed: &actualTotalUncompressed
            )
        }
        guard actualTotalUncompressed == totalUncompressed else {
            throw UpdateFailure.invalidArtifact("The ZIP payload sizes conflict with the central directory.")
        }
        return UpdateArchiveMetadata(entryCount: entryCount, totalCompressedBytes: totalCompressed, totalUncompressedBytes: totalUncompressed)
    }

    static func validateAvailableExtractionCapacity(
        _ availableBytes: UInt64?,
        metadata: UpdateArchiveMetadata,
        policy: UpdateArchivePolicy = .production
    ) throws {
        guard policy.extractionSafetyMarginBytes > 0,
              policy.extractionSafetyMarginBytes <= 1_024 * 1_024 * 1_024,
              let required = adding(metadata.totalUncompressedBytes, policy.extractionSafetyMarginBytes) else {
            throw UpdateFailure.invalidArtifact("The update extraction capacity requirement overflowed.")
        }
        guard let availableBytes else {
            throw UpdateFailure.invalidArtifact("Available update extraction capacity could not be determined.")
        }
        guard availableBytes >= required else {
            throw UpdateFailure.invalidArtifact("The update requires more temporary-disk capacity than is safely available.")
        }
    }

    static func requireAvailableExtractionCapacity(
        at destination: URL,
        metadata: UpdateArchiveMetadata,
        policy: UpdateArchivePolicy = .production
    ) throws {
        let values = try? destination.resourceValues(forKeys: [
            .volumeAvailableCapacityForImportantUsageKey,
            .volumeAvailableCapacityKey,
        ])
        let available: UInt64?
        if let important = values?.volumeAvailableCapacityForImportantUsage, important >= 0 {
            available = UInt64(important)
        } else if let fallback = values?.volumeAvailableCapacity, fallback >= 0 {
            available = UInt64(fallback)
        } else {
            available = nil
        }
        try validateAvailableExtractionCapacity(available, metadata: metadata, policy: policy)
    }

    static func validateExtractedTree(at root: URL, policy: UpdateArchivePolicy = .production) throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: nil,
            options: []
        ) else { throw UpdateFailure.invalidArtifact("The extracted update could not be enumerated.") }
        let urls = enumerator.allObjects.compactMap { $0 as? URL }
        guard urls.count <= policy.maximumEntries else {
            throw UpdateFailure.invalidArtifact("The extracted update exceeds the entry-count limit.")
        }
        var total: UInt64 = 0
        for url in urls {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let type = attributes[.type] as? FileAttributeType,
                  type == .typeDirectory || type == .typeRegular else {
                throw UpdateFailure.invalidArtifact("The extracted update contains a symbolic link or special file.")
            }
            if type == .typeRegular {
                let size = (attributes[.size] as? NSNumber)?.uint64Value ?? 0
                let linkCount = (attributes[.referenceCount] as? NSNumber)?.uint64Value ?? 1
                guard linkCount == 1 else {
                    throw UpdateFailure.invalidArtifact("The extracted update contains a hard-linked file.")
                }
                guard size <= policy.maximumEntryUncompressedBytes,
                      let next = adding(total, size), next <= policy.maximumTotalUncompressedBytes else {
                    throw UpdateFailure.invalidArtifact("The extracted update exceeds its uncompressed-size limit.")
                }
                total = next
            }
        }
        return urls
    }

    private static func endOfCentralDirectory(in archive: Data) -> Int? {
        let earliest = max(0, archive.count - 22 - Int(UInt16.max))
        var offset = archive.count - 22
        while offset >= earliest {
            if archive.uint32LE(at: offset) == endOfCentralDirectorySignature,
               let commentLength = archive.uint16LE(at: offset + 20),
               checkedEnd(offset + 22, Int(commentLength), limit: archive.count) == archive.count {
                return offset
            }
            offset -= 1
        }
        return nil
    }

    private static func validateLocalHeader(
        _ archive: Data,
        offset: Int,
        expectedName: Data,
        expectedFlags: UInt16,
        expectedMethod: UInt16,
        expectedCRC32: UInt32,
        expectedCompressedSize: UInt32,
        expectedUncompressedSize: UInt32,
        centralDirectoryOffset: Int
    ) throws -> EntryRecord {
        guard checkedEnd(offset, 30, limit: centralDirectoryOffset) != nil,
              archive.uint32LE(at: offset) == localFileHeaderSignature,
              archive.uint16LE(at: offset + 6) == expectedFlags,
              archive.uint16LE(at: offset + 8) == expectedMethod,
              let localCRC32 = archive.uint32LE(at: offset + 14),
              let localCompressedSize = archive.uint32LE(at: offset + 18),
              let localUncompressedSize = archive.uint32LE(at: offset + 22),
              let nameLength = archive.uint16LE(at: offset + 26),
              let extraLength = archive.uint16LE(at: offset + 28),
              Int(nameLength) == expectedName.count,
              let dataStart = checkedEnd(offset + 30, Int(nameLength) + Int(extraLength), limit: centralDirectoryOffset),
              archive.subdata(in: (offset + 30)..<(offset + 30 + Int(nameLength))) == expectedName,
              let dataEnd = checkedEnd(dataStart, Int(expectedCompressedSize), limit: centralDirectoryOffset) else {
            throw UpdateFailure.invalidArtifact("A ZIP local file record conflicts with its central directory entry.")
        }
        let usesDataDescriptor = expectedFlags & 0x0008 != 0
        let recordEnd: Int
        if usesDataDescriptor {
            guard localCRC32 == 0, localCompressedSize == 0, localUncompressedSize == 0 else {
                throw UpdateFailure.invalidArtifact("A data-descriptor ZIP entry contains nonzero local sizes or CRC-32.")
            }
            let signedEnd = checkedEnd(dataEnd, 16, limit: centralDirectoryOffset)
            let signedMatches = archive.uint32LE(at: dataEnd) == dataDescriptorSignature &&
                archive.uint32LE(at: dataEnd + 4) == expectedCRC32 &&
                archive.uint32LE(at: dataEnd + 8) == expectedCompressedSize &&
                archive.uint32LE(at: dataEnd + 12) == expectedUncompressedSize && signedEnd != nil
            let unsignedEnd = checkedEnd(dataEnd, 12, limit: centralDirectoryOffset)
            let unsignedMatches = archive.uint32LE(at: dataEnd) == expectedCRC32 &&
                archive.uint32LE(at: dataEnd + 4) == expectedCompressedSize &&
                archive.uint32LE(at: dataEnd + 8) == expectedUncompressedSize && unsignedEnd != nil
            guard signedMatches != unsignedMatches else {
                throw UpdateFailure.invalidArtifact("A ZIP data descriptor is missing, malformed, or ambiguous.")
            }
            guard let descriptorEnd = signedMatches ? signedEnd : unsignedEnd else {
                throw UpdateFailure.invalidArtifact("A ZIP data descriptor is missing or truncated.")
            }
            recordEnd = descriptorEnd
        } else {
            guard localCRC32 == expectedCRC32,
                  localCompressedSize == expectedCompressedSize,
                  localUncompressedSize == expectedUncompressedSize else {
                throw UpdateFailure.invalidArtifact("A ZIP local file record conflicts with its central directory entry.")
            }
            recordEnd = dataEnd
        }
        return EntryRecord(
            recordRange: offset..<recordEnd,
            payloadRange: dataStart..<dataEnd,
            method: expectedMethod,
            expectedCRC32: expectedCRC32,
            expectedUncompressedSize: UInt64(expectedUncompressedSize)
        )
    }

    private static func validatePayload(
        _ archive: Data,
        record: EntryRecord,
        policy: UpdateArchivePolicy,
        actualTotalUncompressed: inout UInt64
    ) throws {
        if record.method == 0 {
            let actualSize = UInt64(record.payloadRange.count)
            guard actualSize == record.expectedUncompressedSize,
                  actualSize <= policy.maximumEntryUncompressedBytes,
                  let nextTotal = adding(actualTotalUncompressed, actualSize),
                  nextTotal <= policy.maximumTotalUncompressedBytes else {
                throw UpdateFailure.invalidArtifact("A stored ZIP payload conflicts with its declared size.")
            }
            let crc = archive.withUnsafeBytes { rawBuffer -> UInt32 in
                let bytes = rawBuffer.bindMemory(to: UInt8.self)
                return finalizeCRC32(updateCRC32(.max, bytes: UnsafeBufferPointer(rebasing: bytes[record.payloadRange])))
            }
            guard crc == record.expectedCRC32 else {
                throw UpdateFailure.invalidArtifact("A ZIP payload failed its CRC-32 integrity check.")
            }
            actualTotalUncompressed = nextTotal
            return
        }

        guard record.method == 8 else {
            throw UpdateFailure.invalidArtifact("The archive uses an unsupported compression method.")
        }
        let placeholder = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        defer { placeholder.deallocate() }
        var stream = compression_stream(
            dst_ptr: placeholder,
            dst_size: 0,
            src_ptr: UnsafePointer(placeholder),
            src_size: 0,
            state: nil
        )
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
            throw UpdateFailure.invalidArtifact("A deflate payload could not be initialized for validation.")
        }
        defer { compression_stream_destroy(&stream) }

        var entryUncompressed: UInt64 = 0
        var crcState = UInt32.max
        var output = [UInt8](repeating: 0, count: 64 * 1_024)
        try archive.withUnsafeBytes { rawBuffer in
            let input = rawBuffer.bindMemory(to: UInt8.self)
            guard let inputBase = input.baseAddress else {
                throw UpdateFailure.invalidArtifact("A deflate payload was unavailable for validation.")
            }
            stream.src_ptr = inputBase.advanced(by: record.payloadRange.lowerBound)
            stream.src_size = record.payloadRange.count
            try output.withUnsafeMutableBufferPointer { outputBuffer in
                guard let outputBase = outputBuffer.baseAddress else {
                    throw UpdateFailure.invalidArtifact("A deflate validation buffer could not be allocated.")
                }
                while true {
                    stream.dst_ptr = outputBase
                    stream.dst_size = outputBuffer.count
                    let inputBefore = stream.src_size
                    let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                    let produced = outputBuffer.count - stream.dst_size
                    if produced > 0 {
                        guard let nextEntry = adding(entryUncompressed, UInt64(produced)),
                              nextEntry <= record.expectedUncompressedSize,
                              nextEntry <= policy.maximumEntryUncompressedBytes,
                              let nextTotal = adding(actualTotalUncompressed, UInt64(produced)),
                              nextTotal <= policy.maximumTotalUncompressedBytes else {
                            throw UpdateFailure.invalidArtifact("A deflate payload exceeds its declared or permitted expansion limit.")
                        }
                        crcState = updateCRC32(crcState, bytes: UnsafeBufferPointer(start: outputBase, count: produced))
                        entryUncompressed = nextEntry
                        actualTotalUncompressed = nextTotal
                    }
                    switch status {
                    case COMPRESSION_STATUS_END:
                        guard stream.src_size == 0,
                              entryUncompressed == record.expectedUncompressedSize,
                              finalizeCRC32(crcState) == record.expectedCRC32 else {
                            throw UpdateFailure.invalidArtifact("A deflate payload conflicts with its declared size or CRC-32.")
                        }
                        return
                    case COMPRESSION_STATUS_OK:
                        guard inputBefore != stream.src_size || produced > 0 else {
                            throw UpdateFailure.invalidArtifact("A deflate payload is truncated or malformed.")
                        }
                    default:
                        throw UpdateFailure.invalidArtifact("A deflate payload is malformed.")
                    }
                }
            }
        }
    }

    private static func updateCRC32(_ current: UInt32, bytes: UnsafeBufferPointer<UInt8>) -> UInt32 {
        var crc = current
        for byte in bytes {
            crc = crc32Table[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8)
        }
        return crc
    }

    private static func finalizeCRC32(_ current: UInt32) -> UInt32 {
        current ^ .max
    }

    private static func isSafePath(_ path: String, maximumBytes: Int) -> Bool {
        guard !path.isEmpty, path.utf8.count <= maximumBytes, !path.hasPrefix("/"), !path.hasPrefix("\\"),
              !path.contains("\\"), !path.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              path.range(of: "^[A-Za-z]:", options: .regularExpression) == nil else { return false }
        var components = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if components.last == "" { components.removeLast() }
        return !components.isEmpty && components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    private static func checkedEnd(_ offset: Int, _ length: Int, limit: Int) -> Int? {
        guard offset >= 0, length >= 0 else { return nil }
        let (end, overflow) = offset.addingReportingOverflow(length)
        return !overflow && end <= limit ? end : nil
    }

    private static func adding(_ left: UInt64, _ right: UInt64) -> UInt64? {
        let (result, overflow) = left.addingReportingOverflow(right)
        return overflow ? nil : result
    }

    private static func withinCompressionRatio(_ uncompressed: UInt64, compressed: UInt64, maximumRatio: UInt64) -> Bool {
        if uncompressed == 0 { return true }
        guard compressed > 0 else { return false }
        let (limit, overflow) = compressed.multipliedReportingOverflow(by: maximumRatio)
        return overflow || uncompressed <= limit
    }
}

struct UpdateProcessRunner: Sendable {
    let timeoutSeconds: TimeInterval
    let maximumOutputBytes: Int

    init(timeoutSeconds: TimeInterval = 180, maximumOutputBytes: Int = 1_024 * 1_024) {
        self.timeoutSeconds = timeoutSeconds
        self.maximumOutputBytes = maximumOutputBytes
    }

    func run(_ executable: String, _ arguments: [String], includeStandardError: Bool = false) async throws -> String {
        guard executable.hasPrefix("/"), timeoutSeconds > 0, timeoutSeconds <= 600,
              (1...8 * 1_024 * 1_024).contains(maximumOutputBytes), arguments.count <= 32,
              arguments.allSatisfy({ $0.utf8.count <= 4_096 && !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) }) else {
            throw UpdateFailure.invalidArtifact("A release verification command was invalid.")
        }
        let process = Process()
        return try await withTaskCancellationHandler(operation: {
            do {
                try Task.checkCancellation()
                let outputPipe = Pipe()
                let errorPipe = Pipe()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
                process.standardOutput = outputPipe
                process.standardError = errorPipe
                do { try process.run() }
                catch { throw UpdateFailure.invalidArtifact("A release verification command could not start.") }
                let outputReader = Task.detached(priority: .userInitiated) {
                    try Self.readBounded(outputPipe.fileHandleForReading, process: process, maximumBytes: maximumOutputBytes)
                }
                let errorReader = Task.detached(priority: .userInitiated) {
                    try Self.readBounded(errorPipe.fileHandleForReading, process: process, maximumBytes: maximumOutputBytes)
                }
                let deadline = Date().addingTimeInterval(timeoutSeconds)
                var pendingFailure: Error?
                while process.isRunning {
                    if Task.isCancelled {
                        pendingFailure = CancellationError()
                        Self.stop(process)
                        break
                    }
                    if Date() >= deadline {
                        pendingFailure = UpdateFailure.invalidArtifact("A release verification command timed out.")
                        Self.stop(process)
                        break
                    }
                    do { try await Task.sleep(nanoseconds: 25_000_000) }
                    catch {
                        pendingFailure = CancellationError()
                        Self.stop(process)
                        break
                    }
                }
                process.waitUntilExit()
                var stdout = Data()
                var stderr = Data()
                do { stdout = try await outputReader.value }
                catch { pendingFailure = pendingFailure ?? error }
                do { stderr = try await errorReader.value }
                catch { pendingFailure = pendingFailure ?? error }
                if let pendingFailure { throw pendingFailure }
                guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                    throw UpdateFailure.invalidArtifact(Self.safeDiagnostic(stderr))
                }
                let result = includeStandardError ? stdout + stderr : stdout
                try Task.checkCancellation()
                return String(decoding: result, as: UTF8.self)
            } catch {
                if Task.isCancelled { throw CancellationError() }
                throw error
            }
        }, onCancel: {
            Self.stop(process)
        })
    }

    private static func readBounded(_ handle: FileHandle, process: Process, maximumBytes: Int) throws -> Data {
        var result = Data()
        do {
            while true {
                let remaining = maximumBytes + 1 - result.count
                guard remaining > 0 else {
                    throw UpdateFailure.invalidArtifact("A release verification command exceeded its output limit.")
                }
                let chunk = try handle.read(upToCount: min(8_192, remaining)) ?? Data()
                if chunk.isEmpty { return result }
                result.append(chunk)
                if result.count > maximumBytes {
                    throw UpdateFailure.invalidArtifact("A release verification command exceeded its output limit.")
                }
            }
        } catch {
            Self.stop(process)
            throw error
        }
    }

    private static func safeDiagnostic(_ data: Data) -> String {
        let value = String(decoding: data.prefix(2_048), as: UTF8.self)
            .unicodeScalars
            .filter { !CharacterSet.controlCharacters.contains($0) || $0 == "\n" || $0 == "\t" }
        let diagnostic = String(String.UnicodeScalarView(value)).trimmingCharacters(in: .whitespacesAndNewlines)
        return diagnostic.isEmpty ? "A release verification command failed." : String(diagnostic.prefix(500))
    }

    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        for _ in 0..<20 where process.isRunning { Thread.sleep(forTimeInterval: 0.025) }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
    }
}

private extension Data {
    func uint16LE(at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= count else { return nil }
        return UInt16(self[offset]) | UInt16(self[offset + 1]) << 8
    }

    func uint32LE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        return UInt32(self[offset]) | UInt32(self[offset + 1]) << 8 |
            UInt32(self[offset + 2]) << 16 | UInt32(self[offset + 3]) << 24
    }
}

actor UpdateService {
    private var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.10.0" }
    private let commandRunner = UpdateProcessRunner()

    func check(serverURL: URL?) async throws -> ReleaseManifest? {
        guard let server = BackendTrust.normalizedOrigin(serverURL) else { throw UploadFailure.invalidServer }
        guard let token = KeychainStore.readToken(for: server), !token.isEmpty else { throw UploadFailure.notConfigured }
        var request = URLRequest(url: server.appendingPathComponent("api/native/releases/latest"))
        request.timeoutInterval = 20
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(appVersion, forHTTPHeaderField: "X-Scopeproof-Version")
        let (data, response) = try await BackendHTTP.data(for: request, audience: server)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), data.count <= 32 * 1024,
              let envelope = try? JSONDecoder().decode(ReleaseEnvelope.self, from: data) else { throw UploadFailure.invalidResponse }
        guard let identity = ReleaseVerifier.configuredIdentity(), let downloadOrigin = ReleaseVerifier.configuredDownloadOrigin() else { throw UpdateFailure.invalidMetadata("the compiled update identity or download origin is not configured") }
        let release = try ReleaseVerifier.verify(envelope, keys: ReleaseVerifier.trustedKeys(), expectedTeamIdentifier: identity.teamIdentifier, expectedDesignatedRequirement: identity.designatedRequirement, expectedDownloadOrigin: downloadOrigin, installedVersion: appVersion, previousRelease: KeychainStore.verifiedUpdateFloor())
        return ReleaseVerifier.compareVersions(release.version, appVersion) == .orderedSame ? nil : release
    }

    func downloadAndVerify(_ manifest: ReleaseManifest) async throws -> URL {
        guard let downloadOrigin = ReleaseVerifier.configuredDownloadOrigin(),
              ReleaseVerifier.approvedDownloadURL(manifest.downloadUrl, version: manifest.version, origin: downloadOrigin) else {
            throw UpdateFailure.unapprovedDownload
        }
        let (download, _) = try await BackendHTTP.download(manifest.downloadUrl, approvedOrigins: [downloadOrigin.absoluteString], maximumBytes: manifest.byteSize)
        defer { try? FileManager.default.removeItem(at: download) }
        let data = try Data(contentsOf: download, options: [.mappedIfSafe])
        guard data.count == manifest.byteSize, SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == manifest.sha256 else { throw UpdateFailure.invalidArtifact("SHA-256 or byte size does not match the signed manifest.") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-update-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let archiveMetadata = try UpdateArchiveValidator.validate(data)
        try UpdateArchiveValidator.requireAvailableExtractionCapacity(at: root, metadata: archiveMetadata)
        _ = try await commandRunner.run("/usr/bin/ditto", ["-x", "-k", download.path, root.path])
        let extracted = try UpdateArchiveValidator.validateExtractedTree(at: root)
        let apps = extracted.filter { $0.lastPathComponent == "Scopeproof Capture.app" }
        guard apps.count == 1 else { throw UpdateFailure.invalidArtifact("The archive must contain exactly one Scopeproof Capture.app.") }
        let app = apps[0]
        let infoPlist = app.appendingPathComponent("Contents/Info.plist")
        let bundleIdentifier = try await commandRunner.run("/usr/bin/plutil", ["-extract", "CFBundleIdentifier", "raw", "-o", "-", infoPlist.path]).trimmingCharacters(in: .whitespacesAndNewlines)
        let bundleVersion = try await commandRunner.run("/usr/bin/plutil", ["-extract", "CFBundleShortVersionString", "raw", "-o", "-", infoPlist.path]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard ReleaseVerifier.approvedBundleMetadata(identifier: bundleIdentifier, version: bundleVersion, manifest: manifest) else {
            throw UpdateFailure.invalidArtifact("The signed app bundle identity or version does not match the release manifest.")
        }
        _ = try await commandRunner.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", "-R", manifest.designatedRequirement, app.path])
        let signing = try await commandRunner.run("/usr/bin/codesign", ["-dv", "--verbose=4", app.path], includeStandardError: true)
        guard signing.contains("TeamIdentifier=\(manifest.teamIdentifier)") else { throw UpdateFailure.invalidArtifact("Developer ID team does not match the signed manifest.") }
        _ = try await commandRunner.run("/usr/sbin/spctl", ["-a", "-t", "exec", "-vv", app.path], includeStandardError: true)
        _ = try await commandRunner.run("/usr/bin/xcrun", ["stapler", "validate", app.path], includeStandardError: true)
        let updates = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Scopeproof Capture/Verified Updates", isDirectory: true)
        try FileManager.default.createDirectory(at: updates, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let destination = updates.appendingPathComponent("Scopeproof-Capture-\(manifest.version).zip")
        if FileManager.default.fileExists(atPath: destination.path) { try FileManager.default.removeItem(at: destination) }
        try FileManager.default.copyItem(at: download, to: destination)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        try KeychainStore.saveVerifiedUpdateRelease(VerifiedUpdateRelease(sequence: manifest.sequence, version: manifest.version, sha256: manifest.sha256))
        return destination
    }

}
