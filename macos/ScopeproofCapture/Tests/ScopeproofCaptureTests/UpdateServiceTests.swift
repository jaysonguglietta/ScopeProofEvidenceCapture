import Compression
import CryptoKit
import Foundation
import Testing
@testable import ScopeproofCapture

@Suite("Signed updater archive hardening")
struct UpdateServiceTests {
    @Test("Accepts a bounded regular ZIP entry")
    func acceptsBoundedArchive() throws {
        let archive = makeArchive([
            Entry(path: "Scopeproof Capture.app/Contents/Info.plist", compressedSize: 64, uncompressedSize: 64),
        ])
        let metadata = try UpdateArchiveValidator.validate(archive)
        #expect(metadata == UpdateArchiveMetadata(entryCount: 1, totalCompressedBytes: 64, totalUncompressedBytes: 64))
    }

    @Test("Accepts the ZIP format produced by the release packaging tool")
    func acceptsDittoArchive() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-ditto-update-test-\(UUID().uuidString)", isDirectory: true)
        let app = root.appendingPathComponent("Scopeproof Capture.app/Contents", isDirectory: true)
        let archive = root.appendingPathComponent("Scopeproof-Capture.zip")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("test update payload".utf8).write(to: app.appendingPathComponent("Info.plist"))
        _ = try await UpdateProcessRunner(timeoutSeconds: 5, maximumOutputBytes: 32 * 1_024)
            .run("/usr/bin/ditto", ["-c", "-k", "--keepParent", app.deletingLastPathComponent().path, archive.path])
        let metadata = try UpdateArchiveValidator.validate(Data(contentsOf: archive))
        #expect(metadata.entryCount > 0)
        #expect(metadata.totalUncompressedBytes > 0)
    }

    @Test("Rejects path traversal and local-header name differentials")
    func rejectsUnsafeAndConflictingPaths() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "../Scopeproof Capture.app", compressedSize: 1, uncompressedSize: 1),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(
                    path: "Scopeproof Capture.app/Contents/Info.plist",
                    compressedSize: 1,
                    uncompressedSize: 1,
                    localPath: "../Info.plist"
                ),
            ]))
        }
    }

    @Test("Rejects malformed data descriptors and local-header size differentials")
    func rejectsAmbiguousLocalRecords() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/descriptor", compressedSize: 1, uncompressedSize: 1, flags: 0x0008),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(
                    path: "Scopeproof Capture.app/size-differential",
                    compressedSize: 1,
                    uncompressedSize: 1,
                    localCompressedSize: 2
                ),
            ]))
        }
    }

    @Test("Accepts a strict signed data descriptor and rejects missing or conflicting descriptors")
    func validatesDataDescriptors() throws {
        let valid = Entry(
            path: "Scopeproof Capture.app/descriptor",
            compressedSize: 1,
            uncompressedSize: 1,
            flags: 0x0008,
            localCRC32: 0,
            localCompressedSize: 0,
            localUncompressedSize: 0,
            appendDescriptor: true
        )
        _ = try UpdateArchiveValidator.validate(makeArchive([valid]))
        var unsigned = valid
        unsigned.descriptorHasSignature = false
        _ = try UpdateArchiveValidator.validate(makeArchive([unsigned]))

        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(
                    path: "Scopeproof Capture.app/missing-descriptor",
                    compressedSize: 1,
                    uncompressedSize: 1,
                    flags: 0x0008,
                    localCRC32: 0,
                    localCompressedSize: 0,
                    localUncompressedSize: 0
                ),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(
                    path: "Scopeproof Capture.app/conflicting-descriptor",
                    compressedSize: 1,
                    uncompressedSize: 1,
                    flags: 0x0008,
                    localCRC32: 0,
                    localCompressedSize: 0,
                    localUncompressedSize: 0,
                    appendDescriptor: true,
                    descriptorCompressedSize: 2
                ),
            ]))
        }
    }

    @Test("Rejects overlapping complete local records")
    func rejectsOverlappingLocalRecords() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/one", compressedSize: 20, uncompressedSize: 20, payloadSize: 1),
                Entry(path: "Scopeproof Capture.app/two", compressedSize: 1, uncompressedSize: 1),
            ]))
        }
    }

    @Test("Rejects overlong and canonically colliding paths")
    func rejectsAmbiguousPaths() {
        let policy = policy(maximumPathBytes: 24)
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/Contents/Info.plist", compressedSize: 1, uncompressedSize: 1),
            ]), policy: policy)
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/A", compressedSize: 1, uncompressedSize: 1),
                Entry(path: "scopeproof capture.app/a", compressedSize: 1, uncompressedSize: 1),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/conflict", compressedSize: 1, uncompressedSize: 1),
                Entry(path: "Scopeproof Capture.app/conflict/", compressedSize: 0, uncompressedSize: 0, unixMode: 0o040755),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/regular-parent", compressedSize: 1, uncompressedSize: 1),
                Entry(path: "Scopeproof Capture.app/regular-parent/child", compressedSize: 1, uncompressedSize: 1),
            ]))
        }
    }

    @Test("Rejects symbolic links, special files, and encrypted entries")
    func rejectsUnsafeFileTypes() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/link", compressedSize: 4, uncompressedSize: 4, unixMode: 0o120777),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/socket", compressedSize: 4, uncompressedSize: 4, unixMode: 0o140777),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/non-unix-link", compressedSize: 4, uncompressedSize: 4, hostSystem: 0, unixMode: 0o120777),
            ]))
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(path: "Scopeproof Capture.app/secret", compressedSize: 4, uncompressedSize: 4, flags: 0x0001),
            ]))
        }
    }

    @Test("Rejects per-file, total, and compression-ratio expansion")
    func rejectsArchiveExpansion() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(
                makeArchive([Entry(path: "Scopeproof Capture.app/large", compressedSize: 5, uncompressedSize: 5)]),
                policy: policy(maximumEntryBytes: 4)
            )
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(
                makeArchive([
                    Entry(path: "Scopeproof Capture.app/one", compressedSize: 4, uncompressedSize: 4),
                    Entry(path: "Scopeproof Capture.app/two", compressedSize: 4, uncompressedSize: 4),
                ]),
                policy: policy(maximumTotalBytes: 7)
            )
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(
                makeArchive([Entry(path: "Scopeproof Capture.app/bomb", compressedSize: 1, uncompressedSize: 5)]),
                policy: policy(maximumCompressionRatio: 4)
            )
        }
    }

    @Test("Accepts a valid raw-deflate payload")
    func acceptsValidDeflatePayload() throws {
        let expanded = deterministicBytes(count: 256 * 1_024)
        let compressed = try rawDeflate(expanded)
        let archive = makeArchive([
            Entry(
                path: "Scopeproof Capture.app/Contents/payload",
                compressedSize: compressed.count,
                uncompressedSize: expanded.count,
                method: 8,
                crc32: crc32(expanded),
                payload: compressed
            ),
        ])
        let metadata = try UpdateArchiveValidator.validate(archive)
        #expect(metadata.totalCompressedBytes == UInt64(compressed.count))
        #expect(metadata.totalUncompressedBytes == UInt64(expanded.count))
    }

    @Test("Rejects a consistent-header false-size deflate bomb before extraction")
    func rejectsFalseSizeDeflateBomb() throws {
        let expanded = Data(repeating: 0x42, count: 16 * 1_024 * 1_024)
        let compressed = try rawDeflate(expanded)
        let archive = makeArchive([
            Entry(
                path: "Scopeproof Capture.app/Contents/payload",
                compressedSize: compressed.count,
                uncompressedSize: 1,
                method: 8,
                crc32: crc32(expanded),
                payload: compressed
            ),
        ])
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(archive)
        }
    }

    @Test("Fails closed when temporary extraction capacity is insufficient or unknown")
    func validatesExtractionCapacity() throws {
        let metadata = UpdateArchiveMetadata(entryCount: 1, totalCompressedBytes: 25, totalUncompressedBytes: 100)
        let boundedPolicy = policy(extractionSafetyMarginBytes: 20)
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validateAvailableExtractionCapacity(nil, metadata: metadata, policy: boundedPolicy)
        }
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validateAvailableExtractionCapacity(119, metadata: metadata, policy: boundedPolicy)
        }
        try UpdateArchiveValidator.validateAvailableExtractionCapacity(120, metadata: metadata, policy: boundedPolicy)
    }

    @Test("Rejects a local payload range that reaches the central directory")
    func rejectsPayloadOverlappingCentralDirectory() {
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validate(makeArchive([
                Entry(
                    path: "Scopeproof Capture.app/Contents/payload",
                    compressedSize: 10,
                    uncompressedSize: 10,
                    payloadSize: 1
                ),
            ]))
        }
    }

    @Test("Rejects an extracted symbolic link")
    func rejectsExtractedSymbolicLink() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-update-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target")
        try Data("safe".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: target)
        #expect(throws: UpdateFailure.self) {
            try UpdateArchiveValidator.validateExtractedTree(at: root)
        }
    }

    @Test("Bounds release-command output")
    func boundsProcessOutput() async {
        let runner = UpdateProcessRunner(timeoutSeconds: 2, maximumOutputBytes: 4_096)
        do {
            _ = try await runner.run("/usr/bin/yes", ["scopeproof-update-output"])
            Issue.record("Expected excessive command output to be rejected")
        } catch let failure as UpdateFailure {
            guard case .invalidArtifact(let message) = failure else {
                Issue.record("Expected an invalid-artifact failure")
                return
            }
            #expect(message.contains("output limit"))
        } catch {
            Issue.record("Expected UpdateFailure, received \(error)")
        }
    }

    @Test("Terminates a stalled release command")
    func timesOutProcess() async {
        let runner = UpdateProcessRunner(timeoutSeconds: 0.1, maximumOutputBytes: 4_096)
        do {
            _ = try await runner.run("/bin/sleep", ["10"])
            Issue.record("Expected the command deadline to be enforced")
        } catch let failure as UpdateFailure {
            guard case .invalidArtifact(let message) = failure else {
                Issue.record("Expected an invalid-artifact failure")
                return
            }
            #expect(message.contains("timed out"))
        } catch {
            Issue.record("Expected UpdateFailure, received \(error)")
        }
    }

    @Test("Cancels a running release command")
    func cancelsProcess() async {
        let runner = UpdateProcessRunner(timeoutSeconds: 10, maximumOutputBytes: 4_096)
        let task = Task { try await runner.run("/bin/sleep", ["10"]) }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Expected cancellation to terminate the process")
        } catch {
            #expect(error is CancellationError)
        }
    }

    @Test("Commits the rollback floor before atomically replacing a verified archive")
    func commitsRollbackFloorBeforeArchivePublication() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-update-commit-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let download = root.appendingPathComponent("download.zip")
        let destination = root.appendingPathComponent("Scopeproof-Capture-99.0.0.zip")
        let expectedBytes = Data("new verified archive".utf8)
        let expectedDigest = SHA256.hash(data: expectedBytes).map { String(format: "%02x", $0) }.joined()
        try expectedBytes.write(to: download)
        try Data("previous verified archive".utf8).write(to: destination)
        let staged = try VerifiedUpdateArtifactStore.stage(downloadedArchive: download, in: root)
        try Data("mutated source bytes".utf8).write(to: download)

        var observedPreviousDuringFloorCommit = false
        #expect(throws: UpdateFailure.self) {
            try VerifiedUpdateArtifactStore.commit(stagedArchive: staged, destination: destination, expectedByteSize: expectedBytes.count, expectedSHA256: expectedDigest) {
                observedPreviousDuringFloorCommit = (try? Data(contentsOf: destination)) == Data("previous verified archive".utf8)
                throw UpdateFailure.rollback
            }
        }
        #expect(observedPreviousDuringFloorCommit)
        #expect(try Data(contentsOf: destination) == Data("previous verified archive".utf8))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).filter { $0.hasSuffix(".pending") }.isEmpty)

        try expectedBytes.write(to: download)
        let successfulStage = try VerifiedUpdateArtifactStore.stage(downloadedArchive: download, in: root)
        var floorCommitted = false
        try VerifiedUpdateArtifactStore.commit(stagedArchive: successfulStage, destination: destination, expectedByteSize: expectedBytes.count, expectedSHA256: expectedDigest) {
            let previous = try Data(contentsOf: destination)
            #expect(previous == Data("previous verified archive".utf8))
            floorCommitted = true
        }
        #expect(floorCommitted)
        #expect(try Data(contentsOf: destination) == Data("new verified archive".utf8))
    }

    @Test("Rejects a staged update mutated before rollback-floor persistence")
    func rejectsMutatedStagedArchive() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("scopeproof-update-mutation-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let expectedBytes = Data("signed update bytes".utf8)
        let expectedDigest = SHA256.hash(data: expectedBytes).map { String(format: "%02x", $0) }.joined()
        let download = root.appendingPathComponent("download.zip")
        let destination = root.appendingPathComponent("Scopeproof-Capture-99.0.0.zip")
        try expectedBytes.write(to: download)
        try Data("previous archive!".utf8).write(to: destination)
        let staged = try VerifiedUpdateArtifactStore.stage(downloadedArchive: download, in: root)
        try Data(repeating: 0x58, count: expectedBytes.count).write(to: staged)

        var floorWasPersisted = false
        #expect(throws: UpdateFailure.self) {
            try VerifiedUpdateArtifactStore.commit(stagedArchive: staged, destination: destination, expectedByteSize: expectedBytes.count, expectedSHA256: expectedDigest) {
                floorWasPersisted = true
            }
        }
        #expect(!floorWasPersisted)
        #expect(try Data(contentsOf: destination) == Data("previous archive!".utf8))
    }

    private struct Entry {
        let path: String
        let compressedSize: Int
        let uncompressedSize: Int
        var hostSystem: UInt8 = 3
        var unixMode: UInt16 = 0o100644
        var flags: UInt16 = 0
        var method: UInt16 = 0
        var localPath: String?
        var localCRC32: UInt32?
        var localCompressedSize: Int?
        var localUncompressedSize: Int?
        var payloadSize: Int?
        var crc32: UInt32?
        var payload: Data?
        var appendDescriptor = false
        var descriptorHasSignature = true
        var descriptorCRC32: UInt32?
        var descriptorCompressedSize: Int?
        var descriptorUncompressedSize: Int?
    }

    private struct CentralEntry {
        let entry: Entry
        let localOffset: UInt32
    }

    private func policy(
        maximumEntries: Int = 100,
        maximumPathBytes: Int = 1_024,
        maximumEntryBytes: UInt64 = 1_024,
        maximumTotalBytes: UInt64 = 4_096,
        maximumCompressionRatio: UInt64 = 200,
        extractionSafetyMarginBytes: UInt64 = 16 * 1_024 * 1_024
    ) -> UpdateArchivePolicy {
        UpdateArchivePolicy(
            maximumEntries: maximumEntries,
            maximumPathBytes: maximumPathBytes,
            maximumEntryUncompressedBytes: maximumEntryBytes,
            maximumTotalUncompressedBytes: maximumTotalBytes,
            maximumCompressionRatio: maximumCompressionRatio,
            extractionSafetyMarginBytes: extractionSafetyMarginBytes
        )
    }

    private func makeArchive(_ entries: [Entry]) -> Data {
        var archive = Data()
        var centralEntries: [CentralEntry] = []
        for entry in entries {
            let localOffset = UInt32(archive.count)
            let localName = Data((entry.localPath ?? entry.path).utf8)
            let payload = entry.payload ?? Data(repeating: 0x41, count: entry.payloadSize ?? entry.compressedSize)
            let expectedCRC32 = entry.crc32 ?? crc32(payload)
            archive.appendLE(UInt32(0x0403_4b50))
            archive.appendLE(UInt16(20))
            archive.appendLE(entry.flags)
            archive.appendLE(entry.method)
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt16(0))
            archive.appendLE(entry.localCRC32 ?? expectedCRC32)
            archive.appendLE(UInt32(entry.localCompressedSize ?? entry.compressedSize))
            archive.appendLE(UInt32(entry.localUncompressedSize ?? entry.uncompressedSize))
            archive.appendLE(UInt16(localName.count))
            archive.appendLE(UInt16(0))
            archive.append(localName)
            archive.append(payload)
            if entry.appendDescriptor {
                if entry.descriptorHasSignature { archive.appendLE(UInt32(0x0807_4b50)) }
                archive.appendLE(entry.descriptorCRC32 ?? expectedCRC32)
                archive.appendLE(UInt32(entry.descriptorCompressedSize ?? entry.compressedSize))
                archive.appendLE(UInt32(entry.descriptorUncompressedSize ?? entry.uncompressedSize))
            }
            centralEntries.append(CentralEntry(entry: entry, localOffset: localOffset))
        }
        let centralOffset = UInt32(archive.count)
        for item in centralEntries {
            let entry = item.entry
            let name = Data(entry.path.utf8)
            archive.appendLE(UInt32(0x0201_4b50))
            archive.appendLE(UInt16(entry.hostSystem) << 8 | UInt16(20))
            archive.appendLE(UInt16(20))
            archive.appendLE(entry.flags)
            archive.appendLE(entry.method)
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt16(0))
            archive.appendLE(entry.crc32 ?? crc32(entry.payload ?? Data(repeating: 0x41, count: entry.payloadSize ?? entry.compressedSize)))
            archive.appendLE(UInt32(entry.compressedSize))
            archive.appendLE(UInt32(entry.uncompressedSize))
            archive.appendLE(UInt16(name.count))
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt16(0))
            archive.appendLE(UInt32(entry.unixMode) << 16)
            archive.appendLE(item.localOffset)
            archive.append(name)
        }
        let centralSize = UInt32(archive.count) - centralOffset
        archive.appendLE(UInt32(0x0605_4b50))
        archive.appendLE(UInt16(0))
        archive.appendLE(UInt16(0))
        archive.appendLE(UInt16(entries.count))
        archive.appendLE(UInt16(entries.count))
        archive.appendLE(centralSize)
        archive.appendLE(centralOffset)
        archive.appendLE(UInt16(0))
        return archive
    }

    private func rawDeflate(_ input: Data) throws -> Data {
        var output = Data(count: input.count + 1_024)
        let written = input.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { destination in
                guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress,
                      let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_encode_buffer(
                    destinationBase,
                    destination.count,
                    sourceBase,
                    source.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 else {
            throw UpdateFailure.invalidArtifact("The test deflate payload could not be encoded.")
        }
        return output.prefix(written)
    }

    private func deterministicBytes(count: Int) -> Data {
        var state: UInt64 = 0x4d59_5df4_d0f3_3173
        var output = Data(capacity: count)
        for _ in 0..<count {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            output.append(UInt8(truncatingIfNeeded: state >> 32))
        }
        return output
    }

    private func crc32(_ data: Data) -> UInt32 {
        let table: [UInt32] = (0..<256).map { value in
            var crc = UInt32(value)
            for _ in 0..<8 {
                crc = crc & 1 == 1 ? 0xedb8_8320 ^ (crc >> 1) : crc >> 1
            }
            return crc
        }
        var crc = UInt32.max
        for byte in data {
            crc = table[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8)
        }
        return crc ^ .max
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value))
        append(UInt8(truncatingIfNeeded: value >> 8))
    }

    mutating func appendLE(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 24))
    }
}
