import Foundation

struct CaptureHistoryEntry: Sendable {
    let manifest: CaptureManifest
    let manifestURL: URL
    let imageURL: URL
    let receiptURL: URL
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
        }.sorted { $0.manifest.capturedAt > $1.manifest.capturedAt }
    }

    private static func entriesOnly(in directory: URL) -> [CaptureHistoryEntry] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return [] }
        let urls = enumerator.compactMap { $0 as? URL }
        return urls.filter { $0.pathExtension == "json" && !$0.lastPathComponent.hasSuffix(".receipt.json") && !$0.lastPathComponent.hasSuffix(".review.json") && !$0.lastPathComponent.hasSuffix(".s3.json") }.compactMap { url in
            guard let data = try? Data(contentsOf: url), let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data) else { return nil }
            let image = url.deletingLastPathComponent().appendingPathComponent(URL(fileURLWithPath: manifest.screenshotFilename).lastPathComponent)
            let receipt = url.deletingPathExtension().appendingPathExtension("receipt.json")
            guard FileManager.default.fileExists(atPath: image.path) else { return nil }
            return CaptureHistoryEntry(manifest: manifest, manifestURL: url, imageURL: image, receiptURL: receipt)
        }
    }

    static func removeExpired(in directory: URL, retentionDays: Int) throws -> Int {
        let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86_400)
        var removed = 0
        for entry in entries(in: directory) {
            guard let date = ISO8601DateFormatter().date(from: entry.manifest.capturedAt), date < cutoff else { continue }
            let lifecycleURL = EvidenceLifecycleStore.url(for: entry.manifestURL)
            for url in [entry.imageURL, entry.manifestURL, entry.receiptURL, entry.jiraReceiptURL, entry.s3ReceiptURL, lifecycleURL] where FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.trashItem(at: url, resultingItemURL: nil)
            }
            removed += 1
        }
        return removed
    }
}
