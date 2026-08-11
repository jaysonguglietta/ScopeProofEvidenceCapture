import Foundation

struct CaptureHistoryEntry: Sendable {
    let manifest: CaptureManifest
    let manifestURL: URL
    let imageURL: URL
    let receiptURL: URL
    var isUploaded: Bool { FileManager.default.fileExists(atPath: receiptURL.path) }
    var lifecycle: EvidenceLifecycleRecord { EvidenceLifecycleStore.load(for: self) }
}

enum CaptureHistory {
    static func entries(in directory: URL) -> [CaptureHistoryEntry] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return [] }
        let urls = enumerator.compactMap { $0 as? URL }
        return urls.filter { $0.pathExtension == "json" && !$0.lastPathComponent.hasSuffix(".receipt.json") && !$0.lastPathComponent.hasSuffix(".review.json") }.compactMap { url in
            guard let data = try? Data(contentsOf: url), let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data) else { return nil }
            let image = url.deletingLastPathComponent().appendingPathComponent(URL(fileURLWithPath: manifest.screenshotFilename).lastPathComponent)
            let receipt = url.deletingPathExtension().appendingPathExtension("receipt.json")
            guard FileManager.default.fileExists(atPath: image.path) else { return nil }
            return CaptureHistoryEntry(manifest: manifest, manifestURL: url, imageURL: image, receiptURL: receipt)
        }.sorted { $0.manifest.capturedAt > $1.manifest.capturedAt }
    }

    static func removeExpired(in directory: URL, retentionDays: Int) throws -> Int {
        let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86_400)
        var removed = 0
        for entry in entries(in: directory) {
            guard let date = ISO8601DateFormatter().date(from: entry.manifest.capturedAt), date < cutoff else { continue }
            let lifecycleURL = EvidenceLifecycleStore.url(for: entry.manifestURL)
            for url in [entry.imageURL, entry.manifestURL, entry.receiptURL, lifecycleURL] where FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.trashItem(at: url, resultingItemURL: nil)
            }
            removed += 1
        }
        return removed
    }
}
