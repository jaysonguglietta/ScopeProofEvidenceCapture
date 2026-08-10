import Foundation

struct CaptureHistoryEntry: Sendable {
    let manifest: CaptureManifest
    let manifestURL: URL
    let imageURL: URL
    let receiptURL: URL
    var isUploaded: Bool { FileManager.default.fileExists(atPath: receiptURL.path) }
}

enum CaptureHistory {
    static func entries(in directory: URL) -> [CaptureHistoryEntry] {
        let urls = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])) ?? []
        return urls.filter { $0.pathExtension == "json" && !$0.lastPathComponent.hasSuffix(".receipt.json") }.compactMap { url in
            guard let data = try? Data(contentsOf: url), let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data) else { return nil }
            let image = directory.appendingPathComponent(manifest.screenshotFilename)
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
            for url in [entry.imageURL, entry.manifestURL, entry.receiptURL] where FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.trashItem(at: url, resultingItemURL: nil)
            }
            removed += 1
        }
        return removed
    }
}
