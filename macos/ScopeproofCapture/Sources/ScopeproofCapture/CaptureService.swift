@preconcurrency import AppKit
import CoreGraphics
import CryptoKit
import ImageIO
@preconcurrency import ScreenCaptureKit
import UniformTypeIdentifiers

struct CaptureResult: Sendable {
    let imageURL: URL
    let manifestURL: URL
    let evidenceID: String
    let context: CaptureContext
    let capturedAt: String
    let safetyStatus: String
    let findings: [SensitiveFinding]
    let sha256: String
    let chainPreviousHash: String
    let chainEventHash: String
}

struct CaptureManifest: Codable, Sendable {
    let schemaVersion: Int
    let evidenceID: String
    let capturedAt: String
    let localTimestamp: String
    let timezone: String
    let sourceURL: String?
    let sourceHost: String?
    let browser: String
    let windowTitle: String
    let screenshotFilename: String
    let sha256: String
    let pixelWidth: Int
    let pixelHeight: Int
    let captureMethod: String
    let timestampAuthority: String
    let safetyStatus: String
    let redactionFindings: [SensitiveFinding]
    let redactedRegions: Int
    let sessionID: String
    let sessionName: String
    let controlID: String
    let title: String
    let system: String
    let environment: String
    let assessmentPeriod: String
    let description: String
    let chainPreviousHash: String
    let chainEventHash: String
}

struct BrowserWindow: Sendable {
    let id: CGWindowID
    let owner: String
    let title: String
    var displayTitle: String { "\(owner) — \(title.isEmpty ? "Untitled window" : title)" }
}

enum CaptureFailure: LocalizedError {
    case permissionRequired
    case invalidURL
    case browserUnavailable(String)
    case noBrowserWindow
    case screenshotFailed(String)
    case imageProcessingFailed
    case cancelled

    var errorDescription: String? {
        switch self {
        case .permissionRequired: return "Screen Recording permission is required. Enable Scopeproof Capture in System Settings → Privacy & Security → Screen & System Audio Recording, then reopen the app."
        case .invalidURL: return "Enter a complete HTTP or HTTPS URL."
        case .browserUnavailable(let name): return "\(name) is not installed on this Mac."
        case .noBrowserWindow: return "No visible browser window was found. Bring the evidence page to the front and try again."
        case .screenshotFailed(let detail): return "macOS could not capture the browser window. \(detail)"
        case .imageProcessingFailed: return "The screenshot was captured but the protected evidence files could not be created."
        case .cancelled: return "The capture was discarded during review."
        }
    }
}

typealias CaptureCompletion = @MainActor @Sendable (Result<CaptureResult, CaptureFailure>) -> Void

@MainActor
final class CaptureService {
    private let fileManager = FileManager.default
    private let preferences: CapturePreferences
    private let localFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        return formatter
    }()
    private let filenameFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        return formatter
    }()

    init(preferences: CapturePreferences) { self.preferences = preferences }

    var outputDirectory: URL {
        let pictures = fileManager.urls(for: .picturesDirectory, in: .userDomainMask).first ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Pictures")
        return pictures.appendingPathComponent("Scopeproof Evidence", isDirectory: true)
    }

    var hasScreenRecordingPermission: Bool { CGPreflightScreenCaptureAccess() }

    func requestScreenRecordingPermissionIfNeeded() -> Bool {
        if hasScreenRecordingPermission { return true }
        _ = CGRequestScreenCaptureAccess()
        return false
    }

    func openAndCapture(urlString: String, browser: BrowserChoice, delay: Int, context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard let url = URL(string: urlString), ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil else {
            completion(.failure(.invalidURL)); return
        }
        guard requestScreenRecordingPermissionIfNeeded() else { completion(.failure(.permissionRequired)); return }
        if let bundleID = browser.bundleIdentifier {
            guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { completion(.failure(.browserUnavailable(browser.name))); return }
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.activates = true
            NSWorkspace.shared.open([url], withApplicationAt: appURL, configuration: configuration) { _, error in
                Task { @MainActor in
                    if let error { completion(.failure(.screenshotFailed(error.localizedDescription))); return }
                    self.captureAfterDelay(delay, sourceURL: url, expectedOwner: browser.name, context: context, completion: completion)
                }
            }
        } else {
            guard NSWorkspace.shared.open(url) else { completion(.failure(.browserUnavailable("the default browser"))); return }
            captureAfterDelay(delay, sourceURL: url, expectedOwner: nil, context: context, completion: completion)
        }
    }

    func captureFrontmostBrowser(context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard requestScreenRecordingPermissionIfNeeded() else { completion(.failure(.permissionRequired)); return }
        let owner = NSWorkspace.shared.frontmostApplication?.localizedName
        guard let window = browserWindows(expectedOwner: owner).first else { completion(.failure(.noBrowserWindow)); return }
        capture(window: window, sourceURL: nil, context: context, completion: completion)
    }

    func captureWindow(_ window: BrowserWindow, context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard requestScreenRecordingPermissionIfNeeded() else { completion(.failure(.permissionRequired)); return }
        capture(window: window, sourceURL: nil, context: context, completion: completion)
    }

    func captureEntireDisplay(context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard requestScreenRecordingPermissionIfNeeded() else { completion(.failure(.permissionRequired)); return }
        Task { @MainActor in
            do {
                try prepareOutputDirectory()
                let content = try await SCShareableContent.current
                guard let display = content.displays.first(where: { $0.displayID == CGMainDisplayID() }) else { throw CaptureFailure.screenshotFailed("The main display is not available to ScreenCaptureKit.") }
                let filter = SCContentFilter(display: display, excludingWindows: [])
                if #available(macOS 14.2, *) { filter.includeMenuBar = true }
                let configuration = captureConfiguration(width: CGFloat(display.width), height: CGFloat(display.height), scale: CGFloat(filter.pointPixelScale))
                let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
                let temporary = outputDirectory.appendingPathComponent(".scopeproof-display-\(UUID().uuidString).png")
                defer { try? fileManager.removeItem(at: temporary) }
                try writePNG(image, to: temporary)
                completion(.success(try finalizeCapture(temporaryURL: temporary, sourceURL: nil, browser: "Entire Display", windowTitle: "Full display with menu bar", method: "ScreenCaptureKit full-display", context: context)))
            } catch { completion(.failure(error as? CaptureFailure ?? .screenshotFailed(error.localizedDescription))) }
        }
    }

    func browserWindows(expectedOwner: String? = nil) -> [BrowserWindow] {
        guard let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] else { return [] }
        let browserNames = ["Safari", "Google Chrome", "Microsoft Edge", "Firefox", "Arc"]
        return raw.compactMap { info -> BrowserWindow? in
            guard let layer = info[kCGWindowLayer as String] as? Int, layer == 0,
                  let number = info[kCGWindowNumber as String] as? UInt32,
                  let owner = info[kCGWindowOwnerName as String] as? String,
                  let bounds = info[kCGWindowBounds as String] as? [String: CGFloat],
                  (bounds["Width"] ?? 0) > 400, (bounds["Height"] ?? 0) > 300 else { return nil }
            let title = (info[kCGWindowName as String] as? String) ?? "Browser window"
            let ownerMatches = expectedOwner.map { owner.localizedCaseInsensitiveContains($0) || $0.localizedCaseInsensitiveContains(owner) } ?? false
            guard ownerMatches || browserNames.contains(where: { owner.localizedCaseInsensitiveContains($0) }) else { return nil }
            return BrowserWindow(id: CGWindowID(number), owner: owner, title: title)
        }
    }

    private func captureAfterDelay(_ delay: Int, sourceURL: URL, expectedOwner: String?, context: CaptureContext, completion: @escaping CaptureCompletion) {
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(delay)) {
            guard let window = self.browserWindows(expectedOwner: expectedOwner).first else { completion(.failure(.noBrowserWindow)); return }
            self.capture(window: window, sourceURL: sourceURL, context: context, completion: completion)
        }
    }

    private func capture(window: BrowserWindow, sourceURL: URL?, context: CaptureContext, completion: @escaping CaptureCompletion) {
        Task { @MainActor in
            do {
                try prepareOutputDirectory()
                let content = try await SCShareableContent.current
                guard let shareableWindow = content.windows.first(where: { $0.windowID == window.id }) else { throw CaptureFailure.noBrowserWindow }
                let filter = SCContentFilter(desktopIndependentWindow: shareableWindow)
                let configuration = captureConfiguration(width: shareableWindow.frame.width, height: shareableWindow.frame.height, scale: CGFloat(filter.pointPixelScale))
                let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
                let temporary = outputDirectory.appendingPathComponent(".scopeproof-window-\(UUID().uuidString).png")
                defer { try? fileManager.removeItem(at: temporary) }
                try writePNG(image, to: temporary)
                completion(.success(try finalizeCapture(temporaryURL: temporary, sourceURL: sourceURL, browser: window.owner, windowTitle: window.title, method: "ScreenCaptureKit desktop-independent-window", context: context)))
            } catch { completion(.failure(error as? CaptureFailure ?? .screenshotFailed(error.localizedDescription))) }
        }
    }

    private func prepareOutputDirectory() throws {
        try fileManager.createDirectory(at: outputDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    private func captureConfiguration(width: CGFloat, height: CGFloat, scale: CGFloat) -> SCStreamConfiguration {
        let configuration = SCStreamConfiguration()
        configuration.width = max(1, Int(width * max(scale, 1)))
        configuration.height = max(1, Int(height * max(scale, 1)))
        configuration.showsCursor = false
        return configuration
    }

    private func writePNG(_ image: CGImage, to url: URL) throws {
        guard let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { throw CaptureFailure.imageProcessingFailed }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw CaptureFailure.imageProcessingFailed }
    }

    private func finalizeCapture(temporaryURL: URL, sourceURL: URL?, browser: String, windowTitle: String, method: String, context: CaptureContext) throws -> CaptureResult {
        guard let imageSource = CGImageSourceCreateWithURL(temporaryURL as CFURL, nil), let original = CGImageSourceCreateImageAtIndex(imageSource, 0, nil) else { throw CaptureFailure.imageProcessingFailed }
        let scan = try SensitiveDataScanner.scanAndRedact(original)
        let now = Date()
        let capturedAt = ISO8601DateFormatter().string(from: now)
        let evidenceID = "EV-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(10).uppercased())"
        let host = sourceURL?.host?.replacingOccurrences(of: ".", with: "-") ?? "local"
        let baseName = "PCI-Evidence_\(filenameFormatter.string(from: now))_\(host)_\(evidenceID)"
        let imageURL = outputDirectory.appendingPathComponent(baseName).appendingPathExtension("png")
        let manifestURL = outputDirectory.appendingPathComponent(baseName).appendingPathExtension("json")
        let localTimestamp = localFormatter.string(from: now)
        let sourceLabel = sourceURL?.absoluteString ?? windowTitle
        let stamp = "SCOPEPROOF EVIDENCE  •  \(localTimestamp)\n\(browser)  •  \(sourceLabel)  •  \(evidenceID)\nPCI \(context.controlID)  •  \(context.system) / \(context.environment)  •  \(context.assessmentPeriod)"
        let dimensions = try stampImage(source: scan.image, destination: imageURL, stamp: stamp)
        let imageData = try Data(contentsOf: imageURL, options: [.mappedIfSafe])
        let digest = sha256(imageData)
        let previousHash = preferences.chainHead
        let eventHash = sha256(Data("\(previousHash)|\(digest)|\(evidenceID)|\(capturedAt)|\(context.sessionID)".utf8))
        let safetyStatus = scan.redactedRegions > 0 ? "redacted" : "passed"
        let manifest = CaptureManifest(
            schemaVersion: 2, evidenceID: evidenceID, capturedAt: capturedAt, localTimestamp: localTimestamp, timezone: TimeZone.current.identifier,
            sourceURL: sourceURL?.absoluteString, sourceHost: sourceURL?.host, browser: browser, windowTitle: windowTitle, screenshotFilename: imageURL.lastPathComponent,
            sha256: digest, pixelWidth: dimensions.width, pixelHeight: dimensions.height, captureMethod: method,
            timestampAuthority: "Local macOS clock; signed Scopeproof server attestation is stored in the upload receipt",
            safetyStatus: safetyStatus, redactionFindings: scan.findings, redactedRegions: scan.redactedRegions,
            sessionID: context.sessionID, sessionName: context.sessionName, controlID: context.controlID, title: context.title, system: context.system,
            environment: context.environment, assessmentPeriod: context.assessmentPeriod, description: context.description,
            chainPreviousHash: previousHash, chainEventHash: eventHash
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(manifest).write(to: manifestURL, options: [.atomic, .completeFileProtection])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        guard reviewCapture(imageURL: imageURL, findings: scan.findings, redactedRegions: scan.redactedRegions, context: context) else {
            try? fileManager.removeItem(at: imageURL)
            try? fileManager.removeItem(at: manifestURL)
            throw CaptureFailure.cancelled
        }
        preferences.chainHead = eventHash
        return CaptureResult(imageURL: imageURL, manifestURL: manifestURL, evidenceID: evidenceID, context: context, capturedAt: capturedAt, safetyStatus: safetyStatus, findings: scan.findings, sha256: digest, chainPreviousHash: previousHash, chainEventHash: eventHash)
    }

    private func reviewCapture(imageURL: URL, findings: [SensitiveFinding], redactedRegions: Int, context: CaptureContext) -> Bool {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = redactedRegions > 0 ? "Review redacted PCI evidence" : "Review PCI evidence"
        alert.informativeText = redactedRegions > 0
            ? "Scopeproof detected and masked \(redactedRegions) sensitive text region(s). Confirm the masking and surrounding context before saving. The unredacted image is not retained."
            : "No PAN, secret, or token patterns were detected by local OCR. Confirm the selected window and PCI \(context.controlID) context before saving."
        alert.alertStyle = redactedRegions > 0 ? .warning : .informational
        alert.addButton(withTitle: "Save Evidence")
        alert.addButton(withTitle: "Discard")
        let preview = NSImageView(frame: NSRect(x: 0, y: 0, width: 720, height: 420))
        preview.image = NSImage(contentsOf: imageURL)
        preview.imageScaling = .scaleProportionallyUpOrDown
        preview.wantsLayer = true
        preview.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        preview.layer?.cornerRadius = 8
        alert.accessoryView = preview
        if !findings.isEmpty { alert.informativeText += "\nDetected: " + findings.map { "\($0.kind.rawValue) ×\($0.count)" }.joined(separator: ", ") }
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func stampImage(source: CGImage, destination: URL, stamp: String) throws -> (width: Int, height: Int) {
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: source.width, height: source.height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw CaptureFailure.imageProcessingFailed }
        context.draw(source, in: CGRect(x: 0, y: 0, width: source.width, height: source.height))
        let graphics = NSGraphicsContext(cgContext: context, flipped: false)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = graphics
        let padding: CGFloat = max(18, CGFloat(source.width) * 0.012)
        let fontSize: CGFloat = max(15, min(24, CGFloat(source.width) * 0.012))
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineSpacing = 3
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.monospacedSystemFont(ofSize: fontSize, weight: .semibold), .foregroundColor: NSColor.white, .paragraphStyle: paragraph]
        let attributed = NSAttributedString(string: stamp, attributes: attributes)
        let textSize = attributed.boundingRect(with: NSSize(width: CGFloat(source.width) * 0.84, height: .greatestFiniteMagnitude), options: [.usesLineFragmentOrigin, .usesFontLeading]).size
        let box = CGRect(x: padding, y: padding, width: min(CGFloat(source.width) - padding * 2, textSize.width + padding * 1.5), height: textSize.height + padding)
        NSColor(calibratedRed: 0.05, green: 0.09, blue: 0.16, alpha: 0.9).setFill()
        NSBezierPath(roundedRect: box, xRadius: 10, yRadius: 10).fill()
        attributed.draw(in: box.insetBy(dx: padding * 0.75, dy: padding * 0.5))
        NSGraphicsContext.restoreGraphicsState()
        guard let stamped = context.makeImage(), let destinationRef = CGImageDestinationCreateWithURL(destination as CFURL, UTType.png.identifier as CFString, 1, nil) else { throw CaptureFailure.imageProcessingFailed }
        CGImageDestinationAddImage(destinationRef, stamped, [kCGImagePropertyPNGDictionary: [:]] as CFDictionary)
        guard CGImageDestinationFinalize(destinationRef) else { throw CaptureFailure.imageProcessingFailed }
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        return (source.width, source.height)
    }

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
