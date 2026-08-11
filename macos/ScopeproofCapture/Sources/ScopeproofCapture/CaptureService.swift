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
    let safetyScanSha256: String?
    let safetyScanPolicy: String?
    let safetyScanCompletedAt: String?
    let sessionID: String
    let sessionName: String
    let controlID: String
    let title: String
    let system: String
    let environment: String
    let assessmentPeriod: String
    let description: String
    let complianceArea: String?
    let controlTitle: String?
    let customFileName: String?
    let catalogVersion: String?
    let evidenceOwner: String?
    let tags: [String]?
    let expectedEvidence: String?
    let mappedControls: [ControlMapping]?
    let manualRedactions: Int?
    let reviewerNote: String?
    let jiraIssueKey: String?
    let jiraIssueURL: String?
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
    case safetyScanFailed(String)
    case imageProcessingFailed
    case cancelled

    var errorDescription: String? {
        switch self {
        case .permissionRequired: return "Screen Recording permission is required. Enable Scopeproof Capture in System Settings → Privacy & Security → Screen & System Audio Recording, then reopen the app."
        case .invalidURL: return "Enter a complete HTTP or HTTPS URL."
        case .browserUnavailable(let name): return "\(name) is not installed on this Mac."
        case .noBrowserWindow: return "No visible browser window was found. Bring the evidence page to the front and try again."
        case .screenshotFailed(let detail): return "macOS could not capture the browser window. \(detail)"
        case .safetyScanFailed(let detail): return "The required final-image safety scan did not complete. No evidence was saved. \(detail)"
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
    private let reviewController = CaptureReviewController()
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
                completion(.success(try finalizeCapture(original: image, sourceURL: nil, browser: "Entire Display", windowTitle: "Full display with menu bar", method: "ScreenCaptureKit full-display", context: context)))
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
                completion(.success(try finalizeCapture(original: image, sourceURL: sourceURL, browser: window.owner, windowTitle: window.title, method: "ScreenCaptureKit desktop-independent-window", context: context)))
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

    private func pngData(_ image: CGImage) throws -> Data {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data as CFMutableData, UTType.png.identifier as CFString, 1, nil) else { throw CaptureFailure.imageProcessingFailed }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw CaptureFailure.imageProcessingFailed }
        return data as Data
    }

    private func finalizeCapture(original: CGImage, sourceURL: URL?, browser: String, windowTitle: String, method: String, context: CaptureContext) throws -> CaptureResult {
        let initialScan = try requiredSafetyScan(original)
        let now = Date()
        let capturedAt = ISO8601DateFormatter().string(from: now)
        let evidenceID = "EV-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(10).uppercased())"
        let framework = ComplianceCatalog.framework(named: context.resolvedComplianceArea)
        let controlComponent = String(ComplianceCatalog.safeFileBase(context.controlID).prefix(64))
        let periodComponent = String(ComplianceCatalog.safeFileBase(context.assessmentPeriod).prefix(64))
        let evidenceDirectory = outputDirectory
            .appendingPathComponent(framework.folderName, isDirectory: true)
            .appendingPathComponent(controlComponent, isDirectory: true)
            .appendingPathComponent(periodComponent, isDirectory: true)
        try fileManager.createDirectory(at: evidenceDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let controlFile = ComplianceCatalog.safeFileBase(context.controlID)
        let customFile = ComplianceCatalog.safeFileBase(context.resolvedCustomFileName)
        let jiraIssueKey = JiraHandoff.normalizedIssueKey(context.jiraIssueKey ?? "")
        let jiraFile = jiraIssueKey.isEmpty ? "" : "_\(ComplianceCatalog.safeFileBase(jiraIssueKey))"
        let baseName = "\(framework.fileCode)_\(controlFile)\(jiraFile)_\(customFile)_\(filenameFormatter.string(from: now))_\(evidenceID)"
        let imageURL = evidenceDirectory.appendingPathComponent(baseName).appendingPathExtension("png")
        let manifestURL = evidenceDirectory.appendingPathComponent(baseName).appendingPathExtension("json")
        let localTimestamp = localFormatter.string(from: now)
        let recordedSourceURL = sanitizedSourceURL(sourceURL)
        let rawSourceLabel = recordedSourceURL?.absoluteString ?? windowTitle
        let sourceLabel = rawSourceLabel.count > 220 ? "\(rawSourceLabel.prefix(219))…" : rawSourceLabel
        let controlLabel = context.resolvedControlTitle.isEmpty ? context.controlID : "\(context.controlID) — \(context.resolvedControlTitle)"
        let ownerLabel = context.resolvedEvidenceOwner.isEmpty ? "UNASSIGNED" : context.resolvedEvidenceOwner
        let jiraLabel = jiraIssueKey.isEmpty ? "" : "  •  JIRA \(jiraIssueKey)"
        let stamp = "SCOPEPROOF EVIDENCE  •  CAPTURED \(localTimestamp)  •  \(evidenceID)\n\(framework.name.uppercased())  •  CONTROL \(controlLabel)\(jiraLabel)\nEVIDENCE \(context.title)  •  OWNER \(ownerLabel)\n\(context.system) / \(context.environment)  •  \(context.assessmentPeriod)  •  SOURCE \(browser) — \(sourceLabel)"
        let stamped = try stampedImage(source: initialScan.image, stamp: stamp)
        let stampedScan = try requiredSafetyScan(stamped)
        let automaticFindings = mergedFindings(initialScan.findings + stampedScan.findings)
        let automaticRedactions = initialScan.redactedRegions + stampedScan.redactedRegions
        guard let review = reviewController.review(image: stampedScan.image, findings: automaticFindings, automaticRedactions: automaticRedactions, context: context) else { throw CaptureFailure.cancelled }
        let imageData = try pngData(review.image)
        guard let exactSource = CGImageSourceCreateWithData(imageData as CFData, nil), let exactImage = CGImageSourceCreateImageAtIndex(exactSource, 0, nil) else { throw CaptureFailure.imageProcessingFailed }
        let exactScan = try requiredSafetyScan(exactImage)
        guard exactScan.redactedRegions == 0 else { throw CaptureFailure.safetyScanFailed("Sensitive content remained after review; capture again and remove the reported value.") }
        let digest = sha256(imageData)
        try imageData.write(to: imageURL, options: [.atomic, .completeFileProtection])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: imageURL.path)
        let dimensions = (width: review.image.width, height: review.image.height)
        let previousHash = preferences.chainHead
        let eventHash = sha256(Data("\(previousHash)|\(digest)|\(evidenceID)|\(capturedAt)|\(context.sessionID)".utf8))
        let safetyStatus = automaticRedactions + review.manualRedactions > 0 ? "redacted" : "passed"
        let mappings = ComplianceCatalog.mappings(frameworkName: framework.name, controlID: context.controlID)
        let manifest = CaptureManifest(
            schemaVersion: 6, evidenceID: evidenceID, capturedAt: capturedAt, localTimestamp: localTimestamp, timezone: TimeZone.current.identifier,
            sourceURL: recordedSourceURL?.absoluteString, sourceHost: recordedSourceURL?.host, browser: browser, windowTitle: windowTitle, screenshotFilename: imageURL.lastPathComponent,
            sha256: digest, pixelWidth: dimensions.width, pixelHeight: dimensions.height, captureMethod: method,
            timestampAuthority: "Local macOS clock; signed Scopeproof server attestation is stored in the upload receipt",
            safetyStatus: safetyStatus, redactionFindings: automaticFindings, redactedRegions: automaticRedactions,
            safetyScanSha256: digest, safetyScanPolicy: SensitiveDataScanner.policyVersion, safetyScanCompletedAt: capturedAt,
            sessionID: context.sessionID, sessionName: context.sessionName, controlID: context.controlID, title: context.title, system: context.system,
            environment: context.environment, assessmentPeriod: context.assessmentPeriod, description: context.description,
            complianceArea: framework.name, controlTitle: context.resolvedControlTitle, customFileName: context.resolvedCustomFileName,
            catalogVersion: framework.version ?? ComplianceCatalog.catalogVersion, evidenceOwner: context.resolvedEvidenceOwner, tags: context.resolvedTags,
            expectedEvidence: context.expectedEvidence, mappedControls: mappings, manualRedactions: review.manualRedactions, reviewerNote: review.reviewerNote,
            jiraIssueKey: jiraIssueKey.isEmpty ? nil : jiraIssueKey, jiraIssueURL: preferences.jiraHandoff.issueURL(for: jiraIssueKey)?.absoluteString,
            chainPreviousHash: previousHash, chainEventHash: eventHash
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(manifest).write(to: manifestURL, options: [.atomic, .completeFileProtection])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        let historyEntry = CaptureHistoryEntry(
            manifest: manifest,
            manifestURL: manifestURL,
            imageURL: imageURL,
            receiptURL: manifestURL.deletingPathExtension().appendingPathExtension("receipt.json")
        )
        try EvidenceLifecycleStore.update(
            entry: historyEntry,
            status: .draft,
            owner: context.resolvedEvidenceOwner,
            reviewer: context.resolvedEvidenceOwner,
            notes: review.reviewerNote,
            tags: context.resolvedTags
        )
        preferences.chainHead = eventHash
        return CaptureResult(imageURL: imageURL, manifestURL: manifestURL, evidenceID: evidenceID, context: context, capturedAt: capturedAt, safetyStatus: safetyStatus, findings: automaticFindings, sha256: digest, chainPreviousHash: previousHash, chainEventHash: eventHash)
    }

    func stampedImage(source: CGImage, stamp: String) throws -> CGImage {
        let padding: CGFloat = max(16, CGFloat(source.width) * 0.012)
        let fontSize: CGFloat = max(14, min(24, CGFloat(source.width) * 0.012))
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineSpacing = 3
        paragraph.lineBreakMode = .byWordWrapping
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: fontSize, weight: .semibold),
            .foregroundColor: NSColor.white,
            .paragraphStyle: paragraph,
        ]
        let attributed = NSAttributedString(string: stamp, attributes: attributes)
        let textWidth = max(1, CGFloat(source.width) - padding * 2)
        let textSize = attributed.boundingRect(
            with: NSSize(width: textWidth, height: .greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading]
        ).size
        let headerHeight = max(88, Int(ceil(textSize.height + padding * 2)))
        let outputHeight = source.height + headerHeight
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: source.width, height: outputHeight, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw CaptureFailure.imageProcessingFailed }
        context.draw(source, in: CGRect(x: 0, y: 0, width: source.width, height: source.height))
        let header = CGRect(x: 0, y: source.height, width: source.width, height: headerHeight)
        context.setFillColor(CGColor(red: 0.035, green: 0.065, blue: 0.12, alpha: 1))
        context.fill(header)
        context.setFillColor(CGColor(red: 0.29, green: 0.45, blue: 0.95, alpha: 1))
        let accentHeight: CGFloat = Swift.max(4.0, CGFloat(source.width) * 0.003)
        context.fill(CGRect(x: 0, y: CGFloat(source.height), width: CGFloat(source.width), height: accentHeight))
        let graphics = NSGraphicsContext(cgContext: context, flipped: false)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = graphics
        attributed.draw(in: CGRect(x: padding, y: CGFloat(source.height) + padding, width: textWidth, height: textSize.height + 2))
        NSGraphicsContext.restoreGraphicsState()
        guard let stamped = context.makeImage() else { throw CaptureFailure.imageProcessingFailed }
        return stamped
    }

    private func mergedFindings(_ findings: [SensitiveFinding]) -> [SensitiveFinding] {
        let counts = findings.reduce(into: [SensitiveKind: Int]()) { result, finding in result[finding.kind, default: 0] += finding.count }
        return counts.sorted { $0.key.rawValue < $1.key.rawValue }.map { SensitiveFinding(kind: $0.key, count: $0.value) }
    }

    private func requiredSafetyScan(_ image: CGImage) throws -> ScanResult {
        do { return try SensitiveDataScanner.scanAndRedact(image) }
        catch let failure as CaptureFailure { throw failure }
        catch { throw CaptureFailure.safetyScanFailed(error.localizedDescription) }
    }

    private func sanitizedSourceURL(_ sourceURL: URL?) -> URL? {
        guard let sourceURL, var components = URLComponents(url: sourceURL, resolvingAgainstBaseURL: false) else { return sourceURL }
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil
        return components.url
    }

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
