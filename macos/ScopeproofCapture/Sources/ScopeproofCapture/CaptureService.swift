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

private struct BrowserWindowPixels {
    let image: CGImage
    let menuBar: CGImage?
    let capturedAt: Date
}

enum CaptureFailure: LocalizedError {
    case permissionRequired
    case invalidURL
    case browserUnavailable(String)
    case noBrowserWindow
    case screenshotFailed(String)
    case scrollingCaptureFailed(String)
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
        case .scrollingCaptureFailed(let detail): return "The scrolling evidence capture could not be completed. No evidence was saved. \(detail)"
        case .safetyScanFailed(let detail): return "The required final-image safety scan did not complete. No evidence was saved. \(detail)"
        case .imageProcessingFailed: return "The screenshot was captured but the protected evidence files could not be created."
        case .cancelled: return "The capture was discarded during review."
        }
    }
}

typealias CaptureCompletion = @MainActor @Sendable (Result<CaptureResult, CaptureFailure>) -> Void

@MainActor
final class CaptureService {
    private let scrollingViewportLimit = 8
    private let scrollingPixelBudget = 14_000_000
    private let scrollingHeightBudget = 15_000
    private let scrollingMaximumPixelWidth = 2_560
    private let fileManager = FileManager.default
    private let preferences: CapturePreferences
    private let onReviewPresented: @MainActor () -> Void
    private let reviewController = CaptureReviewController()
    private let localFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        return formatter
    }()
    private let menuBarFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .full
        formatter.timeStyle = .medium
        formatter.locale = .current
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

    init(preferences: CapturePreferences, onReviewPresented: @escaping @MainActor () -> Void = {}) {
        self.preferences = preferences
        self.onReviewPresented = onReviewPresented
    }

    var outputDirectory: URL {
        CaptureHistory.defaultEvidenceRoot(homeDirectory: fileManager.homeDirectoryForCurrentUser)
    }

    var hasScreenRecordingPermission: Bool { CGPreflightScreenCaptureAccess() }

    func requestScreenRecordingPermissionIfNeeded() -> Bool {
        if hasScreenRecordingPermission { return true }
        _ = CGRequestScreenCaptureAccess()
        return false
    }

    func openAndCapture(urlString: String, browser: BrowserChoice, delay: Int, context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard let url = EvidenceSourceURL.sanitized(urlString) else {
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

    func captureScrollingWindow(_ window: BrowserWindow, context: CaptureContext, completion: @escaping CaptureCompletion) {
        guard requestScreenRecordingPermissionIfNeeded() else { completion(.failure(.permissionRequired)); return }
        Task { @MainActor in
            do {
                try prepareOutputDirectory()
                let firstCapture = try await browserWindowPixels(window, maximumPixelWidth: scrollingMaximumPixelWidth, includeMenuBar: false)
                var viewports = [firstCapture.image]
                var viewportDigests = [sha256(try pngData(viewports[0]))]
                let maximumViewports = maximumScrollingViewports(for: viewports[0])
                guard maximumViewports >= 2 else {
                    throw CaptureFailure.scrollingCaptureFailed("This window is too large for a multi-section assessor artifact. Make the browser window smaller and try again.")
                }

                while true {
                    switch scrollingCaptureChoice(capturedCount: viewports.count, maximumCount: maximumViewports, window: window) {
                    case .captureNext:
                        let next = try await browserWindowPixels(window, maximumPixelWidth: scrollingMaximumPixelWidth, includeMenuBar: false).image
                        guard next.width == viewports[0].width, next.height == viewports[0].height else {
                            throw CaptureFailure.scrollingCaptureFailed("The browser window size or display scale changed between sections. Keep the window size and zoom unchanged, then start again.")
                        }
                        let nextDigest = sha256(try pngData(next))
                        if viewportDigests.contains(nextDigest) {
                            showDuplicateViewportWarning(window: window)
                            continue
                        }
                        viewports.append(next)
                        viewportDigests.append(nextDigest)
                    case .finish:
                        guard viewports.count >= 2 else {
                            throw CaptureFailure.scrollingCaptureFailed("Capture at least two sections before finishing.")
                        }
                        let composite = try scrollingComposite(viewports: viewports)
                        let liveMenuBar = try await liveMenuBarPixels(window: window, targetPixelWidth: composite.width)
                        let captureDate = Date()
                        let method = "ScreenCaptureKit operator-guided scrolling composite (\(viewports.count) viewports; intermediate frames memory-only)"
                        completion(.success(try finalizeCapture(original: composite, menuBar: liveMenuBar, sourceURL: nil, browser: window.owner, windowTitle: window.title, method: "\(method) + live macOS menu-bar strip", context: context, captureDate: captureDate)))
                        return
                    case .cancel:
                        throw CaptureFailure.cancelled
                    }
                }
            } catch {
                completion(.failure(error as? CaptureFailure ?? .screenshotFailed(error.localizedDescription)))
            }
        }
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
                completion(.success(try finalizeCapture(original: image, menuBar: nil, sourceURL: nil, browser: "Entire Display", windowTitle: "Full display with menu bar", method: "ScreenCaptureKit full-display with live macOS menu bar", context: context, captureDate: Date(), liveMenuBarCaptured: true)))
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
                let pixels = try await browserWindowPixels(window, includeMenuBar: true)
                completion(.success(try finalizeCapture(original: pixels.image, menuBar: pixels.menuBar, sourceURL: sourceURL, browser: window.owner, windowTitle: window.title, method: "ScreenCaptureKit desktop-independent-window + live macOS menu-bar strip", context: context, captureDate: pixels.capturedAt)))
            } catch { completion(.failure(error as? CaptureFailure ?? .screenshotFailed(error.localizedDescription))) }
        }
    }

    private func browserWindowPixels(_ window: BrowserWindow, maximumPixelWidth: Int? = nil, includeMenuBar: Bool) async throws -> BrowserWindowPixels {
        let content = try await SCShareableContent.current
        guard let shareableWindow = content.windows.first(where: { $0.windowID == window.id }) else { throw CaptureFailure.noBrowserWindow }
        let filter = SCContentFilter(desktopIndependentWindow: shareableWindow)
        let configuration = captureConfiguration(
            width: shareableWindow.frame.width,
            height: shareableWindow.frame.height,
            scale: CGFloat(filter.pointPixelScale),
            maximumPixelWidth: maximumPixelWidth
        )
        let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        let menuBar = includeMenuBar ? try await liveMenuBarImage(content: content, above: shareableWindow, targetPixelWidth: image.width) : nil
        return BrowserWindowPixels(image: image, menuBar: menuBar, capturedAt: Date())
    }

    private func liveMenuBarPixels(window: BrowserWindow, targetPixelWidth: Int) async throws -> CGImage {
        let content = try await SCShareableContent.current
        guard let shareableWindow = content.windows.first(where: { $0.windowID == window.id }) else { throw CaptureFailure.noBrowserWindow }
        return try await liveMenuBarImage(content: content, above: shareableWindow, targetPixelWidth: targetPixelWidth)
    }

    private func liveMenuBarImage(content: SCShareableContent, above window: SCWindow, targetPixelWidth: Int) async throws -> CGImage {
        let windowCenter = CGPoint(x: window.frame.midX, y: window.frame.midY)
        let display = content.displays.first(where: { CGDisplayBounds($0.displayID).contains(windowCenter) })
            ?? content.displays.first(where: { $0.displayID == CGMainDisplayID() })
            ?? content.displays.first
        guard let display else { throw CaptureFailure.screenshotFailed("The display containing the live Mac menu bar is not available.") }

        let displayBounds = CGDisplayBounds(display.displayID)
        let sourceWidth = min(displayBounds.width, max(1, window.frame.width))
        let menuBarHeight = liveMenuBarHeight(displayID: display.displayID)
        let sourceRect = CGRect(
            x: max(0, displayBounds.width - sourceWidth),
            y: 0,
            width: sourceWidth,
            height: min(displayBounds.height, menuBarHeight)
        )
        let filter = SCContentFilter(display: display, excludingWindows: [])
        if #available(macOS 14.2, *) { filter.includeMenuBar = true }
        let configuration = SCStreamConfiguration()
        configuration.sourceRect = sourceRect
        configuration.width = max(1, targetPixelWidth)
        configuration.height = max(1, Int(ceil(sourceRect.height * CGFloat(targetPixelWidth) / sourceRect.width)))
        configuration.showsCursor = false
        let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        guard image.width > 0, image.height > 0 else { throw CaptureFailure.screenshotFailed("The live Mac menu bar returned an empty image.") }
        return image
    }

    private func liveMenuBarHeight(displayID: CGDirectDisplayID) -> CGFloat {
        let screen = NSScreen.screens.first { ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == displayID }
        let visibleInset = screen.map { max(0, $0.frame.maxY - $0.visibleFrame.maxY) } ?? 0
        return max(24, NSStatusBar.system.thickness, visibleInset)
    }

    private func prepareOutputDirectory() throws {
        try fileManager.createDirectory(at: outputDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    private func captureConfiguration(width: CGFloat, height: CGFloat, scale: CGFloat, maximumPixelWidth: Int? = nil) -> SCStreamConfiguration {
        let configuration = SCStreamConfiguration()
        let nativeWidth = max(1, Int(width * max(scale, 1)))
        let nativeHeight = max(1, Int(height * max(scale, 1)))
        let reduction = maximumPixelWidth.map { min(1, CGFloat($0) / CGFloat(nativeWidth)) } ?? 1
        configuration.width = max(1, Int(CGFloat(nativeWidth) * reduction))
        configuration.height = max(1, Int(CGFloat(nativeHeight) * reduction))
        configuration.showsCursor = false
        return configuration
    }

    private enum ScrollingCaptureChoice { case captureNext, finish, cancel }

    private func scrollingCaptureChoice(capturedCount: Int, maximumCount: Int, window: BrowserWindow) -> ScrollingCaptureChoice {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let atLimit = capturedCount >= maximumCount
        let alert = NSAlert()
        alert.messageText = atLimit ? "Maximum sections captured" : "Section \(capturedCount) captured"
        alert.informativeText = atLimit
            ? "Scopeproof has captured the maximum safe size for one evidence image. Finish and review the combined artifact, or cancel to discard every section."
            : "Switch to \(window.owner), scroll to the next evidence section with a small visible overlap, then return here and choose Capture Next Section. Keep the browser window size and zoom unchanged. Nothing is saved until you finish the review."

        if atLimit {
            alert.addButton(withTitle: "Finish & Review")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn ? .finish : .cancel
        }

        alert.addButton(withTitle: "Capture Next Section")
        if capturedCount >= 2 { alert.addButton(withTitle: "Finish & Review") }
        alert.addButton(withTitle: "Cancel")
        let response = alert.runModal()
        if response == .alertFirstButtonReturn { return .captureNext }
        if capturedCount >= 2, response == .alertSecondButtonReturn { return .finish }
        return .cancel
    }

    private func scrollingDividerHeight(for width: Int) -> Int { max(44, min(72, width / 32)) }

    private func showDuplicateViewportWarning(window: BrowserWindow) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "No new section detected"
        alert.informativeText = "The captured \(window.owner) viewport matches an earlier section exactly. Scroll to new evidence content, then try again."
        alert.addButton(withTitle: "Continue")
        alert.runModal()
    }

    private func maximumScrollingViewports(for image: CGImage) -> Int {
        let divider = scrollingDividerHeight(for: image.width)
        let heightLimited = (scrollingHeightBudget + divider) / (image.height + divider)
        let pixelsPerSection = image.width * (image.height + divider)
        let pixelLimited = (scrollingPixelBudget + image.width * divider) / max(1, pixelsPerSection)
        return max(0, min(scrollingViewportLimit, heightLimited, pixelLimited))
    }

    func scrollingComposite(viewports: [CGImage]) throws -> CGImage {
        guard viewports.count >= 2, viewports.count <= scrollingViewportLimit, let first = viewports.first else {
            throw CaptureFailure.scrollingCaptureFailed("A scrolling artifact requires between 2 and \(scrollingViewportLimit) sections.")
        }
        guard viewports.allSatisfy({ $0.width == first.width && $0.height == first.height }) else {
            throw CaptureFailure.scrollingCaptureFailed("Every section must have identical dimensions.")
        }
        guard viewports.count <= maximumScrollingViewports(for: first) else {
            throw CaptureFailure.scrollingCaptureFailed("The combined artifact would exceed the safe image-size limit. Finish with fewer sections or use a smaller browser window.")
        }

        let dividerHeight = scrollingDividerHeight(for: first.width)
        let totalHeight = first.height * viewports.count + dividerHeight * (viewports.count - 1)
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: first.width, height: totalHeight, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw CaptureFailure.imageProcessingFailed
        }

        let fontSize = max(13, min(20, CGFloat(first.width) * 0.009))
        let labelAttributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: fontSize, weight: .semibold),
            .foregroundColor: NSColor.white,
        ]
        var cursor = totalHeight
        for (index, viewport) in viewports.enumerated() {
            cursor -= viewport.height
            context.draw(viewport, in: CGRect(x: 0, y: cursor, width: first.width, height: first.height))
            guard index < viewports.count - 1 else { continue }

            cursor -= dividerHeight
            context.setFillColor(CGColor(red: 0.035, green: 0.065, blue: 0.12, alpha: 1))
            context.fill(CGRect(x: 0, y: cursor, width: first.width, height: dividerHeight))
            context.setFillColor(CGColor(red: 0.29, green: 0.45, blue: 0.95, alpha: 1))
            context.fill(CGRect(x: 0, y: cursor + dividerHeight - 4, width: first.width, height: 4))
            let label = NSAttributedString(string: "CONTINUED  •  VIEWPORT \(index + 2) OF \(viewports.count)", attributes: labelAttributes)
            let graphics = NSGraphicsContext(cgContext: context, flipped: false)
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = graphics
            label.draw(at: NSPoint(
                x: CGFloat(max(16, first.width / 100)),
                y: CGFloat(cursor + max(10, (dividerHeight - Int(fontSize)) / 2))
            ))
            NSGraphicsContext.restoreGraphicsState()
        }
        guard let composite = context.makeImage() else { throw CaptureFailure.imageProcessingFailed }
        return composite
    }

    private func pngData(_ image: CGImage) throws -> Data {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data as CFMutableData, UTType.png.identifier as CFString, 1, nil) else { throw CaptureFailure.imageProcessingFailed }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw CaptureFailure.imageProcessingFailed }
        return data as Data
    }

    private func finalizeCapture(original: CGImage, menuBar: CGImage?, sourceURL: URL?, browser: String, windowTitle: String, method: String, context: CaptureContext, captureDate: Date, liveMenuBarCaptured: Bool = false) throws -> CaptureResult {
        let initialScan = try requiredSafetyScan(original)
        let menuBarScan = try menuBar.map { try requiredSafetyScan($0) }
        let includesLiveMenuBar = liveMenuBarCaptured || menuBarScan != nil
        let now = captureDate
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
        let menuBarTimestamp = menuBarFormatter.string(from: now)
        let menuBarTimeZone = TimeZone.current.abbreviation().map {
            $0 == TimeZone.current.identifier ? $0 : "\($0) / \(TimeZone.current.identifier)"
        } ?? TimeZone.current.identifier
        let recordedSourceURL = EvidenceSourceURL.sanitized(sourceURL?.absoluteString ?? context.sourceURL)
        let sourceLabel = recordedSourceURL?.absoluteString ?? "NOT PROVIDED"
        let safeWindowTitle = windowTitle.count > 220 ? "\(windowTitle.prefix(219))…" : windowTitle
        let controlLabel = context.resolvedControlTitle.isEmpty ? context.controlID : "\(context.controlID) — \(context.resolvedControlTitle)"
        let ownerLabel = context.resolvedEvidenceOwner.isEmpty ? "UNASSIGNED" : context.resolvedEvidenceOwner
        let jiraLabel = jiraIssueKey.isEmpty ? "" : "  •  JIRA \(jiraIssueKey)"
        let liveMenuBarLabel = includesLiveMenuBar
            ? "LIVE MAC MENU BAR PIXELS INCLUDED \(menuBarScan == nil ? "IN CAPTURE" : "ABOVE")  •  CLOCK READING \(menuBarTimestamp)  •  \(menuBarTimeZone)"
            : "MAC CLOCK READING  \(menuBarTimestamp)  •  \(menuBarTimeZone)"
        let stamp = "SCOPEPROOF EVIDENCE  •  CAPTURED \(localTimestamp)  •  \(evidenceID)\n\(liveMenuBarLabel)\n\(framework.name.uppercased())  •  CONTROL \(controlLabel)\(jiraLabel)\nEVIDENCE \(context.title)  •  OWNER \(ownerLabel)\n\(context.system) / \(context.environment)  •  \(context.assessmentPeriod)  •  SOURCE \(browser) — \(safeWindowTitle)\nFULL URL  \(sourceLabel)"
        let stamped = try stampedImage(source: initialScan.image, stamp: stamp)
        let evidencePixels = try menuBarScan.map { try evidenceImageWithMenuBar(menuBar: $0.image, evidence: stamped) } ?? stamped
        let stampedScan = try requiredSafetyScan(evidencePixels)
        let automaticFindings = mergedFindings(initialScan.findings + (menuBarScan?.findings ?? []) + stampedScan.findings)
        let automaticRedactions = initialScan.redactedRegions + (menuBarScan?.redactedRegions ?? 0) + stampedScan.redactedRegions
        onReviewPresented()
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
            timestampAuthority: includesLiveMenuBar
                ? "Live macOS menu-bar pixels and a local clock reading were captured in the operator-initiated workflow as corroborating context; a signed Scopeproof server attestation is stored in the upload receipt"
                : "Local macOS system clock displayed with date, time, and timezone; a signed Scopeproof server attestation is stored in the upload receipt",
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
        paragraph.lineBreakMode = .byCharWrapping
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

    func evidenceImageWithMenuBar(menuBar: CGImage, evidence: CGImage) throws -> CGImage {
        guard menuBar.width > 0, menuBar.height > 0, evidence.width > 0, evidence.height > 0 else { throw CaptureFailure.imageProcessingFailed }
        let menuBarHeight = max(1, Int(ceil(CGFloat(menuBar.height) * CGFloat(evidence.width) / CGFloat(menuBar.width))))
        let outputHeight = evidence.height + menuBarHeight
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: evidence.width, height: outputHeight, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw CaptureFailure.imageProcessingFailed
        }
        context.draw(evidence, in: CGRect(x: 0, y: 0, width: evidence.width, height: evidence.height))
        context.draw(menuBar, in: CGRect(x: 0, y: evidence.height, width: evidence.width, height: menuBarHeight))
        guard let combined = context.makeImage() else { throw CaptureFailure.imageProcessingFailed }
        return combined
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

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
