import AppKit
import Testing
@testable import ScopeproofCapture

@Suite("Capture review presentation")
struct CaptureReviewPresentationTests {
    @Test("Uses an explicit waiting status and keeps review above browser windows")
    @MainActor
    func configuresModalReviewWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )

        CaptureReviewPresentation.configure(window)

        #expect(CaptureReviewPresentation.waitingStatus == "Waiting for evidence review…")
        #expect(window.level == .modalPanel)
        #expect(window.collectionBehavior.contains(.moveToActiveSpace))
        #expect(window.hidesOnDeactivate == false)
        #expect(window.tabbingMode == .disallowed)
    }

    @Test("Places live menu-bar pixels above the evidence image")
    @MainActor
    func combinesMenuBarAndEvidencePixels() throws {
        let menuBar = makeImage(width: 1_200, height: 48, gray: 0.2)
        let evidence = makeImage(width: 1_200, height: 700, gray: 0.8)
        let service = CaptureService(preferences: CapturePreferences())

        let combined = try service.evidenceImageWithMenuBar(menuBar: menuBar, evidence: evidence)

        #expect(combined.width == evidence.width)
        #expect(combined.height == evidence.height + menuBar.height)
    }

    @MainActor
    private func makeImage(width: Int, height: Int, gray: CGFloat) -> CGImage {
        let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
        let context = CGContext(
            data: nil,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        )!
        context.setFillColor(CGColor(gray: gray, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        return context.makeImage()!
    }
}
