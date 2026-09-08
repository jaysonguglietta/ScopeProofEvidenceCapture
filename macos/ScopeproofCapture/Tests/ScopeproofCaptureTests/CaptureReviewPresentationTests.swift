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

    @Test("Keyboard regions move and resize in source pixels and stay within the image")
    @MainActor
    func boundsKeyboardRegionsInSourceCoordinates() throws {
        let canvas = RedactionCanvasView(image: makeImage(width: 1000, height: 800, gray: 1))
        canvas.frame = NSRect(x: 0, y: 0, width: 500, height: 400)
        canvas.beginKeyboardRegion()
        let original = try #require(canvas.keyboardRegion)
        canvas.adjustKeyboardRegion(dx: 1, dy: -1, resize: false, accelerated: false)
        let moved = try #require(canvas.keyboardRegion)
        #expect(abs(moved.minX - original.minX - 0.001) < 0.000001)
        #expect(abs(moved.minY - original.minY + 0.00125) < 0.000001)
        canvas.adjustKeyboardRegion(dx: 1, dy: 1, resize: true, accelerated: true)
        #expect(abs(try #require(canvas.keyboardRegion).width - original.width - 0.01) < 0.000001)
        for _ in 0..<200 {
            canvas.adjustKeyboardRegion(dx: -1, dy: -1, resize: false, accelerated: true)
            canvas.adjustKeyboardRegion(dx: -1, dy: -1, resize: true, accelerated: true)
        }
        let bounded = try #require(canvas.keyboardRegion)
        #expect(bounded.minX >= 0 && bounded.minY >= 0 && bounded.maxX <= 1 && bounded.maxY <= 1)
        #expect(bounded.width >= 0.001 && bounded.height >= 0.00125)
        canvas.applyKeyboardRegion()
        #expect(canvas.keyboardRegion == nil)
        #expect(canvas.redactionCount == 1)
        canvas.undo()
        #expect(canvas.redactionCount == 0)
    }

    @Test("Zoom and resize never change the exact pixels of an applied mask")
    @MainActor
    func preservesRedactionPixelsAcrossZoom() throws {
        let canvas = RedactionCanvasView(image: makeImage(width: 1000, height: 800, gray: 1))
        let scroll = RedactionScrollView(canvas: canvas)
        scroll.frame = NSRect(x: 0, y: 0, width: 500, height: 400)
        scroll.layoutSubtreeIfNeeded()
        scroll.layout()
        #expect(scroll.allowsMagnification && scroll.hasHorizontalScroller && scroll.hasVerticalScroller)
        canvas.beginKeyboardRegion()
        canvas.applyKeyboardRegion()
        let first = try #require(canvas.renderRedactedImage())
        let originalScale = canvas.displayScale
        scroll.magnification = 4
        scroll.layout()
        #expect(abs(canvas.displayScale - originalScale) < 0.000001)
        scroll.frame.size = NSSize(width: 800, height: 600)
        scroll.layout()
        let second = try #require(canvas.renderRedactedImage())
        #expect(first.width == second.width && first.height == second.height)
        #expect(first.dataProvider?.data == second.dataProvider?.data)
    }

    @Test("Space applies and Escape cancels a keyboard redaction without saving capture")
    @MainActor
    func handlesKeyboardApplyAndCancel() throws {
        let canvas = RedactionCanvasView(image: makeImage(width: 10, height: 10, gray: 1))
        canvas.frame = NSRect(x: 0, y: 0, width: 500, height: 400)
        func event(key: UInt16, text: String) -> NSEvent {
            NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
                windowNumber: 0, context: nil, characters: text, charactersIgnoringModifiers: text,
                isARepeat: false, keyCode: key)!
        }
        canvas.beginKeyboardRegion()
        canvas.keyDown(with: event(key: 53, text: "\u{1b}"))
        #expect(canvas.keyboardRegion == nil && canvas.redactionCount == 0)
        canvas.beginKeyboardRegion()
        canvas.keyDown(with: event(key: 49, text: " "))
        #expect(canvas.keyboardRegion == nil && canvas.redactionCount == 1)
        let output = try #require(canvas.renderRedactedImage())
        #expect(output.width == 10 && output.height == 10)
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
