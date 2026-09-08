@preconcurrency import AppKit
import CoreGraphics

struct CaptureReviewDecision {
    let image: CGImage
    let manualRedactions: Int
    let reviewerNote: String
}

enum CaptureReviewPresentation {
    static let waitingStatus = "Waiting for evidence review…"

    @MainActor
    static func configure(_ window: NSWindow) {
        window.level = .modalPanel
        window.collectionBehavior.insert(.moveToActiveSpace)
        window.hidesOnDeactivate = false
        window.tabbingMode = .disallowed
    }

    @MainActor
    static func present(_ window: NSWindow) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }
}

@MainActor
final class CaptureReviewController: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private var decision: CaptureReviewDecision?
    private var canvas: RedactionCanvasView?
    private var noteField: NSTextField?
    private var countLabel: NSTextField?
    private var previewScroll: RedactionScrollView?

    func review(image: CGImage, findings: [SensitiveFinding], automaticRedactions: Int, context: CaptureContext) -> CaptureReviewDecision? {
        decision = nil
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 760),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = automaticRedactions > 0 ? "Review Redacted Evidence" : "Review Evidence"
        window.minSize = NSSize(width: 900, height: 680)
        window.isReleasedWhenClosed = false
        window.center()
        window.delegate = self
        CaptureReviewPresentation.configure(window)

        let content = NSView()
        window.contentView = content
        let heading = NSTextField(labelWithString: "Confirm the evidence before it becomes part of the audit record")
        heading.font = .systemFont(ofSize: 20, weight: .bold)
        let automaticSummary = automaticRedactions > 0
            ? "Scopeproof automatically masked \(automaticRedactions) sensitive region(s). Drag across any additional value that should not be disclosed to an assessor."
            : "No PAN, secret, or token patterns were detected. Drag across any value that should not be disclosed to an assessor."
        let subtitle = NSTextField(wrappingLabelWithString: automaticSummary)
        subtitle.textColor = .secondaryLabelColor
        subtitle.maximumNumberOfLines = 3

        let canvas = RedactionCanvasView(image: image)
        canvas.wantsLayer = true
        canvas.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.08).cgColor
        canvas.layer?.cornerRadius = 8
        canvas.layer?.borderColor = NSColor.separatorColor.cgColor
        canvas.layer?.borderWidth = 1
        canvas.onChange = { [weak self] count in self?.updateCount(count: count, automatic: automaticRedactions) }
        self.canvas = canvas
        let previewScroll = RedactionScrollView(canvas: canvas)
        self.previewScroll = previewScroll

        let fit = NSButton(title: "Fit", target: self, action: #selector(fitPreview))
        let actual = NSButton(title: "100%", target: self, action: #selector(actualSizePreview))
        actual.toolTip = "One source pixel per point. Scroll to inspect the entire capture."
        let zoomIn = NSButton(title: "Zoom In", target: self, action: #selector(zoomInPreview))
        let zoomOut = NSButton(title: "Zoom Out", target: self, action: #selector(zoomOutPreview))
        let keyboard = NSButton(title: "Keyboard Region", target: self, action: #selector(keyboardRegion))
        let keyboardHint = NSTextField(wrappingLabelWithString: "Arrows move · Shift+arrows resize · Option moves 10 px · Space applies · Esc cancels")
        keyboardHint.font = .systemFont(ofSize: 11)
        keyboardHint.textColor = .secondaryLabelColor
        let navigation = NSStackView(views: [fit, actual, zoomOut, zoomIn, keyboard, keyboardHint])
        navigation.orientation = .horizontal
        navigation.spacing = 8
        navigation.alignment = .centerY

        let countLabel = NSTextField(labelWithString: "Manual redactions: 0")
        countLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        self.countLabel = countLabel
        let undo = NSButton(title: "Undo Redaction", target: self, action: #selector(undoRedaction))
        undo.keyEquivalent = "z"
        undo.keyEquivalentModifierMask = .command
        let clear = NSButton(title: "Clear Manual Redactions", target: self, action: #selector(clearRedactions))
        let toolHint = NSTextField(labelWithString: "Redactions are burned in-memory. These exact final pixels are scanned again, hashed, and only then saved.")
        toolHint.textColor = .secondaryLabelColor
        toolHint.font = .systemFont(ofSize: 11)
        toolHint.lineBreakMode = .byTruncatingTail
        let toolSpacer = NSView()
        let tools = NSStackView(views: [countLabel, undo, clear, toolSpacer, toolHint])
        tools.orientation = .horizontal
        tools.alignment = .centerY
        tools.spacing = 10
        toolSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let noteLabel = NSTextField(labelWithString: "Reviewer note (optional)")
        noteLabel.font = .systemFont(ofSize: 11, weight: .semibold)
        let note = NSTextField(string: context.description)
        note.placeholderString = "Explain what this screenshot proves or any reviewer caveat"
        note.setAccessibilityLabel("Evidence reviewer note")
        self.noteField = note
        let discard = NSButton(title: "Discard", target: self, action: #selector(discardCapture))
        let save = NSButton(title: "Save Evidence", target: self, action: #selector(saveCapture))
        save.keyEquivalent = "\r"
        save.bezelStyle = .rounded
        let actionSpacer = NSView()
        let actions = NSStackView(views: [noteLabel, note, actionSpacer, discard, save])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 10
        note.translatesAutoresizingMaskIntoConstraints = false
        note.widthAnchor.constraint(greaterThanOrEqualToConstant: 320).isActive = true
        actionSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let stack = NSStackView(views: [heading, subtitle, navigation, previewScroll, tools, actions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18),
            subtitle.widthAnchor.constraint(equalTo: stack.widthAnchor),
            navigation.widthAnchor.constraint(equalTo: stack.widthAnchor),
            previewScroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            previewScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 320),
            tools.widthAnchor.constraint(equalTo: stack.widthAnchor),
            actions.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        self.window = window
        CaptureReviewPresentation.present(window)
        NSApplication.shared.runModal(for: window)
        window.orderOut(nil)
        self.window = nil
        self.canvas = nil
        self.previewScroll = nil
        self.noteField = nil
        self.countLabel = nil
        return decision
    }

    private func updateCount(count: Int, automatic: Int) {
        countLabel?.stringValue = "Automatic: \(automatic)  ·  Manual: \(count)"
    }

    @objc private func undoRedaction() { canvas?.undo() }
    @objc private func clearRedactions() { canvas?.clear() }
    @objc private func fitPreview() { previewScroll?.magnification = 1 }
    @objc private func actualSizePreview() {
        guard let canvas, let previewScroll else { return }
        previewScroll.magnification = min(previewScroll.maxMagnification, max(1, 1 / max(canvas.displayScale, 0.0001)))
    }
    @objc private func zoomInPreview() {
        guard let previewScroll else { return }
        previewScroll.magnification = min(previewScroll.maxMagnification, previewScroll.magnification * 1.5)
    }
    @objc private func zoomOutPreview() {
        guard let previewScroll else { return }
        previewScroll.magnification = max(1, previewScroll.magnification / 1.5)
    }
    @objc private func keyboardRegion() { canvas?.beginKeyboardRegion() }
    @objc private func discardCapture() { decision = nil; NSApplication.shared.stopModal() }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        discardCapture()
        return false
    }
    @objc private func saveCapture() {
        guard let canvas else { return }
        if canvas.keyboardRegion != nil {
            let alert = NSAlert()
            alert.messageText = "Apply or cancel the selected redaction first"
            alert.informativeText = "The outlined keyboard region has not been masked. Focus the preview and press Space to apply it, or Escape to cancel it."
            alert.runModal()
            window?.makeFirstResponder(canvas)
            return
        }
        guard let output = canvas.renderRedactedImage() else { NSSound.beep(); return }
        decision = CaptureReviewDecision(image: output, manualRedactions: canvas.redactionCount, reviewerNote: noteField?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        NSApplication.shared.stopModal()
    }
}

@MainActor
final class RedactionScrollView: NSScrollView {
    private let canvas: RedactionCanvasView
    init(canvas: RedactionCanvasView) {
        self.canvas = canvas
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        hasVerticalScroller = true
        hasHorizontalScroller = true
        scrollerStyle = .overlay
        allowsMagnification = true
        minMagnification = 1
        maxMagnification = 256
        documentView = canvas
        setAccessibilityLabel("Zoomable evidence preview")
    }
    required init?(coder: NSCoder) { nil }
    override func layout() {
        super.layout()
        // Keep the fit coordinate system stable when magnification changes the
        // clip view's bounds. Redactions remain normalized to source pixels.
        let size = contentView.frame.size
        if canvas.frame.size != size { canvas.setFrameSize(size) }
    }
}

@MainActor
final class RedactionCanvasView: NSView {
    private let source: CGImage
    private var normalizedRedactions: [CGRect] = []
    private var dragStart: CGPoint?
    private var activeRect: CGRect?
    private(set) var keyboardRegion: CGRect?
    var onChange: ((Int) -> Void)?
    var redactionCount: Int { normalizedRedactions.count }
    var displayScale: CGFloat { imageRect.width / CGFloat(source.width) }

    init(image: CGImage) {
        source = image
        super.init(frame: .zero)
        setAccessibilityLabel("Evidence preview and manual redaction canvas")
        setAccessibilityHelp("Drag to mask sensitive content, or choose Keyboard Region. Arrows move, Shift arrows resize, Option changes by ten pixels, Space applies, Escape cancels. Command Z undoes the last manual mask.")
    }

    required init?(coder: NSCoder) { nil }
    override var acceptsFirstResponder: Bool { true }
    override func becomeFirstResponder() -> Bool { needsDisplay = true; return true }
    override func resignFirstResponder() -> Bool { needsDisplay = true; return true }

    private var imageRect: CGRect {
        let available = bounds.insetBy(dx: 12, dy: 12)
        let sourceRatio = CGFloat(source.width) / CGFloat(source.height)
        let availableRatio = available.width / max(available.height, 1)
        if sourceRatio > availableRatio {
            let height = available.width / sourceRatio
            return CGRect(x: available.minX, y: available.midY - height / 2, width: available.width, height: height)
        }
        let width = available.height * sourceRatio
        return CGRect(x: available.midX - width / 2, y: available.minY, width: width, height: available.height)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let target = imageRect
        NSGraphicsContext.current?.cgContext.interpolationQuality = .high
        NSGraphicsContext.current?.cgContext.draw(source, in: target)
        NSColor.black.setFill()
        for normalized in normalizedRedactions { normalized.denormalized(in: target).fill() }
        if let activeRect {
            NSColor.systemRed.withAlphaComponent(0.28).setFill(); activeRect.fill()
            NSColor.systemRed.setStroke(); let path = NSBezierPath(rect: activeRect); path.lineWidth = 2; path.stroke()
        }
        if let keyboardRegion {
            NSColor.systemBlue.setStroke()
            let path = NSBezierPath(rect: keyboardRegion.denormalized(in: target))
            path.lineWidth = 2 / max(enclosingScrollView?.magnification ?? 1, 1)
            path.stroke()
        }
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke()
            NSBezierPath(rect: visibleRect.insetBy(dx: 2, dy: 2)).stroke()
        }
    }

    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        keyboardRegion = nil
        let point = convert(event.locationInWindow, from: nil)
        guard imageRect.contains(point) else { return }
        dragStart = point
        activeRect = CGRect(origin: point, size: .zero)
    }

    override func mouseDragged(with event: NSEvent) {
        guard let start = dragStart else { return }
        let point = convert(event.locationInWindow, from: nil)
        activeRect = CGRect(x: min(start.x, point.x), y: min(start.y, point.y), width: abs(point.x - start.x), height: abs(point.y - start.y)).intersection(imageRect)
        needsDisplay = true
    }

    override func mouseUp(with event: NSEvent) {
        defer { dragStart = nil; activeRect = nil; needsDisplay = true }
        guard let rect = activeRect, rect.width >= displayScale, rect.height >= displayScale else { return }
        normalizedRedactions.append(rect.normalized(in: imageRect))
        onChange?(normalizedRedactions.count)
    }

    func undo() { if !normalizedRedactions.isEmpty { normalizedRedactions.removeLast(); onChange?(normalizedRedactions.count); needsDisplay = true } }
    func clear() { normalizedRedactions.removeAll(); onChange?(0); needsDisplay = true }

    func beginKeyboardRegion() {
        let width = max(1 / CGFloat(source.width), min(100 / CGFloat(source.width), 0.25))
        let height = max(1 / CGFloat(source.height), min(40 / CGFloat(source.height), 0.15))
        keyboardRegion = CGRect(x: 0.5 - width / 2, y: 0.5 - height / 2, width: width, height: height)
        window?.makeFirstResponder(self)
        revealKeyboardRegion()
    }

    func adjustKeyboardRegion(dx: Int, dy: Int, resize: Bool, accelerated: Bool) {
        guard var region = keyboardRegion else { return }
        let unit = accelerated ? CGFloat(10) : 1
        let stepX = unit * CGFloat(dx) / CGFloat(source.width)
        let stepY = unit * CGFloat(dy) / CGFloat(source.height)
        if resize {
            region.size.width = min(1 - region.minX, max(1 / CGFloat(source.width), region.width + stepX))
            region.size.height = min(1 - region.minY, max(1 / CGFloat(source.height), region.height + stepY))
        } else {
            region.origin.x = min(1 - region.width, max(0, region.minX + stepX))
            region.origin.y = min(1 - region.height, max(0, region.minY + stepY))
        }
        keyboardRegion = region
        revealKeyboardRegion()
    }

    func applyKeyboardRegion() {
        guard let keyboardRegion else { return }
        normalizedRedactions.append(keyboardRegion)
        self.keyboardRegion = nil
        onChange?(normalizedRedactions.count)
        needsDisplay = true
    }

    override func keyDown(with event: NSEvent) {
        guard keyboardRegion != nil else { super.keyDown(with: event); return }
        switch event.keyCode {
        case 123, 124, 125, 126:
            adjustKeyboardRegion(dx: event.keyCode == 123 ? -1 : (event.keyCode == 124 ? 1 : 0),
                dy: event.keyCode == 125 ? -1 : (event.keyCode == 126 ? 1 : 0),
                resize: event.modifierFlags.contains(.shift), accelerated: event.modifierFlags.contains(.option))
        case 49: applyKeyboardRegion()
        case 53: keyboardRegion = nil; needsDisplay = true
        default: super.keyDown(with: event)
        }
    }

    private func revealKeyboardRegion() {
        if let keyboardRegion { scrollToVisible(keyboardRegion.denormalized(in: imageRect).insetBy(dx: -12, dy: -12)) }
        needsDisplay = true
    }

    func renderRedactedImage() -> CGImage? {
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB), let context = CGContext(data: nil, width: source.width, height: source.height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.draw(source, in: CGRect(x: 0, y: 0, width: source.width, height: source.height))
        context.setFillColor(NSColor.black.cgColor)
        for rect in normalizedRedactions {
            // Cover boundary pixels completely; fractional edges must never
            // leave partially transparent sensitive source pixels visible.
            context.fill(CGRect(x: rect.minX * CGFloat(source.width), y: rect.minY * CGFloat(source.height), width: rect.width * CGFloat(source.width), height: rect.height * CGFloat(source.height)).integral)
        }
        return context.makeImage()
    }
}

private extension CGRect {
    func normalized(in container: CGRect) -> CGRect {
        CGRect(x: (minX - container.minX) / container.width, y: (minY - container.minY) / container.height, width: width / container.width, height: height / container.height)
    }
    func denormalized(in container: CGRect) -> CGRect {
        CGRect(x: container.minX + minX * container.width, y: container.minY + minY * container.height, width: width * container.width, height: height * container.height)
    }
}
