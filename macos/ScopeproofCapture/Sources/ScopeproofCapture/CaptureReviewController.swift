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

    func review(image: CGImage, findings: [SensitiveFinding], automaticRedactions: Int, context: CaptureContext) -> CaptureReviewDecision? {
        decision = nil
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 760),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = automaticRedactions > 0 ? "Review Redacted Evidence" : "Review Evidence"
        window.minSize = NSSize(width: 760, height: 600)
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
        canvas.translatesAutoresizingMaskIntoConstraints = false
        canvas.wantsLayer = true
        canvas.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.08).cgColor
        canvas.layer?.cornerRadius = 8
        canvas.layer?.borderColor = NSColor.separatorColor.cgColor
        canvas.layer?.borderWidth = 1
        canvas.onChange = { [weak self] count in self?.updateCount(count: count, automatic: automaticRedactions) }
        self.canvas = canvas

        let countLabel = NSTextField(labelWithString: "Manual redactions: 0")
        countLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        self.countLabel = countLabel
        let undo = NSButton(title: "Undo Redaction", target: self, action: #selector(undoRedaction))
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
        discard.keyEquivalent = "\u{1b}"
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

        let stack = NSStackView(views: [heading, subtitle, canvas, tools, actions])
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
            canvas.widthAnchor.constraint(equalTo: stack.widthAnchor),
            canvas.heightAnchor.constraint(greaterThanOrEqualToConstant: 400),
            tools.widthAnchor.constraint(equalTo: stack.widthAnchor),
            actions.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        self.window = window
        CaptureReviewPresentation.present(window)
        NSApplication.shared.runModal(for: window)
        window.orderOut(nil)
        self.window = nil
        self.canvas = nil
        self.noteField = nil
        self.countLabel = nil
        return decision
    }

    private func updateCount(count: Int, automatic: Int) {
        countLabel?.stringValue = "Automatic: \(automatic)  ·  Manual: \(count)"
    }

    @objc private func undoRedaction() { canvas?.undo() }
    @objc private func clearRedactions() { canvas?.clear() }
    @objc private func discardCapture() { decision = nil; NSApplication.shared.stopModal() }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        discardCapture()
        return false
    }
    @objc private func saveCapture() {
        guard let canvas, let output = canvas.renderRedactedImage() else { NSSound.beep(); return }
        decision = CaptureReviewDecision(image: output, manualRedactions: canvas.redactionCount, reviewerNote: noteField?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        NSApplication.shared.stopModal()
    }
}

@MainActor
final class RedactionCanvasView: NSView {
    private let source: CGImage
    private var normalizedRedactions: [CGRect] = []
    private var dragStart: CGPoint?
    private var activeRect: CGRect?
    var onChange: ((Int) -> Void)?
    var redactionCount: Int { normalizedRedactions.count }

    init(image: CGImage) {
        source = image
        super.init(frame: .zero)
        setAccessibilityLabel("Evidence preview and manual redaction canvas")
        setAccessibilityHelp("Drag over sensitive content to permanently mask it before saving.")
    }

    required init?(coder: NSCoder) { nil }
    override var acceptsFirstResponder: Bool { true }

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
    }

    override func mouseDown(with event: NSEvent) {
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
        guard let rect = activeRect, rect.width >= 6, rect.height >= 6 else { return }
        normalizedRedactions.append(rect.normalized(in: imageRect))
        onChange?(normalizedRedactions.count)
    }

    func undo() { if !normalizedRedactions.isEmpty { normalizedRedactions.removeLast(); onChange?(normalizedRedactions.count); needsDisplay = true } }
    func clear() { normalizedRedactions.removeAll(); onChange?(0); needsDisplay = true }

    func renderRedactedImage() -> CGImage? {
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB), let context = CGContext(data: nil, width: source.width, height: source.height, bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.draw(source, in: CGRect(x: 0, y: 0, width: source.width, height: source.height))
        context.setFillColor(NSColor.black.cgColor)
        for rect in normalizedRedactions {
            context.fill(CGRect(x: rect.minX * CGFloat(source.width), y: rect.minY * CGFloat(source.height), width: rect.width * CGFloat(source.width), height: rect.height * CGFloat(source.height)))
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
