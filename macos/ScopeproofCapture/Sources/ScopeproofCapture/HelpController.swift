@preconcurrency import AppKit

@MainActor
final class HelpController: NSObject, NSWindowDelegate {
    private var window: NSWindow?

    func show(outputDirectory: URL) {
        if let window { window.makeKeyAndOrderFront(nil); NSApplication.shared.activate(ignoringOtherApps: true); return }
        let frame = NSRect(x: 0, y: 0, width: 720, height: 660)
        let window = NSWindow(contentRect: frame, styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Scopeproof Capture Help"
        window.center()
        window.delegate = self
        let scroll = NSScrollView(frame: frame)
        scroll.hasVerticalScroller = true
        scroll.autoresizingMask = [.width, .height]
        let text = NSTextView(frame: frame.insetBy(dx: 28, dy: 24))
        text.isEditable = false
        text.isSelectable = true
        text.drawsBackground = false
        text.textContainerInset = NSSize(width: 26, height: 24)
        text.textStorage?.setAttributedString(helpText(outputDirectory: outputDirectory))
        scroll.documentView = text
        window.contentView = scroll
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        self.window = window
    }

    func windowWillClose(_ notification: Notification) { window = nil }

    private func helpText(outputDirectory: URL) -> NSAttributedString {
        let body = NSMutableAttributedString()
        func add(_ value: String, size: CGFloat, weight: NSFont.Weight = .regular, color: NSColor = .labelColor, spacing: CGFloat = 10) {
            let paragraph = NSMutableParagraphStyle(); paragraph.paragraphSpacing = spacing; paragraph.lineSpacing = 3
            body.append(NSAttributedString(string: value, attributes: [.font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: color, .paragraphStyle: paragraph]))
        }
        add("Scopeproof Capture\n", size: 28, weight: .bold, color: .systemIndigo, spacing: 4)
        add("Secure PCI evidence capture from the macOS menu bar\n\n", size: 15, weight: .medium, color: .secondaryLabelColor)
        add("Quick start\n", size: 19, weight: .semibold)
        add("1. Choose Start or Change Capture Session and enter the PCI control, system, environment, and assessment period.\n2. Open the evidence page in a supported browser.\n3. Choose Capture Frontmost Browser Window, Choose Browser Window, Open URL & Capture, or Capture Entire Display.\n4. Scopeproof uses local OCR to find PANs, credentials, tokens, and private-key markers. Detected regions are masked before anything is saved.\n5. Review the preview. Save only when it shows the correct system, control, and state.\n6. If connected, Scopeproof uploads the reviewed files into encrypted storage and returns a signed server-time receipt.\n\n", size: 14)
        add("What gets created\n", size: 19, weight: .semibold)
        add("Each capture produces a PNG and an adjacent JSON manifest. The image contains a visible local date, time, timezone, evidence ID, PCI control, system, and assessment period. The manifest records SHA-256 integrity, capture method, redaction counts, session metadata, and the previous/current hash-chain links. Successful uploads add a .receipt.json file containing the server evidence ID and signed time attestation.\n\n", size: 14)
        add("Where files are stored\n", size: 19, weight: .semibold)
        add("\(outputDirectory.path)\nFiles are private to your macOS account. Use Open Evidence Folder from the menu. The configured retention action moves expired local evidence to Trash; it never deletes hosted evidence.\n\n", size: 14)
        add("Connecting to the web application\n", size: 19, weight: .semibold)
        add("In the Scopeproof web console, open Connections and enroll a Mac capture device. Copy the one-time token into Capture Settings. The token is stored in your login Keychain, not preferences. Turn on Upload after capture when you are ready. Failed or offline uploads remain local and can be retried from the menu.\n\n", size: 14)
        add("Permissions and safety\n", size: 19, weight: .semibold)
        add("Screen Recording is required so Apple’s ScreenCaptureKit can read the selected pixels. Scopeproof never captures on a timer or without an explicit menu action. OCR happens locally. The app does not read browser passwords, cookies, or page source. Always inspect the preview—automated detectors reduce risk but cannot guarantee that every sensitive value is found.\n\n", size: 14)
        add("Troubleshooting\n", size: 19, weight: .semibold)
        add("• Permission unavailable: enable Scopeproof Capture in System Settings → Privacy & Security → Screen & System Audio Recording, then restart it.\n• Wrong window: use Choose Browser Window instead of frontmost capture.\n• Upload unavailable: verify the server URL and replace a revoked or expired device token in Settings.\n• No menu icon: open Scopeproof Capture from /Applications.\n• Update available: Check for Updates verifies release metadata; production releases must be Developer ID signed and notarized.\n", size: 14)
        return body
    }
}
