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
        add("Secure multi-framework compliance evidence from the macOS menu bar\n\n", size: 15, weight: .medium, color: .secondaryLabelColor)
        add("Quick start\n", size: 19, weight: .semibold)
        add("1. Open the evidence page, then choose Capture Frontmost Browser Window, Choose Browser Window, Open URL & Capture, or Capture Entire Display.\n2. Before every screenshot, select PCI DSS, HIPAA, FedRAMP, SOC 2, ISO 27001, an imported catalog, or Custom, then select the corresponding control. Use Capture Presets for recurring collections.\n3. Customize the filename and add the evidence title, owner, system, environment, assessment period, tags, expected evidence, and assessor note. The Saved as line previews the final folder and filename.\n4. Scopeproof uses local OCR to find PANs, credentials, tokens, and private-key markers. Detected regions are masked before anything is saved.\n5. In Review Evidence, drag across any additional sensitive value. Manual masks are permanently burned into the image before hashing; the unredacted capture is never retained.\n6. If connected, Scopeproof uploads the reviewed files into encrypted storage and returns a signed server-time receipt.\n\n", size: 14)
        add("What gets created\n", size: 19, weight: .semibold)
        add("Each capture produces a PNG and an adjacent immutable JSON manifest. A full-width header is added above the captured pixels with the local date, time, timezone, evidence ID, compliance framework, control number and title, system, assessment period, and source. Because the header is outside the original image, it never obscures evidence. The manifest records SHA-256 integrity, catalog version, owner, tags, expected evidence, control mappings, automated/manual redaction counts, session metadata, and capture-chain links. Review decisions live in a separate .review.json lifecycle record so the original capture manifest never has to be rewritten. Successful uploads add a .receipt.json file containing the server evidence ID and signed time attestation.\n\n", size: 14)
        add("Where files are stored\n", size: 19, weight: .semibold)
        add("\(outputDirectory.path)\nNew files are organized as Compliance area / Control / Assessment period. Filenames include the framework, control, your custom name, capture time, and evidence ID. Files are private to your macOS account. Use Open Evidence Folder from the menu. The configured retention action moves expired local evidence to Trash; it never deletes hosted evidence.\n\n", size: 14)
        add("Finding an earlier screenshot\n", size: 19, weight: .semibold)
        add("Choose Search Evidence from the shield menu. Filter by compliance area, control, review status, capture age, system, owner, tags, or keywords. Thumbnails make visual confirmation faster. Select Review Status to assign an owner and reviewer, record a rationale, add tags, and move evidence through Draft, In Review, Approved, Rejected, or Superseded. Approval, rejection, and supersession require a note. Search includes legacy root-level captures and every nested framework folder.\n\n", size: 14)
        add("Preparing an external assessor package\n", size: 19, weight: .semibold)
        add("1. Open Search Evidence and review each artifact. Confirm its scope, timestamp, redactions, system, control mapping, and what it proves.\n2. Mark only complete, current artifacts Approved. Mark replaced evidence Superseded; rejected or superseded files never enter a package.\n3. Choose Export Assessor Package from the shield menu. Filter by compliance area and assessment period, enter a package name and preparer, then choose a save location.\n4. Scopeproof re-hashes every artifact, verifies each review-event chain, and creates a ZIP organized by framework and control. The package includes a Read Me, control-coverage/gap report, evidence index, signed JSON manifest, verification guide, PNGs, capture manifests, review histories, and server receipts. A separate ZIP checksum is written beside it.\n5. Transfer both the ZIP and checksum through your approved secure file-sharing channel. Confirm the persistent signing-key fingerprint with the assessor through a separate trusted channel. Do not email regulated evidence unless organizational policy explicitly permits it.\n\n", size: 14)
        add("Control catalogs and mappings\n", size: 19, weight: .semibold)
        add("Built-in catalogs are versioned. Import Control Catalog accepts Scopeproof JSON, OSCAL catalog JSON, or CSV control lists. Curated cross-framework mappings appear as related controls and are included in manifests and packages, but they are aids—not a substitute for assessor judgment or an authoritative framework crosswalk.\n\n", size: 14)
        add("Connecting to the web application\n", size: 19, weight: .semibold)
        add("In the Scopeproof web console, open Connections and enroll a Mac capture device. Copy the one-time token into Capture Settings. The token is stored in your login Keychain, not preferences. Turn on Upload after capture when you are ready. Failed or offline uploads remain local and can be retried from the menu.\n\n", size: 14)
        add("Permissions and safety\n", size: 19, weight: .semibold)
        add("Screen Recording is required so Apple’s ScreenCaptureKit can read the selected pixels. Scopeproof never captures on a timer or without an explicit menu action. OCR happens locally. The app does not read browser passwords, cookies, or page source. Always inspect the preview—automated detectors reduce risk but cannot guarantee that every sensitive value is found.\n\n", size: 14)
        add("Troubleshooting\n", size: 19, weight: .semibold)
        add("• Permission unavailable: enable Scopeproof Capture in System Settings → Privacy & Security → Screen & System Audio Recording, then restart it.\n• Wrong window: use Choose Browser Window instead of frontmost capture.\n• Cannot export: at least one matching artifact must be Approved, and all included hashes and lifecycle chains must validate.\n• Upload unavailable: verify the server URL and replace a revoked or expired device token in Settings.\n• No menu icon: open Scopeproof Capture from /Applications.\n• Update available: Check for Updates verifies release metadata; production releases can be Developer ID signed and notarized by the release script when credentials are configured.\n", size: 14)
        return body
    }
}
