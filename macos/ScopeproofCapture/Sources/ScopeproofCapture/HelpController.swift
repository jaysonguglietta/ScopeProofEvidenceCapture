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
        add("Local Console\n", size: 19, weight: .semibold)
        add("Choose Open Local Console from the shield menu. Scopeproof starts a private loopback-only console, opens it in your browser, and creates a short-lived authenticated session for this app launch. The console searches the local evidence folder, displays verified previews, records lifecycle decisions, and maintains a disposable SQLite index with an immutable HMAC-authenticated local audit chain. It never accepts filesystem paths from the browser. No hosted login or device-enrollment token is required for local capture, review, search, or assessor-package export.\n\n", size: 14)
        add("Quick start\n", size: 19, weight: .semibold)
        add("1. Open the evidence page, then choose Capture Frontmost Browser Window, Choose Browser Window, Open URL & Capture, or Capture Entire Display.\n2. Before every screenshot, select PCI DSS, HIPAA, FedRAMP, SOC 2, ISO 27001, an imported catalog, or Custom, then select the corresponding control. Use Capture Presets for recurring collections.\n3. Customize the filename and add the evidence title, owner, system, environment, assessment period, optional Jira issue, tags, expected evidence, and assessor note. The Saved as line previews the final folder and filename.\n4. Scopeproof keeps source pixels in memory, uses local OCR to find PANs, credentials, tokens, and private-key markers, adds the evidence header, and scans that composite again.\n5. In Review Evidence, drag across any additional sensitive value. Scopeproof then encodes and scans those exact final PNG pixels. A failed or incomplete scan saves nothing; no unreviewed PNG is written to disk.\n6. If connected, Scopeproof uploads the reviewed files into encrypted storage and returns a signed server-time receipt.\n\n", size: 14)
        add("What gets created\n", size: 19, weight: .semibold)
        add("Each capture produces a PNG and an adjacent immutable JSON manifest. A full-width header is added above the captured pixels with the local date, time, timezone, evidence ID, compliance framework, control number and title, optional Jira issue, system, assessment period, and source. Because the header is outside the original image, it never obscures evidence. The manifest records SHA-256 integrity, catalog version, owner, tags, expected evidence, Jira reference, control mappings, automated/manual redaction counts, session metadata, and capture-chain links. Review state is derived only from the final verified .review.json lifecycle event, which binds reviewer, timestamp, artifact digest, rationale, and policy. Inconsistent or obsolete histories cannot be exported. Successful uploads add a .receipt.json file containing the server evidence ID and signed time attestation.\n\n", size: 14)
        add("Where files are stored\n", size: 19, weight: .semibold)
        add("\(outputDirectory.path)\nNew files are organized as Compliance area / Control / Assessment period. Filenames include the framework, control, your custom name, capture time, and evidence ID. Files are private to your macOS account. Use Open Evidence Folder from the menu. The configured retention action moves expired local evidence to Trash; it never deletes hosted evidence.\n\n", size: 14)
        add("Finding an earlier screenshot\n", size: 19, weight: .semibold)
        add("Choose Search Evidence from the shield menu. Filter by compliance area, control, review status, capture age, system, owner, tags, or keywords. Thumbnails make visual confirmation faster. Select Review Status to assign an owner and reviewer, record a rationale, add tags, and move evidence through Draft, In Review, Approved, Rejected, or Superseded. Approval, rejection, and supersession require a note. Search includes legacy root-level captures and every nested framework folder.\n\n", size: 14)
        add("Attaching evidence to Jira\n", size: 19, weight: .semibold)
        add("1. In the Scopeproof web console, open Connections → Jira Cloud. Enter the Jira Cloud site and approved project keys, continue to Atlassian OAuth, and test the connection. OAuth tokens remain encrypted on the hosted service and never enter this Mac app.\n2. Open Capture & Jira Settings on the Mac to set routing defaults, then enter the destination issue key (for example, GRC-123) while classifying a capture.\n3. Review the evidence and mark it Approved with a rationale. Upload those exact bytes to Scopeproof and have an authenticated web reviewer approve the hosted artifact.\n4. In Search Evidence, select the item and choose Upload to Jira Cloud. Scopeproof retrieves the live issue summary for confirmation, then verifies both approvals, the PNG digest, safety state, lifecycle chain, site, project allowlist, and Jira permissions before attaching the complete evidence set. A signed .jira.json receipt is saved beside the evidence.\n5. Copy Jira Comment and manual attachment remain available as a fallback. Confirm project permissions, external-auditor access, classification, and retention before any disclosure. Never attach an unredacted image, password, cookie, token, private key, or PAN.\n\n", size: 14)
        add("Preparing an external assessor package\n", size: 19, weight: .semibold)
        add("1. Open Search Evidence and review each artifact. Confirm its scope, timestamp, redactions, system, control mapping, and what it proves.\n2. Mark only complete, current artifacts Approved. Mark replaced evidence Superseded; rejected or superseded files never enter a package.\n3. Choose Export Assessor Package from the shield menu. Filter by compliance area and assessment period, enter a package name and preparer, then choose a save location.\n4. Scopeproof re-hashes every artifact, derives approval from the verified review-event chain, and creates a ZIP organized by framework and control. The package includes a Read Me, control-coverage/gap report, evidence index, signed JSON manifest, verification guide, PNGs, capture manifests, review histories, and server receipts. A separate ZIP checksum is written beside it.\n5. Approve the Keychain user-presence prompt to use the device-bound package-signing identity. Transfer both the ZIP and checksum through your approved secure file-sharing channel, then confirm the signing-key fingerprint out of band. Do not email regulated evidence unless policy explicitly permits it.\n\n", size: 14)
        add("Control catalogs and mappings\n", size: 19, weight: .semibold)
        add("Built-in catalogs are versioned. Import Control Catalog accepts Scopeproof JSON, OSCAL catalog JSON, or CSV control lists. Curated cross-framework mappings appear as related controls and are included in manifests and packages, but they are aids—not a substitute for assessor judgment or an authoritative framework crosswalk.\n\n", size: 14)
        add("Connecting to the web application\n", size: 19, weight: .semibold)
        add("Hosted synchronization is optional. For team review or Jira Cloud delivery, open the hosted Scopeproof console, enroll a Mac capture device, and copy the one-time token into Capture & Jira Settings. The token is stored in your login Keychain, not preferences. Leave Server URL blank for local-only mode. Failed or offline uploads always remain local and can be retried later.\n\n", size: 14)
        add("Permissions and safety\n", size: 19, weight: .semibold)
        add("Screen Recording is required so Apple’s ScreenCaptureKit can read the selected pixels. Scopeproof never captures on a timer or without an explicit menu action. OCR happens locally. The app does not read browser passwords, cookies, or page source. Always inspect the preview—automated detectors reduce risk but cannot guarantee that every sensitive value is found.\n\n", size: 14)
        add("Troubleshooting\n", size: 19, weight: .semibold)
        add("• Local Console unavailable: quit and reopen Scopeproof Capture; the loopback address and browser session are recreated at launch.\n• Permission unavailable: enable Scopeproof Capture in System Settings → Privacy & Security → Screen & System Audio Recording, then restart it.\n• Wrong window: use Choose Browser Window instead of frontmost capture.\n• Cannot export: at least one matching artifact must be Approved, and all included hashes and lifecycle chains must validate.\n• Hosted upload unavailable: verify the server URL and replace a revoked or expired device token in Settings.\n• Jira Cloud upload unavailable: connect or reauthorize Jira under Scopeproof web → Connections, test it, and confirm the issue project is allowlisted.\n• No menu icon: open Scopeproof Capture from your Applications folder.\n• Update available: Check for Updates verifies release metadata; production releases can be Developer ID signed and notarized by the release script when credentials are configured.\n", size: 14)
        return body
    }
}
