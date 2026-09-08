import AppKit
import Foundation

enum TransferRecoveryState: Equatable {
    case pending, running, verified, failed(String), cancelled
    var summary: String {
        switch self {
        case .pending: return "No verified response for this destination."
        case .running: return "Transferring… Cancel requests interruption; remote commit may already have occurred."
        case .verified: return "Verified authenticated response with this Mac's device seal."
        case .failed(let code): return "Attempt failed (\(code)). Check connection/credential expiry, then reconcile or explicitly retry. Local evidence is preserved."
        case .cancelled: return "Canceled locally. Remote commit is uncertain; refresh receipts before retrying."
        }
    }
    var running: Bool { if case .running = self { return true }; return false }
    static func failureCode(_ error: Error) -> String {
        let value = error as NSError
        // Do not copy arbitrary server bodies, URLs, credentials or free-text
        // LocalizedError descriptions into a durable UI status/error log.
        return value.domain == NSURLErrorDomain ? "network \(value.code)" : "verification or destination check"
    }
}

/// This is a recovery view, not another source of delivery authority. Success
/// always comes from re-reading the expected destination's verified receipt.
@MainActor
final class TransferRecoveryController: NSObject, NSWindowDelegate {
    private let entries: [CaptureHistoryEntry]
    private let destinationLabel: (TransferReceiptKind) -> String
    private let verified: (CaptureHistoryEntry, TransferReceiptKind) -> Bool
    private let retry: (CaptureHistoryEntry, TransferReceiptKind) async throws -> Void
    private let onReconcileJira: (CaptureHistoryEntry) -> Void
    private var window: NSWindow?
    private var states: [String: TransferRecoveryState] = [:]
    private var tasks: [String: Task<Void, Never>] = [:]
    private var labels: [String: NSTextField] = [:]
    private var buttons: [String: NSButton] = [:]
    private var notice: NSTextField?
    private var invalidated = false

    init(entries: [CaptureHistoryEntry], destinationLabel: @escaping (TransferReceiptKind) -> String,
         verified: @escaping (CaptureHistoryEntry, TransferReceiptKind) -> Bool,
         retry: @escaping (CaptureHistoryEntry, TransferReceiptKind) async throws -> Void,
         onReconcileJira: @escaping (CaptureHistoryEntry) -> Void) {
        self.entries = entries
        self.destinationLabel = destinationLabel
        self.verified = verified
        self.retry = retry
        self.onReconcileJira = onReconcileJira
        super.init()
    }

    func show() {
        guard !invalidated else { return }
        if let window { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 680),
            styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Scopeproof · Transfer recovery"
        window.minSize = NSSize(width: 660, height: 420)
        window.isReleasedWhenClosed = false
        window.delegate = self
        let root = NSView(); window.contentView = root
        let heading = NSTextField(labelWithString: "Recover individual evidence transfers")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        let explanation = NSTextField(wrappingLabelWithString: "Local evidence is never deleted here. Only a verified, destination-bound receipt means delivery was recorded. Refresh credentials in connection settings when needed. Jira requires explicit reconciliation; this window never automatically uploads to Jira.")
        let refresh = NSButton(title: "Refresh verified receipts", target: self, action: #selector(refreshReceipts))
        let summary = NSTextField(wrappingLabelWithString: "Recent captures are shown below. Attempt errors remain visible for this window; after restart status is rebuilt from verified receipts, not from a success flag.")
        notice = summary
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 18
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        scroll.documentView = stack
        for view in [heading, explanation, refresh, summary, scroll] { view.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(view) }
        stack.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 22), heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22), heading.trailingAnchor.constraint(lessThanOrEqualTo: root.trailingAnchor, constant: -22),
            explanation.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 10), explanation.leadingAnchor.constraint(equalTo: heading.leadingAnchor), explanation.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            refresh.topAnchor.constraint(equalTo: explanation.bottomAnchor, constant: 14), refresh.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            summary.topAnchor.constraint(equalTo: refresh.bottomAnchor, constant: 10), summary.leadingAnchor.constraint(equalTo: heading.leadingAnchor), summary.trailingAnchor.constraint(equalTo: explanation.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: summary.bottomAnchor, constant: 12), scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 10), scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -10), scroll.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -12),
            stack.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
        ])
        let shown = Array(entries.prefix(100))
        if shown.isEmpty { stack.addArrangedSubview(NSTextField(wrappingLabelWithString: "No captures in this workspace. Capture and review evidence first; optional transfer destinations can then be used.")) }
        if entries.count > shown.count { summary.stringValue += " Showing the newest 100 of \(entries.count) captures. Use Search Evidence to locate older artifacts; no older record is labeled complete by this limit." }
        for (index, entry) in shown.enumerated() {
            let title = NSTextField(wrappingLabelWithString: "\(entry.manifest.controlID) · \(entry.manifest.title)\n\(entry.manifest.evidenceID)")
            title.font = .systemFont(ofSize: 14, weight: .semibold); stack.addArrangedSubview(title)
            title.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -24).isActive = true
            for kind in TransferReceiptKind.allCases {
                let key = "\(index):\(kind.rawValue)"
                let row = NSStackView(); row.orientation = .horizontal; row.alignment = .centerY; row.spacing = 12
                let text = NSTextField(wrappingLabelWithString: ""); text.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
                let control = NSButton(title: kind == .jira ? "Reconcile Jira…" : "Retry item", target: self, action: #selector(controlClicked(_:)))
                control.identifier = NSUserInterfaceItemIdentifier(key)
                control.setAccessibilityLabel("\(kind.rawValue) recovery for \(entry.manifest.evidenceID)")
                row.addArrangedSubview(text); row.addArrangedSubview(control); stack.addArrangedSubview(row)
                row.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -24).isActive = true
                control.widthAnchor.constraint(greaterThanOrEqualToConstant: 130).isActive = true
                labels[key] = text; buttons[key] = control
                states[key] = verified(entry, kind) ? .verified : .pending
                render(key, entry: entry, kind: kind)
            }
            let separator = NSBox(); separator.boxType = .separator; stack.addArrangedSubview(separator)
            separator.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -24).isActive = true
        }
        self.window = window; window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    /// A workspace switch must immediately remove old-customer content and
    /// prevent late completion callbacks from reviving its controls.
    func invalidateForWorkspaceChange() {
        invalidated = true
        tasks.values.forEach { $0.cancel() }
        buttons.values.forEach { $0.isEnabled = false }
        labels.values.forEach { $0.stringValue = "" }
        states.removeAll(); labels.removeAll(); buttons.removeAll()
        notice?.stringValue = "Workspace changed. Reopen Transfer recovery for the current workspace."
        window?.delegate = nil
        window?.contentView = NSView()
        window?.close(); window = nil
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard !invalidated else { return true }
        guard !tasks.isEmpty else { return true }
        let alert = NSAlert(); alert.messageText = "Transfers are still running"
        alert.informativeText = "Keep this window open to see their verified outcomes, or request cancellation. Cancellation does not prove the receiver did not commit."
        alert.addButton(withTitle: "Keep Open"); alert.addButton(withTitle: "Cancel Transfers")
        if alert.runModal() == .alertSecondButtonReturn { tasks.values.forEach { $0.cancel() }; notice?.stringValue = "Cancellation requested. The window stays open until each outcome is reconciled." }
        return false
    }

    @objc private func refreshReceipts() {
        guard !invalidated else { return }
        for (index, entry) in entries.prefix(100).enumerated() { for kind in TransferReceiptKind.allCases {
            let key = "\(index):\(kind.rawValue)"; guard tasks[key] == nil else { continue }
            if verified(entry, kind) { states[key] = .verified }
            else if states[key] == .verified { states[key] = .pending }
            render(key, entry: entry, kind: kind)
        } }
        notice?.stringValue = "Receipts rechecked against this window's destination and workspace. A device seal records the original response, not today's remote availability."
    }

    @objc private func controlClicked(_ sender: NSButton) {
        guard !invalidated else { return }
        guard let key = sender.identifier?.rawValue else { return }
        let pieces = key.split(separator: ":"); guard pieces.count == 2, let index = Int(pieces[0]), entries.indices.contains(index), let kind = TransferReceiptKind(rawValue: String(pieces[1])) else { return }
        let entry = entries[index]
        if let task = tasks[key] { task.cancel(); sender.isEnabled = false; labels[key]?.stringValue = "Cancellation requested. Waiting for the operation to stop; remote delivery may have committed."; return }
        if kind == .jira { onReconcileJira(entry); return }
        guard tasks.count < 2 else { notice?.stringValue = "Two transfers are already in progress. Wait for one to finish or cancel an item."; return }
        guard !entry.isPayloadArchived else { notice?.stringValue = "Restore the archived payload before attempting another transfer."; return }
        let alert = NSAlert(); alert.messageText = "Retry this exact artifact?"
        alert.informativeText = "\(entry.manifest.evidenceID)\nDestination: \(destinationLabel(kind))\nThe service revalidates workspace and destination. If a previous commit was uncertain, existing exact receipts and remote idempotency must reconcile it; a differing destination is never overwritten silently."
        alert.addButton(withTitle: "Retry Item"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        states[key] = .running; render(key, entry: entry, kind: kind)
        tasks[key] = Task { [weak self] in
            guard let self else { return }
            do {
                try Task.checkCancellation()
                try await retry(entry, kind)
                guard !invalidated else { tasks.removeValue(forKey: key); return }
                states[key] = verified(entry, kind) ? .verified : .failed("response could not be verified")
            } catch {
                guard !invalidated else { tasks.removeValue(forKey: key); return }
                if verified(entry, kind) { states[key] = .verified }
                else { states[key] = Task.isCancelled ? .cancelled : .failed(TransferRecoveryState.failureCode(error)) }
            }
            tasks.removeValue(forKey: key); render(key, entry: entry, kind: kind)
            notice?.stringValue = "\(tasks.count) transfer(s) still running. Each artifact's outcome is shown separately; a failure does not hide other results."
        }
    }

    private func render(_ key: String, entry: CaptureHistoryEntry, kind: TransferReceiptKind) {
        guard !invalidated else { return }
        let state = states[key] ?? .pending
        labels[key]?.stringValue = "\(kind.rawValue.uppercased()) · \(destinationLabel(kind))\n\(entry.isPayloadArchived ? "Payload archived — restore before transferring." : state.summary)"
        buttons[key]?.title = state.running ? "Cancel item" : kind == .jira ? "Reconcile Jira…" : "Retry item"
        buttons[key]?.isEnabled = !entry.isPayloadArchived && (kind == .jira || state != .verified)
    }
}
