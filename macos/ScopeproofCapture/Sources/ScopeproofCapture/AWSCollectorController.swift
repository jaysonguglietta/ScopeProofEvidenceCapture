@preconcurrency import AppKit
@preconcurrency import AuthenticationServices
import Foundation

@MainActor
final class AWSCollectorController: NSObject, ASWebAuthenticationPresentationContextProviding, NSWindowDelegate {
    private let service = AWSCollectorService()
    private let oauth = HostedOAuthCoordinator()
    private let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 450), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
    private let tenantPicker = NSPopUpButton()
    private let status = NSTextField(wrappingLabelWithString: "")
    private let connect = NSButton(title: "Connect & Choose Assessment…", target: nil, action: nil)
    private let cancel = NSButton(title: "Cancel", target: nil, action: nil)
    private let signOut = NSButton(title: "Sign Out on This Mac", target: nil, action: nil)
    private let submit = NSButton(title: "Submit / Check Capture…", target: nil, action: nil)
    private let portal = NSButton(title: "Open Reviewer Portal", target: nil, action: nil)
    private var configurations: [AWSCollectorConfiguration] = []
    private var task: Task<Void, Never>?
    private var authentication: ASWebAuthenticationSession?
    private var callbackContinuation: CheckedContinuation<URL, any Error>?
    var onSelection: ((AWSCollectorSelection, CaptureContext) -> Void)?
    var evidenceProvider: (() -> [CaptureHistoryEntry])?
    var selectionProvider: (() -> AWSCollectorSelection?)?

    override init() {
        super.init()
        window.title = "AWS Customer Workspace"; window.isReleasedWhenClosed = false; window.delegate = self
        window.minSize = NSSize(width: 620, height: 430)
        let intro = NSTextField(wrappingLabelWithString: "Sign in to your approved customer workspace, prove possession of this Mac's device key, and choose assessment scope. No AWS access keys are requested.")
        tenantPicker.setAccessibilityLabel("Approved customer workspace")
        tenantPicker.target = self; tenantPicker.action = #selector(tenantChanged)
        connect.target = self; connect.action = #selector(begin)
        cancel.target = self; cancel.action = #selector(cancelWork)
        signOut.target = self; signOut.action = #selector(signOutHere)
        submit.target = self; submit.action = #selector(submitCapture)
        portal.target = self; portal.action = #selector(openPortal)
        status.setAccessibilityLabel("Customer connection status")
        let buttons = NSStackView(views: [connect, cancel, signOut]); buttons.spacing = 10
        let evidenceActions = NSStackView(views: [submit, portal]); evidenceActions.spacing = 12
        let stack = NSStackView(views: [intro, tenantPicker, buttons, evidenceActions, status]); stack.orientation = .vertical
        stack.alignment = .leading; stack.spacing = 16; stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView?.addSubview(stack)
        if let view = window.contentView {
            NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 22),
                stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -22), stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 22)])
        }
    }
    func show() {
        if task == nil {
            configurations = AWSCollectorConfiguration.bundled
            tenantPicker.removeAllItems(); tenantPicker.addItems(withTitles: configurations.map { $0.oauth.tenant.displayName })
            status.stringValue = configurations.isEmpty ? AWSCollectorFailure.configuration.localizedDescription : "Ready. Enrollment proves key possession, not hardware attestation."
            updateControls()
        }
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { window }
    func windowWillClose(_ notification: Notification) { cancelWork() }
    private func updateControls() {
        connect.isEnabled = task == nil && !configurations.isEmpty; tenantPicker.isEnabled = task == nil
        cancel.isEnabled = task != nil; signOut.isEnabled = task == nil && !configurations.isEmpty
        submit.isEnabled = task == nil && configurations.indices.contains(tenantPicker.indexOfSelectedItem) && selectionProvider?()?.apiOrigin == configurations[tenantPicker.indexOfSelectedItem].apiOrigin.absoluteString
        portal.isEnabled = configurations.indices.contains(tenantPicker.indexOfSelectedItem) && configurations[tenantPicker.indexOfSelectedItem].portalOrigin != nil
        portal.toolTip = portal.isEnabled ? "Open the separately approved customer web portal" : "No approved portal origin is bundled in this release"
    }
    @objc private func tenantChanged() { updateControls() }

    @objc private func begin() {
        guard task == nil, configurations.indices.contains(tenantPicker.indexOfSelectedItem) else { return }
        let configuration = configurations[tenantPicker.indexOfSelectedItem]
        task = Task {
            do {
                status.stringValue = "Checking this Mac's saved customer session…"
                let profile: AWSCollectorProfile
                do { profile = try await service.resume(configuration: configuration) }
                catch {
                    try Task.checkCancellation()
                    status.stringValue = "Sign in in the secure browser window…"
                    let authorization = try await oauth.begin(configuration: configuration.oauth)
                    let callback = try await browserCallback(authorization.authorizationURL)
                    let grant = try await oauth.consume(callbackURL: callback)
                    profile = try await service.exchange(grant: grant, configuration: configuration)
                }
                try Task.checkCancellation()
                let nameKey = "capture.awsDeviceName." + LocalEvidenceArchive.digest(Data((configuration.keyScope + "\n" + profile.userId).utf8))
                let name = NSTextField(string: UserDefaults.standard.string(forKey: nameKey) ?? Host.current().localizedName ?? "My Mac")
                name.frame.size.width = 360; name.setAccessibilityLabel("Device display name")
                let confirm = NSAlert(); confirm.messageText = "Enroll or verify this Mac in \(configuration.oauth.tenant.displayName)?"
                confirm.informativeText = "The server will bind this Mac's protected signing key to your current membership. Reuse the original display name for an existing enrollment. Administrators can revoke it; this app cannot reactivate a revoked key."
                confirm.accessoryView = name; confirm.addButton(withTitle: "Verify This Mac"); confirm.addButton(withTitle: "Cancel")
                guard confirm.runModal() == .alertFirstButtonReturn else { throw CancellationError() }
                status.stringValue = "Verifying this Mac's signed enrollment…"
                let (device, _) = try await service.enroll(configuration: configuration, displayName: name.stringValue)
                UserDefaults.standard.set(name.stringValue, forKey: nameKey)
                try Task.checkCancellation()
                var cursor: String?
                var chosen: (AWSCollectorAssessment, AWSCollectorCatalog)?
                repeat {
                    status.stringValue = "Loading active assessments…"
                    let page = try await service.assessments(configuration: configuration, cursor: cursor)
                    try Task.checkCancellation()
                    let valid = page.items.filter { $0.status == "ACTIVE" && $0.catalogId != nil && !$0.controls.isEmpty && !$0.systems.isEmpty }
                    let picker = NSPopUpButton(); picker.addItems(withTitles: valid.map { "\($0.name) · \($0.periodStart)–\($0.periodEnd)" }); picker.setAccessibilityLabel("Active assessment")
                    let prompt = NSAlert(); prompt.messageText = "Choose an active assessment"
                    prompt.informativeText = valid.isEmpty ? "No active, catalog-backed assessment on this page. Ask your administrator to create or activate one." : "The chosen assessment limits available controls and systems."
                    prompt.accessoryView = picker; prompt.addButton(withTitle: "Choose"); prompt.buttons[0].isEnabled = !valid.isEmpty
                    prompt.addButton(withTitle: page.nextCursor == nil ? "Cancel" : "Next Page"); if page.nextCursor != nil { prompt.addButton(withTitle: "Cancel") }
                    let result = prompt.runModal()
                    if result == .alertFirstButtonReturn, valid.indices.contains(picker.indexOfSelectedItem) {
                        let assessment = valid[picker.indexOfSelectedItem]
                        guard let catalog = page.catalogs.first(where: { $0.id == assessment.catalogId }) else { throw AWSCollectorFailure.invalidSelection }
                        chosen = (assessment, catalog)
                    } else if result == .alertSecondButtonReturn, let next = page.nextCursor, next != cursor { cursor = next }
                    else { throw CancellationError() }
                } while chosen == nil
                guard let (assessment, catalog) = chosen else { throw AWSCollectorFailure.invalidSelection }
                let scopedControls = catalog.controls.filter { assessment.controls.contains($0.id) }
                guard !scopedControls.isEmpty else { throw AWSCollectorFailure.invalidSelection }
                let control = NSPopUpButton(); control.addItems(withTitles: scopedControls.map { "\($0.id) · \($0.title)" }); control.setAccessibilityLabel("Assessment control")
                let system = NSPopUpButton(); system.addItems(withTitles: assessment.systems); system.setAccessibilityLabel("Assessment system")
                let scope = NSAlert(); scope.messageText = "Use assessment scope on this Mac?"
                scope.informativeText = "Local captures will use this customer and assessment workspace. Existing evidence is preserved. Legacy automatic hosted uploads are disabled. After capture and local review, use Submit / Check Capture to send the exact PNG to this customer and track server scanning and review."
                scope.accessoryView = NSGridView(views: [[NSTextField(labelWithString: "Control"), control], [NSTextField(labelWithString: "System"), system]])
                scope.addButton(withTitle: "Use Scope for Local Capture"); scope.addButton(withTitle: "Cancel")
                guard scope.runModal() == .alertFirstButtonReturn else { throw CancellationError() }
                let selectedControl = scopedControls[control.indexOfSelectedItem]
                let selection = try await service.select(assessment: assessment, catalog: catalog, control: selectedControl.id,
                    system: system.titleOfSelectedItem ?? "", device: device, configuration: configuration)
                try Task.checkCancellation()
                var context = CaptureContext.new(binding: TenantWorkspaceBinding(tenantID: selection.tenantId, workspaceID: selection.assessmentId))
                context.sessionName = assessment.name; context.controlID = selectedControl.id; context.title = selectedControl.title
                context.controlTitle = selectedControl.title; context.system = selection.systemName; context.assessmentPeriod = "\(assessment.periodStart)–\(assessment.periodEnd)"
                context.complianceArea = assessment.framework; context.description = selectedControl.defaultEvidence
                context.expectedEvidence = selectedControl.defaultEvidence; context.customFileName = selectedControl.title; context.evidenceOwner = profile.userId
                onSelection?(selection, context)
                status.stringValue = "This Mac is enrolled. Capture and locally review evidence, then use Submit / Check Capture. Server validation and independent review remain separate from upload."
            } catch is CancellationError { status.stringValue = "Canceled. No assessment selection changed. Any completed enrollment remains visible to your administrator." }
            catch { status.stringValue = error.localizedDescription }
            task = nil; updateControls()
        }
        updateControls()
    }

    private func browserCallback(_ url: URL) async throws -> URL {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                callbackContinuation = continuation
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "scopeproof-capture") { [weak self] callback, error in
                    Task { @MainActor in
                        guard let self, let pending = self.callbackContinuation else { return }
                        self.callbackContinuation = nil; self.authentication = nil
                        if let callback { pending.resume(returning: callback) }
                        else { pending.resume(throwing: error ?? CancellationError()) }
                    }
                }
                session.presentationContextProvider = self; session.prefersEphemeralWebBrowserSession = true
                authentication = session
                if !session.start() { callbackContinuation = nil; authentication = nil; continuation.resume(throwing: AWSCollectorFailure.configuration) }
            }
        }, onCancel: { Task { @MainActor [weak self] in self?.cancelBrowser() } })
    }
    private func cancelBrowser() {
        authentication?.cancel(); authentication = nil
        let pending = callbackContinuation; callbackContinuation = nil; pending?.resume(throwing: CancellationError())
    }
    @objc func cancelWork() { task?.cancel(); cancelBrowser() }
    @objc private func openPortal() {
        guard configurations.indices.contains(tenantPicker.indexOfSelectedItem), let url = configurations[tenantPicker.indexOfSelectedItem].portalOrigin else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func submitCapture() {
        guard task == nil, let selection = selectionProvider?(),
              let configuration = configurations.first(where: { $0.apiOrigin.absoluteString == selection.apiOrigin && $0.oauth.tenant.tenantID == selection.tenantId }) else { return }
        let binding = TenantWorkspaceBinding(tenantID: selection.tenantId, workspaceID: selection.assessmentId)
        let entries = Array((evidenceProvider?() ?? []).filter { $0.manifest.belongs(to: binding) && $0.manifest.controlID == selection.controlId && $0.manifest.system == selection.systemName && !$0.isPayloadArchived }.prefix(100))
        guard !entries.isEmpty else { status.stringValue = "No local capture matches the selected customer, assessment, control, and system. Capture evidence first or restore its archived payload."; return }
        let picker = NSPopUpButton(); picker.addItems(withTitles: entries.map { "\($0.manifest.evidenceID) · \($0.manifest.title)" }); picker.setAccessibilityLabel("Exact local capture to submit or check")
        let confirm = NSAlert(); confirm.messageText = "Submit or check this exact customer capture?"
        confirm.informativeText = "Destination: \(configuration.oauth.tenant.displayName) (\(configuration.apiOrigin.host ?? ""))\nThe original PNG and bounded capture metadata will be sent under the current assessment scope. Existing signed local history stays unchanged. A previous submitted or uncertain upload is status-checked, not silently uploaded again. A successful PUT does not mean scanning or review passed. Showing newest 100 matching captures."
        confirm.accessoryView = picker; confirm.addButton(withTitle: "Submit / Check Status"); confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }
        let entry = entries[picker.indexOfSelectedItem]
        task = Task {
            do {
                status.stringValue = "Refreshing this customer session and validating exact capture scope…"
                _ = try await service.resume(configuration: configuration)
                try Task.checkCancellation()
                guard let current = selectionProvider?(), current.tenantId == selection.tenantId,
                      current.assessmentId == selection.assessmentId, current.deviceId == selection.deviceId else { throw AWSCollectorUploadFailure.scope }
                let result = try await service.submit(entry: entry, selection: selection, configuration: configuration)
                status.stringValue = "\(entry.manifest.evidenceID) → \(result.evidenceId)\n\(result.presentation) Use this button to refresh processing or review status; open the approved reviewer portal for independent review."
            } catch is CancellationError { status.stringValue = "Canceled locally. Remote commit may already have occurred. Submit / Check Capture will reconcile server state." }
            catch { status.stringValue = error.localizedDescription }
            task = nil; updateControls()
        }
        updateControls()
    }
    @objc private func signOutHere() {
        guard configurations.indices.contains(tenantPicker.indexOfSelectedItem) else { return }
        let configuration = configurations[tenantPicker.indexOfSelectedItem]
        let alert = NSAlert(); alert.messageText = "Sign out on this Mac?"
        alert.informativeText = "Removes the saved refresh token and in-memory session. It does not delete evidence, revoke this Mac, or end sessions on other devices."
        alert.addButton(withTitle: "Sign Out"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do { try HostedKeychainRefreshTokenStore().delete(for: configuration.oauth); Task { await service.clear() }; status.stringValue = "Signed out on this Mac. Device enrollment and evidence preserved." }
        catch { status.stringValue = error.localizedDescription }
    }
}
