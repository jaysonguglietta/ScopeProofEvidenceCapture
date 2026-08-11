@preconcurrency import AppKit
import OSLog
import ServiceManagement
import UniformTypeIdentifiers
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let preferences = CapturePreferences()
    private lazy var captureService = CaptureService(preferences: preferences)
    private let uploadService = UploadService()
    private let helpController = HelpController()
    private let evidenceSearchController = EvidenceSearchController()
    private let logger = Logger(subsystem: "com.scopeproof.capture", category: "application")
    private var statusMenuItem = NSMenuItem(title: "Ready to capture", action: nil, keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        configureStatusItem()
        rebuildMenu()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        if KeychainStore.readToken() != nil, Date().timeIntervalSince(preferences.lastUpdateCheck ?? .distantPast) > 86_400 { checkForUpdates(silent: true) }
    }

    func menuWillOpen(_ menu: NSMenu) { rebuildMenu() }

    private func configureStatusItem() {
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Scopeproof Capture")
            button.toolTip = "Scopeproof Compliance Evidence Capture"
        }
        menu.delegate = self
        statusItem.menu = menu
    }

    private func rebuildMenu() {
        menu.removeAllItems()
        let heading = NSMenuItem(title: "Scopeproof Evidence Capture", action: nil, keyEquivalent: "")
        heading.isEnabled = false
        menu.addItem(heading)
        statusMenuItem = NSMenuItem(title: statusMenuItem.title, action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)
        let permission = NSMenuItem(title: captureService.hasScreenRecordingPermission ? "Screen Recording: Ready" : "Screen Recording: Permission needed", action: captureService.hasScreenRecordingPermission ? nil : #selector(openPermissionSettings), keyEquivalent: "")
        permission.state = captureService.hasScreenRecordingPermission ? .on : .off
        permission.target = self
        menu.addItem(permission)
        menu.addItem(.separator())

        let context = preferences.activeContext
        let sessionFramework = context.map { ComplianceCatalog.framework(named: $0.resolvedComplianceArea).fileCode } ?? ""
        let session = NSMenuItem(title: context?.isValid == true ? "Session: \(context!.sessionName) · \(sessionFramework) \(context!.controlID)" : "Session: Not configured", action: nil, keyEquivalent: "")
        session.isEnabled = false
        menu.addItem(session)
        let newSession = NSMenuItem(title: context?.isValid == true ? "Edit Capture Defaults…" : "Configure Capture Defaults…", action: #selector(startCaptureSession), keyEquivalent: "s")
        newSession.keyEquivalentModifierMask = [.command, .shift]
        newSession.target = self
        menu.addItem(newSession)
        let presetsItem = NSMenuItem(title: "Capture Presets", action: nil, keyEquivalent: "")
        let presetsMenu = NSMenu()
        for preset in preferences.presets {
            let item = NSMenuItem(title: preset.name, action: #selector(applyPreset(_:)), keyEquivalent: "")
            item.representedObject = preset.id; item.target = self; presetsMenu.addItem(item)
        }
        if !preferences.presets.isEmpty { presetsMenu.addItem(.separator()) }
        let savePreset = NSMenuItem(title: "Save Current as Preset…", action: #selector(saveCurrentPreset), keyEquivalent: ""); savePreset.target = self; savePreset.isEnabled = context?.isValid == true; presetsMenu.addItem(savePreset)
        let managePresets = NSMenuItem(title: "Remove a Preset…", action: #selector(removePreset), keyEquivalent: ""); managePresets.target = self; managePresets.isEnabled = !preferences.presets.isEmpty; presetsMenu.addItem(managePresets)
        presetsItem.submenu = presetsMenu
        menu.addItem(presetsItem)
        addItem("Import Control Catalog…", action: #selector(importControlCatalog))
        let removeCatalog = NSMenuItem(title: "Remove Imported Catalog…", action: #selector(removeImportedCatalog), keyEquivalent: ""); removeCatalog.target = self; removeCatalog.isEnabled = !ComplianceCatalog.importedFrameworks.isEmpty; menu.addItem(removeCatalog)
        menu.addItem(.separator())

        addItem("Capture Frontmost Browser Window", action: #selector(captureFrontmost), key: "e", modifiers: [.command, .shift])
        addItem("Choose Browser Window…", action: #selector(chooseBrowserWindow), key: "w", modifiers: [.command, .shift])
        addItem("Open URL & Capture…", action: #selector(promptForURL), key: "u", modifiers: [.command, .shift])

        let targetsItem = NSMenuItem(title: "Saved Evidence URLs", action: nil, keyEquivalent: "")
        let targetsMenu = NSMenu()
        for target in preferences.targets {
            let item = NSMenuItem(title: target, action: #selector(captureSavedTarget(_:)), keyEquivalent: "")
            item.representedObject = target
            item.target = self
            targetsMenu.addItem(item)
        }
        targetsMenu.addItem(.separator())
        let addTarget = NSMenuItem(title: "Add Evidence URL…", action: #selector(addSavedTarget), keyEquivalent: "")
        addTarget.target = self
        targetsMenu.addItem(addTarget)
        targetsItem.submenu = targetsMenu
        menu.addItem(targetsItem)
        addItem("Capture Entire Display (includes menu bar)", action: #selector(captureDisplay))
        menu.addItem(.separator())

        let browserItem = NSMenuItem(title: "Browser: \(preferences.browser.name)", action: nil, keyEquivalent: "")
        let browserMenu = NSMenu()
        for browser in BrowserChoice.supported {
            let item = NSMenuItem(title: browser.name, action: #selector(selectBrowser(_:)), keyEquivalent: "")
            item.representedObject = browser.bundleIdentifier ?? ""
            item.state = browser == preferences.browser ? .on : .off
            item.target = self
            browserMenu.addItem(item)
        }
        browserItem.submenu = browserMenu
        menu.addItem(browserItem)

        let delayItem = NSMenuItem(title: "Capture Delay: \(preferences.delay) seconds", action: nil, keyEquivalent: "")
        let delayMenu = NSMenu()
        for delay in [3, 5, 10, 15] {
            let item = NSMenuItem(title: "\(delay) seconds", action: #selector(selectDelay(_:)), keyEquivalent: "")
            item.tag = delay
            item.state = delay == preferences.delay ? .on : .off
            item.target = self
            delayMenu.addItem(item)
        }
        delayItem.submenu = delayMenu
        menu.addItem(delayItem)

        let safety = NSMenuItem(title: "OCR safety scan, redaction, preview & hash chain", action: nil, keyEquivalent: "")
        safety.state = .on
        safety.isEnabled = false
        menu.addItem(safety)
        let upload = NSMenuItem(title: uploadStatusTitle(), action: nil, keyEquivalent: "")
        upload.state = preferences.autoUpload && KeychainStore.readToken() != nil ? .on : .off
        upload.isEnabled = false
        menu.addItem(upload)
        menu.addItem(.separator())

        addItem("Search Evidence…", action: #selector(searchEvidence), key: "f", modifiers: [.command, .shift])
        addItem("Export Assessor Package…", action: #selector(exportAssessorPackage), key: "x", modifiers: [.command, .shift])
        let historyItem = NSMenuItem(title: "Recent Captures", action: nil, keyEquivalent: "")
        let historyMenu = NSMenu()
        let entries = Array(CaptureHistory.entries(in: captureService.outputDirectory).prefix(10))
        if entries.isEmpty {
            let empty = NSMenuItem(title: "No captures yet", action: nil, keyEquivalent: ""); empty.isEnabled = false; historyMenu.addItem(empty)
        } else {
            for entry in entries {
                let marker = entry.isUploaded ? "✓" : "↥"
                let framework = ComplianceCatalog.framework(named: entry.manifest.complianceArea).fileCode
                let item = NSMenuItem(title: "\(marker) \(framework) \(entry.manifest.controlID) · \(entry.manifest.evidenceID) · \(entry.manifest.localTimestamp)", action: #selector(openHistoryEntry(_:)), keyEquivalent: "")
                item.representedObject = entry.imageURL.path
                item.target = self
                historyMenu.addItem(item)
            }
        }
        historyItem.submenu = historyMenu
        menu.addItem(historyItem)
        addItem("Retry Pending Uploads", action: #selector(retryPendingUploads))
        addItem("Open Evidence Folder", action: #selector(openEvidenceFolder), key: "o")
        addItem("Apply \(preferences.retentionDays)-Day Local Retention…", action: #selector(applyRetention))
        menu.addItem(.separator())

        let login = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin(_:)), keyEquivalent: "")
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        login.target = self
        menu.addItem(login)
        addItem("Capture & Jira Settings…", action: #selector(openSettings), key: ",", modifiers: [.command])
        addItem("Check for Updates…", action: #selector(checkForUpdatesAction))
        addItem("Help & How to Use…", action: #selector(showHelp), key: "?", modifiers: [.command, .shift])
        addItem("Screen Recording Settings…", action: #selector(openPermissionSettings))
        menu.addItem(.separator())
        addItem("Quit Scopeproof Capture", action: #selector(quitApp), key: "q", modifiers: [.command])
    }

    private func addItem(_ title: String, action: Selector, key: String = "", modifiers: NSEvent.ModifierFlags = []) {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.keyEquivalentModifierMask = modifiers
        item.target = self
        menu.addItem(item)
    }

    private func captureContext() -> CaptureContext? {
        promptForCaptureSession(actionTitle: "Continue to Capture")
    }

    @objc private func startCaptureSession() { _ = promptForCaptureSession(actionTitle: "Save Defaults") }

    private func promptForCaptureSession(actionTitle: String) -> CaptureContext? {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let previous = preferences.activeContext
        let defaultPeriod = CaptureContext.new().assessmentPeriod
        var frameworkValue = previous?.complianceArea ?? ComplianceCatalog.defaultFramework.name
        var sessionValue = previous?.sessionName ?? "Compliance Evidence – \(defaultPeriod)"
        var controlValue = previous?.controlID ?? ""
        var filenameValue = previous?.customFileName ?? previous?.title ?? "Evidence"
        var titleValue = previous?.title ?? ""
        var systemValue = previous?.system ?? ""
        var environmentValue = previous?.environment ?? "Production"
        var periodValue = previous?.assessmentPeriod ?? defaultPeriod
        var descriptionValue = previous?.description ?? ""
        var ownerValue = previous?.evidenceOwner ?? NSFullUserName()
        var tagsValue = previous?.tags?.joined(separator: ", ") ?? ""
        var expectedValue = previous?.expectedEvidence ?? ""
        var jiraIssueValue = previous?.jiraIssueKey ?? ""
        var missingFields: [String] = []

        while true {
            let alert = NSAlert()
            alert.messageText = missingFields.isEmpty ? "Classify this evidence capture" : "Complete the required capture context"
            alert.informativeText = missingFields.isEmpty
                ? "Confirm the prefilled classification before every capture. Required context is embedded in the screenshot and immutable manifest."
                : "Enter \(missingFields.joined(separator: ", ")). Your previous entries have been preserved below."
            alert.alertStyle = missingFields.isEmpty ? .informational : .warning
            alert.addButton(withTitle: actionTitle)
            alert.addButton(withTitle: "Cancel")

            let framework = NSPopUpButton()
            framework.addItems(withTitles: ComplianceCatalog.frameworks.map(\.name))
            framework.selectItem(withTitle: frameworkValue)
            let control = NSComboBox()
            control.isEditable = true
            control.completes = true
            control.numberOfVisibleItems = 12
            let fileName = NSTextField(string: filenameValue)
            let sessionName = NSTextField(string: sessionValue)
            let title = NSTextField(string: titleValue)
            let system = NSTextField(string: systemValue)
            let environment = NSPopUpButton()
            environment.addItems(withTitles: ["Production", "Staging", "Development", "Corporate", "Other"])
            environment.selectItem(withTitle: environmentValue)
            let period = NSTextField(string: periodValue)
            let description = NSTextField(string: descriptionValue)
            let owner = NSTextField(string: ownerValue)
            let tags = NSTextField(string: tagsValue)
            let expected = NSTextField(string: expectedValue)
            let jiraIssue = NSTextField(string: jiraIssueValue)
            control.placeholderString = "Select or type a control ID"
            fileName.placeholderString = "e.g. Production-MFA-Settings"
            title.placeholderString = "e.g. Production MFA settings"
            system.placeholderString = "e.g. Okta production tenant"
            description.placeholderString = "Optional assessor note"
            owner.placeholderString = "Control owner or evidence custodian"
            tags.placeholderString = "identity, quarterly, production"
            expected.placeholderString = "What should an assessor verify in this artifact?"
            jiraIssue.placeholderString = preferences.jiraHandoff.projectKey.isEmpty ? "Optional, e.g. GRC-123" : "Optional, e.g. \(preferences.jiraHandoff.projectKey)-123"
            let preview = NSTextField(wrappingLabelWithString: "")
            preview.textColor = .secondaryLabelColor
            preview.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            preview.maximumNumberOfLines = 2
            let mappings = NSTextField(wrappingLabelWithString: "")
            mappings.textColor = .secondaryLabelColor
            mappings.font = .systemFont(ofSize: 10)
            mappings.maximumNumberOfLines = 2
            for field in [fileName, sessionName, title, system, period, description, owner, tags, expected, jiraIssue] { field.frame.size.width = 400 }
            control.frame.size.width = 400
            framework.frame.size.width = 400
            preview.frame.size.width = 400
            mappings.frame.size.width = 400
            let grid = NSGridView(views: [
                [label("Compliance area *"), framework], [label("Control *"), control], [label("File name *"), fileName], [label("Saved as"), preview],
                [label("Evidence title *"), title], [label("System or asset *"), system], [label("Environment *"), environment],
                [label("Assessment period *"), period], [label("Session name *"), sessionName], [label("Evidence owner"), owner],
                [label("Jira issue"), jiraIssue], [label("Tags"), tags], [label("Expected evidence"), expected], [label("What this proves"), description], [label("Related controls"), mappings],
            ])
            grid.column(at: 0).xPlacement = .trailing
            grid.column(at: 1).xPlacement = .fill
            grid.rowSpacing = 10
            grid.columnSpacing = 12
            grid.frame = NSRect(x: 0, y: 0, width: 560, height: 535)
            alert.accessoryView = grid
            let coordinator = CaptureMetadataCoordinator(
                frameworkPopup: framework, controlCombo: control, filenameField: fileName, periodField: period, jiraIssueField: jiraIssue,
                previewLabel: preview, preferredControlID: controlValue, mappingLabel: mappings
            )
            alert.window.initialFirstResponder = missingFields.contains("control") ? control : (missingFields.contains("file name") ? fileName : (missingFields.contains("evidence title") ? title : control))

            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            frameworkValue = coordinator.frameworkName
            sessionValue = sessionName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            controlValue = coordinator.controlID
            filenameValue = fileName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            titleValue = title.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            systemValue = system.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            environmentValue = environment.titleOfSelectedItem ?? "Production"
            periodValue = period.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            descriptionValue = description.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            ownerValue = owner.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            tagsValue = tags.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            expectedValue = expected.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            jiraIssueValue = JiraHandoff.normalizedIssueKey(jiraIssue.stringValue)
            let missing = [("compliance area", frameworkValue), ("control", controlValue), ("file name", filenameValue), ("session name", sessionValue), ("evidence title", titleValue), ("system or asset", systemValue), ("environment", environmentValue), ("assessment period", periodValue)].filter { $0.1.isEmpty }.map(\.0)
            guard missing.isEmpty else { missingFields = missing; continue }
            guard JiraHandoff.isValidIssueKey(jiraIssueValue) else { missingFields = ["a Jira issue key such as GRC-123 (or leave it blank)"]; continue }
            let context = CaptureContext(
                sessionID: previous?.sessionID ?? "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
                sessionName: sessionValue, controlID: controlValue, title: titleValue, system: systemValue,
                environment: environmentValue, assessmentPeriod: periodValue,
                description: descriptionValue, complianceArea: frameworkValue,
                controlTitle: coordinator.controlTitle, customFileName: filenameValue,
                evidenceOwner: ownerValue, tags: tagsValue.split(separator: ",").map(String.init), expectedEvidence: expectedValue, jiraIssueKey: jiraIssueValue
            )
            preferences.activeContext = context
            setReady("Session \(context.sessionName) ready")
            rebuildMenu()
            return context
        }
    }

    private func label(_ value: String) -> NSTextField {
        let field = NSTextField(labelWithString: value)
        field.font = .systemFont(ofSize: 12, weight: .medium)
        return field
    }

    @objc private func captureFrontmost() {
        guard let context = captureContext() else { return }
        setBusy("Capturing and scanning browser…")
        captureService.captureFrontmostBrowser(context: context, completion: finishCapture)
    }

    @objc private func chooseBrowserWindow() {
        guard let context = captureContext() else { return }
        guard captureService.requestScreenRecordingPermissionIfNeeded() else { showError(CaptureFailure.permissionRequired); return }
        let windows = captureService.browserWindows()
        guard !windows.isEmpty else { showError(CaptureFailure.noBrowserWindow); return }
        let alert = NSAlert()
        alert.messageText = "Choose a browser window"
        alert.informativeText = "Select the exact evidence window to capture."
        alert.addButton(withTitle: "Capture")
        alert.addButton(withTitle: "Cancel")
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 520, height: 28))
        picker.addItems(withTitles: windows.map(\.displayTitle))
        alert.accessoryView = picker
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        setBusy("Capturing selected window…")
        captureService.captureWindow(windows[max(0, picker.indexOfSelectedItem)], context: context, completion: finishCapture)
    }

    @objc private func captureDisplay() {
        guard let context = captureContext() else { return }
        setBusy("Capturing and scanning display…")
        captureService.captureEntireDisplay(context: context, completion: finishCapture)
    }

    @objc private func promptForURL() {
        guard let context = captureContext(), let target = prompt(title: "Open URL & Capture", message: "The selected browser will open this page, wait \(preferences.delay) seconds, then capture and scan its window.", placeholder: "https://admin.example.com/security") else { return }
        preferences.addTarget(target)
        openAndCapture(target, context: context)
    }

    @objc private func addSavedTarget() {
        guard let target = prompt(title: "Add Evidence URL", message: "Save a frequently captured PCI evidence page.", placeholder: "https://admin.example.com/security") else { return }
        guard let url = URL(string: target), ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil else { showError(CaptureFailure.invalidURL); return }
        preferences.addTarget(target)
        setReady("Evidence URL saved")
    }

    @objc private func captureSavedTarget(_ sender: NSMenuItem) {
        guard let context = captureContext(), let target = sender.representedObject as? String else { return }
        openAndCapture(target, context: context)
    }

    private func openAndCapture(_ target: String, context: CaptureContext) {
        setBusy("Opening \(URL(string: target)?.host ?? "browser")…")
        captureService.openAndCapture(urlString: target, browser: preferences.browser, delay: preferences.delay, context: context, completion: finishCapture)
    }

    private func finishCapture(_ result: Result<CaptureResult, CaptureFailure>) {
        switch result {
        case .success(let capture):
            setReady("Saved \(capture.evidenceID)")
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(capture.imageURL.path, forType: .string)
            notify(title: "Compliance evidence captured", body: "\(capture.context.resolvedComplianceArea) \(capture.context.controlID) was saved. The file path is on your clipboard.")
            if preferences.autoUpload { upload(capture) }
        case .failure(.cancelled): setReady("Capture discarded")
        case .failure(let error): setReady("Capture failed"); showError(error)
        }
    }

    private func upload(_ capture: CaptureResult) {
        setBusy("Uploading \(capture.evidenceID)…")
        Task {
            do {
                _ = try await uploadService.upload(capture, serverURL: preferences.serverURL)
                await MainActor.run { self.setReady("Uploaded \(capture.evidenceID)"); self.notify(title: "Evidence uploaded", body: "\(capture.evidenceID) is encrypted and waiting for review in Scopeproof.") }
            } catch {
                await MainActor.run { self.setReady("Saved locally · upload pending"); self.notify(title: "Evidence saved locally", body: "Upload is pending: \(error.localizedDescription)") }
            }
        }
    }

    @objc private func retryPendingUploads() {
        let pending = CaptureHistory.entries(in: captureService.outputDirectory).filter { !$0.isUploaded }
        guard !pending.isEmpty else { setReady("No pending uploads"); return }
        setBusy("Retrying \(pending.count) upload(s)…")
        Task {
            var completed = 0
            for entry in pending {
                let capture = CaptureResult(imageURL: entry.imageURL, manifestURL: entry.manifestURL, evidenceID: entry.manifest.evidenceID,
                    context: CaptureContext(sessionID: entry.manifest.sessionID, sessionName: entry.manifest.sessionName, controlID: entry.manifest.controlID, title: entry.manifest.title, system: entry.manifest.system, environment: entry.manifest.environment, assessmentPeriod: entry.manifest.assessmentPeriod, description: entry.manifest.description, complianceArea: entry.manifest.complianceArea, controlTitle: entry.manifest.controlTitle, customFileName: entry.manifest.customFileName, evidenceOwner: entry.manifest.evidenceOwner, tags: entry.manifest.tags, expectedEvidence: entry.manifest.expectedEvidence, jiraIssueKey: entry.manifest.jiraIssueKey),
                    capturedAt: entry.manifest.capturedAt, safetyStatus: entry.manifest.safetyStatus, findings: entry.manifest.redactionFindings, sha256: entry.manifest.sha256, chainPreviousHash: entry.manifest.chainPreviousHash, chainEventHash: entry.manifest.chainEventHash)
                if (try? await uploadService.upload(capture, serverURL: preferences.serverURL)) != nil { completed += 1 }
            }
            await MainActor.run { self.setReady("Uploaded \(completed) of \(pending.count)"); self.notify(title: "Upload retry complete", body: "\(completed) evidence capture(s) reached Scopeproof.") }
        }
    }

    @objc private func openHistoryEntry(_ sender: NSMenuItem) { if let path = sender.representedObject as? String { NSWorkspace.shared.open(URL(fileURLWithPath: path)) } }
    @objc private func searchEvidence() { evidenceSearchController.show(evidenceRoot: captureService.outputDirectory, jiraSettings: preferences.jiraHandoff, serverURL: preferences.serverURL) }

    @objc private func applyPreset(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let preset = preferences.presets.first(where: { $0.id == id }) else { return }
        let source = preset.context
        let context = CaptureContext(
            sessionID: "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
            sessionName: source.sessionName, controlID: source.controlID, title: source.title, system: source.system,
            environment: source.environment, assessmentPeriod: source.assessmentPeriod, description: source.description,
            complianceArea: source.complianceArea, controlTitle: source.controlTitle, customFileName: source.customFileName,
            evidenceOwner: source.evidenceOwner, tags: source.tags, expectedEvidence: source.expectedEvidence, jiraIssueKey: source.jiraIssueKey
        )
        preferences.activeContext = context
        setReady("Preset \(preset.name) applied")
        rebuildMenu()
    }

    @objc private func saveCurrentPreset() {
        guard let context = preferences.activeContext, context.isValid,
              let name = prompt(title: "Save Capture Preset", message: "Presets reuse framework, control, system, owner, tags, and assessor context. Each applied preset starts a new capture session.", placeholder: "e.g. Quarterly Okta MFA Review"), !name.isEmpty else { return }
        preferences.savePreset(name: name, context: context)
        setReady("Capture preset saved")
        rebuildMenu()
    }

    @objc private func removePreset() {
        let presets = preferences.presets
        guard !presets.isEmpty else { return }
        let alert = NSAlert(); alert.messageText = "Remove a capture preset"; alert.informativeText = "Existing evidence is not affected."; alert.addButton(withTitle: "Remove"); alert.addButton(withTitle: "Cancel")
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 420, height: 28)); picker.addItems(withTitles: presets.map(\.name)); alert.accessoryView = picker
        guard alert.runModal() == .alertFirstButtonReturn, picker.indexOfSelectedItem >= 0 else { return }
        preferences.deletePreset(id: presets[picker.indexOfSelectedItem].id); setReady("Capture preset removed"); rebuildMenu()
    }

    @objc private func importControlCatalog() {
        let panel = NSOpenPanel(); panel.title = "Import Control Catalog"; panel.message = "Choose Scopeproof JSON, OSCAL catalog JSON, or CSV with control ID and title columns."; panel.allowedContentTypes = [.json, .commaSeparatedText]; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { let catalog = try ComplianceCatalog.importCatalog(from: url); setReady("Imported \(catalog.name) · \(catalog.controls.count) controls"); rebuildMenu() }
        catch { showError(NSError(domain: "Scopeproof", code: 14, userInfo: [NSLocalizedDescriptionKey: "The catalog could not be imported. Use a Scopeproof framework JSON object, OSCAL catalog JSON, or CSV with a header followed by control ID,title rows."])) }
    }

    @objc private func removeImportedCatalog() {
        let catalogs = ComplianceCatalog.importedFrameworks
        guard !catalogs.isEmpty else { return }
        let alert = NSAlert(); alert.messageText = "Remove an imported control catalog"; alert.informativeText = "Existing evidence keeps its framework, catalog version, and control metadata. Only future selection options are affected."; alert.addButton(withTitle: "Remove"); alert.addButton(withTitle: "Cancel")
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 430, height: 28)); picker.addItems(withTitles: catalogs.map { "\($0.name)\($0.version.map { " · \($0)" } ?? "")" }); alert.accessoryView = picker
        guard alert.runModal() == .alertFirstButtonReturn, picker.indexOfSelectedItem >= 0 else { return }
        ComplianceCatalog.removeImportedCatalog(named: catalogs[picker.indexOfSelectedItem].name); setReady("Imported catalog removed"); rebuildMenu()
    }

    @objc private func exportAssessorPackage() {
        let allEntries = CaptureHistory.entries(in: captureService.outputDirectory)
        let approved = allEntries.filter { $0.lifecycle.status == .approved }
        guard !approved.isEmpty else { showError(AssessorPackageFailure.noApprovedEvidence); return }
        let frameworks = Array(Set(approved.map { $0.manifest.complianceArea ?? "PCI DSS 4.0.1" })).sorted()
        let periods = Array(Set(approved.map { $0.manifest.assessmentPeriod })).sorted()
        let alert = NSAlert(); alert.messageText = "Build assessor evidence package"; alert.informativeText = "Only Approved evidence is included. Every artifact is re-hashed and every lifecycle chain is verified before export."; alert.addButton(withTitle: "Choose Save Location"); alert.addButton(withTitle: "Cancel")
        let framework = NSPopUpButton(); framework.addItem(withTitle: "All compliance areas"); framework.addItems(withTitles: frameworks)
        let period = NSPopUpButton(); period.addItem(withTitle: "All assessment periods"); period.addItems(withTitles: periods)
        let name = NSTextField(string: "External Assessor Evidence – \(CaptureContext.new().assessmentPeriod)")
        let preparedBy = NSTextField(string: NSFullUserName())
        for field in [name, preparedBy] { field.frame.size.width = 390 }
        let grid = NSGridView(views: [[label("Package name"), name], [label("Compliance area"), framework], [label("Assessment period"), period], [label("Prepared by"), preparedBy]])
        grid.rowSpacing = 10; grid.columnSpacing = 12; grid.column(at: 0).xPlacement = .trailing; grid.column(at: 1).xPlacement = .fill; alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let selected = approved.filter { entry in
            (framework.indexOfSelectedItem == 0 || (entry.manifest.complianceArea ?? "PCI DSS 4.0.1") == framework.titleOfSelectedItem) &&
            (period.indexOfSelectedItem == 0 || entry.manifest.assessmentPeriod == period.titleOfSelectedItem)
        }
        guard !selected.isEmpty else { showError(AssessorPackageFailure.noApprovedEvidence); return }
        let save = NSSavePanel(); save.title = "Save Assessor Package"; save.allowedContentTypes = [.zip]; save.nameFieldStringValue = "Scopeproof-Assessor-Package-\(ComplianceCatalog.safeFileBase(name.stringValue)).zip"
        guard save.runModal() == .OK, let destination = save.url else { return }
        do {
            let result = try AssessorPackageExporter.export(entries: selected, to: destination, preparedBy: preparedBy.stringValue, packageName: name.stringValue, jiraSettings: preferences.jiraHandoff)
            setReady("Exported \(result.evidenceCount) approved evidence items")
            NSWorkspace.shared.activateFileViewerSelecting([result.zipURL, result.checksumURL])
            notify(title: "Assessor package ready", body: "\(result.evidenceCount) approved artifacts were validated and packaged.")
        } catch { showError(error) }
    }
    @objc private func selectBrowser(_ sender: NSMenuItem) { let bundleID = (sender.representedObject as? String).flatMap { $0.isEmpty ? nil : $0 }; if let browser = BrowserChoice.supported.first(where: { $0.bundleIdentifier == bundleID }) { preferences.browser = browser }; rebuildMenu() }
    @objc private func selectDelay(_ sender: NSMenuItem) { preferences.delay = sender.tag; rebuildMenu() }

    @objc private func openEvidenceFolder() {
        try? FileManager.default.createDirectory(at: captureService.outputDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        NSWorkspace.shared.open(captureService.outputDirectory)
    }

    @objc private func applyRetention() {
        let alert = NSAlert()
        alert.messageText = "Apply local retention policy?"
        alert.informativeText = "PNG, manifest, review lifecycle, and receipt files older than \(preferences.retentionDays) days will be moved to Trash. Hosted evidence is not affected."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Move Expired Files to Trash")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do { let count = try CaptureHistory.removeExpired(in: captureService.outputDirectory, retentionDays: preferences.retentionDays); setReady("Moved \(count) expired capture(s) to Trash") }
        catch { showError(error) }
    }

    @objc private func toggleLaunchAtLogin(_ sender: NSMenuItem) {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() }
            rebuildMenu()
        } catch {
            showError(error)
            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") { NSWorkspace.shared.open(url) }
        }
    }

    @objc private func openSettings() {
        let alert = NSAlert()
        alert.messageText = "Scopeproof Capture & Jira Settings"
        alert.informativeText = "Jira handoff defaults create ticket-ready labels. Authorize Jira Cloud in the Scopeproof web console under Connections; the Mac never stores Atlassian credentials. Device tokens remain protected in your login Keychain."
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let server = NSTextField(string: preferences.serverURL?.absoluteString ?? "")
        let token = NSSecureTextField(string: "")
        token.placeholderString = KeychainStore.readToken() == nil ? "Paste one-time spdev_ token" : "Token saved — leave blank to keep it"
        let auto = NSButton(checkboxWithTitle: "Upload reviewed captures automatically", target: nil, action: nil)
        auto.state = preferences.autoUpload ? .on : .off
        let retention = NSPopUpButton(); retention.addItems(withTitles: ["30 days", "90 days", "180 days", "365 days", "1095 days"]); retention.selectItem(withTitle: "\(preferences.retentionDays) days")
        let jira = preferences.jiraHandoff
        let jiraSite = NSTextField(string: jira.baseURL)
        jiraSite.placeholderString = "https://your-company.atlassian.net"
        let jiraProject = NSTextField(string: jira.projectKey)
        jiraProject.placeholderString = "e.g. GRC"
        let attachmentMode = NSPopUpButton(); attachmentMode.addItems(withTitles: JiraAttachmentMode.allCases.map(\.rawValue)); attachmentMode.selectItem(withTitle: jira.attachmentMode.rawValue)
        let includeGuide = NSButton(checkboxWithTitle: "Include Jira handoff guide in assessor packages", target: nil, action: nil); includeGuide.state = jira.includeGuideInPackages ? .on : .off
        let instructions = NSTextField(string: jira.customInstructions)
        instructions.placeholderString = "Optional: project, issue type, reviewers, retention, or internal handling steps"
        for field in [server, token, jiraSite, jiraProject, instructions] { field.frame.size.width = 430 }
        let section = NSTextField(labelWithString: "Jira handoff defaults (OAuth: web Connections)"); section.font = .systemFont(ofSize: 12, weight: .semibold); section.textColor = .secondaryLabelColor
        let grid = NSGridView(views: [
            [label("Server URL"), server], [label("Device token"), token], [label("Local retention"), retention], [NSTextField(labelWithString: ""), auto],
            [NSTextField(labelWithString: ""), section], [label("Jira site URL"), jiraSite], [label("Default project"), jiraProject],
            [label("Attachment set"), attachmentMode], [NSTextField(labelWithString: ""), includeGuide], [label("Organization instructions"), instructions],
        ])
        grid.rowSpacing = 10; grid.columnSpacing = 12; grid.column(at: 0).xPlacement = .trailing; grid.column(at: 1).xPlacement = .fill
        alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let url = URL(string: server.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)), isAllowedServerURL(url) else { showError(UploadFailure.invalidServer); return }
        let jiraSiteValue = jiraSite.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let jiraProjectValue = jiraProject.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if !jiraSiteValue.isEmpty {
            let candidate = JiraHandoffSettings(baseURL: jiraSiteValue, projectKey: jiraProjectValue, attachmentMode: .evidenceSet, includeGuideInPackages: true, customInstructions: "")
            guard candidate.validatedBaseURL != nil else { showError(NSError(domain: "Scopeproof", code: 21, userInfo: [NSLocalizedDescriptionKey: "The Jira site must be a complete HTTPS URL without a query, fragment, or embedded credentials."])); return }
        }
        guard JiraHandoff.isValidProjectKey(jiraProjectValue) else { showError(NSError(domain: "Scopeproof", code: 22, userInfo: [NSLocalizedDescriptionKey: "The Jira project key must start with a letter and contain only uppercase letters, numbers, or underscores."])); return }
        let newToken = token.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard newToken.isEmpty || newToken.hasPrefix("spdev_dev_") else { showError(NSError(domain: "Scopeproof", code: 2, userInfo: [NSLocalizedDescriptionKey: "The device token must begin with spdev_dev_."])); return }
        let selectedMode = JiraAttachmentMode(rawValue: attachmentMode.titleOfSelectedItem ?? "") ?? .evidenceSet
        preferences.serverURL = url
        preferences.autoUpload = auto.state == .on
        preferences.retentionDays = Int(retention.titleOfSelectedItem?.split(separator: " ").first ?? "365") ?? 365
        preferences.jiraHandoff = JiraHandoffSettings(baseURL: jiraSiteValue, projectKey: jiraProjectValue, attachmentMode: selectedMode, includeGuideInPackages: includeGuide.state == .on, customInstructions: String(instructions.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2_000)))
        if !newToken.isEmpty {
            do { try KeychainStore.saveToken(newToken) } catch { showError(error); return }
        }
        setReady("Capture and Jira settings saved")
    }

    private func isAllowedServerURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else { return false }
        if scheme == "https" { return true }
        return scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(host)
    }

    @objc private func checkForUpdatesAction() { checkForUpdates(silent: false) }
    private func checkForUpdates(silent: Bool) {
        Task {
            do {
                let release = try await uploadService.checkForUpdates(serverURL: preferences.serverURL)
                await MainActor.run {
                    self.preferences.lastUpdateCheck = Date()
                    let installedVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.3.1"
                    guard self.isNewer(release.version, than: installedVersion) else { if !silent { self.setReady("Scopeproof Capture is up to date") }; return }
                    let alert = NSAlert(); alert.messageText = "Scopeproof Capture \(release.version) is available"; alert.informativeText = release.notes
                    alert.addButton(withTitle: release.downloadUrl == nil ? "OK" : "Open Download"); alert.addButton(withTitle: "Later")
                    if alert.runModal() == .alertFirstButtonReturn, let url = release.downloadUrl { NSWorkspace.shared.open(url) }
                }
            } catch { if !silent { await MainActor.run { self.showError(error) } } }
        }
    }

    private func isNewer(_ candidate: String, than current: String) -> Bool {
        let left = candidate.split(separator: ".").map { Int($0) ?? 0 }; let right = current.split(separator: ".").map { Int($0) ?? 0 }
        for index in 0..<max(left.count, right.count) { let l = index < left.count ? left[index] : 0; let r = index < right.count ? right[index] : 0; if l != r { return l > r } }
        return false
    }

    @objc private func showHelp() { helpController.show(outputDirectory: captureService.outputDirectory) }
    @objc private func openPermissionSettings() { if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") { NSWorkspace.shared.open(url) } }
    @objc private func quitApp() { NSApplication.shared.terminate(nil) }

    private func uploadStatusTitle() -> String {
        guard KeychainStore.readToken() != nil else { return "Web upload: Not connected" }
        return preferences.autoUpload ? "Web upload: Automatic" : "Web upload: Manual retry"
    }

    private func setBusy(_ value: String) { statusMenuItem.title = value; statusItem.button?.image = NSImage(systemSymbolName: "camera.metering.center.weighted", accessibilityDescription: value) }
    private func setReady(_ value: String) { statusMenuItem.title = value; statusItem.button?.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Scopeproof Capture") }

    private func prompt(title: String, message: String, placeholder: String) -> String? {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert(); alert.messageText = title; alert.informativeText = message; alert.addButton(withTitle: "Continue"); alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 430, height: 26)); field.placeholderString = placeholder; alert.accessoryView = field; alert.window.initialFirstResponder = field
        return alert.runModal() == .alertFirstButtonReturn ? field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) : nil
    }

    private func showError(_ error: Error) {
        logger.error("Operation failed: \(error.localizedDescription, privacy: .public)")
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Scopeproof could not complete the operation"
        alert.informativeText = error.localizedDescription
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
    private func notify(title: String, body: String) { NSSound(named: "Glass")?.play(); let content = UNMutableNotificationContent(); content.title = title; content.body = body; content.sound = .default; UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) }
}
