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
    private lazy var captureService = CaptureService(preferences: preferences) { [weak self] in
        self?.setBusy(CaptureReviewPresentation.waitingStatus)
        self?.rebuildMenu()
    }
    private let uploadService = UploadService()
    private let s3StorageService = S3StorageService()
    private let updateService = UpdateService()
    private let repositorySBOMService = RepositorySBOMService()
    private lazy var s3ObjectBrowserController = S3ObjectBrowserController(service: s3StorageService)
    private let helpController = HelpController()
    private let evidenceSearchController = EvidenceSearchController()
    private let logger = Logger(subsystem: "com.scopeproof.capture", category: "application")
    private var statusMenuItem = NSMenuItem(title: "Ready to capture", action: nil, keyEquivalent: "")
    private var repositorySBOMTask: Task<Void, Never>?
    private var s3RetryTask: Task<Void, Never>?
    private var s3ConfigurationTask: Task<Void, Never>?
    private lazy var localConsole = LocalConsoleServer(evidenceRoot: captureService.outputDirectory, preferences: preferences) { [weak self] in
        self?.chooseBrowserWindow()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        configureStatusItem()
        rebuildMenu()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        if let server = BackendTrust.normalizedOrigin(preferences.serverURL), KeychainStore.readToken(for: server) != nil, Date().timeIntervalSince(preferences.lastUpdateCheck ?? .distantPast) > 86_400 { checkForUpdates(silent: true) }
        if preferences.openLocalConsoleAtLaunch { openLocalConsole() }
    }

    func menuWillOpen(_ menu: NSMenu) { rebuildMenu() }

    func applicationWillTerminate(_ notification: Notification) {
        repositorySBOMTask?.cancel()
        s3RetryTask?.cancel()
        s3ConfigurationTask?.cancel()
        localConsole.stop()
    }

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
        addItem("Capture Scrolling Evidence…", action: #selector(captureScrollingEvidence), key: "s", modifiers: [.command, .shift])
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
        upload.state = preferences.autoUpload && BackendTrust.normalizedOrigin(preferences.serverURL).flatMap(KeychainStore.readToken(for:)) != nil ? .on : .off
        upload.isEnabled = false
        menu.addItem(upload)
        let s3Storage = NSMenuItem(title: s3StorageStatusTitle(), action: nil, keyEquivalent: "")
        s3Storage.state = preferences.s3Storage.canUpload && KeychainStore.readS3Credentials() != nil &&
            KeychainStore.readS3VerifiedDestination()?.matches(preferences.s3Storage) == true ? .on : .off
        s3Storage.isEnabled = false
        menu.addItem(s3Storage)
        menu.addItem(.separator())

        addItem("Open Local Console", action: #selector(openLocalConsole), key: "l", modifiers: [.command, .shift])
        addItem("Search Evidence…", action: #selector(searchEvidence), key: "f", modifiers: [.command, .shift])
        addItem("Export Assessor Package…", action: #selector(exportAssessorPackage), key: "x", modifiers: [.command, .shift])
        let repositorySBOM = NSMenuItem(title: repositorySBOMTask == nil ? "Generate Repository SBOM…" : "Generating Repository SBOM…", action: #selector(generateRepositorySBOM), keyEquivalent: "b")
        repositorySBOM.keyEquivalentModifierMask = [.command, .shift]
        repositorySBOM.target = self
        repositorySBOM.isEnabled = repositorySBOMTask == nil
        menu.addItem(repositorySBOM)
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
        let browseS3 = NSMenuItem(title: "Browse S3 Evidence…", action: #selector(openS3Browser), keyEquivalent: "")
        browseS3.target = self
        browseS3.isEnabled = preferences.s3Storage.canUpload && preferences.s3Storage.downloadsAllowed &&
            KeychainStore.readS3Credentials() != nil && KeychainStore.readS3VerifiedDestination()?.matches(preferences.s3Storage) == true &&
            s3ConfigurationTask == nil
        menu.addItem(browseS3)
        let retryS3 = NSMenuItem(title: s3RetryTask == nil ? "Upload Pending Evidence to S3" : "Uploading Pending Evidence to S3…", action: #selector(retryPendingS3Uploads), keyEquivalent: "")
        retryS3.target = self
        retryS3.isEnabled = s3RetryTask == nil && s3ConfigurationTask == nil && preferences.s3Storage.canUpload &&
            KeychainStore.readS3VerifiedDestination()?.matches(preferences.s3Storage) == true
        menu.addItem(retryS3)
        addItem("Open Evidence Folder", action: #selector(openEvidenceFolder), key: "o")
        addItem("Apply \(preferences.retentionDays)-Day Local Retention…", action: #selector(applyRetention))
        menu.addItem(.separator())

        let login = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin(_:)), keyEquivalent: "")
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        login.target = self
        menu.addItem(login)
        let s3Settings = NSMenuItem(title: s3ConfigurationTask == nil ? "AWS S3 Storage…" : "AWS S3 setup in progress…", action: #selector(openS3Settings), keyEquivalent: "")
        s3Settings.target = self
        s3Settings.isEnabled = s3ConfigurationTask == nil
        menu.addItem(s3Settings)
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

    private func captureContext(suggestedSourceURL: String? = nil, retainPreviousSourceURL: Bool = true) -> CaptureContext? {
        promptForCaptureSession(actionTitle: "Continue to Capture", suggestedSourceURL: suggestedSourceURL, retainPreviousSourceURL: retainPreviousSourceURL)
    }

    @objc private func startCaptureSession() { _ = promptForCaptureSession(actionTitle: "Save Defaults") }

    private func promptForCaptureSession(actionTitle: String, suggestedSourceURL: String? = nil, retainPreviousSourceURL: Bool = true) -> CaptureContext? {
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
        let detectedSourceURL = EvidenceSourceURL.sanitized(suggestedSourceURL)?.absoluteString
        var sourceURLValue = detectedSourceURL ?? (retainPreviousSourceURL ? previous?.sourceURL : nil) ?? ""
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
            let sourceURL = NSTextField(string: sourceURLValue)
            control.placeholderString = "Select or type a control ID"
            fileName.placeholderString = "e.g. Production-MFA-Settings"
            title.placeholderString = "e.g. Production MFA settings"
            system.placeholderString = "e.g. Okta production tenant"
            description.placeholderString = "Optional assessor note"
            owner.placeholderString = "Control owner or evidence custodian"
            tags.placeholderString = "identity, quarterly, production"
            expected.placeholderString = "What should an assessor verify in this artifact?"
            jiraIssue.placeholderString = preferences.jiraHandoff.projectKey.isEmpty ? "Optional, e.g. GRC-123" : "Optional, e.g. \(preferences.jiraHandoff.projectKey)-123"
            sourceURL.placeholderString = "Optional full page URL, e.g. https://admin.example.com/security/settings"
            sourceURL.toolTip = "Scopeproof prints this URL in full in the screenshot header. URL credentials and sensitive query values are removed before saving."
            let preview = NSTextField(wrappingLabelWithString: "")
            preview.textColor = .secondaryLabelColor
            preview.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            preview.maximumNumberOfLines = 2
            let mappings = NSTextField(wrappingLabelWithString: "")
            mappings.textColor = .secondaryLabelColor
            mappings.font = .systemFont(ofSize: 10)
            mappings.maximumNumberOfLines = 2
            for field in [fileName, sessionName, title, system, period, description, owner, tags, expected, jiraIssue, sourceURL] { field.frame.size.width = 400 }
            control.frame.size.width = 400
            framework.frame.size.width = 400
            preview.frame.size.width = 400
            mappings.frame.size.width = 400
            let grid = NSGridView(views: [
                [label("Compliance area *"), framework], [label("Control *"), control], [label("File name *"), fileName], [label("Saved as"), preview],
                [label("Evidence title *"), title], [label("System or asset *"), system], [label("Environment *"), environment],
                [label(detectedSourceURL == nil ? "Page URL" : "Page URL (detected)"), sourceURL],
                [label("Assessment period *"), period], [label("Session name *"), sessionName], [label("Evidence owner"), owner],
                [label("Jira issue"), jiraIssue], [label("Tags"), tags], [label("Expected evidence"), expected], [label("What this proves"), description], [label("Related controls"), mappings],
            ])
            grid.column(at: 0).xPlacement = .trailing
            grid.column(at: 1).xPlacement = .fill
            grid.rowSpacing = 10
            grid.columnSpacing = 12
            grid.frame = NSRect(x: 0, y: 0, width: 560, height: 575)
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
            sourceURLValue = sourceURL.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let missing = [("compliance area", frameworkValue), ("control", controlValue), ("file name", filenameValue), ("session name", sessionValue), ("evidence title", titleValue), ("system or asset", systemValue), ("environment", environmentValue), ("assessment period", periodValue)].filter { $0.1.isEmpty }.map(\.0)
            guard missing.isEmpty else { missingFields = missing; continue }
            guard JiraHandoff.isValidIssueKey(jiraIssueValue) else { missingFields = ["a Jira issue key such as GRC-123 (or leave it blank)"]; continue }
            guard EvidenceSourceURL.isValidOrEmpty(sourceURLValue) else { missingFields = ["a complete HTTP or HTTPS page URL (or leave it blank)"]; continue }
            let sanitizedSourceURL = EvidenceSourceURL.sanitized(sourceURLValue)?.absoluteString ?? ""
            let context = CaptureContext(
                sessionID: previous?.sessionID ?? "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
                sessionName: sessionValue, controlID: controlValue, title: titleValue, system: systemValue,
                environment: environmentValue, assessmentPeriod: periodValue,
                description: descriptionValue, complianceArea: frameworkValue,
                controlTitle: coordinator.controlTitle, customFileName: filenameValue,
                evidenceOwner: ownerValue, tags: tagsValue.split(separator: ",").map(String.init), expectedEvidence: expectedValue,
                jiraIssueKey: jiraIssueValue, sourceURL: sanitizedSourceURL
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
        guard captureService.requestScreenRecordingPermissionIfNeeded() else { showError(CaptureFailure.permissionRequired); return }
        guard let window = captureService.browserWindows().first else { showError(CaptureFailure.noBrowserWindow); return }
        let detectedURL = BrowserPageURL.currentURL(for: window.owner)?.absoluteString
        guard let context = captureContext(suggestedSourceURL: detectedURL, retainPreviousSourceURL: false) else { return }
        setBusy("Capturing and scanning browser…")
        captureService.captureWindow(window, context: context, completion: finishCapture)
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

    @objc private func captureScrollingEvidence() {
        guard let context = captureContext() else { return }
        guard captureService.requestScreenRecordingPermissionIfNeeded() else { showError(CaptureFailure.permissionRequired); return }
        let windows = captureService.browserWindows()
        guard !windows.isEmpty else { showError(CaptureFailure.noBrowserWindow); return }
        let alert = NSAlert()
        alert.messageText = "Choose a browser window for scrolling evidence"
        alert.informativeText = "Scopeproof will capture the current viewport, then guide you through at least one more section. Keep the selected window size and browser zoom unchanged."
        alert.addButton(withTitle: "Start Capture")
        alert.addButton(withTitle: "Cancel")
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 520, height: 28))
        picker.addItems(withTitles: windows.map(\.displayTitle))
        picker.setAccessibilityLabel("Browser window")
        alert.accessoryView = picker
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        setBusy("Capturing scrolling evidence…")
        captureService.captureScrollingWindow(windows[max(0, picker.indexOfSelectedItem)], context: context, completion: finishCapture)
    }

    @objc private func captureDisplay() {
        guard let context = captureContext() else { return }
        setBusy("Capturing and scanning display…")
        captureService.captureEntireDisplay(context: context, completion: finishCapture)
    }

    @objc private func promptForURL() {
        guard let rawTarget = prompt(title: "Open URL & Capture", message: "The selected browser will open this page, wait \(preferences.delay) seconds, then capture and scan its window.", placeholder: "https://admin.example.com/security") else { return }
        guard let target = EvidenceSourceURL.sanitized(rawTarget)?.absoluteString else { showError(CaptureFailure.invalidURL); return }
        guard let context = captureContext(suggestedSourceURL: target) else { return }
        preferences.addTarget(target)
        openAndCapture(target, context: context)
    }

    @objc private func addSavedTarget() {
        guard let target = prompt(title: "Add Evidence URL", message: "Save a frequently captured PCI evidence page.", placeholder: "https://admin.example.com/security") else { return }
        guard let url = EvidenceSourceURL.sanitized(target) else { showError(CaptureFailure.invalidURL); return }
        preferences.addTarget(url.absoluteString)
        setReady("Evidence URL saved")
    }

    @objc private func captureSavedTarget(_ sender: NSMenuItem) {
        guard let target = sender.representedObject as? String, let context = captureContext(suggestedSourceURL: target) else { return }
        openAndCapture(target, context: context)
    }

    private func openAndCapture(_ target: String, context: CaptureContext) {
        setBusy("Opening \(URL(string: target)?.host ?? "browser")…")
        var captureContext = context
        captureContext.sourceURL = EvidenceSourceURL.sanitized(target)?.absoluteString
        preferences.activeContext = captureContext
        captureService.openAndCapture(urlString: target, browser: preferences.browser, delay: preferences.delay, context: captureContext, completion: finishCapture)
    }

    private func finishCapture(_ result: Result<CaptureResult, CaptureFailure>) {
        switch result {
        case .success(let capture):
            setReady("Saved \(capture.evidenceID)")
            try? localConsole.syncIndex(action: "capture.saved")
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(capture.imageURL.path, forType: .string)
            notify(title: "Compliance evidence captured", body: "\(capture.context.resolvedComplianceArea) \(capture.context.controlID) was saved. The file path is on your clipboard.")
            if preferences.autoUpload { upload(capture) }
            if preferences.s3Storage.autoUpload && preferences.s3Storage.canUpload { uploadToS3(capture) }
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
                    context: CaptureContext(sessionID: entry.manifest.sessionID, sessionName: entry.manifest.sessionName, controlID: entry.manifest.controlID, title: entry.manifest.title, system: entry.manifest.system, environment: entry.manifest.environment, assessmentPeriod: entry.manifest.assessmentPeriod, description: entry.manifest.description, complianceArea: entry.manifest.complianceArea, controlTitle: entry.manifest.controlTitle, customFileName: entry.manifest.customFileName, evidenceOwner: entry.manifest.evidenceOwner, tags: entry.manifest.tags, expectedEvidence: entry.manifest.expectedEvidence, jiraIssueKey: entry.manifest.jiraIssueKey, sourceURL: entry.manifest.sourceURL),
                    capturedAt: entry.manifest.capturedAt, safetyStatus: entry.manifest.safetyStatus, findings: entry.manifest.redactionFindings, sha256: entry.manifest.sha256, chainPreviousHash: entry.manifest.chainPreviousHash, chainEventHash: entry.manifest.chainEventHash)
                if (try? await uploadService.upload(capture, serverURL: preferences.serverURL)) != nil { completed += 1 }
            }
            await MainActor.run { self.setReady("Uploaded \(completed) of \(pending.count)"); self.notify(title: "Upload retry complete", body: "\(completed) evidence capture(s) reached Scopeproof.") }
        }
    }

    private func uploadToS3(_ capture: CaptureResult) {
        let settings = preferences.s3Storage
        guard settings.canUpload, let credentials = KeychainStore.readS3Credentials(),
              let binding = KeychainStore.readS3VerifiedDestination(), binding.matches(settings) else {
            setReady("Saved locally · S3 not configured")
            return
        }
        setBusy("Copying \(capture.evidenceID) to S3…")
        Task {
            do {
                _ = try await s3StorageService.upload(capture, settings: settings, credentials: credentials, binding: binding)
                await MainActor.run {
                    self.setReady("Stored \(capture.evidenceID) in S3")
                    self.notify(title: "Evidence stored in S3", body: "\(capture.context.controlID) / \(capture.evidenceID) was copied with an encrypted upload receipt.")
                    self.rebuildMenu()
                }
            } catch {
                await MainActor.run {
                    self.setReady("Saved locally · S3 upload pending")
                    self.notify(title: "Evidence saved locally", body: "S3 upload is pending: \(error.localizedDescription)")
                    self.rebuildMenu()
                }
            }
        }
    }

    @objc private func retryPendingS3Uploads() {
        guard s3RetryTask == nil else { return }
        let settings = preferences.s3Storage
        guard settings.canUpload, let credentials = KeychainStore.readS3Credentials(),
              let binding = KeychainStore.readS3VerifiedDestination(), binding.matches(settings) else {
            showError(settings.isConfigured ? S3StorageFailure.destinationBindingMismatch : S3StorageFailure.notConfigured); return
        }
        let pending = Array(CaptureHistory.entries(in: captureService.outputDirectory).filter { !$0.isStoredInS3 }.prefix(100))
        guard !pending.isEmpty else { setReady("No pending S3 uploads"); return }
        setBusy("Uploading \(pending.count) capture(s) to S3…")
        s3RetryTask = Task {
            var completed = 0
            for entry in pending {
                guard !Task.isCancelled else { break }
                let capture = CaptureResult(imageURL: entry.imageURL, manifestURL: entry.manifestURL, evidenceID: entry.manifest.evidenceID,
                    context: CaptureContext(sessionID: entry.manifest.sessionID, sessionName: entry.manifest.sessionName, controlID: entry.manifest.controlID, title: entry.manifest.title, system: entry.manifest.system, environment: entry.manifest.environment, assessmentPeriod: entry.manifest.assessmentPeriod, description: entry.manifest.description, complianceArea: entry.manifest.complianceArea, controlTitle: entry.manifest.controlTitle, customFileName: entry.manifest.customFileName, evidenceOwner: entry.manifest.evidenceOwner, tags: entry.manifest.tags, expectedEvidence: entry.manifest.expectedEvidence, jiraIssueKey: entry.manifest.jiraIssueKey, sourceURL: entry.manifest.sourceURL),
                    capturedAt: entry.manifest.capturedAt, safetyStatus: entry.manifest.safetyStatus, findings: entry.manifest.redactionFindings, sha256: entry.manifest.sha256, chainPreviousHash: entry.manifest.chainPreviousHash, chainEventHash: entry.manifest.chainEventHash)
                if (try? await s3StorageService.upload(capture, settings: settings, credentials: credentials, binding: binding)) != nil { completed += 1 }
            }
            await MainActor.run {
                self.s3RetryTask = nil
                self.setReady("Stored \(completed) of \(pending.count) in S3")
                self.notify(title: "S3 upload complete", body: "\(completed) of \(pending.count) evidence capture(s) were stored in \(settings.bucket).")
                self.rebuildMenu()
            }
        }
    }

    @objc private func openHistoryEntry(_ sender: NSMenuItem) { if let path = sender.representedObject as? String { NSWorkspace.shared.open(URL(fileURLWithPath: path)) } }
    @objc private func searchEvidence() { evidenceSearchController.show(evidenceRoot: captureService.outputDirectory, jiraSettings: preferences.jiraHandoff, serverURL: preferences.serverURL) }
    @objc private func openS3Browser() { s3ObjectBrowserController.show(settings: preferences.s3Storage) }
    @objc private func openLocalConsole() {
        setBusy("Opening local console…")
        Task {
            do { try await localConsole.open(); setReady("Local console ready") }
            catch { setReady("Local console unavailable"); showError(error) }
        }
    }

    @objc private func generateRepositorySBOM() {
        guard repositorySBOMTask == nil else { return }
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.icon = NSImage(systemSymbolName: "doc.text.magnifyingglass", accessibilityDescription: "Repository SBOM")
        alert.messageText = "Generate a one-time repository SBOM"
        alert.informativeText = "Scopeproof reads supported lockfiles at one immutable GitHub commit. Repository code is never cloned, built, installed, or executed."
        alert.addButton(withTitle: "Generate")
        alert.addButton(withTitle: "Cancel")

        let repositoryURL = NSTextField(string: "")
        repositoryURL.placeholderString = "https://github.com/owner/repository"
        repositoryURL.toolTip = "Exact GitHub HTTPS repository URL. Embedded credentials, query strings, fragments, ports, and other hosts are rejected."
        repositoryURL.setAccessibilityLabel("GitHub repository URL")
        let token = NSSecureTextField(string: "")
        token.placeholderString = "Short-lived, repository-scoped token"
        token.toolTip = "Use Metadata: read and Contents: read only. The token is cleared after submission and is not saved."
        token.setAccessibilityLabel("One-time GitHub token")
        let ref = NSTextField(string: "main")
        ref.placeholderString = "Branch, tag, or commit"
        ref.setAccessibilityLabel("Git branch, tag, or commit")
        let format = NSPopUpButton()
        format.addItems(withTitles: RepositorySBOMFormat.allCases.map(\.displayName))
        format.setAccessibilityLabel("SBOM format")
        let safety = NSTextField(wrappingLabelWithString: "One-time credential: used only for this request, never written to settings, Keychain, evidence, logs, or a retry queue. Revoke it after the file is generated.")
        safety.textColor = .secondaryLabelColor
        safety.maximumNumberOfLines = 3
        for field in [repositoryURL, token, ref] {
            field.frame = NSRect(x: 0, y: 0, width: 430, height: 26)
        }
        format.frame = NSRect(x: 0, y: 0, width: 430, height: 28)
        safety.frame = NSRect(x: 0, y: 0, width: 430, height: 54)
        let grid = NSGridView(views: [
            [label("GitHub repository *"), repositoryURL],
            [label("One-time token *"), token],
            [label("Branch, tag, or commit *"), ref],
            [label("Format *"), format],
            [NSTextField(labelWithString: ""), safety],
        ])
        grid.rowSpacing = 11
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        // NSAlert does not establish constraints for an NSGridView accessory. Without
        // an explicit frame AppKit can collapse the form to a few pixels above the
        // buttons, leaving every input invisible.
        grid.frame = NSRect(x: 0, y: 0, width: 590, height: 210)
        alert.accessoryView = grid
        alert.window.initialFirstResponder = repositoryURL

        let response = alert.runModal()
        let tokenValue = token.stringValue
        token.stringValue = ""
        guard response == .alertFirstButtonReturn else { return }
        var request = RepositorySBOMRequest(
            repositoryURL: repositoryURL.stringValue,
            token: tokenValue,
            ref: ref.stringValue,
            format: RepositorySBOMFormat.allCases[max(0, format.indexOfSelectedItem)]
        )
        do {
            _ = try RepositorySBOMService.parseRepositoryURL(request.repositoryURL)
            try RepositorySBOMService.validateToken(request.token)
            _ = try RepositorySBOMService.validateRef(request.ref)
        } catch {
            showError(error)
            return
        }

        setBusy("Generating repository SBOM…")
        repositorySBOMTask = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await repositorySBOMService.generate(request)
                request.token.removeAll(keepingCapacity: false)
                guard !Task.isCancelled else { return }
                repositorySBOMTask = nil
                setReady("SBOM ready · \(result.componentCount) components")
                saveRepositorySBOM(result)
            } catch is CancellationError {
                request.token.removeAll(keepingCapacity: false)
                repositorySBOMTask = nil
                setReady("SBOM generation cancelled")
            } catch {
                request.token.removeAll(keepingCapacity: false)
                repositorySBOMTask = nil
                setReady("SBOM generation failed")
                showError(error)
            }
            rebuildMenu()
        }
        rebuildMenu()
    }

    private func saveRepositorySBOM(_ result: RepositorySBOMResult) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let panel = NSSavePanel()
        panel.title = "Save Repository SBOM"
        panel.message = "Save the auditor-facing JSON and its SHA-256 checksum."
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = result.suggestedFilename
        guard panel.runModal() == .OK, let destination = panel.url else {
            setReady("SBOM generated but not saved")
            return
        }
        let checksumURL = destination.appendingPathExtension("sha256.txt")
        do {
            try result.data.write(to: destination, options: .atomic)
            let checksum = "\(result.artifactSHA256)  \(destination.lastPathComponent)\n"
            try Data(checksum.utf8).write(to: checksumURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: checksumURL.path)
            let completion = NSAlert()
            completion.messageText = "Repository SBOM saved"
            completion.informativeText = "\(result.repository) at \(result.resolvedCommit.prefix(12))\n\(result.componentCount) components from \(result.manifestPaths.count) lockfile(s)\nSHA-256: \(result.artifactSHA256)"
            completion.addButton(withTitle: "Reveal in Finder")
            completion.addButton(withTitle: "Done")
            if completion.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.activateFileViewerSelecting([destination, checksumURL]) }
            setReady("Saved SBOM · \(result.componentCount) components")
            notify(title: "Repository SBOM ready", body: "\(result.repository) at \(result.resolvedCommit.prefix(12)) was saved with a checksum.")
        } catch {
            try? FileManager.default.trashItem(at: destination, resultingItemURL: nil)
            try? FileManager.default.trashItem(at: checksumURL, resultingItemURL: nil)
            showError(error)
        }
    }

    @objc private func applyPreset(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let preset = preferences.presets.first(where: { $0.id == id }) else { return }
        let source = preset.context
        let context = CaptureContext(
            sessionID: "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
            sessionName: source.sessionName, controlID: source.controlID, title: source.title, system: source.system,
            environment: source.environment, assessmentPeriod: source.assessmentPeriod, description: source.description,
            complianceArea: source.complianceArea, controlTitle: source.controlTitle, customFileName: source.customFileName,
            evidenceOwner: source.evidenceOwner, tags: source.tags, expectedEvidence: source.expectedEvidence,
            jiraIssueKey: source.jiraIssueKey, sourceURL: source.sourceURL
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
        alert.informativeText = "Local mode works without a server or device token. Hosted sync and Jira Cloud are optional; when enabled, device tokens remain protected in your login Keychain and Atlassian credentials stay on the hosted service."
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let server = NSTextField(string: preferences.serverURL?.absoluteString ?? "")
        let token = NSSecureTextField(string: "")
        let currentAudience = BackendTrust.normalizedOrigin(preferences.serverURL)
        token.placeholderString = currentAudience.flatMap(KeychainStore.readToken(for:)) == nil ? "Paste one-time spdev_ token" : "Token saved — leave blank to keep it"
        let auto = NSButton(checkboxWithTitle: "Upload reviewed captures automatically", target: nil, action: nil)
        auto.state = preferences.autoUpload ? .on : .off
        let openLocal = NSButton(checkboxWithTitle: "Open Local Console when Scopeproof launches", target: nil, action: nil)
        openLocal.state = preferences.openLocalConsoleAtLaunch ? .on : .off
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
            [NSTextField(labelWithString: ""), openLocal], [label("Server URL"), server], [label("Device token"), token], [label("Local retention"), retention], [NSTextField(labelWithString: ""), auto],
            [NSTextField(labelWithString: ""), section], [label("Jira site URL"), jiraSite], [label("Default project"), jiraProject],
            [label("Attachment set"), attachmentMode], [NSTextField(labelWithString: ""), includeGuide], [label("Organization instructions"), instructions],
        ])
        grid.rowSpacing = 10; grid.columnSpacing = 12; grid.column(at: 0).xPlacement = .trailing; grid.column(at: 1).xPlacement = .fill
        alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let serverValue = server.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let url = serverValue.isEmpty ? nil : URL(string: serverValue).flatMap(BackendTrust.normalizedOrigin)
        if !serverValue.isEmpty && url == nil { showError(UploadFailure.invalidServer); return }
        let jiraSiteValue = jiraSite.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let jiraProjectValue = jiraProject.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if !jiraSiteValue.isEmpty {
            let candidate = JiraHandoffSettings(baseURL: jiraSiteValue, projectKey: jiraProjectValue, attachmentMode: .evidenceSet, includeGuideInPackages: true, customInstructions: "")
            guard candidate.validatedBaseURL != nil else { showError(NSError(domain: "Scopeproof", code: 21, userInfo: [NSLocalizedDescriptionKey: "The Jira site must be a complete HTTPS URL without a query, fragment, or embedded credentials."])); return }
        }
        guard JiraHandoff.isValidProjectKey(jiraProjectValue) else { showError(NSError(domain: "Scopeproof", code: 22, userInfo: [NSLocalizedDescriptionKey: "The Jira project key must start with a letter and contain only uppercase letters, numbers, or underscores."])); return }
        let newToken = token.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard newToken.isEmpty || newToken.hasPrefix("spdev_dev_") else { showError(NSError(domain: "Scopeproof", code: 2, userInfo: [NSLocalizedDescriptionKey: "The device token must begin with spdev_dev_."])); return }
        if let url, newToken.isEmpty, KeychainStore.tokenAudience() != nil, KeychainStore.tokenAudience() != url.absoluteString { showError(NSError(domain: "Scopeproof", code: 23, userInfo: [NSLocalizedDescriptionKey: "Changing the hosted Scopeproof server requires a new device token issued for that exact server. Clear the Server URL to use local-only mode."])); return }
        let selectedMode = JiraAttachmentMode(rawValue: attachmentMode.titleOfSelectedItem ?? "") ?? .evidenceSet
        if !newToken.isEmpty, let url {
            do { try KeychainStore.saveToken(newToken, audience: url) } catch { showError(error); return }
        }
        preferences.serverURL = url
        preferences.autoUpload = url != nil && auto.state == .on
        preferences.openLocalConsoleAtLaunch = openLocal.state == .on
        preferences.retentionDays = Int(retention.titleOfSelectedItem?.split(separator: " ").first ?? "365") ?? 365
        preferences.jiraHandoff = JiraHandoffSettings(baseURL: jiraSiteValue, projectKey: jiraProjectValue, attachmentMode: selectedMode, includeGuideInPackages: includeGuide.state == .on, customInstructions: String(instructions.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2_000)))
        setReady(url == nil ? "Local-only settings saved" : "Capture and Jira settings saved")
    }

    @objc private func openS3Settings() {
        guard s3ConfigurationTask == nil else { return }
        NSApplication.shared.activate(ignoringOtherApps: true)
        let current = preferences.s3Storage
        let existingCredentials = KeychainStore.readS3Credentials()
        let alert = NSAlert()
        alert.icon = NSImage(systemSymbolName: "externaldrive.badge.icloud", accessibilityDescription: "AWS S3 evidence storage")
        alert.messageText = "AWS S3 evidence storage"
        alert.informativeText = "Verify an existing bucket or create a hardened evidence bucket. Production compliance mode requires temporary STS credentials, KMS, Object Lock, versioning, private ownership, and a prefix-scoped destination."
        alert.addButton(withTitle: "Save & Verify")
        alert.addButton(withTitle: "Create & Harden Bucket")
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Disconnect")

        let bucket = NSTextField(string: current.bucket)
        bucket.placeholderString = "company-compliance-evidence"
        bucket.setAccessibilityLabel("S3 bucket name")
        let region = NSTextField(string: current.region)
        region.placeholderString = "us-east-1"
        region.setAccessibilityLabel("AWS region")
        let prefix = NSTextField(string: current.prefix)
        prefix.placeholderString = "scopeproof-evidence"
        prefix.setAccessibilityLabel("S3 object prefix")
        let profile = NSPopUpButton()
        profile.addItems(withTitles: S3SecurityProfile.allCases.map(\.rawValue))
        profile.selectItem(withTitle: current.securityProfile.rawValue)
        profile.setAccessibilityLabel("S3 security profile")
        let encryption = NSPopUpButton()
        encryption.addItems(withTitles: S3EncryptionMode.allCases.map(\.displayName))
        encryption.selectItem(withTitle: current.encryptionMode.displayName)
        encryption.setAccessibilityLabel("S3 encryption mode")
        let kmsKey = NSTextField(string: current.kmsKeyARN)
        kmsKey.placeholderString = "arn:aws:kms:us-east-1:123456789012:key/…"
        kmsKey.setAccessibilityLabel("AWS KMS key ARN")
        let retentionMode = NSPopUpButton()
        retentionMode.addItems(withTitles: S3RetentionMode.allCases.map(\.displayName))
        retentionMode.selectItem(withTitle: current.retentionMode.displayName)
        retentionMode.setAccessibilityLabel("S3 Object Lock retention mode")
        let retentionDays = NSTextField(string: String(current.retentionDays))
        retentionDays.setAccessibilityLabel("S3 Object Lock retention days")
        let archiveDays = NSTextField(string: String(current.archiveAfterDays))
        archiveDays.placeholderString = "0 disables Deep Archive transition"
        archiveDays.setAccessibilityLabel("S3 Deep Archive transition days")
        let allowDownloads = NSButton(checkboxWithTitle: "Allow prefix-scoped browsing and validated downloads", target: nil, action: nil)
        allowDownloads.state = current.downloadsAllowed ? .on : .off
        let useFIPS = NSButton(checkboxWithTitle: "Use AWS FIPS endpoints", target: nil, action: nil)
        useFIPS.state = current.useFIPSEndpoint ? .on : .off
        let replicaBucket = NSTextField(string: current.replicationDestinationBucketARN)
        replicaBucket.placeholderString = "Optional destination bucket ARN"
        replicaBucket.setAccessibilityLabel("S3 replication destination bucket ARN")
        let replicaRole = NSTextField(string: current.replicationRoleARN)
        replicaRole.placeholderString = "Optional replication IAM role ARN"
        replicaRole.setAccessibilityLabel("S3 replication IAM role ARN")
        let replicaKMS = NSTextField(string: current.replicationKMSKeyARN)
        replicaKMS.placeholderString = "Destination KMS key ARN when KMS is selected"
        replicaKMS.setAccessibilityLabel("S3 replication KMS key ARN")
        let accessKey = NSSecureTextField(string: "")
        accessKey.placeholderString = existingCredentials == nil ? "AWS access key ID" : "Access key saved — leave blank to keep it"
        accessKey.setAccessibilityLabel("AWS access key ID")
        let secretKey = NSSecureTextField(string: "")
        secretKey.placeholderString = existingCredentials == nil ? "AWS secret access key" : "Secret key saved — leave blank to keep it"
        secretKey.setAccessibilityLabel("AWS secret access key")
        let sessionToken = NSSecureTextField(string: "")
        sessionToken.placeholderString = existingCredentials == nil ? "STS session token (required in production mode)" : "Session token saved — leave blank to keep it"
        sessionToken.setAccessibilityLabel("AWS session token")
        let credentialExpiration = NSTextField(string: existingCredentials?.expiresAt.map { ISO8601DateFormatter().string(from: $0) } ?? "")
        credentialExpiration.placeholderString = "STS expiration, e.g. 2026-08-20T22:00:00Z"
        credentialExpiration.setAccessibilityLabel("AWS temporary credential expiration")
        let automatic = NSButton(checkboxWithTitle: "Copy new captures to S3 after the local safety scan", target: nil, action: nil)
        automatic.state = current.autoUpload ? .on : .off
        let security = NSTextField(wrappingLabelWithString: "Production mode is fail-closed. Object Lock is irreversible once enabled. Bucket creation may also configure Deep Archive and replication when supplied. Remove all bucket-management permissions after setup; daily credentials remain in Keychain and are bound to the verified AWS account and destination.")
        security.textColor = .secondaryLabelColor
        security.maximumNumberOfLines = 3
        for field in [bucket, region, prefix, kmsKey, retentionDays, archiveDays, replicaBucket, replicaRole, replicaKMS, accessKey, secretKey, sessionToken, credentialExpiration] { field.frame = NSRect(x: 0, y: 0, width: 440, height: 26) }
        security.frame = NSRect(x: 0, y: 0, width: 440, height: 72)
        let grid = NSGridView(views: [
            [label("Security profile"), profile], [label("Bucket *"), bucket], [label("Region *"), region], [label("Object prefix *"), prefix],
            [label("Encryption"), encryption], [label("KMS key ARN"), kmsKey],
            [label("Object Lock"), retentionMode], [label("Retention days"), retentionDays], [label("Archive after days"), archiveDays],
            [NSTextField(labelWithString: ""), allowDownloads], [NSTextField(labelWithString: ""), useFIPS],
            [label("Replica bucket"), replicaBucket], [label("Replication role"), replicaRole], [label("Replica KMS key"), replicaKMS],
            [label("Access key ID *"), accessKey], [label("Secret access key *"), secretKey], [label("Session token"), sessionToken],
            [label("STS expires at"), credentialExpiration], [NSTextField(labelWithString: ""), automatic],
            [NSTextField(labelWithString: ""), security],
        ])
        grid.rowSpacing = 7
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.frame = NSRect(x: 0, y: 0, width: 640, height: 650)
        let formScroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 660, height: 470))
        formScroll.documentView = grid
        formScroll.hasVerticalScroller = true
        formScroll.autohidesScrollers = false
        formScroll.drawsBackground = false
        formScroll.borderType = .noBorder
        formScroll.setAccessibilityLabel("Scrollable AWS S3 storage settings")
        alert.accessoryView = formScroll
        alert.window.initialFirstResponder = bucket

        let response = alert.runModal()
        let accessValue = accessKey.stringValue
        let secretValue = secretKey.stringValue
        let sessionValue = sessionToken.stringValue
        let expirationValue = credentialExpiration.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        accessKey.stringValue = ""
        secretKey.stringValue = ""
        sessionToken.stringValue = ""
        credentialExpiration.stringValue = ""
        let disconnectResponse = NSApplication.ModalResponse(rawValue: NSApplication.ModalResponse.alertFirstButtonReturn.rawValue + 3)
        if response == disconnectResponse {
            let confirmation = NSAlert()
            confirmation.alertStyle = .warning
            confirmation.messageText = "Disconnect AWS S3 storage?"
            confirmation.informativeText = "This removes the bucket configuration and AWS credentials from this Mac. Existing S3 objects and local evidence are not deleted."
            confirmation.addButton(withTitle: "Keep Configuration")
            confirmation.addButton(withTitle: "Disconnect")
            guard confirmation.runModal() == .alertSecondButtonReturn else { return }
            KeychainStore.deleteS3Credentials()
            preferences.s3Storage = .defaults
            setReady("S3 storage disconnected")
            rebuildMenu()
            return
        }
        let isCreatingBucket = response == .alertSecondButtonReturn
        guard response == .alertFirstButtonReturn || isCreatingBucket else { return }

        let settings: S3StorageSettings
        do {
            let selectedProfile = S3SecurityProfile(rawValue: profile.titleOfSelectedItem ?? "") ?? .production
            let selectedEncryption = S3EncryptionMode.allCases.first(where: { $0.displayName == encryption.titleOfSelectedItem }) ?? .sseKMS
            let selectedRetention = S3RetentionMode.allCases.first(where: { $0.displayName == retentionMode.titleOfSelectedItem }) ?? .governance
            settings = try S3StorageSettings.validated(
                bucket: bucket.stringValue, region: region.stringValue, prefix: prefix.stringValue,
                autoUpload: automatic.state == .on, securityProfile: selectedProfile,
                encryptionMode: selectedEncryption, kmsKeyARN: kmsKey.stringValue,
                retentionMode: selectedRetention, retentionDays: Int(retentionDays.stringValue) ?? 0,
                archiveAfterDays: Int(archiveDays.stringValue) ?? -1,
                downloadsAllowed: allowDownloads.state == .on, useFIPSEndpoint: useFIPS.state == .on,
                replicationDestinationBucketARN: replicaBucket.stringValue,
                replicationRoleARN: replicaRole.stringValue, replicationKMSKeyARN: replicaKMS.stringValue
            )
        } catch { showError(error); return }
        let suppliedAccess = accessValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let suppliedSecret = secretValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let credentials: S3Credentials
        if suppliedAccess.isEmpty && suppliedSecret.isEmpty {
            guard let existingCredentials else { showError(S3StorageFailure.invalidCredentials); return }
            credentials = existingCredentials
        } else {
            let expiresAt: Date?
            if expirationValue.isEmpty { expiresAt = nil }
            else {
                guard let parsed = ISO8601DateFormatter().date(from: expirationValue) else { showError(S3StorageFailure.invalidCredentials); return }
                expiresAt = parsed
            }
            do { credentials = try S3Credentials.validated(accessKeyID: suppliedAccess, secretAccessKey: suppliedSecret, sessionToken: sessionValue, expiresAt: expiresAt) }
            catch { showError(error); return }
        }
        if settings.securityProfile == .production && !credentials.isTemporary { showError(S3StorageFailure.temporaryCredentialsRequired); return }
        if settings.securityProfile == .production && credentials.expiresAt == nil { showError(S3StorageFailure.invalidCredentials); return }
        if isCreatingBucket && settings.securityProfile == .production {
            let irreversible = NSAlert()
            irreversible.alertStyle = .critical
            irreversible.messageText = "Enable irreversible S3 Object Lock?"
            irreversible.informativeText = "Scopeproof will enable \(settings.retentionMode.displayName) Object Lock for at least \(settings.retentionDays) days. Object Lock cannot later be disabled on this bucket. Confirm the retention policy with your compliance and records owners before continuing."
            irreversible.addButton(withTitle: "Enable Object Lock")
            irreversible.addButton(withTitle: "Cancel")
            guard irreversible.runModal() == .alertFirstButtonReturn else { return }
        }
        do { try KeychainStore.saveS3Credentials(credentials) }
        catch { showError(error); return }
        var storedSettings = settings
        storedSettings.autoUpload = false
        storedSettings.uploadsAllowed = false
        preferences.s3Storage = storedSettings
        setBusy(isCreatingBucket ? "Creating and securing S3 bucket…" : "Testing S3 connection…")
        s3ConfigurationTask = Task {
            do {
                let binding: S3VerifiedDestination
                if isCreatingBucket {
                    binding = try await s3StorageService.createAndSecureBucket(settings: settings, credentials: credentials)
                } else {
                    binding = try await s3StorageService.testConnection(settings: settings, credentials: credentials)
                }
                await MainActor.run {
                    do {
                        try KeychainStore.saveS3VerifiedDestination(binding)
                        var verifiedSettings = settings
                        verifiedSettings.uploadsAllowed = true
                        self.preferences.s3Storage = verifiedSettings
                        self.s3ConfigurationTask = nil
                        self.setReady(isCreatingBucket ? "Secure S3 bucket ready · \(settings.bucket)" : "S3 verified · \(settings.bucket)")
                        self.notify(
                            title: isCreatingBucket ? "Secure S3 bucket ready" : "AWS S3 destination verified",
                            body: "AWS account \(binding.accountID) · \(settings.securityProfile.rawValue) · \(settings.encryptionMode.displayName)"
                        )
                        self.rebuildMenu()
                    } catch {
                        self.s3ConfigurationTask = nil
                        self.showError(error)
                        self.rebuildMenu()
                    }
                }
            } catch {
                await MainActor.run {
                    self.s3ConfigurationTask = nil
                    self.setReady(isCreatingBucket ? "S3 bucket setup incomplete · automatic upload off" : "S3 settings saved · connection failed")
                    self.showError(error)
                    self.rebuildMenu()
                }
            }
        }
        rebuildMenu()
    }

    @objc private func checkForUpdatesAction() { checkForUpdates(silent: false) }
    private func checkForUpdates(silent: Bool) {
        Task {
            do {
                guard let release = try await updateService.check(serverURL: preferences.serverURL) else {
                    if !silent { await MainActor.run { self.setReady("Scopeproof Capture is up to date") } }
                    return
                }
                await MainActor.run {
                    self.preferences.lastUpdateCheck = Date()
                    let alert = NSAlert(); alert.messageText = "Scopeproof Capture \(release.version) is available"; alert.informativeText = release.notes
                    alert.addButton(withTitle: "Download and Verify"); alert.addButton(withTitle: "Later")
                    guard alert.runModal() == .alertFirstButtonReturn else { return }
                    self.setBusy("Downloading and verifying update…")
                    Task {
                        do {
                            let local = try await self.updateService.downloadAndVerify(release)
                            await MainActor.run { self.setReady("Verified update ready"); NSWorkspace.shared.open(local) }
                        } catch { await MainActor.run { self.showError(error) } }
                    }
                }
            } catch { if !silent { await MainActor.run { self.showError(error) } } }
        }
    }

    @objc private func showHelp() { helpController.show(outputDirectory: captureService.outputDirectory) }
    @objc private func openPermissionSettings() { if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") { NSWorkspace.shared.open(url) } }
    @objc private func quitApp() { NSApplication.shared.terminate(nil) }

    private func uploadStatusTitle() -> String {
        guard let server = BackendTrust.normalizedOrigin(preferences.serverURL), KeychainStore.readToken(for: server) != nil else { return "Web upload: Not connected" }
        return preferences.autoUpload ? "Web upload: Automatic" : "Web upload: Manual retry"
    }

    private func s3StorageStatusTitle() -> String {
        let settings = preferences.s3Storage
        guard settings.isConfigured, KeychainStore.readS3Credentials() != nil else { return "S3 storage: Not connected" }
        guard settings.canUpload, KeychainStore.readS3VerifiedDestination()?.matches(settings) == true else { return "S3 storage: Needs verification · \(settings.bucket)" }
        return settings.autoUpload ? "S3 storage: Automatic · \(settings.bucket)" : "S3 storage: Manual · \(settings.bucket)"
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
        alert.icon = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: "Scopeproof warning")
        alert.messageText = "Scopeproof could not complete the operation"
        alert.informativeText = error.localizedDescription
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
    private func notify(title: String, body: String) { NSSound(named: "Glass")?.play(); let content = UNMutableNotificationContent(); content.title = title; content.body = body; content.sound = .default; UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) }
}
