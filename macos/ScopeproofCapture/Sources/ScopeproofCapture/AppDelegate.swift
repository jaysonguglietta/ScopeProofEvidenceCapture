@preconcurrency import AppKit
import ServiceManagement
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let preferences = CapturePreferences()
    private lazy var captureService = CaptureService(preferences: preferences)
    private let uploadService = UploadService()
    private let helpController = HelpController()
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
            button.toolTip = "Scopeproof PCI Evidence Capture"
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
        let session = NSMenuItem(title: context?.isValid == true ? "Session: \(context!.sessionName) · PCI \(context!.controlID)" : "Session: Not configured", action: nil, keyEquivalent: "")
        session.isEnabled = false
        menu.addItem(session)
        let newSession = NSMenuItem(title: context?.isValid == true ? "Start or Change Capture Session…" : "Start Capture Session…", action: #selector(startCaptureSession), keyEquivalent: "s")
        newSession.keyEquivalentModifierMask = [.command, .shift]
        newSession.target = self
        menu.addItem(newSession)
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

        let historyItem = NSMenuItem(title: "Recent Captures", action: nil, keyEquivalent: "")
        let historyMenu = NSMenu()
        let entries = Array(CaptureHistory.entries(in: captureService.outputDirectory).prefix(10))
        if entries.isEmpty {
            let empty = NSMenuItem(title: "No captures yet", action: nil, keyEquivalent: ""); empty.isEnabled = false; historyMenu.addItem(empty)
        } else {
            for entry in entries {
                let marker = entry.isUploaded ? "✓" : "↥"
                let item = NSMenuItem(title: "\(marker) \(entry.manifest.controlID) · \(entry.manifest.evidenceID) · \(entry.manifest.localTimestamp)", action: #selector(openHistoryEntry(_:)), keyEquivalent: "")
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
        addItem("Capture Settings…", action: #selector(openSettings), key: ",", modifiers: [.command])
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
        if let context = preferences.activeContext, context.isValid { return context }
        return promptForCaptureSession()
    }

    @objc private func startCaptureSession() { _ = promptForCaptureSession() }

    private func promptForCaptureSession() -> CaptureContext? {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let previous = preferences.activeContext
        let alert = NSAlert()
        alert.messageText = "Start a PCI evidence capture session"
        alert.informativeText = "This context is embedded in every screenshot and manifest until you change sessions."
        alert.addButton(withTitle: "Start Session")
        alert.addButton(withTitle: "Cancel")
        let sessionName = NSTextField(string: previous?.sessionName ?? "")
        let control = NSTextField(string: previous?.controlID ?? "")
        let title = NSTextField(string: previous?.title ?? "")
        let system = NSTextField(string: previous?.system ?? "")
        let environment = NSPopUpButton(); environment.addItems(withTitles: ["Production", "Staging", "Development", "Corporate", "Other"]); environment.selectItem(withTitle: previous?.environment ?? "Production")
        let period = NSTextField(string: previous?.assessmentPeriod ?? CaptureContext.new().assessmentPeriod)
        let description = NSTextField(string: previous?.description ?? "")
        for field in [sessionName, control, title, system, period, description] { field.frame.size.width = 380 }
        let grid = NSGridView(views: [
            [label("Session name"), sessionName], [label("PCI control"), control], [label("Evidence title"), title], [label("System or asset"), system],
            [label("Environment"), environment], [label("Assessment period"), period], [label("What this proves"), description],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.rowSpacing = 10
        grid.columnSpacing = 12
        alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let context = CaptureContext(
            sessionID: "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
            sessionName: sessionName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), controlID: control.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            title: title.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), system: system.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            environment: environment.titleOfSelectedItem ?? "Production", assessmentPeriod: period.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            description: description.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        guard context.isValid else { showError(NSError(domain: "Scopeproof", code: 1, userInfo: [NSLocalizedDescriptionKey: "Session name, PCI control, evidence title, system, environment, and assessment period are required."])); return nil }
        preferences.activeContext = context
        setReady("Session \(context.sessionName) ready")
        rebuildMenu()
        return context
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
            notify(title: "PCI evidence captured", body: "\(capture.evidenceID) passed review and was saved. The file path is on your clipboard.")
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
                    context: CaptureContext(sessionID: entry.manifest.sessionID, sessionName: entry.manifest.sessionName, controlID: entry.manifest.controlID, title: entry.manifest.title, system: entry.manifest.system, environment: entry.manifest.environment, assessmentPeriod: entry.manifest.assessmentPeriod, description: entry.manifest.description),
                    capturedAt: entry.manifest.capturedAt, safetyStatus: entry.manifest.safetyStatus, findings: entry.manifest.redactionFindings, sha256: entry.manifest.sha256, chainPreviousHash: entry.manifest.chainPreviousHash, chainEventHash: entry.manifest.chainEventHash)
                if (try? await uploadService.upload(capture, serverURL: preferences.serverURL)) != nil { completed += 1 }
            }
            await MainActor.run { self.setReady("Uploaded \(completed) of \(pending.count)"); self.notify(title: "Upload retry complete", body: "\(completed) evidence capture(s) reached Scopeproof.") }
        }
    }

    @objc private func openHistoryEntry(_ sender: NSMenuItem) { if let path = sender.representedObject as? String { NSWorkspace.shared.open(URL(fileURLWithPath: path)) } }
    @objc private func selectBrowser(_ sender: NSMenuItem) { let bundleID = (sender.representedObject as? String).flatMap { $0.isEmpty ? nil : $0 }; if let browser = BrowserChoice.supported.first(where: { $0.bundleIdentifier == bundleID }) { preferences.browser = browser }; rebuildMenu() }
    @objc private func selectDelay(_ sender: NSMenuItem) { preferences.delay = sender.tag; rebuildMenu() }

    @objc private func openEvidenceFolder() {
        try? FileManager.default.createDirectory(at: captureService.outputDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        NSWorkspace.shared.open(captureService.outputDirectory)
    }

    @objc private func applyRetention() {
        let alert = NSAlert()
        alert.messageText = "Apply local retention policy?"
        alert.informativeText = "PNG, manifest, and receipt files older than \(preferences.retentionDays) days will be moved to Trash. Hosted evidence is not affected."
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
        alert.messageText = "Scopeproof Capture Settings"
        alert.informativeText = "Device tokens are stored in your login Keychain. Create or revoke tokens in the Scopeproof Connections view."
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let server = NSTextField(string: preferences.serverURL?.absoluteString ?? "")
        let token = NSSecureTextField(string: "")
        token.placeholderString = KeychainStore.readToken() == nil ? "Paste one-time spdev_ token" : "Token saved — leave blank to keep it"
        let auto = NSButton(checkboxWithTitle: "Upload reviewed captures automatically", target: nil, action: nil)
        auto.state = preferences.autoUpload ? .on : .off
        let retention = NSPopUpButton(); retention.addItems(withTitles: ["30 days", "90 days", "180 days", "365 days", "1095 days"]); retention.selectItem(withTitle: "\(preferences.retentionDays) days")
        server.frame.size.width = 430; token.frame.size.width = 430
        let grid = NSGridView(views: [[label("Server URL"), server], [label("Device token"), token], [label("Local retention"), retention], [NSTextField(labelWithString: ""), auto]])
        grid.rowSpacing = 10; grid.columnSpacing = 12; grid.column(at: 0).xPlacement = .trailing; grid.column(at: 1).xPlacement = .fill
        alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let url = URL(string: server.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)), isAllowedServerURL(url) else { showError(UploadFailure.invalidServer); return }
        preferences.serverURL = url
        preferences.autoUpload = auto.state == .on
        preferences.retentionDays = Int(retention.titleOfSelectedItem?.split(separator: " ").first ?? "365") ?? 365
        let newToken = token.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !newToken.isEmpty {
            guard newToken.hasPrefix("spdev_dev_") else { showError(NSError(domain: "Scopeproof", code: 2, userInfo: [NSLocalizedDescriptionKey: "The device token must begin with spdev_dev_."])); return }
            do { try KeychainStore.saveToken(newToken) } catch { showError(error); return }
        }
        setReady("Capture settings saved")
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
                    guard self.isNewer(release.version, than: "1.1.0") else { if !silent { self.setReady("Scopeproof Capture is up to date") }; return }
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

    private func showError(_ error: Error) { NSApplication.shared.activate(ignoringOtherApps: true); let alert = NSAlert(error: error); alert.messageText = "Scopeproof could not complete the operation"; alert.runModal() }
    private func notify(title: String, body: String) { NSSound(named: "Glass")?.play(); let content = UNMutableNotificationContent(); content.title = title; content.body = body; content.sound = .default; UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) }
}
