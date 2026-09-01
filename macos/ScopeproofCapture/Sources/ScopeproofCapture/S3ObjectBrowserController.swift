@preconcurrency import AppKit

@MainActor
final class S3ObjectBrowserController: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate, NSWindowDelegate {
    private let service: S3StorageService
    private let credentialProvider: S3CredentialProvider
    private var settings: S3StorageSettings = .defaults
    private var binding: S3VerifiedDestination?
    private var window: NSWindow?
    private var allObjects: [S3StoredObject] = []
    private var visibleObjects: [S3StoredObject] = []
    private var listTask: Task<Void, Never>?
    private var downloadTask: Task<Void, Never>?
    private var operationGeneration = 0
    private var lastDownloadURL: URL?

    private let searchField = NSSearchField()
    private let tableView = NSTableView()
    private let statusLabel = NSTextField(labelWithString: "")
    private let detailsLabel = NSTextField(wrappingLabelWithString: "")
    private let progress = NSProgressIndicator()
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let downloadButton = NSButton(title: "Download Selected…", target: nil, action: nil)
    private let revealButton = NSButton(title: "Reveal Download", target: nil, action: nil)

    init(service: S3StorageService, credentialProvider: S3CredentialProvider) {
        self.service = service
        self.credentialProvider = credentialProvider
    }

    func show(settings: S3StorageSettings) {
        guard settings.canUpload, settings.downloadsAllowed, S3CredentialProvider.hasConfiguredSource(settings),
              let binding = KeychainStore.readS3VerifiedDestination(), binding.matches(settings) else {
            presentStandaloneError(settings.isConfigured ? S3StorageFailure.verificationRequired : S3StorageFailure.notConfigured)
            return
        }
        self.settings = settings
        self.binding = binding
        if window == nil { buildWindow() }
        window?.title = "Browse S3 Evidence — \(settings.bucket)"
        window?.center()
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        refresh()
    }

    private func buildWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_080, height: 680),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.minSize = NSSize(width: 780, height: 500)
        window.isReleasedWhenClosed = false
        window.delegate = self
        let content = NSView()
        window.contentView = content

        let heading = NSTextField(labelWithString: "Browse stored compliance evidence")
        heading.font = .systemFont(ofSize: 22, weight: .bold)
        let subtitle = NSTextField(wrappingLabelWithString: "Files are listed only from the configured S3 evidence prefix. Select one file to download an immutable copy to a location you choose.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.maximumNumberOfLines = 2

        searchField.placeholderString = "Search control, assessment period, evidence ID, or filename"
        searchField.setAccessibilityLabel("Search S3 evidence files")
        searchField.delegate = self
        searchField.target = self
        searchField.action = #selector(searchChanged)
        refreshButton.target = self
        refreshButton.action = #selector(refreshAction)
        refreshButton.bezelStyle = .rounded
        let topSpacer = NSView()
        topSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let searchRow = NSStackView(views: [searchField, topSpacer, refreshButton])
        searchRow.orientation = .horizontal
        searchRow.alignment = .centerY
        searchRow.spacing = 10

        let columns: [(String, String, CGFloat)] = [
            ("control", "Control folder", 170),
            ("file", "Filename", 235),
            ("path", "Assessment / Evidence path", 220),
            ("version", "Version", 110),
            ("size", "Size", 75),
            ("modified", "Modified", 135),
        ]
        for (identifier, title, width) in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            column.minWidth = identifier == "file" || identifier == "path" ? 180 : 75
            column.sortDescriptorPrototype = NSSortDescriptor(key: identifier, ascending: true)
            tableView.addTableColumn(column)
        }
        tableView.headerView = NSTableHeaderView()
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 30
        tableView.allowsMultipleSelection = false
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(downloadSelected)
        tableView.setAccessibilityLabel("S3 evidence files")

        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder

        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.lineBreakMode = .byTruncatingTail
        detailsLabel.textColor = .secondaryLabelColor
        detailsLabel.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        detailsLabel.maximumNumberOfLines = 2
        progress.style = .spinning
        progress.controlSize = .small
        progress.isDisplayedWhenStopped = false
        downloadButton.target = self
        downloadButton.action = #selector(downloadSelected)
        downloadButton.bezelStyle = .rounded
        downloadButton.keyEquivalent = "\r"
        revealButton.target = self
        revealButton.action = #selector(revealLastDownload)
        revealButton.bezelStyle = .rounded
        revealButton.isEnabled = false
        let actionSpacer = NSView()
        actionSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let actions = NSStackView(views: [progress, statusLabel, actionSpacer, revealButton, downloadButton])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 9

        let stack = NSStackView(views: [heading, subtitle, searchRow, scroll, detailsLabel, actions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        searchRow.translatesAutoresizingMaskIntoConstraints = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        actions.translatesAutoresizingMaskIntoConstraints = false
        searchField.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18),
            searchRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
            searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 420),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 300),
            detailsLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            actions.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        self.window = window
        updateSelectionState()
    }

    @objc private func refreshAction() { refresh() }

    private func refresh() {
        guard listTask == nil, downloadTask == nil else { return }
        guard let binding, binding.matches(settings) else {
            presentError(S3StorageFailure.destinationBindingMismatch); return
        }
        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Loading S3 evidence…")
        listTask = Task {
            do {
                let credentials = try await credentialProvider.credentials(for: settings, binding: binding)
                let objects = try await service.listObjects(settings: settings, credentials: credentials, binding: binding)
                guard !Task.isCancelled, operationGeneration == generation else { return }
                allObjects = objects
                listTask = nil
                applyFilterAndSort()
                setBusy(false, message: summaryMessage)
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                listTask = nil
                setBusy(false, message: "S3 browsing cancelled.")
            } catch {
                guard operationGeneration == generation else { return }
                listTask = nil
                allObjects = []
                applyFilterAndSort()
                setBusy(false, message: "Unable to load S3 evidence.")
                presentError(error)
            }
        }
    }

    @objc private func searchChanged() { applyFilterAndSort() }
    func controlTextDidChange(_ obj: Notification) { applyFilterAndSort() }

    private func applyFilterAndSort() {
        let query = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        visibleObjects = allObjects.filter { query.isEmpty || $0.key.lowercased().contains(query) }
        let descriptor = tableView.sortDescriptors.first
        let key = descriptor?.key ?? "path"
        let ascending = descriptor?.ascending ?? true
        visibleObjects.sort { left, right in
            let order: ComparisonResult
            switch key {
            case "size": order = left.size == right.size ? .orderedSame : (left.size < right.size ? .orderedAscending : .orderedDescending)
            case "modified": order = left.lastModified.compare(right.lastModified)
            case "control": order = controlFolder(for: left).localizedStandardCompare(controlFolder(for: right))
            case "file": order = filename(for: left).localizedStandardCompare(filename(for: right))
            case "version": order = left.versionID.localizedStandardCompare(right.versionID)
            default: order = left.key.localizedStandardCompare(right.key)
            }
            return ascending ? order == .orderedAscending : order == .orderedDescending
        }
        tableView.reloadData()
        if !visibleObjects.isEmpty { tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false) }
        updateSelectionState()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { visibleObjects.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row >= 0, row < visibleObjects.count, let identifier = tableColumn?.identifier.rawValue else { return nil }
        let object = visibleObjects[row]
        let value: String
        switch identifier {
        case "control": value = controlFolder(for: object)
        case "file": value = filename(for: object)
        case "path": value = intermediatePath(for: object)
        case "version": value = object.isLatest ? "Latest · \(object.versionID.prefix(10))" : String(object.versionID.prefix(16))
        case "size": value = Self.byteFormatter.string(fromByteCount: object.size)
        case "modified": value = Self.displayDate(object.lastModified)
        default: value = ""
        }
        let field = NSTextField(labelWithString: value)
        field.lineBreakMode = .byTruncatingMiddle
        field.toolTip = value
        field.font = identifier == "file" ? .systemFont(ofSize: 11, weight: .medium) : .systemFont(ofSize: 11)
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateSelectionState() }
    func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) { applyFilterAndSort() }

    private var selectedObject: S3StoredObject? {
        guard tableView.selectedRow >= 0, tableView.selectedRow < visibleObjects.count else { return nil }
        return visibleObjects[tableView.selectedRow]
    }

    private func updateSelectionState() {
        downloadButton.isEnabled = selectedObject.map(Self.isSupportedEvidenceObject) == true && listTask == nil && downloadTask == nil
        if let object = selectedObject {
            let validation = Self.isSupportedEvidenceObject(object) ? "PNG/JSON validation required on download" : "Unsupported type — download blocked"
            detailsLabel.stringValue = "s3://\(settings.bucket)/\(object.key)?versionId=\(object.versionID)\nETag \(object.eTag) · \(validation)"
        } else {
            detailsLabel.stringValue = visibleObjects.isEmpty ? "No downloadable files are visible." : "Select one S3 object to download."
        }
        if listTask == nil, downloadTask == nil { statusLabel.stringValue = summaryMessage }
    }

    @objc private func downloadSelected() {
        guard downloadTask == nil, listTask == nil, let object = selectedObject,
              Self.isSupportedEvidenceObject(object), let window else { return }
        let panel = NSSavePanel()
        panel.title = "Download S3 Evidence"
        panel.prompt = "Download"
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = Self.safeSuggestedFilename(object.key)
        panel.message = "Save a private local copy of s3://\(settings.bucket)/\(object.key)"
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let destination = panel.url else { return }
            Task { @MainActor [weak self] in self?.startDownload(object, to: destination) }
        }
    }

    private func startDownload(_ object: S3StoredObject, to destination: URL) {
        guard let binding, binding.matches(settings) else {
            presentError(S3StorageFailure.destinationBindingMismatch); return
        }
        operationGeneration += 1
        let generation = operationGeneration
        setBusy(true, message: "Downloading \(filename(for: object))…")
        downloadTask = Task {
            do {
                let credentials = try await credentialProvider.credentials(for: settings, binding: binding)
                let result = try await service.downloadObject(
                    object, settings: settings, credentials: credentials, binding: binding, to: destination
                )
                guard !Task.isCancelled, operationGeneration == generation else { return }
                lastDownloadURL = destination
                revealButton.isEnabled = true
                downloadTask = nil
                let version = result.versionID.isEmpty ? "current version" : "version \(result.versionID.prefix(20))"
                setBusy(false, message: "Downloaded and validated \(version) · SHA-256 \(result.sha256.prefix(16))…")
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                downloadTask = nil
                setBusy(false, message: "S3 download cancelled.")
            } catch {
                guard operationGeneration == generation else { return }
                downloadTask = nil
                setBusy(false, message: "S3 download failed.")
                presentError(error)
            }
        }
    }

    @objc private func revealLastDownload() {
        guard let lastDownloadURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([lastDownloadURL])
    }

    private func setBusy(_ busy: Bool, message: String) {
        if busy { progress.startAnimation(nil) } else { progress.stopAnimation(nil) }
        refreshButton.isEnabled = !busy
        downloadButton.isEnabled = !busy && selectedObject.map(Self.isSupportedEvidenceObject) == true
        searchField.isEnabled = !busy
        statusLabel.stringValue = message
    }

    private var summaryMessage: String {
        if allObjects.isEmpty { return "No files were found in \(settings.bucket)/\(settings.prefix). Upload evidence or verify the configured prefix." }
        let total = visibleObjects.reduce(Int64(0)) { partial, object in
            let (value, overflow) = partial.addingReportingOverflow(object.size)
            return overflow ? Int64.max : value
        }
        let scope = searchField.stringValue.isEmpty ? "" : " matching the search"
        return "\(visibleObjects.count) file\(visibleObjects.count == 1 ? "" : "s")\(scope) · \(Self.byteFormatter.string(fromByteCount: total))"
    }

    private func controlFolder(for object: S3StoredObject) -> String {
        object.relativeKey(prefix: settings.prefix).split(separator: "/", omittingEmptySubsequences: true).first.map(String.init) ?? "—"
    }

    private func filename(for object: S3StoredObject) -> String {
        object.key.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? object.key
    }

    private func intermediatePath(for object: S3StoredObject) -> String {
        let parts = object.relativeKey(prefix: settings.prefix).split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard parts.count > 2 else { return parts.dropLast().joined(separator: " / ") }
        return parts.dropFirst().dropLast().joined(separator: " / ")
    }

    private func presentError(_ error: Error) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Scopeproof could not complete the S3 operation"
        alert.informativeText = error.localizedDescription
        if let window, window.isVisible { alert.beginSheetModal(for: window) } else { alert.runModal() }
    }

    private func presentStandaloneError(_ error: Error) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        presentError(error)
    }

    func windowWillClose(_ notification: Notification) {
        operationGeneration += 1
        listTask?.cancel()
        downloadTask?.cancel()
        listTask = nil
        downloadTask = nil
        allObjects = []
        visibleObjects = []
        lastDownloadURL = nil
        binding = nil
        tableView.reloadData()
        updateSelectionState()
    }

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        return formatter
    }()

    private static func isSupportedEvidenceObject(_ object: S3StoredObject) -> Bool {
        let key = object.key.lowercased()
        return key.hasSuffix(".png") || key.hasSuffix(".json")
    }

    private static func displayDate(_ value: String) -> String {
        guard let date = s3DateFormatter.date(from: value) ?? ISO8601DateFormatter().date(from: value) else { return value }
        return DateFormatter.localizedString(from: date, dateStyle: .medium, timeStyle: .short)
    }

    private static let s3DateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    static func safeSuggestedFilename(_ key: String) -> String {
        let raw = key.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? "scopeproof-s3-object"
        return ComplianceCatalog.safePathComponent(raw, fallback: "scopeproof-s3-object", maximumLength: 180)
    }
}
