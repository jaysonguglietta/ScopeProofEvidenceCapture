@preconcurrency import AppKit

@MainActor
final class EvidenceSearchController: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    private var window: NSWindow?
    private var evidenceRoot: URL?
    private var serverURL: URL?
    private var jiraSettings: JiraHandoffSettings = .defaults
    private let jiraCloudService = JiraCloudService()
    private var allEntries: [CaptureHistoryEntry] = []
    private var filteredEntries: [CaptureHistoryEntry] = []
    private let frameworkPopup = NSPopUpButton()
    private let controlPopup = NSPopUpButton()
    private let statusPopup = NSPopUpButton()
    private let systemPopup = NSPopUpButton()
    private let datePopup = NSPopUpButton()
    private let searchField = NSSearchField()
    private let tableView = NSTableView()
    private let statusLabel = NSTextField(labelWithString: "")
    private let openButton = NSButton(title: "Open Screenshot", target: nil, action: nil)
    private let revealButton = NSButton(title: "Reveal in Finder", target: nil, action: nil)
    private let reviewButton = NSButton(title: "Review Status…", target: nil, action: nil)
    private let holdButton = NSButton(title: "Place Legal Hold…", target: nil, action: nil)
    private let jiraButton = NSButton(title: "Copy Jira Comment", target: nil, action: nil)
    private let jiraUploadButton = NSButton(title: "Upload to Jira Cloud…", target: nil, action: nil)
    private let detailsLabel = NSTextField(wrappingLabelWithString: "")

    func show(evidenceRoot: URL, jiraSettings: JiraHandoffSettings = .defaults, serverURL: URL? = nil) {
        self.evidenceRoot = evidenceRoot
        self.jiraSettings = jiraSettings
        self.serverURL = serverURL
        allEntries = CaptureHistory.entries(in: evidenceRoot)
        if window == nil { buildWindow() }
        populateFrameworks()
        populateControls()
        applyFilters()
        window?.center()
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    private func buildWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 700),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Search Scopeproof Evidence"
        window.minSize = NSSize(width: 900, height: 560)

        let content = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = content

        let heading = NSTextField(labelWithString: "Find evidence by compliance control")
        heading.font = .systemFont(ofSize: 22, weight: .bold)
        let subtitle = NSTextField(labelWithString: "Search every nested evidence folder, including captures created by earlier Scopeproof versions.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.font = .systemFont(ofSize: 12)

        frameworkPopup.target = self
        frameworkPopup.action = #selector(frameworkChanged)
        frameworkPopup.setAccessibilityLabel("Compliance framework filter")
        controlPopup.target = self
        controlPopup.action = #selector(filtersChanged)
        controlPopup.setAccessibilityLabel("Control number filter")
        searchField.placeholderString = "Search filename, Jira issue, title, evidence ID, system, or description"
        searchField.delegate = self
        searchField.target = self
        searchField.action = #selector(filtersChanged)
        searchField.setAccessibilityLabel("Evidence keyword search")
        statusPopup.addItem(withTitle: "All review statuses")
        statusPopup.addItems(withTitles: EvidenceReviewStatus.allCases.map(\.rawValue))
        statusPopup.target = self; statusPopup.action = #selector(filtersChanged); statusPopup.setAccessibilityLabel("Review status filter")
        datePopup.addItems(withTitles: ["Any capture date", "Last 30 days", "Last 90 days", "Last 365 days"])
        datePopup.target = self; datePopup.action = #selector(filtersChanged); datePopup.setAccessibilityLabel("Capture date filter")
        systemPopup.target = self; systemPopup.action = #selector(filtersChanged); systemPopup.setAccessibilityLabel("System filter")

        let frameworkGroup = labeledControl(label: "Compliance area", control: frameworkPopup, width: 240)
        let controlGroup = labeledControl(label: "Control", control: controlPopup, width: 260)
        let statusGroup = labeledControl(label: "Review status", control: statusPopup, width: 160)
        let systemGroup = labeledControl(label: "System / asset", control: systemPopup, width: 190)
        let dateGroup = labeledControl(label: "Captured", control: datePopup, width: 150)
        let keywordGroup = labeledControl(label: "Search", control: searchField, width: 420)
        let filterTop = NSStackView(views: [frameworkGroup, controlGroup, statusGroup, dateGroup])
        filterTop.orientation = .horizontal; filterTop.alignment = .bottom; filterTop.spacing = 12
        let filterBottom = NSStackView(views: [systemGroup, keywordGroup])
        filterBottom.orientation = .horizontal; filterBottom.alignment = .bottom; filterBottom.spacing = 12

        let columns: [(String, String, CGFloat)] = [
            ("preview", "", 64), ("captured", "Captured", 145), ("framework", "Compliance area", 155), ("control", "Control", 100),
            ("jira", "Jira", 95), ("evidence", "Evidence", 220), ("system", "System / asset", 150), ("status", "Review", 90), ("owner", "Owner", 120), ("upload", "Stored", 65),
        ]
        for (identifier, title, width) in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            column.minWidth = identifier == "evidence" ? 180 : 70
            tableView.addTableColumn(column)
        }
        tableView.headerView = NSTableHeaderView()
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 52
        tableView.allowsMultipleSelection = false
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(openSelected)
        tableView.setAccessibilityLabel("Evidence search results")

        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder

        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 11)
        openButton.target = self
        openButton.action = #selector(openSelected)
        openButton.bezelStyle = .rounded
        revealButton.target = self
        revealButton.action = #selector(revealSelected)
        revealButton.bezelStyle = .rounded
        reviewButton.target = self
        reviewButton.action = #selector(reviewSelected)
        reviewButton.bezelStyle = .rounded
        holdButton.target = self
        holdButton.action = #selector(changeLegalHold)
        holdButton.bezelStyle = .rounded
        holdButton.toolTip = "Place or release a signed local retention hold for the selected evidence"
        jiraButton.target = self
        jiraButton.action = #selector(copyJiraComment)
        jiraButton.bezelStyle = .rounded
        jiraButton.toolTip = "Copy a ticket-ready summary and attachment checklist"
        jiraUploadButton.target = self
        jiraUploadButton.action = #selector(uploadToJiraCloud)
        jiraUploadButton.bezelStyle = .rounded
        jiraUploadButton.toolTip = "Upload a hash-verified Approved evidence set through the connected Scopeproof backend"
        detailsLabel.textColor = .secondaryLabelColor
        detailsLabel.font = .systemFont(ofSize: 11)
        detailsLabel.maximumNumberOfLines = 2
        let spacer = NSView()
        let actions = NSStackView(views: [statusLabel, spacer, jiraUploadButton, jiraButton, holdButton, reviewButton, revealButton, openButton])
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 9
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let stack = NSStackView(views: [heading, subtitle, filterTop, filterBottom, scroll, detailsLabel, actions])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        filterTop.translatesAutoresizingMaskIntoConstraints = false
        filterBottom.translatesAutoresizingMaskIntoConstraints = false
        actions.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18),
            filterTop.widthAnchor.constraint(equalTo: stack.widthAnchor),
            filterBottom.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 280),
            actions.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        self.window = window
    }

    private func labeledControl(label: String, control: NSView, width: CGFloat) -> NSView {
        let caption = NSTextField(labelWithString: label)
        caption.font = .systemFont(ofSize: 11, weight: .semibold)
        caption.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [caption, control])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 5
        control.translatesAutoresizingMaskIntoConstraints = false
        control.widthAnchor.constraint(equalToConstant: width).isActive = true
        return stack
    }

    private func populateFrameworks() {
        let selected = frameworkPopup.titleOfSelectedItem
        frameworkPopup.removeAllItems()
        frameworkPopup.addItem(withTitle: "All compliance areas")
        frameworkPopup.addItems(withTitles: ComplianceCatalog.frameworks.map(\.name))
        if let selected, frameworkPopup.itemTitles.contains(selected) { frameworkPopup.selectItem(withTitle: selected) }
        let selectedSystem = systemPopup.titleOfSelectedItem
        systemPopup.removeAllItems(); systemPopup.addItem(withTitle: "All systems")
        systemPopup.addItems(withTitles: Array(Set(allEntries.map { $0.manifest.system })).sorted())
        if let selectedSystem, systemPopup.itemTitles.contains(selectedSystem) { systemPopup.selectItem(withTitle: selectedSystem) }
    }

    private func populateControls() {
        let selectedID = controlPopup.selectedItem?.representedObject as? String
        controlPopup.removeAllItems()
        controlPopup.addItem(withTitle: "All controls")
        guard frameworkPopup.indexOfSelectedItem > 0, let name = frameworkPopup.titleOfSelectedItem else { return }
        for control in ComplianceCatalog.framework(named: name).controls {
            controlPopup.addItem(withTitle: control.displayName)
            controlPopup.lastItem?.representedObject = control.id
        }
        if let selectedID, let item = controlPopup.itemArray.first(where: { ($0.representedObject as? String) == selectedID }) { controlPopup.select(item) }
    }

    @objc private func frameworkChanged() { populateControls(); applyFilters() }
    @objc private func filtersChanged() { applyFilters() }
    func controlTextDidChange(_ obj: Notification) { applyFilters() }

    private func applyFilters() {
        let framework = frameworkPopup.indexOfSelectedItem > 0 ? frameworkPopup.titleOfSelectedItem : nil
        let controlID = controlPopup.indexOfSelectedItem > 0 ? controlPopup.selectedItem?.representedObject as? String : nil
        let query = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let selectedStatus = statusPopup.indexOfSelectedItem > 0 ? statusPopup.titleOfSelectedItem : nil
        let selectedSystem = systemPopup.indexOfSelectedItem > 0 ? systemPopup.titleOfSelectedItem : nil
        let cutoffDays = [0, 30, 90, 365][max(0, datePopup.indexOfSelectedItem)]
        let cutoff = cutoffDays == 0 ? nil : Date().addingTimeInterval(-Double(cutoffDays) * 86_400)
        filteredEntries = allEntries.filter { entry in
            let manifest = entry.manifest
            let lifecycle = entry.lifecycle
            let entryFramework = manifest.complianceArea ?? "PCI DSS 4.0.1"
            guard framework == nil || framework == entryFramework else { return false }
            guard controlID == nil || controlID?.caseInsensitiveCompare(manifest.controlID) == .orderedSame else { return false }
            guard selectedStatus == nil || selectedStatus == lifecycle.status.rawValue else { return false }
            guard selectedSystem == nil || selectedSystem == manifest.system else { return false }
            if let cutoff, let captured = ISO8601DateFormatter().date(from: manifest.capturedAt), captured < cutoff { return false }
            guard !query.isEmpty else { return true }
            return [entry.imageURL.lastPathComponent, manifest.evidenceID, manifest.title, manifest.system, manifest.sessionName, manifest.description, manifest.controlID, manifest.customFileName ?? "", manifest.controlTitle ?? "", manifest.sourceURL ?? "", manifest.sourceHost ?? "", manifest.jiraIssueKey ?? "", manifest.jiraIssueURL ?? "", lifecycle.owner, lifecycle.reviewer, lifecycle.reviewNotes, lifecycle.tags.joined(separator: " ")]
                .joined(separator: " ").lowercased().contains(query)
        }
        tableView.reloadData()
        if !filteredEntries.isEmpty { tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false) }
        updateSelectionState()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { filteredEntries.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row >= 0, row < filteredEntries.count, let identifier = tableColumn?.identifier.rawValue else { return nil }
        let entry = filteredEntries[row]
        let manifest = entry.manifest
        let value: String
        switch identifier {
        case "preview":
            let imageView = NSImageView(frame: NSRect(x: 4, y: 4, width: 54, height: 44))
            if let artifact = try? ValidatedEvidenceArtifact.loadForLegacyBrowsing(
                entry, requireLifecycle: false
            ) {
                imageView.image = NSImage(data: artifact.imageData)
            }
            imageView.imageScaling = .scaleProportionallyUpOrDown
            imageView.setAccessibilityLabel("Preview of \(manifest.title)")
            return imageView
        case "captured": value = manifest.localTimestamp
        case "framework": value = manifest.complianceArea ?? "PCI DSS 4.0.1"
        case "control": value = manifest.controlID
        case "jira": value = manifest.jiraIssueKey ?? "—"
        case "evidence": value = manifest.customFileName?.isEmpty == false ? manifest.customFileName! : manifest.title
        case "system": value = manifest.system
        case "status": value = entry.lifecycle.status.rawValue
        case "owner": value = entry.lifecycle.owner
        case "upload": value = entry.isUploaded ? "Hosted" : "Local"
        default: value = ""
        }
        let field = NSTextField(labelWithString: value)
        field.lineBreakMode = .byTruncatingTail
        field.toolTip = value
        field.font = .systemFont(ofSize: 11)
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateSelectionState() }

    private func updateSelectionState() {
        let hasSelection = tableView.selectedRow >= 0 && tableView.selectedRow < filteredEntries.count
        let provenanceVerified = selectedEntry.flatMap {
            try? ValidatedEvidenceArtifact.load($0, requireLifecycle: false)
        }?.provenanceVerified == true
        openButton.isEnabled = hasSelection
        revealButton.isEnabled = hasSelection
        reviewButton.isEnabled = hasSelection && provenanceVerified
        holdButton.isEnabled = hasSelection && provenanceVerified
        jiraButton.isEnabled = hasSelection && provenanceVerified
        jiraUploadButton.isEnabled = hasSelection && provenanceVerified && selectedEntry?.lifecycle.status == .approved && selectedEntry?.manifest.jiraIssueKey?.isEmpty == false
        statusLabel.stringValue = filteredEntries.isEmpty ? "No screenshots match these filters." : "\(filteredEntries.count) screenshot\(filteredEntries.count == 1 ? "" : "s") found"
        if let entry = selectedEntry {
            let lifecycle = entry.lifecycle
            let holdStatus: String
            switch LocalEvidenceHoldStore.state(for: entry) {
            case .none: holdStatus = "no hold"; holdButton.title = "Place Legal Hold…"
            case .active: holdStatus = "legal hold active"; holdButton.title = "Release Legal Hold…"
            case .released: holdStatus = "hold released"; holdButton.title = "Place Legal Hold…"
            case .invalid: holdStatus = "hold marker invalid (fail-closed)"; holdButton.title = "Legal Hold Invalid"
            }
            let mappings = entry.manifest.mappedControls?.map { "\(ComplianceCatalog.framework(named: $0.framework).fileCode) \($0.controlID)" }.joined(separator: ", ") ?? "None curated"
            let jira = entry.manifest.jiraIssueKey?.isEmpty == false ? entry.manifest.jiraIssueKey! : "not assigned"
            let provenance = provenanceVerified ? "signed provenance verified" : "legacy unsigned · browsing only"
            detailsLabel.stringValue = "\(entry.manifest.evidenceID) · \(provenance) · \(lifecycle.status.rawValue) · \(holdStatus) · Jira: \(jira) · tags: \(lifecycle.tags.isEmpty ? "none" : lifecycle.tags.joined(separator: ", ")) · mapped controls: \(mappings)"
        } else {
            holdButton.title = "Place Legal Hold…"
            detailsLabel.stringValue = "Select evidence to review its lifecycle, ownership, tags, legal hold, and cross-framework mappings."
        }
    }

    private var selectedEntry: CaptureHistoryEntry? {
        guard tableView.selectedRow >= 0, tableView.selectedRow < filteredEntries.count else { return nil }
        return filteredEntries[tableView.selectedRow]
    }

    @objc private func openSelected() {
        guard let entry = selectedEntry,
              (try? ValidatedEvidenceArtifact.loadForLegacyBrowsing(entry, requireLifecycle: false)) != nil else { return }
        NSWorkspace.shared.open(entry.imageURL)
    }
    @objc private func revealSelected() { if let entry = selectedEntry { NSWorkspace.shared.activateFileViewerSelecting([entry.imageURL]) } }

    @objc private func copyJiraComment() {
        guard let entry = selectedEntry else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(JiraHandoff.comment(for: entry, settings: jiraSettings), forType: .string)
        statusLabel.stringValue = "Jira comment copied for \(entry.manifest.jiraIssueKey ?? entry.manifest.evidenceID). Attach only the listed reviewed files."
    }

    @objc private func uploadToJiraCloud() {
        guard let entry = selectedEntry, entry.lifecycle.status == .approved, EvidenceLifecycleStore.verify(entry.lifecycle), let issueKey = entry.manifest.jiraIssueKey, !issueKey.isEmpty else {
            let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = "Approved Jira-linked evidence required"; alert.informativeText = "Assign a Jira issue, mark the evidence Approved with a rationale, and resolve any lifecycle integrity error before upload."; alert.runModal(); return
        }
        statusLabel.stringValue = "Checking Jira Cloud issue \(issueKey)…"
        jiraUploadButton.isEnabled = false
        Task {
            do {
                guard let binding = entry.manifest.tenantBinding else {
                    throw JiraCloudFailure.notConnected
                }
                let connection = try await jiraCloudService.connection(
                    serverURL: serverURL, binding: binding
                )
                guard connection.connected else { throw JiraCloudFailure.rejected("Jira Cloud is not connected for this Scopeproof account. Open Scopeproof web → Connections and authorize it first.") }
                let issue = try await jiraCloudService.issue(
                    issueKey, serverURL: serverURL, binding: binding
                )
                let confirmation = NSAlert()
                confirmation.alertStyle = .warning
                confirmation.messageText = "Upload approved evidence to \(issue.key)?"
                confirmation.informativeText = "Site: \(connection.siteName ?? connection.siteURL ?? "Jira Cloud")\n\(issue.summary)\nStatus: \(issue.status)\n\nScopeproof will require the exact hosted artifact to have authenticated reviewer approval, then attach the redacted PNG, immutable manifest, Approved lifecycle record, and server receipt when available. This disclosure is recorded in the audit chain and cannot be undone from Scopeproof."
                confirmation.addButton(withTitle: "Upload to Jira Cloud")
                confirmation.addButton(withTitle: "Cancel")
                guard confirmation.runModal() == .alertFirstButtonReturn else { updateSelectionState(); return }
                statusLabel.stringValue = "Uploading \(entry.manifest.evidenceID) to \(issue.key)…"
                let receiptURL = try await jiraCloudService.upload(entry: entry, serverURL: serverURL)
                statusLabel.stringValue = "Uploaded to \(issue.key). Signed receipt saved as \(receiptURL.lastPathComponent)."
            } catch {
                let failure = NSAlert(); failure.alertStyle = .warning; failure.messageText = "Jira Cloud upload failed"; failure.informativeText = error.localizedDescription; failure.runModal()
                statusLabel.stringValue = "Jira Cloud upload failed. No successful receipt was recorded."
            }
            updateSelectionState()
        }
    }

    @objc private func reviewSelected() {
        guard let entry = selectedEntry else { return }
        let current = entry.lifecycle
        let alert = NSAlert(); alert.messageText = "Review \(entry.manifest.evidenceID)"; alert.informativeText = "The original capture manifest remains immutable. This decision is written to a separate hash-chained lifecycle record included in assessor exports."; alert.addButton(withTitle: "Save Review"); alert.addButton(withTitle: "Cancel")
        let status = NSPopUpButton(); status.addItems(withTitles: EvidenceReviewStatus.allCases.map(\.rawValue)); status.selectItem(withTitle: current.status.rawValue)
        let owner = NSTextField(string: current.owner)
        let reviewer = NSTextField(labelWithString: "Authenticated macOS user (verified when saved)")
        let tags = NSTextField(string: current.tags.joined(separator: ", "))
        let notes = NSTextField(string: current.reviewNotes)
        let supersedes = NSTextField(string: current.supersedesEvidenceID ?? "")
        owner.placeholderString = "Control owner"; tags.placeholderString = "identity, quarterly"; notes.placeholderString = "Approval rationale, caveat, or rejection reason"; supersedes.placeholderString = "Optional older evidence ID"
        for field in [owner, reviewer, tags, notes, supersedes] { field.frame.size.width = 420 }
        let grid = NSGridView(views: [[caption("Status"), status], [caption("Owner"), owner], [caption("Reviewer"), reviewer], [caption("Tags"), tags], [caption("Review notes"), notes], [caption("Supersedes"), supersedes]])
        grid.rowSpacing = 10; grid.columnSpacing = 12; grid.column(at: 0).xPlacement = .trailing; grid.column(at: 1).xPlacement = .fill; alert.accessoryView = grid
        guard alert.runModal() == .alertFirstButtonReturn, let selectedTitle = status.titleOfSelectedItem, let selectedStatus = EvidenceReviewStatus(rawValue: selectedTitle) else { return }
        if [.approved, .rejected, .superseded].contains(selectedStatus) && notes.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let error = NSAlert(); error.alertStyle = .warning; error.messageText = "Add a review note"; error.informativeText = "Approval, rejection, and supersession decisions require a short rationale for the assessor trail."; error.runModal(); return
        }
        Task { @MainActor in
            do {
                let identity = try await LocalReviewerAuthorizer.authorize(
                    reason: "Authenticate to save the \(selectedStatus.rawValue) decision for \(entry.manifest.evidenceID)"
                )
                _ = try EvidenceLifecycleStore.update(
                    entry: entry, status: selectedStatus, owner: owner.stringValue,
                    reviewer: "", notes: notes.stringValue,
                    tags: tags.stringValue.split(separator: ",").map(String.init),
                    supersedesEvidenceID: supersedes.stringValue,
                    reviewerIdentity: identity
                )
                if let evidenceRoot { allEntries = CaptureHistory.entries(in: evidenceRoot) }
                applyFilters()
            } catch {
                let failure = NSAlert(); failure.alertStyle = .warning; failure.messageText = "Review could not be saved"; failure.informativeText = error.localizedDescription; failure.runModal()
            }
        }
    }

    @objc private func changeLegalHold() {
        guard let entry = selectedEntry else { return }
        let active: Bool
        let title: String
        let action: String
        switch LocalEvidenceHoldStore.state(for: entry) {
        case .active:
            active = false; title = "Release legal hold?"; action = "Release Hold"
        case .none, .released:
            active = true; title = "Place evidence on legal hold?"; action = "Place Hold"
        case .invalid:
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Legal-hold marker is invalid"
            alert.informativeText = "Scopeproof will preserve this evidence and will not overwrite an invalid hold marker. Investigate or restore the signed marker before changing retention state."
            alert.runModal()
            return
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = active
            ? "Local retention will preserve \(entry.manifest.evidenceID) until this signed hold is explicitly released. This local control does not place a legal hold on hosted or S3 copies."
            : "This removes the local retention block only. Confirm that legal, records, and investigation owners have authorized release."
        alert.addButton(withTitle: action)
        alert.addButton(withTitle: "Cancel")
        let reason = NSTextField(frame: NSRect(x: 0, y: 0, width: 440, height: 26))
        reason.placeholderString = active ? "Matter, request, or preservation reason" : "Release authorization and reason"
        reason.setAccessibilityLabel("Legal hold reason")
        alert.accessoryView = reason
        alert.window.initialFirstResponder = reason
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard reason.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).count >= 10 else {
            let error = NSAlert(); error.alertStyle = .warning; error.messageText = "Add a specific hold reason"; error.informativeText = "Enter at least 10 characters identifying the matter or release authorization."; error.runModal(); return
        }
        Task { @MainActor in
            do {
                let identity = try await LocalReviewerAuthorizer.authorize(
                    reason: "Authenticate to \(active ? "place" : "release") the legal hold for \(entry.manifest.evidenceID)"
                )
                _ = try LocalEvidenceHoldStore.set(
                    entry: entry, active: active, reason: reason.stringValue,
                    reviewerIdentity: identity
                )
                if let evidenceRoot { allEntries = CaptureHistory.entries(in: evidenceRoot) }
                applyFilters()
                statusLabel.stringValue = active ? "Legal hold placed on \(entry.manifest.evidenceID)." : "Legal hold released for \(entry.manifest.evidenceID)."
            } catch {
                let failure = NSAlert(); failure.alertStyle = .critical; failure.messageText = "Legal hold could not be changed"; failure.informativeText = error.localizedDescription; failure.runModal()
            }
        }
    }

    private func caption(_ value: String) -> NSTextField {
        let field = NSTextField(labelWithString: value); field.font = .systemFont(ofSize: 12, weight: .medium); return field
    }
}
