@preconcurrency import AppKit

@MainActor
final class CaptureMetadataCoordinator: NSObject, NSTextFieldDelegate, NSComboBoxDelegate {
    let frameworkPopup: NSPopUpButton
    let controlCombo: NSComboBox
    let filenameField: NSTextField
    let periodField: NSTextField
    let jiraIssueField: NSTextField?
    let previewLabel: NSTextField
    let mappingLabel: NSTextField?

    init(
        frameworkPopup: NSPopUpButton,
        controlCombo: NSComboBox,
        filenameField: NSTextField,
        periodField: NSTextField,
        jiraIssueField: NSTextField? = nil,
        previewLabel: NSTextField,
        preferredControlID: String,
        mappingLabel: NSTextField? = nil
    ) {
        self.frameworkPopup = frameworkPopup
        self.controlCombo = controlCombo
        self.filenameField = filenameField
        self.periodField = periodField
        self.jiraIssueField = jiraIssueField
        self.previewLabel = previewLabel
        self.mappingLabel = mappingLabel
        super.init()
        frameworkPopup.target = self
        frameworkPopup.action = #selector(frameworkChanged)
        controlCombo.delegate = self
        filenameField.delegate = self
        periodField.delegate = self
        jiraIssueField?.delegate = self
        populateControls(preferredControlID: preferredControlID)
        updatePreview()
    }

    var frameworkName: String { frameworkPopup.titleOfSelectedItem ?? ComplianceCatalog.defaultFramework.name }
    var controlID: String { ComplianceCatalog.controlID(from: controlCombo.stringValue) }
    var controlTitle: String { ComplianceCatalog.controlTitle(frameworkName: frameworkName, controlID: controlID) ?? "" }

    @objc private func frameworkChanged() {
        populateControls(preferredControlID: "")
        updatePreview()
    }

    private func populateControls(preferredControlID: String) {
        let controls = ComplianceCatalog.framework(named: frameworkName).controls
        controlCombo.removeAllItems()
        controlCombo.addItems(withObjectValues: controls.map(\.displayName))
        if let index = controls.firstIndex(where: { $0.id.caseInsensitiveCompare(preferredControlID) == .orderedSame }) {
            controlCombo.selectItem(at: index)
            controlCombo.stringValue = controls[index].displayName
        } else if !preferredControlID.isEmpty {
            controlCombo.stringValue = preferredControlID
        } else if let first = controls.first {
            controlCombo.selectItem(at: 0)
            controlCombo.stringValue = first.displayName
        }
    }

    func controlTextDidChange(_ obj: Notification) { updatePreview() }
    func comboBoxSelectionDidChange(_ notification: Notification) { updatePreview() }
    func controlTextDidEndEditing(_ obj: Notification) { updatePreview() }

    private func updatePreview() {
        previewLabel.stringValue = ComplianceCatalog.filenamePreview(
            frameworkName: frameworkName,
            controlID: controlID,
            customName: filenameField.stringValue,
            assessmentPeriod: periodField.stringValue,
            jiraIssueKey: jiraIssueField?.stringValue ?? ""
        )
        let mappings = ComplianceCatalog.mappings(frameworkName: frameworkName, controlID: controlID)
        mappingLabel?.stringValue = mappings.isEmpty
            ? "No curated cross-framework mappings for this control."
            : mappings.map { "\(ComplianceCatalog.framework(named: $0.framework).fileCode) \($0.controlID)" }.joined(separator: "  ·  ")
    }
}
