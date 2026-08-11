import Foundation

enum JiraAttachmentMode: String, Codable, CaseIterable, Sendable {
    case evidenceSet = "Evidence set (PNG + metadata)"
    case assessorPackage = "Approved assessor ZIP + checksum"
}

struct JiraHandoffSettings: Codable, Sendable {
    var baseURL: String
    var projectKey: String
    var attachmentMode: JiraAttachmentMode
    var includeGuideInPackages: Bool
    var customInstructions: String

    static let defaults = JiraHandoffSettings(baseURL: "", projectKey: "", attachmentMode: .evidenceSet, includeGuideInPackages: true, customInstructions: "")

    var isConfigured: Bool { validatedBaseURL != nil || !projectKey.isEmpty }
    var validatedBaseURL: URL? {
        guard let url = URL(string: baseURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else { return nil }
        return url
    }

    func issueURL(for key: String) -> URL? {
        guard let base = validatedBaseURL, JiraHandoff.isValidIssueKey(key) else { return nil }
        return base.appendingPathComponent("browse", isDirectory: true).appendingPathComponent(key.uppercased())
    }
}

enum JiraHandoff {
    static func isValidProjectKey(_ value: String) -> Bool {
        value.isEmpty || value.range(of: #"^[A-Z][A-Z0-9_]{1,31}$"#, options: .regularExpression) != nil
    }

    static func isValidIssueKey(_ value: String) -> Bool {
        value.isEmpty || value.uppercased().range(of: #"^[A-Z][A-Z0-9_]{1,31}-[1-9][0-9]*$"#, options: .regularExpression) != nil
    }

    static func normalizedIssueKey(_ value: String) -> String {
        String(value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().prefix(80))
    }

    static func comment(for entry: CaptureHistoryEntry, settings: JiraHandoffSettings) -> String {
        let manifest = entry.manifest
        let lifecycle = entry.lifecycle
        let issueKey = manifest.jiraIssueKey ?? "Not assigned"
        let receipt = FileManager.default.fileExists(atPath: entry.receiptURL.path) ? entry.receiptURL.lastPathComponent : "Not available (local-only or upload pending)"
        let jiraReceipt = FileManager.default.fileExists(atPath: entry.jiraReceiptURL.path) ? entry.jiraReceiptURL.lastPathComponent : "Not available (not uploaded through Scopeproof Jira Cloud)"
        let lifecycleName = EvidenceLifecycleStore.url(for: entry.manifestURL).lastPathComponent
        let issueURL = manifest.jiraIssueURL ?? settings.issueURL(for: issueKey)?.absoluteString ?? "Not configured"
        return """
        Scopeproof compliance evidence

        Jira issue: \(issueKey)
        Jira URL: \(issueURL)
        Evidence ID: \(manifest.evidenceID)
        Framework / control: \(manifest.complianceArea ?? "PCI DSS 4.0.1") · \(manifest.controlID)\(manifest.controlTitle.map { " — \($0)" } ?? "")
        Evidence title: \(manifest.title)
        System / environment: \(manifest.system) / \(manifest.environment)
        Assessment period: \(manifest.assessmentPeriod)
        Captured: \(manifest.localTimestamp)
        Review status: \(lifecycle.status.rawValue)
        Owner / reviewer: \(lifecycle.owner.isEmpty ? "Unassigned" : lifecycle.owner) / \(lifecycle.reviewer.isEmpty ? "Not reviewed" : lifecycle.reviewer)
        Screenshot SHA-256: \(manifest.sha256)

        Attachments
        - \(entry.imageURL.lastPathComponent) — assessor-visible screenshot
        - \(entry.manifestURL.lastPathComponent) — immutable capture and integrity manifest
        - \(lifecycleName) — review status and hash-chained decision history
        - \(receipt) — signed server receipt when available
        - \(jiraReceipt) — signed Jira Cloud upload receipt when available

        What this proves
        \(manifest.description.isEmpty ? (manifest.expectedEvidence ?? "See the screenshot and control context.") : manifest.description)

        Handling note
        Attach only to a Jira project whose permissions and retention policy are approved for this evidence classification. Never attach an unredacted source image, authentication token, or private key. Confirm the SHA-256 after download or transfer.
        """
    }

    static func packageGuide(settings: JiraHandoffSettings, entries: [CaptureHistoryEntry]) -> String {
        let assigned = Dictionary(grouping: entries.filter { !($0.manifest.jiraIssueKey ?? "").isEmpty }, by: { $0.manifest.jiraIssueKey! })
        let issueLines = assigned.keys.sorted().map { key in
            let ids = assigned[key, default: []].map { $0.manifest.evidenceID }.joined(separator: ", ")
            let url = settings.issueURL(for: key)?.absoluteString ?? "URL not configured"
            return "- \(key): \(ids) · \(url)"
        }
        return """
        SCOPEPROOF → JIRA HANDOFF GUIDE

        Jira site: \(settings.validatedBaseURL?.absoluteString ?? "Not configured")
        Default project: \(settings.projectKey.isEmpty ? "Not configured" : settings.projectKey)
        Preferred attachment method: \(settings.attachmentMode.rawValue)

        RECOMMENDED PROCESS
        1. Confirm the Jira project and issue are approved to store the evidence classification and inherit the correct auditor/reviewer permissions.
        2. Confirm each evidence item is Approved and the Jira key in the evidence index matches the intended ticket.
        3. For an evidence set, attach the PNG, capture manifest, review lifecycle, and signed receipt together. For a package handoff, attach the approved ZIP and its separate .sha256.txt file together.
        4. Paste the Scopeproof Jira comment generated from Search Evidence into the ticket description or comment.
        5. After attachment, download the file from Jira and compare its SHA-256 with the Scopeproof manifest or checksum.
        6. Record the Jira ticket in the assessment workpapers. Restrict access and retention according to organizational policy.

        DO NOT ATTACH
        - Unredacted source screenshots
        - Browser cookies, session values, passwords, access tokens, private keys, or PAN
        - Draft, Rejected, or Superseded evidence presented as current proof

        EVIDENCE ASSOCIATED WITH JIRA
        \(issueLines.isEmpty ? "No Jira issue keys were assigned in this package." : issueLines.joined(separator: "\n"))

        ORGANIZATION-SPECIFIC INSTRUCTIONS
        \(settings.customInstructions.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "None configured." : settings.customInstructions)
        """
    }
}
