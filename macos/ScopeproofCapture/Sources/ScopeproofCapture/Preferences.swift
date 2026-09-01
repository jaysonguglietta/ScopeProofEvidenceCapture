import Foundation

struct BrowserChoice: Equatable, Sendable {
    let name: String
    let bundleIdentifier: String?

    static let supported: [BrowserChoice] = [
        BrowserChoice(name: "System Default", bundleIdentifier: nil),
        BrowserChoice(name: "Safari", bundleIdentifier: "com.apple.Safari"),
        BrowserChoice(name: "Google Chrome", bundleIdentifier: "com.google.Chrome"),
        BrowserChoice(name: "Microsoft Edge", bundleIdentifier: "com.microsoft.edgemac"),
        BrowserChoice(name: "Firefox", bundleIdentifier: "org.mozilla.firefox"),
        BrowserChoice(name: "Arc", bundleIdentifier: "company.thebrowser.Browser"),
    ]
}

struct CaptureContext: Codable, Sendable {
    let sessionID: String
    var sessionName: String
    var controlID: String
    var title: String
    var system: String
    var environment: String
    var assessmentPeriod: String
    var description: String
    var complianceArea: String? = nil
    var controlTitle: String? = nil
    var customFileName: String? = nil
    var evidenceOwner: String? = nil
    var tags: [String]? = nil
    var expectedEvidence: String? = nil
    var jiraIssueKey: String? = nil
    var sourceURL: String? = nil

    var isValid: Bool {
        !sessionID.isEmpty && !sessionName.isEmpty && !resolvedComplianceArea.isEmpty && !controlID.isEmpty && !resolvedCustomFileName.isEmpty && !title.isEmpty && !system.isEmpty && !environment.isEmpty && !assessmentPeriod.isEmpty
    }

    var resolvedComplianceArea: String { complianceArea?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "PCI DSS 4.0.1" }
    var resolvedControlTitle: String { controlTitle?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
    var resolvedCustomFileName: String { customFileName?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? title }
    var resolvedEvidenceOwner: String { evidenceOwner?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
    var resolvedTags: [String] {
        Array(Set((tags ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty })).sorted()
    }

    static func new() -> CaptureContext {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy 'Q'Q"
        return CaptureContext(
            sessionID: "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
            sessionName: "",
            controlID: "",
            title: "",
            system: "",
            environment: "Production",
            assessmentPeriod: formatter.string(from: Date()),
            description: "",
            complianceArea: ComplianceCatalog.defaultFramework.name,
            controlTitle: nil,
            customFileName: "",
            evidenceOwner: NSFullUserName(),
            tags: [],
            expectedEvidence: "",
            jiraIssueKey: "",
            sourceURL: ""
        )
    }
}

struct CapturePreset: Codable, Identifiable, Sendable {
    let id: String
    var name: String
    var context: CaptureContext
    var createdAt: String
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}

@MainActor
final class CapturePreferences {
    private let defaults = UserDefaults.standard
    private enum Key {
        static let browser = "capture.browser"
        static let delay = "capture.delay"
        static let targets = "capture.targets"
        static let context = "capture.context"
        static let serverURL = "capture.serverURL"
        static let autoUpload = "capture.autoUpload"
        static let retentionDays = "capture.retentionDays"
        static let lastUpdateCheck = "capture.lastUpdateCheck"
        static let chainHead = "capture.chainHead"
        static let presets = "capture.presets"
        static let jiraHandoff = "capture.jiraHandoff"
        static let openLocalConsoleAtLaunch = "capture.openLocalConsoleAtLaunch"
        static let s3Storage = "capture.s3Storage"
    }

    var browser: BrowserChoice {
        get {
            let saved = defaults.string(forKey: Key.browser)
            return BrowserChoice.supported.first(where: { $0.bundleIdentifier == saved }) ?? .supported[0]
        }
        set { defaults.set(newValue.bundleIdentifier ?? "", forKey: Key.browser) }
    }

    var delay: Int {
        get {
            let value = defaults.integer(forKey: Key.delay)
            return [3, 5, 10, 15].contains(value) ? value : 5
        }
        set { defaults.set(newValue, forKey: Key.delay) }
    }

    var targets: [String] {
        get {
            let saved = defaults.stringArray(forKey: Key.targets) ?? []
            return saved
        }
        set { defaults.set(Array(newValue.prefix(12)), forKey: Key.targets) }
    }

    var activeContext: CaptureContext? {
        get {
            guard let data = defaults.data(forKey: Key.context) else { return nil }
            return try? JSONDecoder().decode(CaptureContext.self, from: data)
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: Key.context) }
    }

    var serverURL: URL? {
        get {
            if defaults.object(forKey: Key.serverURL) == nil { return nil }
            return defaults.string(forKey: Key.serverURL).flatMap(URL.init(string:))
        }
        set { defaults.set(newValue?.absoluteString ?? "", forKey: Key.serverURL) }
    }

    var autoUpload: Bool {
        get { defaults.object(forKey: Key.autoUpload) == nil ? false : defaults.bool(forKey: Key.autoUpload) }
        set { defaults.set(newValue, forKey: Key.autoUpload) }
    }

    var openLocalConsoleAtLaunch: Bool {
        get { defaults.object(forKey: Key.openLocalConsoleAtLaunch) == nil ? true : defaults.bool(forKey: Key.openLocalConsoleAtLaunch) }
        set { defaults.set(newValue, forKey: Key.openLocalConsoleAtLaunch) }
    }

    var retentionDays: Int {
        get {
            let value = defaults.integer(forKey: Key.retentionDays)
            return [30, 90, 180, 365, 1095].contains(value) ? value : 365
        }
        set { defaults.set(newValue, forKey: Key.retentionDays) }
    }

    var chainHead: String {
        get { defaults.string(forKey: Key.chainHead) ?? "GENESIS" }
        set { defaults.set(newValue, forKey: Key.chainHead) }
    }

    var lastUpdateCheck: Date? {
        get { defaults.object(forKey: Key.lastUpdateCheck) as? Date }
        set { defaults.set(newValue, forKey: Key.lastUpdateCheck) }
    }

    var presets: [CapturePreset] {
        get {
            guard let data = defaults.data(forKey: Key.presets), let value = try? JSONDecoder().decode([CapturePreset].self, from: data) else { return [] }
            return value.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        }
        set { defaults.set(try? JSONEncoder().encode(Array(newValue.prefix(50))), forKey: Key.presets) }
    }

    var jiraHandoff: JiraHandoffSettings {
        get {
            guard let data = defaults.data(forKey: Key.jiraHandoff), let value = try? JSONDecoder().decode(JiraHandoffSettings.self, from: data) else { return .defaults }
            return value
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: Key.jiraHandoff) }
    }

    var s3Storage: S3StorageSettings {
        get {
            guard let data = defaults.data(forKey: Key.s3Storage), let value = try? JSONDecoder().decode(S3StorageSettings.self, from: data) else { return .defaults }
            return value
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: Key.s3Storage) }
    }

    func savePreset(name: String, context: CaptureContext) {
        let cleanName = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80))
        guard !cleanName.isEmpty else { return }
        var updated = presets.filter { $0.name.caseInsensitiveCompare(cleanName) != .orderedSame }
        updated.append(CapturePreset(id: "preset_\(UUID().uuidString.lowercased())", name: cleanName, context: context, createdAt: ISO8601DateFormatter().string(from: Date())))
        presets = updated
    }

    func deletePreset(id: String) { presets = presets.filter { $0.id != id } }

    func addTarget(_ target: String) {
        var updated = targets.filter { $0 != target }
        updated.insert(target, at: 0)
        targets = updated
    }
}
