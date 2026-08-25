import CryptoKit
import Foundation

struct ComplianceControl: Codable, Hashable, Sendable {
    let id: String
    let title: String
    var displayName: String { title.isEmpty ? id : "\(id) — \(title)" }
}

struct ComplianceFramework: Codable, Hashable, Sendable {
    let name: String
    let fileCode: String
    let folderName: String
    let controls: [ComplianceControl]
    var version: String? = nil
    var source: String? = nil
}

struct ControlMapping: Codable, Hashable, Sendable {
    let framework: String
    let controlID: String
    let relationship: String
}

enum ComplianceCatalog {
    static let catalogVersion = "2026.08"
    private static let importedCatalogsKey = "capture.importedControlCatalogs"
    static let builtInFrameworks: [ComplianceFramework] = [
        ComplianceFramework(name: "PCI DSS 4.0.1", fileCode: "PCI", folderName: "PCI", controls: [
            .init(id: "1.1.1", title: "Security policy and operational procedures"),
            .init(id: "1.2.1", title: "Network security controls configured and maintained"),
            .init(id: "1.2.5", title: "Permitted services, protocols, and ports"),
            .init(id: "1.3.1", title: "Inbound traffic restricted to the CDE"),
            .init(id: "1.4.2", title: "Inbound traffic from untrusted networks restricted"),
            .init(id: "2.2.1", title: "System configuration standards"),
            .init(id: "2.2.2", title: "Vendor default accounts managed"),
            .init(id: "2.2.5", title: "Unnecessary services removed or disabled"),
            .init(id: "3.3.1", title: "Sensitive authentication data not retained"),
            .init(id: "3.4.1", title: "PAN rendered unreadable"),
            .init(id: "3.5.1", title: "Cryptographic keys protected"),
            .init(id: "4.2.1", title: "Strong cryptography protects PAN in transit"),
            .init(id: "5.2.1", title: "Anti-malware mechanisms deployed"),
            .init(id: "5.3.3", title: "Anti-malware mechanisms active and current"),
            .init(id: "6.2.4", title: "Software engineering techniques prevent attacks"),
            .init(id: "6.3.3", title: "Security vulnerabilities remediated"),
            .init(id: "6.4.2", title: "Automated public-facing application protection"),
            .init(id: "6.5.1", title: "Changes managed securely"),
            .init(id: "7.2.1", title: "Access control model defined"),
            .init(id: "7.2.2", title: "Access assigned by job and least privilege"),
            .init(id: "7.2.5", title: "Access reviewed at least every six months"),
            .init(id: "8.2.1", title: "User identification and account management"),
            .init(id: "8.3.1", title: "Strong authentication for users and administrators"),
            .init(id: "8.4.2", title: "MFA for access into the CDE"),
            .init(id: "8.6.1", title: "System and application accounts managed"),
            .init(id: "9.2.1", title: "Physical access controls"),
            .init(id: "10.2.1", title: "Audit logs enabled and active"),
            .init(id: "10.4.1", title: "Audit logs reviewed daily"),
            .init(id: "10.5.1", title: "Audit history retained"),
            .init(id: "11.3.1", title: "Internal vulnerability scans"),
            .init(id: "11.4.1", title: "Penetration testing methodology"),
            .init(id: "11.5.1", title: "Change- and tamper-detection mechanisms"),
            .init(id: "12.3.1", title: "Targeted risk analyses documented"),
            .init(id: "12.6.1", title: "Security awareness program"),
            .init(id: "12.10.1", title: "Incident response plan")
        ]),
        ComplianceFramework(name: "HIPAA Security Rule", fileCode: "HIPAA", folderName: "HIPAA", controls: [
            .init(id: "164.308(a)(1)(i)", title: "Security management process"),
            .init(id: "164.308(a)(1)(ii)(A)", title: "Risk analysis"),
            .init(id: "164.308(a)(1)(ii)(B)", title: "Risk management"),
            .init(id: "164.308(a)(1)(ii)(C)", title: "Sanction policy"),
            .init(id: "164.308(a)(1)(ii)(D)", title: "Information system activity review"),
            .init(id: "164.308(a)(3)", title: "Workforce security"),
            .init(id: "164.308(a)(4)", title: "Information access management"),
            .init(id: "164.308(a)(5)", title: "Security awareness and training"),
            .init(id: "164.308(a)(6)", title: "Security incident procedures"),
            .init(id: "164.308(a)(7)", title: "Contingency plan"),
            .init(id: "164.308(a)(8)", title: "Evaluation"),
            .init(id: "164.310(a)", title: "Facility access controls"),
            .init(id: "164.310(b)", title: "Workstation use"),
            .init(id: "164.310(c)", title: "Workstation security"),
            .init(id: "164.310(d)", title: "Device and media controls"),
            .init(id: "164.312(a)(1)", title: "Access control"),
            .init(id: "164.312(b)", title: "Audit controls"),
            .init(id: "164.312(c)(1)", title: "Integrity"),
            .init(id: "164.312(d)", title: "Person or entity authentication"),
            .init(id: "164.312(e)(1)", title: "Transmission security"),
            .init(id: "164.314", title: "Organizational requirements"),
            .init(id: "164.316", title: "Policies, procedures, and documentation")
        ]),
        ComplianceFramework(name: "FedRAMP / NIST 800-53", fileCode: "FEDRAMP", folderName: "FedRAMP", controls: [
            .init(id: "AC-2", title: "Account Management"), .init(id: "AC-3", title: "Access Enforcement"),
            .init(id: "AC-6", title: "Least Privilege"), .init(id: "AC-17", title: "Remote Access"),
            .init(id: "AU-2", title: "Event Logging"), .init(id: "AU-6", title: "Audit Record Review, Analysis, and Reporting"),
            .init(id: "AU-9", title: "Protection of Audit Information"), .init(id: "CA-2", title: "Control Assessments"),
            .init(id: "CA-7", title: "Continuous Monitoring"), .init(id: "CM-2", title: "Baseline Configuration"),
            .init(id: "CM-6", title: "Configuration Settings"), .init(id: "CP-9", title: "System Backup"),
            .init(id: "IA-2", title: "Identification and Authentication"), .init(id: "IA-5", title: "Authenticator Management"),
            .init(id: "IR-4", title: "Incident Handling"), .init(id: "RA-5", title: "Vulnerability Monitoring and Scanning"),
            .init(id: "SC-7", title: "Boundary Protection"), .init(id: "SC-8", title: "Transmission Confidentiality and Integrity"),
            .init(id: "SC-13", title: "Cryptographic Protection"), .init(id: "SI-2", title: "Flaw Remediation"),
            .init(id: "SI-3", title: "Malicious Code Protection"), .init(id: "SI-4", title: "System Monitoring")
        ]),
        ComplianceFramework(name: "SOC 2", fileCode: "SOC2", folderName: "SOC 2", controls: [
            .init(id: "CC1.1", title: "Integrity and ethical values"), .init(id: "CC1.2", title: "Board oversight"),
            .init(id: "CC2.1", title: "Quality information"), .init(id: "CC2.2", title: "Internal communication"),
            .init(id: "CC3.1", title: "Objectives and risk identification"), .init(id: "CC3.2", title: "Risk identification and analysis"),
            .init(id: "CC4.1", title: "Ongoing and separate evaluations"), .init(id: "CC5.2", title: "Technology control activities"),
            .init(id: "CC6.1", title: "Logical and physical access controls"), .init(id: "CC6.2", title: "User registration and authorization"),
            .init(id: "CC6.6", title: "System boundary protections"), .init(id: "CC6.7", title: "Restricted transmission and movement"),
            .init(id: "CC7.1", title: "Configuration and vulnerability monitoring"), .init(id: "CC7.2", title: "Security event monitoring"),
            .init(id: "CC7.3", title: "Security event evaluation"), .init(id: "CC7.4", title: "Incident response"),
            .init(id: "CC8.1", title: "Change management"), .init(id: "CC9.1", title: "Business disruption risk"),
            .init(id: "A1.2", title: "Environmental protections and recovery"), .init(id: "C1.1", title: "Confidential information protection")
        ]),
        ComplianceFramework(name: "ISO/IEC 27001:2022", fileCode: "ISO27001", folderName: "ISO 27001", controls: [
            .init(id: "A.5.1", title: "Policies for information security"), .init(id: "A.5.15", title: "Access control"),
            .init(id: "A.5.16", title: "Identity management"), .init(id: "A.5.17", title: "Authentication information"),
            .init(id: "A.5.18", title: "Access rights"), .init(id: "A.5.23", title: "Cloud service security"),
            .init(id: "A.5.24", title: "Incident management planning"), .init(id: "A.5.30", title: "ICT readiness for business continuity"),
            .init(id: "A.6.3", title: "Security awareness, education and training"), .init(id: "A.7.2", title: "Physical entry"),
            .init(id: "A.8.2", title: "Privileged access rights"), .init(id: "A.8.5", title: "Secure authentication"),
            .init(id: "A.8.7", title: "Protection against malware"), .init(id: "A.8.8", title: "Management of technical vulnerabilities"),
            .init(id: "A.8.9", title: "Configuration management"), .init(id: "A.8.13", title: "Information backup"),
            .init(id: "A.8.15", title: "Logging"), .init(id: "A.8.16", title: "Monitoring activities"),
            .init(id: "A.8.20", title: "Network security"), .init(id: "A.8.24", title: "Use of cryptography"),
            .init(id: "A.8.25", title: "Secure development life cycle"), .init(id: "A.8.32", title: "Change management")
        ]),
        ComplianceFramework(name: "Custom / Other", fileCode: "CUSTOM", folderName: "Custom", controls: [
            .init(id: "CUSTOM", title: "Enter a custom control identifier")
        ])
    ]

    static var frameworks: [ComplianceFramework] {
        let imported = importedFrameworks
        let importedNames = Set(imported.map(\.name))
        return imported + builtInFrameworks.filter { !importedNames.contains($0.name) }
    }

    static var importedFrameworks: [ComplianceFramework] {
        guard let data = UserDefaults.standard.data(forKey: importedCatalogsKey) else { return [] }
        return (try? JSONDecoder().decode([ComplianceFramework].self, from: data)) ?? []
    }

    static func removeImportedCatalog(named name: String) {
        let remaining = importedFrameworks.filter { $0.name != name }
        UserDefaults.standard.set(try? JSONEncoder().encode(remaining), forKey: importedCatalogsKey)
    }

    static var defaultFramework: ComplianceFramework { builtInFrameworks[0] }

    static func framework(named name: String?) -> ComplianceFramework {
        frameworks.first(where: { $0.name == name }) ?? defaultFramework
    }

    static func controlID(from displayValue: String) -> String {
        displayValue.components(separatedBy: " — ").first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? displayValue
    }

    static func controlTitle(frameworkName: String, controlID: String) -> String? {
        framework(named: frameworkName).controls.first(where: { $0.id.caseInsensitiveCompare(controlID) == .orderedSame })?.title
    }

    static func mappings(frameworkName: String, controlID: String) -> [ControlMapping] {
        let key = "\(framework(named: frameworkName).fileCode):\(controlID.uppercased())"
        let map: [String: [ControlMapping]] = [
            "PCI:8.3.1": [.init(framework: "HIPAA Security Rule", controlID: "164.312(d)", relationship: "Authentication"), .init(framework: "FedRAMP / NIST 800-53", controlID: "IA-2", relationship: "Authentication"), .init(framework: "SOC 2", controlID: "CC6.1", relationship: "Logical access"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.8.5", relationship: "Secure authentication")],
            "PCI:8.4.2": [.init(framework: "FedRAMP / NIST 800-53", controlID: "IA-2", relationship: "Multi-factor authentication"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.8.5", relationship: "Secure authentication")],
            "PCI:10.2.1": [.init(framework: "HIPAA Security Rule", controlID: "164.312(b)", relationship: "Audit controls"), .init(framework: "FedRAMP / NIST 800-53", controlID: "AU-2", relationship: "Event logging"), .init(framework: "SOC 2", controlID: "CC7.2", relationship: "Security monitoring"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.8.15", relationship: "Logging")],
            "PCI:7.2.5": [.init(framework: "HIPAA Security Rule", controlID: "164.308(a)(4)", relationship: "Access review"), .init(framework: "FedRAMP / NIST 800-53", controlID: "AC-2", relationship: "Account management"), .init(framework: "SOC 2", controlID: "CC6.2", relationship: "Authorization"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.5.18", relationship: "Access rights")],
            "HIPAA:164.312(B)": [.init(framework: "PCI DSS 4.0.1", controlID: "10.2.1", relationship: "Audit logging"), .init(framework: "FedRAMP / NIST 800-53", controlID: "AU-2", relationship: "Event logging"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.8.15", relationship: "Logging")],
            "FEDRAMP:AU-2": [.init(framework: "PCI DSS 4.0.1", controlID: "10.2.1", relationship: "Audit logging"), .init(framework: "HIPAA Security Rule", controlID: "164.312(b)", relationship: "Audit controls"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.8.15", relationship: "Logging")],
            "SOC2:CC6.1": [.init(framework: "PCI DSS 4.0.1", controlID: "7.2.1", relationship: "Access control"), .init(framework: "HIPAA Security Rule", controlID: "164.312(a)(1)", relationship: "Access control"), .init(framework: "FedRAMP / NIST 800-53", controlID: "AC-3", relationship: "Access enforcement"), .init(framework: "ISO/IEC 27001:2022", controlID: "A.5.15", relationship: "Access control")],
            "ISO27001:A.8.15": [.init(framework: "PCI DSS 4.0.1", controlID: "10.2.1", relationship: "Audit logging"), .init(framework: "HIPAA Security Rule", controlID: "164.312(b)", relationship: "Audit controls"), .init(framework: "FedRAMP / NIST 800-53", controlID: "AU-2", relationship: "Event logging")],
        ]
        return map[key] ?? []
    }

    static func importCatalog(from url: URL) throws -> ComplianceFramework {
        let resource = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard resource.isRegularFile == true, let fileSize = resource.fileSize, fileSize > 0, fileSize <= 5 * 1024 * 1024 else { throw CocoaError(.fileReadTooLarge) }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard data.count == fileSize else { throw CocoaError(.fileReadCorruptFile) }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let framework: ComplianceFramework
        if url.pathExtension.lowercased() == "csv" {
            let lines = String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline)
            guard lines.count > 1 else { throw CocoaError(.fileReadCorruptFile) }
            let controls = lines.dropFirst().compactMap { line -> ComplianceControl? in
                let values = line.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false).map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: " \"")) }
                guard let id = values.first, !id.isEmpty else { return nil }
                return ComplianceControl(id: String(id.prefix(80)), title: String((values.count > 1 ? values[1] : "").prefix(240)))
            }
            guard !controls.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
            let name = url.deletingPathExtension().lastPathComponent
            framework = ComplianceFramework(name: name, fileCode: safeFileBase(name).uppercased(), folderName: safePathComponent(name), controls: controls, version: nil, source: url.lastPathComponent)
        } else {
            if let decoded = try? JSONDecoder().decode(ComplianceFramework.self, from: data) {
                framework = decoded
            } else {
                let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                let catalog = object?["catalog"] as? [String: Any]
                let groups = catalog?["groups"] as? [[String: Any]] ?? []
                let controls = groups.flatMap { $0["controls"] as? [[String: Any]] ?? [] }.compactMap { item -> ComplianceControl? in
                    guard let id = item["id"] as? String, !id.isEmpty else { return nil }
                    return ComplianceControl(id: String(id.prefix(80)), title: String((item["title"] as? String ?? "").prefix(240)))
                }
                guard let name = catalog?["title"] as? String, !controls.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
                framework = ComplianceFramework(name: name, fileCode: safeFileBase(name).uppercased(), folderName: safePathComponent(name), controls: controls, version: catalog?["version"] as? String, source: "OSCAL · \(url.lastPathComponent)")
            }
        }
        let cleanName = String(framework.name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        guard !cleanName.isEmpty, !framework.controls.isEmpty, framework.controls.count <= 5_000 else { throw CocoaError(.fileReadCorruptFile) }
        let controls = framework.controls.map { ComplianceControl(id: String($0.id.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)), title: String($0.title.trimmingCharacters(in: .whitespacesAndNewlines).prefix(240))) }.filter { !$0.id.isEmpty }
        let normalizedIDs = controls.map { $0.id.lowercased() }
        guard Set(normalizedIDs).count == normalizedIDs.count else { throw CocoaError(.fileReadCorruptFile) }
        let source = framework.source.map { String($0.prefix(140)) } ?? url.lastPathComponent
        let normalized = ComplianceFramework(
            name: cleanName,
            fileCode: String(safeFileBase(framework.fileCode).uppercased().prefix(24)),
            folderName: safePathComponent(framework.folderName, fallback: "Imported", maximumLength: 100),
            controls: controls,
            version: framework.version.map { String($0.prefix(80)) }, source: "\(source) · SHA-256 \(digest)"
        )
        guard !normalized.controls.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
        var imported = frameworks.filter { $0.source != nil && $0.name != normalized.name }
        imported.append(normalized)
        UserDefaults.standard.set(try JSONEncoder().encode(imported), forKey: importedCatalogsKey)
        return normalized
    }

    static func safePathComponent(_ value: String, fallback: String = "Unclassified", maximumLength: Int = 100) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_. "))
        let mapped = value.unicodeScalars.map { allowed.contains($0) ? Character(String($0)) : "-" }
        var result = String(mapped)
        while result.contains("--") { result = result.replacingOccurrences(of: "--", with: "-") }
        result = result.trimmingCharacters(in: CharacterSet(charactersIn: " .-_"))
        if result.isEmpty { result = fallback }
        return String(result.prefix(maximumLength))
    }

    static func safeFileBase(_ value: String) -> String {
        let readable = safePathComponent(value, fallback: "Evidence", maximumLength: 80)
        return readable.replacingOccurrences(of: " ", with: "-")
    }

    static func filenamePreview(frameworkName: String, controlID: String, customName: String, assessmentPeriod: String, jiraIssueKey: String = "") -> String {
        let framework = framework(named: frameworkName)
        let control = safeFileBase(controlID)
        let name = safeFileBase(customName)
        let period = safeFileBase(assessmentPeriod)
        let jira = JiraHandoff.normalizedIssueKey(jiraIssueKey)
        let jiraComponent = jira.isEmpty ? "" : "_\(safeFileBase(jira))"
        return "\(framework.folderName) / \(control) / \(period) / \(framework.fileCode)_\(control)\(jiraComponent)_\(name)_<date>_<evidence-id>.png"
    }
}
