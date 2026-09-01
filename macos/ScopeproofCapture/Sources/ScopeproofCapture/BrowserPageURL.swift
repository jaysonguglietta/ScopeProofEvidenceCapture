@preconcurrency import AppKit
import Foundation

enum BrowserPageURL {
    static func appleScriptSource(for browserName: String) -> String? {
        switch browserName.lowercased() {
        case "safari":
            return #"tell application id "com.apple.Safari" to get URL of front document"#
        case "google chrome":
            return #"tell application id "com.google.Chrome" to get URL of active tab of front window"#
        case "microsoft edge":
            return #"tell application id "com.microsoft.edgemac" to get URL of active tab of front window"#
        case "arc":
            return #"tell application id "company.thebrowser.Browser" to get URL of active tab of front window"#
        default:
            return nil
        }
    }

    static func detectedURL(for browserName: String, execute: (String) -> String?) -> URL? {
        guard let source = appleScriptSource(for: browserName), let rawURL = execute(source) else { return nil }
        return EvidenceSourceURL.sanitized(rawURL)
    }

    @MainActor
    static func currentURL(for browserName: String) -> URL? {
        detectedURL(for: browserName) { source in
            guard let script = NSAppleScript(source: source) else { return nil }
            var error: NSDictionary?
            let result = script.executeAndReturnError(&error)
            guard error == nil else { return nil }
            return result.stringValue
        }
    }
}
