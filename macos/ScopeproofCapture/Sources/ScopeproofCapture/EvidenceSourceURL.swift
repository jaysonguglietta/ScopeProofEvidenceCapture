import Foundation

enum EvidenceSourceURL {
    static let maximumLength = 2_048

    /// Returns a URL that may be used for the one-time navigation operation. It is
    /// deliberately separate from `sanitized`, which is the much narrower value
    /// permitted to cross the evidence persistence boundary.
    static func navigationURL(_ rawValue: String?) -> URL? {
        guard let rawValue else { return nil }
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= maximumLength,
              !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }),
              var components = URLComponents(string: value),
              ["http", "https"].contains(components.scheme?.lowercased() ?? ""),
              let host = components.host, !host.isEmpty else { return nil }
        components.scheme = components.scheme?.lowercased()
        components.host = host.lowercased()
        components.user = nil
        components.password = nil
        guard let validated = components.url, validated.absoluteString.utf8.count <= maximumLength else { return nil }
        return validated
    }

    static func sanitized(_ rawValue: String?) -> URL? {
        guard let navigation = navigationURL(rawValue),
              var components = URLComponents(url: navigation, resolvingAgainstBaseURL: false) else { return nil }
        // Source provenance is origin-only by default. Paths can contain reset,
        // invitation, tenant, and opaque bearer material just as readily as query
        // strings, so pattern matching is not an adequate persistence boundary.
        components.path = ""
        components.query = nil
        components.fragment = nil
        guard let sanitized = components.url, sanitized.absoluteString.utf8.count <= maximumLength else { return nil }
        return sanitized
    }

    static func savedTarget(_ rawValue: String?) -> URL? {
        guard let navigation = navigationURL(rawValue),
              var components = URLComponents(url: navigation, resolvingAgainstBaseURL: false) else { return nil }
        // Saved navigation targets may retain a useful path, but never credentials,
        // queries, or fragments that can behave as bearer secrets.
        components.query = nil
        components.fragment = nil
        return components.url
    }

    static func isValidOrEmpty(_ rawValue: String) -> Bool {
        rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || sanitized(rawValue) != nil
    }

}
