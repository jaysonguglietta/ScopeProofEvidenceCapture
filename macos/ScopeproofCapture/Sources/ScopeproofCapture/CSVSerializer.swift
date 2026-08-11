import Foundation

enum CSVSerializer {
    static func cell(_ value: String) -> String {
        let firstSignificant = value.unicodeScalars.first { $0.value > 0x20 }
        let neutralized: String
        if let scalar = firstSignificant, ["=", "+", "-", "@"].contains(Character(String(scalar))) {
            neutralized = "'" + value
        } else {
            neutralized = value
        }
        return "\"\(neutralized.replacingOccurrences(of: "\"", with: "\"\""))\""
    }
}
