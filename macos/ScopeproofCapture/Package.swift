// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ScopeproofCapture",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "ScopeproofCapture", targets: ["ScopeproofCapture"])],
    targets: [
        .executableTarget(name: "ScopeproofCapture"),
        .testTarget(name: "ScopeproofCaptureTests", dependencies: ["ScopeproofCapture"]),
    ]
)
