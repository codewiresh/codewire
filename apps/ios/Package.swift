// swift-tools-version: 6.0
import PackageDescription

// Keep the manifest unconditional because xtool strips env vars during
// evaluation. CodewireApp sources are guarded with #if canImport(SwiftUI), and
// the SwiftTerm product dependency is platform-conditional so Linux host tests
// can run without Apple CoreText.
//
// `xtool dev`: builds everything for iOS via --swift-sdk darwin.

let package = Package(
    name: "Codewire",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
    ],
    products: [
        .library(name: "CodewireApp", targets: ["CodewireApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // Fork with cross-compilation patch: platformExcludes removed so
        // Apple/iOS sources are included when xtool cross-compiles from Linux.
        .package(url: "https://github.com/noeljackson/SwiftTerm.git", revision: "77dccb2a81d04f8911032875f9f5b6ce3fee2500"),
    ],
    targets: [
        .target(
            name: "CodewireKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/CodewireKit"
        ),
        .target(
            name: "CodewireApp",
            dependencies: [
                "CodewireKit",
                .product(
                    name: "SwiftTerm",
                    package: "SwiftTerm",
                    condition: .when(platforms: [.iOS, .macOS])
                ),
            ],
            path: "Sources/CodewireApp",
            linkerSettings: [
                .linkedLibrary("resolv"),
            ]
        ),
        .testTarget(
            name: "CodewireKitTests",
            dependencies: ["CodewireKit"],
            path: "Tests/CodewireKitTests"
        ),
    ]
)
