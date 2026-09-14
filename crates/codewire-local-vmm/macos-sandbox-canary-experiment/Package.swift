// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "CodewireMacOSSandboxCanaryExperiment",
  platforms: [.macOS("15.0")],
  products: [
    .executable(name: "sandbox-experiment-owner", targets: ["SandboxExperimentOwner"]),
    .executable(name: "sandbox-candidate", targets: ["SandboxCandidate"]),
    .executable(name: "canary-deputy", targets: ["CanaryDeputy"]),
  ],
  targets: [
    .target(
      name: "CCanarySupport",
      path: "Sources/CCanarySupport",
      publicHeadersPath: "include",
      linkerSettings: [
        .linkedFramework("Security", .when(platforms: [.macOS])),
        .linkedLibrary("bsm", .when(platforms: [.macOS])),
      ]
    ),
    .target(
      name: "SandboxCanaryProtocol",
      dependencies: ["CCanarySupport"],
      path: "Sources/SandboxCanaryProtocol"
    ),
    .executableTarget(
      name: "SandboxExperimentOwner",
      dependencies: ["SandboxCanaryProtocol", "CCanarySupport"],
      path: "Sources/SandboxExperimentOwner",
      linkerSettings: [.linkedFramework("Security", .when(platforms: [.macOS]))]
    ),
    .executableTarget(
      name: "SandboxCandidate",
      dependencies: ["SandboxCanaryProtocol"],
      path: "Sources/SandboxCandidate",
      linkerSettings: [.linkedFramework("AppKit", .when(platforms: [.macOS]))]
    ),
    .executableTarget(
      name: "CanaryDeputy",
      dependencies: ["SandboxCanaryProtocol"],
      path: "Sources/CanaryDeputy",
      linkerSettings: [.linkedFramework("AppKit", .when(platforms: [.macOS]))]
    ),
    .testTarget(
      name: "SandboxCanaryProtocolTests",
      dependencies: ["SandboxCanaryProtocol", "CCanarySupport"],
      path: "Tests/SandboxCanaryProtocolTests"
    ),
  ]
)
