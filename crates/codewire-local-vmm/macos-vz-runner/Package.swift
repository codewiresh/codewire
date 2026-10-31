// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "CodewireVZRunner",
  platforms: [.macOS("26.0")],
  products: [
    .executable(name: "codewire-vz-runner", targets: ["CodewireVZRunner"])
  ],
  targets: [
    .target(
      name: "CVZRunnerIPC",
      path: "Sources/CVZRunnerIPC",
      publicHeadersPath: "include"
    ),
    .target(
      name: "CodewireVZRunnerProtocol",
      dependencies: ["CVZRunnerIPC"],
      path: "Sources/CodewireVZRunnerProtocol"
    ),
    .target(
      name: "CodewireVZRunnerRuntime",
      dependencies: ["CodewireVZRunnerProtocol"],
      path: "Sources/CodewireVZRunnerRuntime",
      linkerSettings: [
        .linkedFramework("Virtualization", .when(platforms: [.macOS]))
      ]
    ),
    .executableTarget(
      name: "CodewireVZRunner",
      dependencies: ["CVZRunnerIPC", "CodewireVZRunnerProtocol", "CodewireVZRunnerRuntime"],
      path: "Sources/CodewireVZRunner"
    ),
    .testTarget(
      name: "CodewireVZRunnerTests",
      dependencies: ["CVZRunnerIPC", "CodewireVZRunnerProtocol", "CodewireVZRunnerRuntime"],
      path: "Tests/CodewireVZRunnerTests"
    ),
  ]
)
