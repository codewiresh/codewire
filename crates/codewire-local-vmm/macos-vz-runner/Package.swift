// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "CodewireVZRunner",
  platforms: [.macOS("15.0")],
  products: [
    .executable(name: "codewire-vz-runner", targets: ["CodewireVZRunner"])
  ],
  targets: [
    .target(
      name: "CVZRunnerIPC",
      path: "Sources/CVZRunnerIPC",
      publicHeadersPath: "include",
      linkerSettings: [.linkedLibrary("proc", .when(platforms: [.macOS]))]
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
    .target(
      name: "CVZRunnerIPCTestSupport",
      dependencies: ["CVZRunnerIPC"],
      path: "Tests/CVZRunnerIPCTestSupport",
      publicHeadersPath: "include"
    ),
    .testTarget(
      name: "CodewireVZRunnerTests",
      dependencies: [
        "CodewireVZRunnerProtocol", "CodewireVZRunnerRuntime", "CVZRunnerIPCTestSupport",
      ],
      path: "Tests/CodewireVZRunnerTests"
    ),
  ]
)
