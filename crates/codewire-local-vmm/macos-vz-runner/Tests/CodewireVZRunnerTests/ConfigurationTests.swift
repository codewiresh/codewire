import CodewireVZRunnerProtocol
import Foundation
import Testing

@Suite(.serialized) struct CodewireVZRunnerTests {
  @Suite struct ConfigurationTests {
    @Test
    func testCanonicalConfigurationIsAccepted() throws {
      let configuration = try RunnerConfiguration.decode(canonical())
      #expect(configuration.schemaVersion == 1)
      #expect(configuration.vmID == "00000000-0000-4000-8000-000000000001")
      #expect(configuration.dataDisk.size == 256 * 1024 * 1024)
      #expect(RunnerProtocol.guestKernelCommandLine == "console=ttyS0 rdinit=/init panic=-1")
      #expect(
        RunnerProtocol.inodeProbeKernelCommandLine
          == "console=ttyS0 rdinit=/init panic=-1 -- vz-inode-probe"
      )
      #expect(RunnerProtocol.inodeProbeVsockPort == 7775)
    }

    @Test
    func testUnknownRootAndNestedFieldsAreRejected() {
      for replacement in [
        "\"extra\":true,\"schemaVersion\":1",
        "\"schemaVersion\":1,\"kernelExtra\":true",
      ] {
        let bytes = canonicalText().replacingOccurrences(
          of: "\"schemaVersion\":1", with: replacement
        ).data(using: .utf8)!
        expectConfigurationError(.unknownFields) { _ = try RunnerConfiguration.decode(bytes) }
      }
      let nested = canonicalText().replacingOccurrences(
        of: "\"sha256\":\"\(String(repeating: "a", count: 64))\"",
        with: "\"extra\":true,\"sha256\":\"\(String(repeating: "a", count: 64))\""
      ).data(using: .utf8)!
      expectConfigurationError(.unknownFields) { _ = try RunnerConfiguration.decode(nested) }
    }

    @Test
    func testIdentityGenerationResourceAndPortBoundsFailClosed() {
      let cases: [(String, String, ConfigurationError)] = [
        ("\"schemaVersion\":1", "\"schemaVersion\":2", .unsupportedSchema),
        ("00000000-0000-4000-8000-000000000001", "not-a-uuid", .invalidIdentity),
        ("\"generation\":1", "\"generation\":0", .invalidGeneration),
        ("\"cpuCount\":1", "\"cpuCount\":0", .invalidCPUCount),
        ("\"cpuCount\":1", "\"cpuCount\":33", .invalidCPUCount),
        ("\"memoryMiB\":512", "\"memoryMiB\":127", .invalidMemory),
        ("\"memoryMiB\":512", "\"memoryMiB\":65537", .invalidMemory),
        ("\"daemonVsockPort\":7777", "\"daemonVsockPort\":0", .invalidVsockPort),
        ("\"daemonVsockPort\":7777", "\"daemonVsockPort\":7775", .invalidVsockPort),
        ("\"daemonVsockPort\":7777", "\"daemonVsockPort\":7776", .invalidVsockPort),
        ("\"daemonVsockPort\":7777", "\"daemonVsockPort\":7778", .invalidVsockPort),
      ]
      for (needle, replacement, expected) in cases {
        let bytes = canonicalText().replacingOccurrences(
          of: needle, with: replacement
        ).data(using: .utf8)!
        expectConfigurationError(expected) { _ = try RunnerConfiguration.decode(bytes) }
      }
    }

    @Test
    func testArtifactAndMutableDiskIdentitiesAreStrict() {
      for (needle, replacement, expected) in [
        (
          String(repeating: "a", count: 64), "A" + String(repeating: "a", count: 63),
          ConfigurationError.invalidArtifact
        ),
        (
          "\"kernel\":{\"sha256\":\"\(String(repeating: "a", count: 64))\",\"size\":1",
          "\"kernel\":{\"sha256\":\"\(String(repeating: "a", count: 64))\",\"size\":0",
          .invalidArtifact
        ),
        (
          "\"size\":268435456", "\"size\":268435455",
          .invalidDataDisk
        ),
        (
          "\"size\":268435456", "\"size\":268439552",
          .invalidDataDisk
        ),
        ("10000000-0000-4000-8000-000000000001", "bad-disk-id", .invalidDataDisk),
        (
          "10000000-0000-4000-8000-000000000001", "00000000-0000-0000-0000-000000000000",
          .invalidDataDisk
        ),
      ] {
        let bytes = canonicalText().replacingOccurrences(
          of: needle, with: replacement
        ).data(using: .utf8)!
        expectConfigurationError(expected) { _ = try RunnerConfiguration.decode(bytes) }
      }
    }

    @Test
    func testMalformedEmptyAndOversizedFramesAreRejected() {
      for bytes in [
        Data(), Data("[]".utf8), Data("{".utf8), Data(repeating: 0x61, count: 16 * 1024 + 1),
      ] {
        #expect(throws: (any Error).self) { try RunnerConfiguration.decode(bytes) }
      }
    }

    @Test
    func testNonCanonicalAndDuplicateKeysAreRejected() {
      expectConfigurationError(.nonCanonical) {
        _ = try RunnerConfiguration.decode(Data(" \(canonicalText())".utf8))
      }
      for (needle, duplicate) in [
        ("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
        (
          "\"kernel\":",
          "\"kernel\":{\"sha256\":\"\(String(repeating: "d", count: 64))\",\"size\":1},\"kernel\":"
        ),
        (
          "\"sha256\":\"\(String(repeating: "a", count: 64))\"",
          "\"sha256\":\"\(String(repeating: "a", count: 64))\",\"sha256\":\"\(String(repeating: "a", count: 64))\""
        ),
        ("\"size\":1}", "\"size\":1,\"size\":1}"),
      ] {
        let bytes = canonicalText().replacingOccurrences(of: needle, with: duplicate)
          .data(using: .utf8)!
        expectConfigurationError(.nonCanonical) { _ = try RunnerConfiguration.decode(bytes) }
      }
    }

    private func expectConfigurationError(
      _ expected: ConfigurationError,
      _ operation: () throws -> Void
    ) {
      do {
        try operation()
        Issue.record("expected configuration error \(expected)")
      } catch {
        #expect(error as? ConfigurationError == expected)
      }
    }

    private func canonical() -> Data { canonicalText().data(using: .utf8)! }

    private func canonicalText() -> String {
      """
      {"cpuCount":1,"daemonVsockPort":7777,"dataDisk":{"filesystemUUID":"10000000-0000-4000-8000-000000000001","size":268435456},"generation":1,"initialRamdisk":{"sha256":"\(String(repeating: "b", count: 64))","size":1},"kernel":{"sha256":"\(String(repeating: "a", count: 64))","size":1},"memoryMiB":512,"schemaVersion":1,"seedDisk":{"sha256":"\(String(repeating: "c", count: 64))","size":4096},"vmID":"00000000-0000-4000-8000-000000000001"}
      """
    }
  }
}
