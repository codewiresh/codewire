#if os(macOS)
  import CryptoKit
  @testable import CodewireVZRunnerProtocol
  @testable import CodewireVZRunnerRuntime
  import Darwin
  import Foundation
  import Testing

  extension CodewireVZRunnerTests {
    @Suite struct RuntimeAdmissionTests {
      @Test
      func testWrongTypeFailsClosed() throws {
        try assertRejected(.directory, as: .descriptorInvalid)
      }

      @Test
      func testWrongModeFailsClosed() throws {
        try assertRejected(.mode, as: .descriptorInvalid)
      }

      @Test
      func testWrongAccessFailsClosed() throws {
        try assertRejected(.access, as: .descriptorAccessInvalid)
      }

      @Test
      func testWrongSizeFailsClosed() throws {
        try assertRejected(.size, as: .descriptorSizeMismatch)
      }

      @Test
      func testWrongDigestFailsClosed() throws {
        try assertRejected(.digest, as: .artifactDigestMismatch)
      }

      @Test
      func testNonExt4DataDiskFailsClosed() throws {
        try assertRejected(.dataFormat, as: .dataDiskFormatInvalid)
      }

      @Test
      func testWrongDataDiskUUIDFailsClosed() throws {
        try assertRejected(.dataUUID, as: .dataDiskIdentityMismatch)
      }

      @Test
      func testNilDataDiskUUIDFailsClosed() throws {
        try assertRejected(.nilDataUUID, as: .dataDiskFormatInvalid)
      }

      @Test
      func testInodeProbeReadinessMatchesGuestCodec() throws {
        let seed = Data(repeating: 0x31, count: 4096)
        let filesystemUUID = [UInt8](repeating: 0x42, count: 16)
        let challenge = Data(repeating: 0x53, count: 32)
        let encoded =
          "435756494e4f44314fdd600892f7d61608383a6f94b6b68a8630b65c0976dea3f"
          + "5e410d4c4ff0bbd42424242424242424242424242424242fe9873626ac6bde0aed0"
          + "c4ffa3f5f35f6a48fb1fa669bde365e28a7fb0d29b6a"
        let frame = try #require(Data(hex: encoded))
        try InodeProbeRuntime.verifyReadiness(
          frame, seed: seed, filesystemUUID: filesystemUUID, challenge: challenge
        )
        var wrongChallenge = challenge
        wrongChallenge[0] ^= 1
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.verifyReadiness(
            frame, seed: seed, filesystemUUID: filesystemUUID, challenge: wrongChallenge
          )
        }
      }

      @Test
      func testInodeProbeDiagnosticsAreOrderedAndNeverReadiness() throws {
        var lastStage: InodeProbeRuntime.DiagnosticStage?
        for stage in InodeProbeRuntime.DiagnosticStage.allCases {
          let frame = InodeProbeRuntime.diagnosticFrame(stage)
          #expect(frame.count == 88)
          #expect(frame.prefix(8) == Data("CWVSTG1\0".utf8))
          #expect(frame[8] == stage.rawValue)
          #expect(frame.dropFirst(9).allSatisfy { $0 == 0 })
          #expect(
            try InodeProbeRuntime.parseReadinessRecord(frame, after: lastStage)
              == .diagnostic(stage)
          )
          lastStage = stage
        }

        let readiness = try #require(
          Data(
            hex:
              "435756494e4f44314fdd600892f7d61608383a6f94b6b68a8630b65c0976dea3f"
              + "5e410d4c4ff0bbd42424242424242424242424242424242fe9873626ac6bde0aed0"
              + "c4ffa3f5f35f6a48fb1fa669bde365e28a7fb0d29b6a"
          )
        )
        #expect(
          try InodeProbeRuntime.parseReadinessRecord(readiness, after: lastStage)
            == .authenticated(readiness)
        )
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(readiness, after: nil)
        }

        var malformed = InodeProbeRuntime.diagnosticFrame(.started)
        malformed[8] = 9
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(malformed, after: nil)
        }
        malformed = InodeProbeRuntime.diagnosticFrame(.started)
        malformed[20] = 1
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(malformed, after: nil)
        }
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(
            InodeProbeRuntime.diagnosticFrame(.seedRead),
            after: .started
          )
        }
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(
            InodeProbeRuntime.diagnosticFrame(.started),
            after: .started
          )
        }
        #expect(throws: (any Error).self) {
          try InodeProbeRuntime.parseReadinessRecord(Data(repeating: 0, count: 87), after: nil)
        }
      }

      @Test
      func testInodeProbeStreamParserHandlesFragmentedAndCoalescedFrames() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
        defer {
          close(descriptors[0])
          close(descriptors[1])
        }
        let frames = InodeProbeRuntime.DiagnosticStage.allCases.map {
          InodeProbeRuntime.diagnosticFrame($0)
        }
        let bytes = frames.reduce(into: Data(), { $0.append($1) })
        try writeAllTest(Data(bytes.prefix(7)), to: descriptors[0])
        let remainder = Data(bytes.dropFirst(7))
        let writer = UncheckedSendableTestBox(remainder)
        let writeDescriptor = descriptors[0]
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.01) {
          try? writeAllTest(writer.value, to: writeDescriptor)
        }

        var lastStage: InodeProbeRuntime.DiagnosticStage?
        for stage in InodeProbeRuntime.DiagnosticStage.allCases {
          let record = try InodeProbeRuntime.readReadinessRecord(
            from: descriptors[1],
            after: lastStage,
            deadline: Date().addingTimeInterval(1)
          )
          #expect(record == .diagnostic(stage))
          lastStage = stage
        }
      }

      @Test
      func testInodeProbeConnectionAdmissionIsOneShot() {
        let gate = OneShotAdmissionGate()
        #expect(gate.admit())
        #expect(!gate.admit())
        let cancelled = OneShotAdmissionGate()
        cancelled.cancel()
        #expect(!cancelled.admit())
      }

      @Test
      func testPathBackedBootControlCopiesAndRehashesPrivateArtifact() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
          "cw-vz-path-control-test-\(UUID().uuidString)",
          isDirectory: true
        )
        try FileManager.default.createDirectory(
          at: directory,
          withIntermediateDirectories: false,
          attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let bytes = Data("reviewed boot artifact".utf8)
        let source = directory.appendingPathComponent("source")
        try bytes.write(to: source)
        #expect(chmod(source.path, 0o600) == 0)
        let descriptor = open(source.path, O_RDONLY | O_NOFOLLOW)
        #expect(descriptor >= 0)
        defer { close(descriptor) }
        let identity = ImmutableArtifact(size: UInt64(bytes.count), sha256: sha256(bytes))

        let copied = try PathBackedBootControl.copyVerified(
          sourceDescriptor: descriptor,
          identity: identity,
          destination: directory.appendingPathComponent("copied")
        )
        #expect(try Data(contentsOf: copied) == bytes)
        var status = stat()
        #expect(lstat(copied.path, &status) == 0)
        #expect((status.st_mode & 0o777) == 0o600)

        do {
          _ = try PathBackedBootControl.copyVerified(
            sourceDescriptor: descriptor,
            identity: ImmutableArtifact(
              size: identity.size,
              sha256: String(repeating: "0", count: 64)
            ),
            destination: directory.appendingPathComponent("wrong-digest")
          )
          Issue.record("path-backed control accepted the wrong digest")
        } catch {
          #expect(error as? RuntimeError == .bootControlCopyFailed)
        }
        let wrongDigest = directory.appendingPathComponent("wrong-digest")
        #expect(!FileManager.default.fileExists(atPath: wrongDigest.path))
      }

      private enum Mutation: Equatable {
        case directory
        case mode
        case access
        case size
        case digest
        case dataFormat
        case dataUUID
        case nilDataUUID
      }

      private func assertRejected(_ mutation: Mutation, as expected: RuntimeError) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
          "cw-vz-runtime-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }

        let kernel = mutation == .size ? Data("aa".utf8) : Data("a".utf8)
        let initialRamdisk = Data("b".utf8)
        let seed = Data(repeating: 0, count: 4096)
        let kernelPath = directory.appendingPathComponent("kernel")
        let initialRamdiskPath = directory.appendingPathComponent("initramfs")
        let seedPath = directory.appendingPathComponent("seed")
        let dataPath = directory.appendingPathComponent("data")
        try kernel.write(to: kernelPath)
        try initialRamdisk.write(to: initialRamdiskPath)
        try seed.write(to: seedPath)
        #expect(FileManager.default.createFile(atPath: dataPath.path, contents: Data()))
        let dataHandle = try FileHandle(forWritingTo: dataPath)
        try dataHandle.truncate(atOffset: 256 * 1024 * 1024)
        try dataHandle.seek(toOffset: 1024)
        var superblock = Data(repeating: 0, count: 0x78)
        if mutation != .dataFormat {
          superblock[0x38] = 0x53
          superblock[0x39] = 0xef
        }
        let filesystemUUID: [UInt8] =
          mutation == .nilDataUUID
          ? Array(repeating: 0, count: 16)
          : [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            mutation == .dataUUID ? 0x02 : 0x01,
          ]
        superblock.replaceSubrange(0x68..<0x78, with: filesystemUUID)
        try dataHandle.write(contentsOf: superblock)
        try dataHandle.close()
        for path in [kernelPath, initialRamdiskPath, seedPath, dataPath] {
          #expect(chmod(path.path, 0o600) == 0)
        }

        let kernelInput = mutation == .directory ? directory : kernelPath
        if mutation == .mode {
          #expect(chmod(kernelPath.path, 0o640) == 0)
        }
        let kernelAccess = mutation == .access ? O_RDWR : O_RDONLY
        let descriptors = [
          open(kernelInput.path, kernelAccess),
          open(initialRamdiskPath.path, O_RDONLY),
          open(seedPath.path, O_RDONLY),
          open(dataPath.path, O_RDWR),
        ]
        let descriptorSet = try DescriptorSet(descriptors)
        let kernelDigest = mutation == .digest ? String(repeating: "0", count: 64) : sha256(kernel)
        let configuration = try RunnerConfiguration.decode(
          Data(
            """
            {"cpuCount":1,"daemonVsockPort":7777,"dataDisk":{"filesystemUUID":"10000000-0000-4000-8000-000000000001","size":268435456},"generation":1,"initialRamdisk":{"sha256":"\(sha256(initialRamdisk))","size":1},"kernel":{"sha256":"\(kernelDigest)","size":1},"memoryMiB":512,"schemaVersion":1,"seedDisk":{"sha256":"\(sha256(seed))","size":4096},"vmID":"00000000-0000-4000-8000-000000000001"}
            """.utf8
          )
        )
        let request = ReceivedRequest(configuration: configuration, descriptors: descriptorSet)
        do {
          _ = try RuntimeAdmission.buildConfiguration(for: request)
          Issue.record("expected runtime admission error \(expected)")
        } catch {
          #expect(error as? RuntimeError == expected)
        }
      }

      private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
      }

    }
  }

  private func writeAllTest(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { raw in
      var written = 0
      while written < data.count {
        let count = Darwin.write(
          descriptor,
          raw.baseAddress?.advanced(by: written),
          data.count - written
        )
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw CocoaError(.fileWriteUnknown) }
        written += count
      }
    }
  }

  private final class UncheckedSendableTestBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
      self.value = value
    }
  }

  extension Data {
    fileprivate init?(hex: String) {
      guard hex.count.isMultiple(of: 2) else { return nil }
      var bytes: [UInt8] = []
      bytes.reserveCapacity(hex.count / 2)
      var offset = hex.startIndex
      while offset < hex.endIndex {
        let end = hex.index(offset, offsetBy: 2)
        guard let byte = UInt8(hex[offset..<end], radix: 16) else { return nil }
        bytes.append(byte)
        offset = end
      }
      self.init(bytes)
    }
  }
#endif
