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
#endif
