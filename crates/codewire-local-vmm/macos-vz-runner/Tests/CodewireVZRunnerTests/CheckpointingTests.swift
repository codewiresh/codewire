#if os(macOS)
  import CVZRunnerIPC
  @testable import CodewireVZRunnerProtocol
  import Darwin
  import Foundation
  import Testing

  extension CodewireVZRunnerTests {
    /// Schema 3 (#4654): the control channel and the checkpoint files, with
    /// cw-security's conditions 2, 3 and 5.
    @Suite struct CheckpointingTests {
      static let directory = "/var/vz-test/native-v1/engine/vms/0b9c"

      static func configuration(_ checkpointing: VMConfiguration.Checkpointing?) -> VMConfiguration
      {
        VMConfiguration(
          kernel: "/runtime/kernel", initialRamdisk: "/runtime/initramfs",
          commandLine: "console=ttyS0", cpuCount: 2, memoryMiB: 4096,
          disks: [
            .init(path: "\(directory)/disks/state.raw", serial: "CWSTATE1", readOnly: false),
            .init(path: "\(directory)/seed/seed.raw", serial: "CWSEED1", readOnly: true),
          ],
          shares: [], vsockSocket: "/tmp/vm/vsock/v", checkpointing: checkpointing)
      }

      static func checkpointing(
        save: String = "\(directory)/checkpoints/vz-save", restore: String? = nil,
        identifier: String? = Data([1, 2, 3]).base64EncodedString(), control: Int32 = 4
      ) -> VMConfiguration.Checkpointing {
        .init(
          machineIdentifier: identifier, saveState: save, restoreState: restore,
          controlDescriptor: control)
      }

      static func decode(_ configuration: VMConfiguration) throws -> VMConfiguration {
        try VMConfiguration.decode(JSONEncoder().encode(configuration), directory: directory)
      }

      @Test
      func testSchemaThreeRoundTripsAndSchemaTwoStillDecodes() throws {
        let full = Self.configuration(
          Self.checkpointing(restore: "\(Self.directory)/checkpoints/in/state.vzsave"))
        #expect(full.schemaVersion == 3)
        #expect(try Self.decode(full) == full)

        let firstStart = Self.configuration(Self.checkpointing(identifier: nil))
        #expect(try Self.decode(firstStart).checkpointing?.machineIdentifier == nil)

        let schemaTwo = Self.configuration(nil)
        #expect(schemaTwo.schemaVersion == 2)
        let decoded = try Self.decode(schemaTwo)
        #expect(decoded == schemaTwo && decoded.checkpointing == nil)
        let keys = try #require(
          JSONSerialization.jsonObject(with: JSONEncoder().encode(schemaTwo)) as? [String: Any]
        ).keys
        #expect(!keys.contains("saveState") && !keys.contains("controlDescriptor"))
      }

      @Test
      func testSchemaThreeNeedsAllItsKeysAndSchemaTwoNone() throws {
        let encoded = try JSONEncoder().encode(Self.configuration(Self.checkpointing()))
        var root = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        root.removeValue(forKey: "restoreState")
        #expect(throws: ConfigurationError.unknownFields) {
          _ = try VMConfiguration.decode(
            JSONSerialization.data(withJSONObject: root), directory: Self.directory)
        }
        root["restoreState"] = NSNull()
        root["schemaVersion"] = 2
        #expect(throws: ConfigurationError.unknownFields) {
          _ = try VMConfiguration.decode(
            JSONSerialization.data(withJSONObject: root), directory: Self.directory)
        }
      }

      /// Condition 5: refused, never escaped.
      @Test
      func testStatePathsAreSafeLiteralsInsideTheVMDirectory() {
        let refused = [
          "relative/vz-save",
          "/var/vz-test/elsewhere/vz-save",
          "\(Self.directory)",
          "\(Self.directory)/",
          "\(Self.directory)/checkpoints/../../other/vz-save",
          "\(Self.directory)/./vz-save",
          "\(Self.directory)//vz-save",
          "\(Self.directory)/checkpoints/vz save",
          "\(Self.directory)/checkpoints/vz\"save",
          "\(Self.directory)/checkpoints/vz\\save",
          "\(Self.directory)/checkpoints/vz\nsave",
          "\(Self.directory)/checkpoints/vz(save)",
          "\(Self.directory)/checkpoints/vz-säve",
          "\(Self.directory)extra/vz-save",
        ]
        for path in refused {
          #expect(throws: ConfigurationError.invalidStatePath, "save \(path)") {
            _ = try Self.decode(Self.configuration(Self.checkpointing(save: path)))
          }
          #expect(throws: ConfigurationError.invalidStatePath, "restore \(path)") {
            _ = try Self.decode(Self.configuration(Self.checkpointing(restore: path)))
          }
        }
        let same = "\(Self.directory)/checkpoints/vz-save"
        #expect(throws: ConfigurationError.invalidStatePath) {
          _ = try Self.decode(Self.configuration(Self.checkpointing(save: same, restore: same)))
        }
        // A VM directory that is itself not a safe literal refuses everything.
        #expect(
          !VMConfiguration.isProfileLiteral(
            "/var/vz test/vms/a/vz-save", inside: "/var/vz test/vms/a"))
      }

      @Test
      func testTheControlNumberAndTheIdentifierAreChecked() {
        for control: Int32 in [-1, 0, 1, 2, 1024] {
          #expect(throws: ConfigurationError.invalidControl, "\(control)") {
            _ = try Self.decode(Self.configuration(Self.checkpointing(control: control)))
          }
        }
        let tooLong = Data(count: VMConfiguration.maxMachineIdentifierBytes + 1)
          .base64EncodedString()
        for identifier in ["not base64!", "", tooLong] {
          #expect(throws: ConfigurationError.invalidMachineIdentifier, "\(identifier.prefix(12))") {
            _ = try Self.decode(Self.configuration(Self.checkpointing(identifier: identifier)))
          }
        }
      }

      /// The profile gains exactly the two literal rules, and only for schema 3.
      @Test
      func testTheProfileGrantsExactlyTheTwoStateFiles() throws {
        let save = "\(Self.directory)/checkpoints/vz-save"
        let restore = "\(Self.directory)/checkpoints/in/state.vzsave"
        let base = try Self.decode(Self.configuration(nil)).sandboxProfile()
        let saving = try Self.decode(Self.configuration(Self.checkpointing())).sandboxProfile()
        let restoring = try Self.decode(Self.configuration(Self.checkpointing(restore: restore)))
          .sandboxProfile()
        let saveRule = "(allow file-read* file-write* (literal \"\(save)\"))"
        let restoreRule = "(allow file-read* (literal \"\(restore)\"))"
        #expect(
          saving.split(separator: "\n").map(String.init).filter { !base.contains($0) } == [saveRule]
        )
        #expect(
          restoring.split(separator: "\n").map(String.init).filter { !base.contains($0) }
            == [saveRule, restoreRule])
      }

      /// Condition 2: only an unnamed AF_UNIX stream socket is a control channel.
      @Test
      func testOnlyAnUnnamedStreamSocketIsAControlChannel() throws {
        var pair: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer { for end in pair { close(end) } }
        #expect(cw_vz_check_control(pair[0]) == 0)
        #expect(fcntl(pair[0], F_GETFD) & FD_CLOEXEC != 0)

        var datagrams: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &datagrams) == 0)
        defer { for end in datagrams { close(end) } }
        #expect(cw_vz_check_control(datagrams[0]) == -1)

        var pipeEnds: [Int32] = [-1, -1]
        #expect(pipe(&pipeEnds) == 0)
        defer { for end in pipeEnds { close(end) } }
        #expect(cw_vz_check_control(pipeEnds[0]) == -1)

        let directory = FileManager.default.temporaryDirectory
          .appendingPathComponent("cwctl-\(getpid())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = open(directory.appendingPathComponent("file").path, O_CREAT | O_RDWR, 0o600)
        defer { close(file) }
        #expect(cw_vz_check_control(file) == -1)

        let listener = cw_vz_listen_unix(directory.appendingPathComponent("s").path)
        #expect(listener >= 0)
        defer { close(listener) }
        #expect(cw_vz_check_control(listener) == -1, "a named socket")

        let closed = dup(pair[1])
        close(closed)
        #expect(cw_vz_check_control(closed) == -1, "a closed number")
        #expect(cw_vz_check_control(1) == -1, "stdio")
      }

      /// Condition 3: descriptors sent with ancillary data are refused and closed.
      @Test
      func testPassedDescriptorsAreRefusedAndClosed() throws {
        var pair: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer { for end in pair { close(end) } }

        // Plain bytes read as bytes.
        #expect(write(pair[1], "abc", 3) == 3)
        var buffer = [UInt8](repeating: 0, count: 16)
        #expect(cw_vz_control_read(pair[0], &buffer, buffer.count) == 3)

        // The same bytes with a descriptor attached are refused.
        let passed = open("/dev/null", O_RDONLY)
        defer { close(passed) }
        let before = Self.openDescriptors()
        var byte: UInt8 = 0x41
        // Darwin's CMSG_LEN and CMSG_SPACE, which Swift does not import: the
        // header and the data each round up to 4 bytes.
        let align = { (size: Int) in (size + 3) & ~3 }
        let headerBytes = align(MemoryLayout<cmsghdr>.size)
        let space = headerBytes + align(MemoryLayout<Int32>.size)
        var control = [UInt8](repeating: 0, count: space)
        let sent = withUnsafeMutablePointer(to: &byte) { bytePointer in
          control.withUnsafeMutableBytes { controlBytes in
            var vector = iovec(iov_base: bytePointer, iov_len: 1)
            return withUnsafeMutablePointer(to: &vector) { vectorPointer in
              var message = msghdr()
              message.msg_iov = vectorPointer
              message.msg_iovlen = 1
              message.msg_control = controlBytes.baseAddress
              message.msg_controllen = socklen_t(space)
              let header = controlBytes.baseAddress!.assumingMemoryBound(to: cmsghdr.self)
              header.pointee.cmsg_level = SOL_SOCKET
              header.pointee.cmsg_type = SCM_RIGHTS
              header.pointee.cmsg_len = socklen_t(headerBytes + MemoryLayout<Int32>.size)
              let data = UnsafeMutableRawPointer(header).advanced(by: headerBytes)
                .assumingMemoryBound(to: Int32.self)
              data.pointee = passed
              return sendmsg(pair[1], &message, 0)
            }
          }
        }
        #expect(sent == 1)
        #expect(cw_vz_control_read(pair[0], &buffer, buffer.count) == -2)
        #expect(Self.openDescriptors() == before, "the received copy was closed")
      }

      static func openDescriptors() -> Int {
        (0..<Int32(getdtablesize())).filter { fcntl($0, F_GETFD) != -1 }.count
      }
    }
  }
#endif
