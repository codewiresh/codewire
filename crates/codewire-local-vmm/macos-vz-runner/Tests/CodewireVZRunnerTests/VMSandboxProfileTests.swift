#if os(macOS)
  import CVZRunnerIPC
  @testable import CodewireVZRunnerProtocol
  import Foundation
  import Testing

  extension CodewireVZRunnerTests {
    @Suite struct VMSandboxProfileTests {
      static func configuration(shares: [VMConfiguration.Share]) throws -> VMConfiguration {
        try VMConfiguration.decode(
          JSONEncoder().encode(
            VMConfiguration(
              kernel: "/runtime/kernel", initialRamdisk: "/runtime/initramfs",
              commandLine: "console=ttyS0", cpuCount: 2, memoryMiB: 4096,
              disks: [
                .init(path: "/vm/state.raw", serial: "CWSTATE1", readOnly: false),
                .init(path: "/vm/seed.raw", serial: "CWSEED1", readOnly: true),
              ],
              shares: shares, vsockSocket: "/tmp/vm/vsock/v")),
          directory: "/vm")
      }

      static func share(_ index: Int, _ path: String, readOnly: Bool) -> VMConfiguration.Share {
        .init(
          tag: VMConfiguration.shareTag(index), path: path, readOnly: readOnly, device: 1,
          inode: 2)
      }

      @Test
      func testOnlyThisVMsFilesAreGranted() throws {
        let rules = try Self.configuration(shares: [
          Self.share(0, "/work/rw", readOnly: false), Self.share(1, "/work/ro", readOnly: true),
        ]).sandboxProfile().split(separator: "\n").map(String.init)
        #expect(rules.starts(with: ["(version 1)", "(deny default)"]))
        #expect(rules.contains("(allow file-read* (literal \"/runtime/kernel\"))"))
        #expect(rules.contains("(allow file-read* (literal \"/vm/seed.raw\"))"))
        #expect(rules.contains("(allow file-read* file-write* (literal \"/vm/state.raw\"))"))
        #expect(
          rules.contains(
            "(allow file-read* file-write* file-issue-extension (subpath \"/work/rw\"))"))
        #expect(rules.contains("(allow file-read* file-issue-extension (subpath \"/work/ro\"))"))
        #expect(
          rules.contains(
            "(allow file-read-metadata file-write-unlink (literal \"/tmp/vm/vsock/v\"))"))
        let writes = rules.filter { $0.contains("file-write") }
        #expect(writes.count == 3)
      }

      @Test
      func testNothingReachesTheNetworkProcessesOrOtherMachServices() throws {
        let profile = try Self.configuration(shares: [
          Self.share(0, "/work/rw", readOnly: false)
        ]).sandboxProfile()
        for forbidden in ["network", "process-", "signal", "iokit", "file-write* (subpath \"/\")"] {
          #expect(!profile.contains(forbidden), "\(forbidden)")
        }
        let mach = profile.split(separator: "\n").filter { $0.contains("mach-") }
        #expect(
          mach == [
            "(allow mach-lookup (xpc-service-name \"com.apple.Virtualization.VirtualMachine\"))"
          ])
      }

      /// macOS 27's cache-directory lookup needs exactly the `/var` symlink's
      /// metadata; nothing under it, and no directory service (#4478).
      @Test
      func testTheCacheDirectoryLookupGetsOnlyTheVarSymlinksMetadata() throws {
        let rules = try Self.configuration(shares: []).sandboxProfile().split(separator: "\n")
          .map(String.init)
        #expect(rules.contains("(allow file-read-metadata (literal \"/var\"))"))
        let system = rules.filter { $0.contains("/var") || $0.contains("/private") }
        #expect(system == ["(allow file-read-metadata (literal \"/var\"))"])
        for forbidden in ["dirhelper", "opendirectoryd", "system-info"] {
          #expect(!rules.joined().contains(forbidden), "\(forbidden)")
        }
      }

      @Test
      func testTheVirtioFSExtensionIsGrantedOnlyWithAShare() throws {
        let unshared = try Self.configuration(shares: []).sandboxProfile()
        #expect(!unshared.contains("issue-extension"))
        let shared = try Self.configuration(shares: [
          Self.share(0, "/work/ro", readOnly: true)
        ]).sandboxProfile()
        #expect(
          shared.contains(
            "(allow generic-issue-extension (extension-class \"com.apple.virtualization.extension.fuse\"))"
          ))
      }

      @Test
      func testPathsAreEscaped() {
        #expect(VMConfiguration.profileString("/a b/é\"q\\s") == "\"/a b/é\\\"q\\\\s\"")
        #expect(VMConfiguration.profileString("/a\tb\nc") == "\"/a\tb\nc\"")
      }

      /// A profile Seatbelt refuses is an error, and the process stays as it
      /// was; so this test can run inside the test process. A profile that
      /// applied would confine the whole test run, so only a refused one runs here.
      @Test
      func testARefusedProfileIsAnError() {
        #expect(cw_vz_apply_sandbox("(version 1)(no-such-operation)") == -1)
      }
    }
  }
#endif
