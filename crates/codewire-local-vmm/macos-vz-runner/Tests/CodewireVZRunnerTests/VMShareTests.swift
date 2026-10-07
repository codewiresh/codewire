#if os(macOS)
  @testable import CodewireVZRunnerProtocol
  @testable import CodewireVZRunnerRuntime
  import Darwin
  import Foundation
  import Testing

  extension CodewireVZRunnerTests {
    @Suite struct VMShareTests {
      /// A private directory under its canonical (`/private/var/...`) path.
      static func directory() throws -> (root: String, share: String) {
        let base = try #require(realpath(NSTemporaryDirectory(), nil))
        defer { free(base) }
        let root = String(cString: base) + "/cw-vz-share-\(UUID().uuidString)"
        try #require(mkdir(root, 0o700) == 0)
        let share = root + "/share"
        try #require(mkdir(share, 0o700) == 0)
        return (root, share)
      }

      static func share(_ path: String, readOnly: Bool = true) throws -> VMConfiguration.Share {
        var status = stat()
        try #require(lstat(path, &status) == 0)
        return .init(
          tag: "cw-direct-00", path: path, readOnly: readOnly,
          device: UInt32(bitPattern: status.st_dev), inode: UInt64(status.st_ino))
      }

      static func rejected(_ shares: [VMConfiguration.Share]) -> Bool {
        do {
          try VMRuntime.verifySharedDirectories(shares)
          return false
        } catch {
          return error as? RuntimeError == .sharedDirectoryChanged
        }
      }

      @Test
      func testTheAdmittedDirectoryIsAccepted() throws {
        let (root, share) = try Self.directory()
        defer { _ = try? FileManager.default.removeItem(atPath: root) }
        try VMRuntime.verifySharedDirectories([try Self.share(share)])
        try VMRuntime.verifySharedDirectories([])
      }

      @Test
      func testAReplacedOrVanishedDirectoryIsRefused() throws {
        let (root, share) = try Self.directory()
        defer { _ = try? FileManager.default.removeItem(atPath: root) }
        let admitted = try Self.share(share)
        try #require(rename(share, root + "/parked") == 0)
        #expect(Self.rejected([admitted]))
        try #require(mkdir(share, 0o700) == 0)
        #expect(Self.rejected([admitted]))
        var wrongInode = try Self.share(share)
        wrongInode.inode += 1
        #expect(Self.rejected([wrongInode]))
      }

      @Test
      func testASymlinkInAnyComponentIsRefused() throws {
        let (root, share) = try Self.directory()
        defer { _ = try? FileManager.default.removeItem(atPath: root) }
        let admitted = try Self.share(share)
        // The directory itself replaced by a symlink to the admitted inode.
        try #require(rename(share, root + "/real") == 0)
        try #require(symlink(root + "/real", share) == 0)
        #expect(Self.rejected([admitted]))
        // A symlinked parent: /var and /tmp are symlinks into /private.
        try #require(share.hasPrefix("/private/var/") || share.hasPrefix("/private/tmp/"))
        let throughSymlink = String(share.dropFirst("/private".count))
        try #require(unlink(share) == 0)
        try #require(rename(root + "/real", share) == 0)
        var spelled = admitted
        spelled.path = throughSymlink
        #expect(Self.rejected([spelled]))
        try VMRuntime.verifySharedDirectories([admitted])
      }
    }
  }
#endif
