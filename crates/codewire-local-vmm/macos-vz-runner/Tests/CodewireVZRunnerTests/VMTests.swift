import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Dispatch
import Foundation
import Testing

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

extension CodewireVZRunnerTests {
  @Suite struct VMTests {
    static func configuration() -> VMConfiguration {
      VMConfiguration(
        kernel: "/state/kernel", initialRamdisk: "/state/initramfs",
        commandLine: "console=hvc0 rdinit=/init", cpuCount: 2, memoryMiB: 1024,
        disks: [
          .init(path: "/state/state.raw", serial: "CWSTATE1", readOnly: false),
          .init(path: "/state/seed.raw", serial: "CWSEED1", readOnly: true),
        ],
        shares: [
          .init(
            tag: "cw-direct-00", path: "/Users/someone/source", readOnly: true, device: 16_777_234,
            inode: 42),
          .init(
            tag: "cw-direct-01", path: "/Users/someone/output", readOnly: false,
            device: 16_777_234, inode: 43),
        ],
        vsockSocket: "/state/vsock.sock")
    }

    static func encoded(_ configuration: VMConfiguration) throws -> Data {
      try JSONEncoder().encode(configuration)
    }

    static func object(_ configuration: VMConfiguration) throws -> [String: Any] {
      try #require(
        JSONSerialization.jsonObject(with: encoded(configuration)) as? [String: Any])
    }

    static func expect(_ expected: ConfigurationError, _ data: Data) {
      #expect(throws: expected) { _ = try VMConfiguration.decode(data) }
    }

    @Test
    func testValidConfigurationRoundTrips() throws {
      let decoded = try VMConfiguration.decode(Self.encoded(Self.configuration()))
      #expect(decoded == Self.configuration())
    }

    @Test
    func testUnknownAndMissingFieldsAreRejected() throws {
      var root = try Self.object(Self.configuration())
      root["extra"] = true
      Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      root = try Self.object(Self.configuration())
      root.removeValue(forKey: "vsockSocket")
      Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      root = try Self.object(Self.configuration())
      var disks = try #require(root["disks"] as? [[String: Any]])
      disks[0]["cache"] = "none"
      root["disks"] = disks
      Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      // Schema 2 requires the shares list, and each share has exactly its fields.
      root = try Self.object(Self.configuration())
      root.removeValue(forKey: "shares")
      Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      for field in ["tag", "path", "readOnly", "device", "inode"] {
        root = try Self.object(Self.configuration())
        var shares = try #require(root["shares"] as? [[String: Any]])
        shares[0].removeValue(forKey: field)
        root["shares"] = shares
        Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      }
      root = try Self.object(Self.configuration())
      var shares = try #require(root["shares"] as? [[String: Any]])
      shares[1]["writable"] = true
      root["shares"] = shares
      Self.expect(.unknownFields, try JSONSerialization.data(withJSONObject: root))
      Self.expect(.malformed, Data("[]".utf8))
      Self.expect(
        .malformed, Data(repeating: 0x20, count: VMConfiguration.maxConfigurationBytes + 1))
    }

    @Test
    func testBoundsAndPathsFailClosed() throws {
      let cases: [(ConfigurationError, (inout VMConfiguration) -> Void)] = [
        (.unsupportedSchema, { $0.schemaVersion = 1 }),
        (.unsupportedSchema, { $0.schemaVersion = 3 }),
        (.invalidArtifact, { $0.kernel = "kernel" }),
        (.invalidArtifact, { $0.initialRamdisk = "/state/../etc/initramfs" }),
        (.invalidArtifact, { $0.commandLine = "" }),
        (.invalidArtifact, { $0.commandLine = "console=hvc0\nrdinit=/init" }),
        (.invalidCPUCount, { $0.cpuCount = 0 }),
        (.invalidCPUCount, { $0.cpuCount = 65 }),
        (.invalidMemory, { $0.memoryMiB = 64 }),
        (.invalidDataDisk, { $0.disks = [] }),
        (.invalidDataDisk, { $0.disks[1].serial = "CWSTATE1" }),
        (.invalidDataDisk, { $0.disks[1].path = "/state/state.raw" }),
        (.invalidDataDisk, { $0.disks[0].serial = String(repeating: "S", count: 21) }),
        (.invalidDataDisk, { $0.disks[0].serial = "CW STATE" }),
        (.invalidDataDisk, { $0.disks[0].path = "./state.raw" }),
        (
          .invalidDataDisk,
          {
            $0.disks = (0...VMConfiguration.maxDisks).map {
              .init(path: "/state/\($0).raw", serial: "CW\($0)", readOnly: true)
            }
          }
        ),
        (.invalidShare, { $0.shares[0].tag = "cw-direct-01" }),
        (.invalidShare, { $0.shares[1].tag = "cw-direct-1" }),
        (.invalidShare, { $0.shares[0].tag = "workspace" }),
        (.invalidShare, { $0.shares[1].path = "/Users/someone/source" }),
        (.invalidShare, { $0.shares[0].path = "Users/someone/source" }),
        (.invalidShare, { $0.shares[0].path = "/Users/someone/../source" }),
        (.invalidShare, { $0.shares[0].path = "/" }),
        (.invalidShare, { $0.shares[0].path = "/" + String(repeating: "p", count: 1023) }),
        (.invalidShare, { $0.shares[0].inode = 0 }),
        (
          .invalidShare,
          {
            $0.shares = (0...VMConfiguration.maxShares).map {
              .init(
                tag: VMConfiguration.shareTag($0), path: "/Users/someone/\($0)", readOnly: true,
                device: 1, inode: UInt64($0) + 1)
            }
          }
        ),
        (.invalidVsockPort, { $0.vsockSocket = "vsock.sock" }),
        (.invalidVsockPort, { $0.vsockSocket = "/" + String(repeating: "v", count: 103) }),
      ]
      for (expected, mutate) in cases {
        var configuration = Self.configuration()
        mutate(&configuration)
        Self.expect(expected, try Self.encoded(configuration))
      }
    }

    @Test
    func testShareTagsFollowGuestPlanOrder() throws {
      #expect(VMConfiguration.shareTag(0) == "cw-direct-00")
      #expect(VMConfiguration.shareTag(15) == "cw-direct-15")
      var configuration = Self.configuration()
      configuration.shares = (0..<VMConfiguration.maxShares).map {
        .init(
          tag: VMConfiguration.shareTag($0), path: "/Users/someone/\($0)", readOnly: $0 % 2 == 0,
          device: 1, inode: UInt64($0) + 1)
      }
      #expect(try VMConfiguration.decode(Self.encoded(configuration)) == configuration)
      configuration.shares = []
      #expect(try VMConfiguration.decode(Self.encoded(configuration)) == configuration)
    }

    @Test
    func testConnectLineIsStrict() throws {
      for (line, port) in [("CONNECT 7777\n", UInt32(7777)), ("CONNECT 1\n", 1)] {
        #expect(try Self.readConnect(line) == port)
      }
      for line in [
        "CONNECT\n", "CONNECT 07\n", "CONNECT -1\n", "CONNECT 4294967296\n", "connect 1\n",
        "CONNECT 1 2\n", "CONNECT 1", "CONNECT 1\r\n",
      ] {
        #expect(try Self.readConnect(line) == nil)
      }
    }

    /// The payload after the newline stays in the socket for the bridge.
    @Test
    func testConnectLeavesPayloadUnread() throws {
      var sockets: [Int32] = [-1, -1]
      try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
      defer { for socket in sockets { _ = close(socket) } }
      let bytes = Array("CONNECT 9\nPRI".utf8)
      try #require(cw_vz_write_all(sockets[0], bytes, bytes.count) == 0)
      var port: UInt32 = 0
      #expect(cw_vz_read_connect(sockets[1], &port) == 0)
      #expect(port == 9)
      var rest = [UInt8](repeating: 0, count: 3)
      #expect(recv(sockets[1], &rest, 3, 0) == 3)
      #expect(rest == Array("PRI".utf8))
    }

    @Test
    func testSpliceCopiesBothDirectionsAndForwardsHalfClose() throws {
      var client: [Int32] = [-1, -1]
      var guest: [Int32] = [-1, -1]
      try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &client) == 0)
      try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &guest) == 0)
      defer { for socket in client + guest { _ = close(socket) } }
      // A regression fails within the timeout instead of hanging the run.
      var timeout = timeval(tv_sec: 10, tv_usec: 0)
      for socket in [client[0], guest[1]] {
        try #require(
          setsockopt(
            socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0)
      }
      let bridgeClient = client[1]
      let bridgeGuest = guest[0]
      let finished = DispatchSemaphore(value: 0)
      let result = SpliceResult()
      Thread.detachNewThread {
        result.value = cw_vz_splice(bridgeClient, bridgeGuest)
        finished.signal()
      }
      // A payload larger than one bridge buffer, in both directions.
      let request = [UInt8]((0..<200_000).map { UInt8($0 % 251) })
      let response = [UInt8]((0..<150_000).map { UInt8($0 % 241) })
      let clientEnd = client[0]
      let writer = Thread {
        _ = cw_vz_write_all(clientEnd, request, request.count)
        shutdown(clientEnd, SHUT_WR)
      }
      writer.start()
      #expect(try Self.readAll(guest[1]) == request)
      // Read the client end while the response is written: socket buffers
      // are far smaller than the payload.
      let received = Received()
      let readerDone = DispatchSemaphore(value: 0)
      Thread.detachNewThread {
        received.bytes = try? Self.readAll(clientEnd)
        readerDone.signal()
      }
      try #require(cw_vz_write_all(guest[1], response, response.count) == 0)
      shutdown(guest[1], SHUT_WR)
      #expect(readerDone.wait(timeout: .now() + 5) == .success)
      #expect(received.bytes == response)
      #expect(finished.wait(timeout: .now() + 5) == .success)
      #expect(result.value == 0)
    }

    final class SpliceResult: @unchecked Sendable { var value: Int32 = -2 }
    final class Received: @unchecked Sendable { var bytes: [UInt8]? }

    static func readConnect(_ line: String) throws -> UInt32? {
      var sockets: [Int32] = [-1, -1]
      try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
      defer { for socket in sockets { _ = close(socket) } }
      let bytes = Array(line.utf8)
      try #require(cw_vz_write_all(sockets[0], bytes, bytes.count) == 0)
      shutdown(sockets[0], SHUT_WR)
      var port: UInt32 = 0
      return cw_vz_read_connect(sockets[1], &port) == 0 ? port : nil
    }

    static func readAll(_ fd: Int32) throws -> [UInt8] {
      var output: [UInt8] = []
      var buffer = [UInt8](repeating: 0, count: 65_536)
      while true {
        let count = recv(fd, &buffer, buffer.count, 0)
        try #require(count >= 0)
        if count == 0 { return output }
        output.append(contentsOf: buffer[0..<count])
      }
    }
  }
}
