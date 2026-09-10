import CVZRunnerIPCTestSupport
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
  @Suite struct IPCTests {
    @Test
    func testExactDescriptorSetAndPayloadAreReceivedWithCloseOnDrop() throws {
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(cw_vz_fixture_socketpair(&sockets) == 0)
      defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
      }
      let originals = try fixtureDescriptors()
      defer { closeAll(originals) }
      let payload = canonical()
      let senderSocket = sockets[0]
      let sender = Self.startSender(senderSocket, payload, originals)

      var receivedNumbers: [Int32] = []
      do {
        let request = try PrivateIPC.receive(controlDescriptor: sockets[1])
        #expect(request.configuration.generation == 1)
        receivedNumbers = DescriptorRole.allCases.map {
          request.descriptors.descriptor(for: $0)
        }
        #expect(Set(receivedNumbers).count == 4)
        for descriptor in receivedNumbers {
          #expect(fcntl(descriptor, F_GETFD) & FD_CLOEXEC != 0)
        }
      }
      let senderResult = sender.wait()
      try #require(senderResult.0 == 0)
      #expect(senderResult.1 == 0)
      for descriptor in receivedNumbers {
        #expect(cw_vz_fixture_descriptor_is_closed(descriptor) == 1)
      }
    }

    @Test
    func testMissingExtraAndTruncatedDescriptorSetsFailClosed() throws {
      let baseline = openDescriptorCount()
      for count in [1, 3, 5, 8] {
        var sockets = [Int32](repeating: -1, count: 2)
        try #require(cw_vz_fixture_socketpair(&sockets) == 0)
        let originals = try fixtureDescriptors(count: count)
        let senderSocket = sockets[0]
        let payload = canonical()
        let sender = Self.startSender(senderSocket, payload, originals)
        #expect(throws: (any Error).self) {
          try PrivateIPC.receive(controlDescriptor: sockets[1])
        }
        let senderResult = sender.wait()
        try #require(senderResult.0 == 0)
        #expect(senderResult.1 == 0)
        closeAll(originals)
        closeAll(sockets)
        #expect(openDescriptorCount() == baseline)
      }
    }

    @Test
    func testOversizedPayloadClosesReceivedDescriptors() throws {
      let baseline = openDescriptorCount()
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(cw_vz_fixture_socketpair(&sockets) == 0)
      let originals = try fixtureDescriptors()
      let payload = Data(repeating: 0x61, count: RunnerProtocol.maxFrameBytes + 1)
      let senderSocket = sockets[0]
      let sender = Self.startSender(senderSocket, payload, originals)
      #expect(throws: (any Error).self) {
        try PrivateIPC.receive(controlDescriptor: sockets[1])
      }
      #expect(close(sockets[1]) == 0)
      sockets[1] = -1
      let senderResult = sender.wait()
      #expect(senderResult.0 == 0 || senderResult.0 == -1)
      #expect(senderResult.1 == 0 || senderResult.1 == -1)
      closeAll(originals)
      closeAll(sockets)
      #expect(openDescriptorCount() == baseline)
    }

    @Test
    func testAliasedDescriptorRolesFailClosed() throws {
      let baseline = openDescriptorCount()
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(cw_vz_fixture_socketpair(&sockets) == 0)
      let original = try fixtureDescriptors(count: 1)[0]
      let aliases = try (0..<RunnerProtocol.descriptorCount).map { _ -> Int32 in
        let descriptor = dup(original)
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        return descriptor
      }
      let senderSocket = sockets[0]
      let payload = canonical()
      let sender = Self.startSender(senderSocket, payload, aliases)
      #expect(throws: (any Error).self) {
        try PrivateIPC.receive(controlDescriptor: sockets[1])
      }
      let senderResult = sender.wait()
      try #require(senderResult.0 == 0)
      #expect(senderResult.1 == 0)
      _ = close(original)
      closeAll(aliases)
      closeAll(sockets)
      #expect(openDescriptorCount() == baseline)
    }

    @Test
    func testMalformedConfigurationClosesReceivedDescriptors() throws {
      let baseline = openDescriptorCount()
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(cw_vz_fixture_socketpair(&sockets) == 0)
      let originals = try fixtureDescriptors()
      let senderSocket = sockets[0]
      let payload = Data("{}".utf8)
      let sender = Self.startSender(senderSocket, payload, originals)
      #expect(throws: (any Error).self) {
        try PrivateIPC.receive(controlDescriptor: sockets[1])
      }
      let senderResult = sender.wait()
      try #require(senderResult.0 == 0)
      #expect(senderResult.1 == 0)
      closeAll(originals)
      closeAll(sockets)
      #expect(openDescriptorCount() == baseline)
    }

    @Test
    func testClosedResponsePeerReturnsErrorWithoutSignal() throws {
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(cw_vz_fixture_socketpair(&sockets) == 0)
      try #require(close(sockets[0]) == 0)
      defer { _ = close(sockets[1]) }
      #expect(throws: (any Error).self) {
        try PrivateIPC.send(controlDescriptor: sockets[1], response: Data("fixture".utf8))
      }
    }

    @Test
    func testDatagramSocketIsRejectedBeforeReading() throws {
      var sockets = [Int32](repeating: -1, count: 2)
      try #require(socketpair(AF_UNIX, socketTypeDatagram(), 0, &sockets) == 0)
      defer { closeAll(sockets) }
      do {
        _ = try PrivateIPC.receive(controlDescriptor: sockets[1])
        Issue.record("expected datagram rejection")
      } catch {
        #expect(error as? IPCError == .rejected(-2))
      }
    }

    private static func send(
      _ socket: Int32,
      _ payload: Data,
      _ descriptors: [Int32]
    ) -> Int32 {
      payload.withUnsafeBytes { raw in
        descriptors.withUnsafeBufferPointer { fds in
          cw_vz_fixture_send_request(
            socket,
            raw.bindMemory(to: UInt8.self).baseAddress,
            payload.count,
            fds.baseAddress,
            descriptors.count
          )
        }
      }
    }

    private static func startSender(
      _ socket: Int32,
      _ payload: Data,
      _ descriptors: [Int32]
    ) -> SenderResult {
      let sender = SenderResult()
      DispatchQueue.global().async {
        let result = send(socket, payload, descriptors)
        sender.complete(result, shutdown(socket, Int32(SHUT_WR)))
      }
      return sender
    }

    private final class SenderResult: @unchecked Sendable {
      private let ready = DispatchSemaphore(value: 0)
      private var value: (Int32, Int32)?

      func complete(_ result: Int32, _ shutdownResult: Int32) {
        value = (result, shutdownResult)
        ready.signal()
      }

      func wait() -> (Int32, Int32) {
        ready.wait()
        return value!
      }
    }

    private func fixtureDescriptors(count: Int = 4) throws -> [Int32] {
      try (0..<count).map { _ in
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(
          "cw-vz-runner-\(UUID().uuidString)"
        )
        guard FileManager.default.createFile(atPath: path.path, contents: Data()) else {
          throw CocoaError(.fileWriteUnknown)
        }
        let descriptor = open(path.path, O_RDONLY)
        try FileManager.default.removeItem(at: path)
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        return descriptor
      }
    }

    private func canonical() -> Data {
      Data(
        """
        {"cpuCount":1,"daemonVsockPort":7777,"dataDisk":{"filesystemUUID":"10000000-0000-4000-8000-000000000001","size":268435456},"generation":1,"initialRamdisk":{"sha256":"\(String(repeating: "b", count: 64))","size":1},"kernel":{"sha256":"\(String(repeating: "a", count: 64))","size":1},"memoryMiB":512,"schemaVersion":1,"seedDisk":{"sha256":"\(String(repeating: "c", count: 64))","size":4096},"vmID":"00000000-0000-4000-8000-000000000001"}
        """.utf8)
    }

    private func socketTypeDatagram() -> Int32 {
      #if canImport(Glibc)
        Int32(SOCK_DGRAM.rawValue)
      #else
        SOCK_DGRAM
      #endif
    }

    private func closeAll(_ descriptors: [Int32]) {
      for descriptor in descriptors {
        _ = close(descriptor)
      }
    }

    private func openDescriptorCount() -> Int {
      let directory =
        FileManager.default.fileExists(atPath: "/proc/self/fd")
        ? "/proc/self/fd" : "/dev/fd"
      return (try? FileManager.default.contentsOfDirectory(atPath: directory).count) ?? -1
    }
  }
}
