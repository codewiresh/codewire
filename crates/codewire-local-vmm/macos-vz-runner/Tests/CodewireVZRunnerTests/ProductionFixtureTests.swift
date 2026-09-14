import CVZRunnerIPC
import CVZRunnerIPCTestSupport
import CodewireVZRunnerRuntime
import Dispatch
import Foundation
import Testing

@testable import CodewireVZRunnerProtocol

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

extension CodewireVZRunnerTests {
  @Suite struct ProductionFixtureTests {
    @Test func canonicalAndBoundedConfiguration() throws {
      let value = try ProductionFixtureConfiguration.decode(configuration())
      #expect(value.schemaVersion == 2)
      #expect(ProductionFixtureProtocol.descriptorCount == 9)
      #expect(ProductionDescriptorRole.network.port == 7775)
      #expect(ProductionDescriptorRole.progress.port == 7776)
      #expect(ProductionDescriptorRole.daemon.port == 7777)
      for (name, replacement) in [
        ("schemaVersion", 1), ("generation", 0), ("cpuCount", 0), ("cpuCount", 33),
        ("memoryMiB", 127), ("memoryMiB", 65537), ("daemonVsockPort", 7775),
      ] {
        var object = object()
        object[name] = replacement
        #expect(throws: (any Error).self) {
          try ProductionFixtureConfiguration.decode(encode(object))
        }
      }
      for size in [0, 4096, 65537, 65 * 1024 * 1024 * 1024 + 4096] {
        var object = object()
        object["setupDisk"] = ["size": size, "sha256": String(repeating: "d", count: 64)]
        #expect(throws: (any Error).self) {
          try ProductionFixtureConfiguration.decode(encode(object))
        }
      }
      var duplicateDisk = object()
      duplicateDisk["rootDisk"] = duplicateDisk["stateDisk"]
      #expect(throws: (any Error).self) {
        try ProductionFixtureConfiguration.decode(encode(duplicateDisk))
      }
    }

    @Test func unknownNonCanonicalAndCrossProtocolInputsFail() throws {
      for key in ["path", "authToken", "network", "timeout", "directShares", "dockerDisk"] {
        var object = object()
        object[key] = "synthetic"
        #expect(throws: (any Error).self) {
          try ProductionFixtureConfiguration.decode(encode(object))
        }
      }
      var nested = object()
      nested["setupDisk"] = [
        "size": 65536, "sha256": String(repeating: "d", count: 64), "path": "synthetic",
      ]
      #expect(throws: (any Error).self) {
        try ProductionFixtureConfiguration.decode(encode(nested))
      }
      let canonical = try configuration()
      #expect(throws: (any Error).self) { try RunnerConfiguration.decode(canonical) }
      for bytes in [
        Data(), Data("[]".utf8), Data(" ".utf8) + canonical,
        Data(repeating: 65, count: 16385),
        Data(
          String(decoding: canonical, as: UTF8.self).replacingOccurrences(
            of: "\"schemaVersion\":2", with: "\"schemaVersion\":2,\"schemaVersion\":2"
          ).utf8),
      ] {
        #expect(throws: (any Error).self) { try ProductionFixtureConfiguration.decode(bytes) }
      }
    }

    @Test func nineDescriptorsAreOwnedAndAliasesRejected() throws {
      for invalid in [
        "none", "file-alias", "channel-alias", "control-alias", "role-swap", "short", "extra",
      ] {
        let fixture = try DescriptorFixture()
        var descriptors = fixture.files + fixture.channels.map { $0[1] }
        switch invalid {
        case "file-alias": descriptors[4] = descriptors[3]
        case "channel-alias": descriptors[7] = descriptors[6]
        case "control-alias": descriptors[6] = fixture.control[1]
        case "role-swap": descriptors.swapAt(5, 6)
        case "short": descriptors.removeLast()
        case "extra": descriptors.append(fixture.files[0])
        default: break
        }
        let payload = try configuration()
        let result = payload.withUnsafeBytes { raw in
          descriptors.withUnsafeBufferPointer {
            cw_vz_fixture_send_request(
              fixture.control[0], raw.bindMemory(to: UInt8.self).baseAddress,
              payload.count, $0.baseAddress, $0.count)
          }
        }
        try #require(result == 0)
        if invalid == "none" {
          var received: [Int32] = []
          do {
            let request = try PrivateIPC.receiveProductionFixture(
              controlDescriptor: fixture.control[1])
            received = ProductionDescriptorRole.allCases.map {
              request.descriptors.descriptor(for: $0)
            }
            #expect(received.count == 9)
            for fd in received { #expect(fcntl(fd, F_GETFD) & FD_CLOEXEC != 0) }
          }
          for fd in received { #expect(cw_vz_fixture_descriptor_is_closed(fd) == 1) }
        } else {
          #expect(throws: (any Error).self) {
            try PrivateIPC.receiveProductionFixture(controlDescriptor: fixture.control[1])
          }
        }
      }
    }

    @Test func lifecycleDoesNotInventReadinessOrReuseChannels() throws {
      let life = ProductionFixtureLifecycle()
      #expect(throws: (any Error).self) { try life.progressClosed() }
      #expect(throws: (any Error).self) { try life.didConnect(.rootDisk) }
      #expect(try life.didConnect(.progress) == "progress-connected")
      #expect(try life.progressClosed() == "progress-closed")
      #expect(life.end == nil)
      #expect(throws: (any Error).self) { try life.progressClosed() }
      #expect(throws: (any Error).self) { try life.didConnect(.progress) }
      #expect(try life.didConnect(.network) == "network-connected")
      #expect(try life.didConnect(.daemon) == "daemon-connected")
      #expect(life.end == nil)
      #expect(life.finish(.parentClosed))
      #expect(!life.finish(.failed))
      #expect(throws: (any Error).self) { try life.didConnect(.network) }
    }

    @Test func opaqueBridgeForwardsBothWaysAndCancels() throws {
      let fixture = try BridgeFixture()
      let result = fixture.start(preserve: false)
      let payload = Data("synthetic-network-frame".utf8)
      try send(payload, fd: fixture.local[0])
      #expect(try receive(payload.count, fd: fixture.guest[0]) == payload)
      try send(payload, fd: fixture.guest[0])
      #expect(try receive(payload.count, fd: fixture.local[0]) == payload)
      try send(Data([1]), fd: fixture.cancel[0])
      #expect(try result.wait() == 0)
    }

    @Test func progressGuestEOFDrainsBeforeHalfClose() throws {
      let fixture = try BridgeFixture()
      let result = fixture.start(preserve: true)
      let payload = Data(repeating: 0x57, count: 96)
      try send(payload, fd: fixture.guest[0])
      try #require(shutdown(fixture.guest[0], Int32(SHUT_WR)) == 0)
      #expect(try receive(payload.count, fd: fixture.local[0]) == payload)
      #expect(try result.wait() == 2)
      var byte: UInt8 = 0
      #expect(read(fixture.local[0], &byte, 1) == 0)
      // The retained parent write direction remains independently observable.
      #expect(cw_vz_control_event(fixture.local[1], 0) == 0)
      try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0)
      #expect(cw_vz_control_event(fixture.local[1], 100) == 1)
    }

    @Test func backpressureStillAllowsBoundedCancellation() throws {
      let fixture = try BridgeFixture()
      var capacity: Int32 = 4096
      try #require(
        setsockopt(
          fixture.guest[1], SOL_SOCKET, SO_SNDBUF, &capacity,
          socklen_t(MemoryLayout<Int32>.size)) == 0)
      let flags = fcntl(fixture.local[0], F_GETFL)
      try #require(flags >= 0 && fcntl(fixture.local[0], F_SETFL, flags | O_NONBLOCK) == 0)
      let result = fixture.start(preserve: false)
      let payload = [UInt8](repeating: 0x4f, count: 32768)
      for _ in 0..<64 {
        let count = payload.withUnsafeBytes { write(fixture.local[0], $0.baseAddress, $0.count) }
        if count < 0 {
          try #require(errno == EAGAIN || errno == EWOULDBLOCK)
          break
        }
      }
      // The guest never consumes output. Cancellation must still win over a
      // blocked forwarding direction without an unbounded queued Data value.
      try send(Data([1]), fd: fixture.cancel[0])
      #expect(try result.wait() == 0)
    }

    @Test func channelEOFAndDeadlineAreNotSuccess() throws {
      for preserve in [false, true] {
        let fixture = try BridgeFixture()
        let result = fixture.start(preserve: preserve)
        try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0)
        #expect(try result.wait() == 1)
      }
      let ordinary = try BridgeFixture()
      let ended = ordinary.start(preserve: false)
      try #require(shutdown(ordinary.guest[0], Int32(SHUT_WR)) == 0)
      #expect(try ended.wait() == 1)
      let timed = try BridgeFixture()
      #expect(try timed.start(preserve: false, seconds: 1).wait() == -1)
    }

    @Test func unsolicitedControlAndInvalidBudgetsFail() throws {
      let fixture = try BridgeFixture()
      #expect(cw_vz_control_event(fixture.local[1], 0) == 0)
      try send(Data([7]), fd: fixture.local[0])
      #expect(cw_vz_control_event(fixture.local[1], 100) == -1)
      for seconds in [Int32(0), 181] {
        #expect(
          cw_vz_bridge_streams(fixture.local[1], fixture.guest[1], fixture.cancel[1], seconds, 0)
            == -1)
      }
    }

    @Test func daemonLocalEOFAloneDoesNotProveGuestDrain() throws {
      let fixture = try BridgeFixture()
      let result = fixture.startDaemon(seconds: 1)
      try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0)
      #expect(try result.wait() == -1)
    }

    @Test func daemonLocalFirstEOFStillForwardsDelayedReply() throws {
      let fixture = try BridgeFixture()
      let result = fixture.startDaemon()
      let request = Data([0, 255, 0x31, 0x80])
      try send(request, fd: fixture.local[0])
      try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0)
      #expect(try receive(request.count, fd: fixture.guest[0]) == request)
      try requireEOF(fixture.guest[0])
      // Guest EOF has deliberately not occurred. The reply starts only after
      // observing the real propagated request half-close; no sleep/timing guess.
      #expect(result.isPending())
      let reply = Data([0xff, 0, 0x80, 0x27, 0])
      try send(reply, fd: fixture.guest[0])
      try #require(shutdown(fixture.guest[0], Int32(SHUT_WR)) == 0)
      #expect(try receive(reply.count, fd: fixture.local[0]) == reply)
      try requireEOF(fixture.local[0])
      #expect(try result.wait() == 2)
    }

    @Test func daemonGuestFirstAndSimultaneousEOFRequireRealGuestDrain() throws {
      for simultaneous in [false, true] {
        let fixture = try BridgeFixture()
        let reply = Data([0, 1, 0xff, 0x80])
        try send(reply, fd: fixture.guest[0])
        try #require(shutdown(fixture.guest[0], Int32(SHUT_WR)) == 0)
        if simultaneous { try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0) }
        let result = fixture.startDaemon()
        #expect(try receive(reply.count, fd: fixture.local[0]) == reply)
        try requireEOF(fixture.local[0])
        #expect(try result.wait() == 2)
        if !simultaneous { try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0) }
      }
    }

    @Test func daemonBufferedRequestsAndRepliesDrainBeforeEOF() throws {
      let fixture = try BridgeFixture()
      var capacity: Int32 = 4096
      for fd in [fixture.local[1], fixture.guest[1]] {
        try #require(
          setsockopt(
            fd, SOL_SOCKET, SO_SNDBUF, &capacity,
            socklen_t(MemoryLayout<Int32>.size)) == 0)
      }
      let result = fixture.startDaemon()
      let request = Data((0..<(3 * 32768)).map { UInt8($0 % 251) })
      let sent = try fixture.writeThenShutdown(request, descriptor: fixture.local[0])
      #expect(try receive(request.count, fd: fixture.guest[0]) == request)
      try requireEOF(fixture.guest[0])
      #expect(try sent.wait() == 0)
      #expect(result.isPending())
      let reply = Data(request.map { $0 ^ 0xa5 })
      let replied = try fixture.writeThenShutdown(reply, descriptor: fixture.guest[0])
      #expect(try receive(reply.count, fd: fixture.local[0]) == reply)
      try requireEOF(fixture.local[0])
      #expect(try replied.wait() == 0)
      #expect(try result.wait() == 2)
    }

    @Test func daemonFullLocalCloseWithReplyIsNotDrainSuccess() throws {
      let fixture = try BridgeFixture()
      try fixture.closeLocalPeer()
      try send(Data([0, 255, 1]), fd: fixture.guest[0])
      try #require(shutdown(fixture.guest[0], Int32(SHUT_WR)) == 0)
      #expect(try fixture.startDaemon().wait() == -1)
    }

    @Test func daemonReadShutdownWithoutWritableReadinessRemainsBoundedFailure() throws {
      let fixture = try BridgeFixture()
      // Unlike actual close, Darwin SHUT_RDWR can withhold POLLOUT while a
      // blind send would claim success and discard bytes. Do not bypass poll.
      try #require(shutdown(fixture.local[0], Int32(SHUT_RDWR)) == 0)
      try send(Data([0, 255, 1]), fd: fixture.guest[0])
      try #require(shutdown(fixture.guest[0], Int32(SHUT_WR)) == 0)
      #expect(try fixture.startDaemon(seconds: 1).wait() == -1)
    }

    @Test func daemonReplyBackpressureStillCancels() throws {
      let fixture = try BridgeFixture()
      var capacity: Int32 = 4096
      try #require(
        setsockopt(
          fixture.local[1], SOL_SOCKET, SO_SNDBUF, &capacity,
          socklen_t(MemoryLayout<Int32>.size)) == 0)
      let flags = fcntl(fixture.guest[0], F_GETFL)
      try #require(flags >= 0 && fcntl(fixture.guest[0], F_SETFL, flags | O_NONBLOCK) == 0)
      let result = fixture.startDaemon()
      try #require(shutdown(fixture.local[0], Int32(SHUT_WR)) == 0)
      try requireEOF(fixture.guest[0])
      let payload = [UInt8](repeating: 0xa5, count: 32768)
      var blocked = false
      for _ in 0..<64 {
        let count = payload.withUnsafeBytes { write(fixture.guest[0], $0.baseAddress, $0.count) }
        if count < 0 {
          try #require(errno == EAGAIN || errno == EWOULDBLOCK)
          blocked = true
          break
        }
      }
      #expect(blocked)
      try send(Data([1]), fd: fixture.cancel[0])
      #expect(try result.wait() == 0)
    }

    private func requireEOF(_ descriptor: Int32) throws {
      var polled = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
      try #require(poll(&polled, 1, 2000) == 1)
      var byte: UInt8 = 0
      try #require(read(descriptor, &byte, 1) == 0)
    }

    private func object() -> [String: Any] {
      [
        "schemaVersion": 2, "vmID": "00000000-0000-4000-8000-000000000001",
        "generation": 1, "cpuCount": 1, "memoryMiB": 512, "daemonVsockPort": 7777,
        "kernel": ["size": 1, "sha256": String(repeating: "a", count: 64)],
        "initialRamdisk": ["size": 1, "sha256": String(repeating: "b", count: 64)],
        "seedDisk": ["size": 4096, "sha256": String(repeating: "c", count: 64)],
        "setupDisk": ["size": 65536, "sha256": String(repeating: "d", count: 64)],
        "stateDisk": [
          "size": 268_435_456, "filesystemUUID": "10000000-0000-4000-8000-000000000001",
        ],
        "rootDisk": [
          "size": 268_435_456, "filesystemUUID": "20000000-0000-4000-8000-000000000001",
        ],
      ]
    }
    private func encode(_ object: [String: Any]) throws -> Data {
      try JSONSerialization.data(
        withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func configuration() throws -> Data { try encode(object()) }
    private func send(_ bytes: Data, fd: Int32) throws {
      try bytes.withUnsafeBytes { raw in
        try #require(write(fd, raw.baseAddress, bytes.count) == bytes.count)
      }
    }
    private func receive(_ size: Int, fd: Int32) throws -> Data {
      var bytes = [UInt8](repeating: 0, count: size)
      var offset = 0
      while offset < size {
        var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        try #require(poll(&item, 1, 2000) == 1)
        let count = bytes.withUnsafeMutableBytes {
          read(fd, $0.baseAddress?.advanced(by: offset), size - offset)
        }
        try #require(count > 0)
        offset += count
      }
      return Data(bytes)
    }
  }
}

private final class DescriptorFixture {
  var control: [Int32] = []
  var channels: [[Int32]] = []
  var files: [Int32] = []
  init() throws {
    control = try pair()
    for _ in 0..<3 { channels.append(try pair()) }
    for _ in 0..<6 {
      var name = Array((NSTemporaryDirectory() + "cw-vz-production.XXXXXX").utf8CString)
      let fd = mkstemp(&name)
      try #require(fd >= 0)
      files.append(fd)
      try #require(unlink(name) == 0)
    }
  }
  deinit { for fd in control + channels.flatMap({ $0 }) + files { _ = close(fd) } }
}

private final class BridgeFixture: @unchecked Sendable {
  let local: [Int32]
  let guest: [Int32]
  let cancel: [Int32]
  private var localPeerClosed = false
  init() throws {
    local = try pair()
    guest = try pair()
    cancel = try pair()
  }
  deinit {
    let retainedLocal = localPeerClosed ? [local[1]] : local
    for fd in retainedLocal + guest + cancel { _ = close(fd) }
  }
  func closeLocalPeer() throws {
    // Called before starting the bridge; never close a reused descriptor in
    // deinit after this exact endpoint was intentionally released.
    try #require(!localPeerClosed)
    try #require(close(local[0]) == 0)
    localPeerClosed = true
  }
  func start(preserve: Bool, seconds: Int32 = 5) -> BridgeResult {
    let result = BridgeResult()
    DispatchQueue.global().async {
      result.complete(
        cw_vz_bridge_streams(
          self.local[1], self.guest[1], self.cancel[1], seconds, preserve ? 1 : 0))
    }
    return result
  }
  func startDaemon(seconds: Int32 = 5) -> BridgeResult {
    let result = BridgeResult()
    DispatchQueue.global().async {
      result.complete(
        cw_vz_bridge_daemon_streams(
          self.local[1], self.guest[1], self.cancel[1], seconds))
    }
    return result
  }
  func writeThenShutdown(_ bytes: Data, descriptor: Int32) throws -> BridgeResult {
    let flags = fcntl(descriptor, F_GETFL)
    try #require(flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0)
    let result = BridgeResult()
    DispatchQueue.global().async {
      // Capture this fixture so every borrowed socket remains owned until the
      // bounded writer has stopped, including after a test assertion fails.
      withExtendedLifetime(self) {
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        var offset = 0
        while offset < bytes.count, ProcessInfo.processInfo.systemUptime < deadline {
          var polled = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
          if poll(&polled, 1, 20) < 0 && errno != EINTR {
            result.complete(-1)
            return
          }
          if polled.revents & Int16(POLLOUT) == 0 { continue }
          let count = bytes.withUnsafeBytes {
            write(descriptor, $0.baseAddress?.advanced(by: offset), bytes.count - offset)
          }
          if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
          if count <= 0 {
            result.complete(-1)
            return
          }
          offset += count
        }
        result.complete(offset == bytes.count && shutdown(descriptor, Int32(SHUT_WR)) == 0 ? 0 : -1)
      }
    }
    return result
  }
}

private final class BridgeResult: @unchecked Sendable {
  let signal = DispatchSemaphore(value: 0)
  var result: Int32 = -9
  func complete(_ value: Int32) {
    result = value
    signal.signal()
  }
  func wait() throws -> Int32 {
    try #require(signal.wait(timeout: .now() + 3) == .success)
    return result
  }
  func isPending() -> Bool {
    if signal.wait(timeout: .now()) == .timedOut { return true }
    signal.signal()
    return false
  }
}

private func pair() throws -> [Int32] {
  var fds: [Int32] = [-1, -1]
  try #require(cw_vz_fixture_socketpair(&fds) == 0)
  return fds
}
