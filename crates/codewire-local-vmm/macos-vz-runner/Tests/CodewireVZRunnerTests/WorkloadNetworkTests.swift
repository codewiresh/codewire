import CVZRunnerIPC
import CVZRunnerIPCTestSupport
import Foundation
import Testing

@testable import CodewireVZRunnerProtocol
@testable import CodewireVZRunnerRuntime

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

// Descriptor-owning tests share the existing serialized suite: unrelated
// concurrent file opens invalidate the whole-process leak-count assertions.
extension CodewireVZRunnerTests {
  @Suite struct WorkloadNetworkTests {
    @Test func strictCombinedTopologyPreservesProductionIdentity() throws {
      let value = try WorkloadNetworkConfiguration.decode(encode(object()))
      #expect(value.schemaVersion == 4)
      #expect(value.production.schemaVersion == 2)
      #expect(value.production.vmID == value.vmID)
      #expect(value.production.generation == value.generation)
      #expect(value.production.setupDisk == value.setupDisk)
      #expect(value.cpuCount == 2 && value.memoryMiB == 2048)
      #expect(WorkloadNetworkProtocol.descriptorCount == 10)
      #expect(WorkloadNetworkDescriptorRole.allCases.map(\.rawValue) == Array(0..<10))
      #expect(WorkloadNetworkDescriptorRole.progress.rawValue == 8)
      #expect(WorkloadNetworkDescriptorRole.daemon.rawValue == 9)
      #expect(throws: (any Error).self) {
        try ProductionFixtureConfiguration.decode(encode(object()))
      }
      #expect(throws: (any Error).self) { try ConsolePairConfiguration.decode(encode(object())) }
    }

    @Test func resourceIdentityAndCrossSchemaChangesReject() throws {
      for (field, replacement) in [
        ("schemaVersion", 2), ("generation", 0), ("cpuCount", 1), ("memoryMiB", 512),
        ("daemonVsockPort", 7775),
      ] {
        var value = object()
        value[field] = replacement
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(encode(value)) }
      }
      for nonce in ["", String(repeating: "0", count: 64), String(repeating: "F", count: 64)] {
        var value = object()
        value["runNonce"] = nonce
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(encode(value)) }
      }
      for size in [0, 4095, 4097] {
        var value = object()
        value["serviceBinding"] = ["size": size, "sha256": String(repeating: "f", count: 64)]
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(encode(value)) }
      }
      var sameDisk = object()
      sameDisk["rootDisk"] = sameDisk["stateDisk"]
      #expect(throws: (any Error).self) {
        try WorkloadNetworkConfiguration.decode(encode(sameDisk))
      }
    }

    @Test func unknownFieldsCanonicalBytesAndArtifactBoundsReject() throws {
      for field in ["networkChannel", "packetFD", "path", "timeout", "nic", "provider"] {
        var value = object()
        value[field] = "synthetic"
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(encode(value)) }
      }
      for artifact in ["kernel", "serviceInitialRamdisk", "serviceBinding", "setupDisk"] {
        var value = object()
        var nested = try #require(value[artifact] as? [String: Any])
        nested["path"] = "synthetic"
        value[artifact] = nested
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(encode(value)) }
      }
      let canonical = try encode(object())
      let duplicate = Data(
        String(decoding: canonical, as: UTF8.self).replacingOccurrences(
          of: "\"schemaVersion\":4", with: "\"schemaVersion\":4,\"schemaVersion\":4"
        ).utf8)
      for bytes in [
        Data(), Data("[]".utf8), Data([32]) + canonical, duplicate,
        Data(repeating: 65, count: 16385),
      ] {
        #expect(throws: (any Error).self) { try WorkloadNetworkConfiguration.decode(bytes) }
      }
    }

    @Test func exactTenDescriptorsAndAliases() throws {
      for variant in [
        "valid", "file-alias", "channel-alias", "control-alias", "role-swap", "short", "extra",
      ] {
        let fixture = try WorkloadDescriptorFixture()
        var descriptors = fixture.files + fixture.channels.map { $0[1] }
        switch variant {
        case "file-alias": descriptors[7] = descriptors[0]
        case "channel-alias": descriptors[9] = descriptors[8]
        case "control-alias": descriptors[8] = fixture.control[1]
        case "role-swap": descriptors.swapAt(7, 8)
        case "short": descriptors.removeLast()
        case "extra": descriptors.append(fixture.files[0])
        default: break
        }
        let bytes = try encode(object())
        let sent = bytes.withUnsafeBytes { raw in
          descriptors.withUnsafeBufferPointer {
            cw_vz_fixture_send_request(
              fixture.control[0], raw.bindMemory(to: UInt8.self).baseAddress,
              bytes.count, $0.baseAddress, $0.count)
          }
        }
        try #require(sent == 0)
        if variant == "valid" {
          var received: [Int32] = []
          do {
            let request = try PrivateIPC.receiveWorkloadNetwork(
              controlDescriptor: fixture.control[1])
            received = WorkloadNetworkDescriptorRole.allCases.map {
              request.descriptors.descriptor(for: $0)
            }
            #expect(request.descriptors.productionBootDescriptors == Array(received.prefix(6)))
            #expect(received.count == 10)
            for fd in received { #expect(fcntl(fd, F_GETFD) & FD_CLOEXEC != 0) }
          }
          for fd in received { #expect(cw_vz_fixture_descriptor_is_closed(fd) == 1) }
        } else {
          #expect(throws: (any Error).self) {
            try PrivateIPC.receiveWorkloadNetwork(controlDescriptor: fixture.control[1])
          }
        }
      }
    }

    @Test func heldStartIsOneUseAndSubsequentControlsWaitForForward() throws {
      var life = WorkloadNetworkLifecycle()
      #expect(throws: (any Error).self) { try life.begin(frame(0x41), bothStarted: false) }
      #expect(life.phase == .waiting)
      #expect(try life.begin(frame(0x41), bothStarted: true) == Data(frame(0x41).dropFirst(2)))
      #expect(throws: (any Error).self) { try life.begin(frame(0x41), bothStarted: true) }
      #expect(throws: (any Error).self) { try life.subsequent(frame(0x43)) }
      try life.didAttach()
      #expect(throws: (any Error).self) { try life.didAttach() }
      #expect(throws: (any Error).self) { try life.subsequent(frame(0x43)) }
      try life.didForward()
      #expect(try life.subsequent(frame(0x43)).count == 128)
      #expect(throws: (any Error).self) { try life.didForward() }
      #expect(throws: (any Error).self) { try life.begin(frame(0x41), bothStarted: true) }
    }

    @Test func wrongOuterOrInnerRolesAndLengthsNeverAdvance() {
      for bytes in [
        frame(0x43), frame(0x41, role: 1), Data(frame(0x41).dropLast()),
        frame(0x41) + Data([0]),
      ] {
        var life = WorkloadNetworkLifecycle()
        #expect(throws: (any Error).self) { try life.begin(bytes, bothStarted: true) }
        #expect(life.phase == .waiting)
      }
      var mismatch = frame(0x41)
      mismatch[10] = 1
      var life = WorkloadNetworkLifecycle()
      #expect(throws: (any Error).self) { try life.begin(mismatch, bothStarted: true) }
      #expect(life.phase == .waiting)
    }

    @Test func cancellationWinsBeforeDuringAndAfterAttachment() throws {
      for stage in 0...3 {
        var life = WorkloadNetworkLifecycle()
        if stage > 0 { _ = try life.begin(frame(0x41), bothStarted: true) }
        if stage > 1 { try life.didAttach() }
        if stage > 2 { try life.didForward() }
        life.cancel()
        life.cancel()
        #expect(throws: (any Error).self) { try life.begin(frame(0x41), bothStarted: true) }
        #expect(throws: (any Error).self) { try life.didAttach() }
        #expect(throws: (any Error).self) { try life.didForward() }
        #expect(throws: (any Error).self) { try life.subsequent(frame(0x43)) }
        if stage > 1 {
          #expect(throws: (any Error).self) { try life.claimClose() }
          #expect(throws: (any Error).self) { try life.didDetach(consumerTerminal: false) }
          try life.didDetach(consumerTerminal: true)
        }
        #expect(try life.claimClose())
        #expect(try !life.claimClose())
        #expect(throws: (any Error).self) { try life.didDetach(consumerTerminal: true) }
      }
      var abandoned = WorkloadNetworkLifecycle()
      _ = try abandoned.begin(frame(0x41), bothStarted: true)
      #expect(try abandoned.claimClose())
      #expect(throws: (any Error).self) { try abandoned.didAttach() }
    }

    @Test func relayPreservesOpaqueBytesAndPreStartedStatuses() throws {
      var wire = WorkloadNetworkWire()
      var status = Data(repeating: 0xa7, count: 128)
      status[8] = 2
      // No global-start argument or gate exists on the service status carrier.
      #expect(try wire.statuses(Data(status.prefix(17))).isEmpty)
      let relayed = try wire.statuses(Data(status.dropFirst(17)))
      #expect(relayed == [WorkloadNetworkWire.framed(Data([0x52, 2]) + status)])
      let expected = frame(0x41)
      let input = WorkloadNetworkWire.framed(expected)
      #expect(try wire.controls(Data(input.prefix(3))).isEmpty)
      #expect(try wire.controls(Data(input.dropFirst(3))) == [expected])
      #expect(wire.input.isEmpty && wire.status.isEmpty)
    }

    @Test func relayRejectsUnboundedWrongRoleAndUnexpectedFrames() throws {
      for bytes in [
        Data([0, 0, 0, 0]), Data([0, 0, 0, 129]), Data([255, 255, 255, 255]),
        WorkloadNetworkWire.framed(Data([0x01])), Data(repeating: 0, count: 1025),
      ] {
        var wire = WorkloadNetworkWire()
        #expect(throws: (any Error).self) { try wire.controls(bytes) }
      }
      var wire = WorkloadNetworkWire()
      #expect(throws: (any Error).self) { try wire.statuses(Data(repeating: 1, count: 128)) }
      var events = WorkloadNetworkWire()
      for _ in 0..<64 { _ = try events.event(Data([0x56, 2, 0])) }
      #expect(throws: (any Error).self) { try events.event(Data([0x56, 2, 0])) }
    }

    @Test func borrowedWrapperDoesNotCloseDescriptor() throws {
      let fixture = try WorkloadDescriptorFixture()
      let fd = fixture.channels[0][1]
      do {
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        #expect(handle.fileDescriptor == fd)
        withExtendedLifetime(handle) {}
      }
      #expect(fcntl(fd, F_GETFD) >= 0)
    }

    @Test func actualStopsDoNotDiscardUndrainedDaemonPoweroffResponse() {
      #expect(!WorkloadNetworkLifecycle.mayComplete(actualStops: [1, 2], daemonDrained: false))
      #expect(!WorkloadNetworkLifecycle.mayComplete(actualStops: [1], daemonDrained: true))
      #expect(!WorkloadNetworkLifecycle.mayComplete(actualStops: [], daemonDrained: true))
      #expect(WorkloadNetworkLifecycle.mayComplete(actualStops: [1, 2], daemonDrained: true))
      var forced = ConsolePairLifecycle()
      forced.apply(.stopSucceeded)
      #expect(forced.terminal)
      #expect(forced.drain().events == [2])  // Never an actual guestStopped event0.
    }

    @Test func diagnosticPreservesFirstFailureAndUnsentActualEventOnce() throws {
      var diagnostic = WorkloadNetworkDiagnostic()
      diagnostic.bridge(.progress, result: 2)
      diagnostic.bridge(.daemon, result: 1)
      diagnostic.reject(.daemonBridgeResult)
      diagnostic.vm(role: 2, event: 0)
      // A newly observed event can be recorded even if the failure prevents
      // its normal control-stream write. Neither event is a receipt or PASS.
      diagnostic.vm(role: 1, event: 0)
      diagnostic.reject(.workerFailure)
      let captured = diagnostic.takeLine(fallback: .runtime)
      let line = try #require(captured)
      #expect(
        String(decoding: line, as: UTF8.self)
          == "workload-network-diagnostic first=daemon-bridge-result progress=guest-drained daemon=local-eof production=guest-stopped service=guest-stopped\n"
      )
      diagnostic.vm(role: 1, event: 2)
      #expect(diagnostic.production == .guestStopped)
      #expect(diagnostic.takeLine(fallback: .normalCleanup) == nil)
      #expect(!WorkloadNetworkLifecycle.mayComplete(actualStops: [1, 2], daemonDrained: false))
    }

    @Test func diagnosticVocabularyAndOutputAreFiniteAndBounded() throws {
      let sites = Set(WorkloadNetworkDiagnostic.Site.allCases.map(\.rawValue))
      let bridges = Set(WorkloadNetworkDiagnostic.Bridge.allCases.map(\.rawValue))
      let machines = Set(WorkloadNetworkDiagnostic.VM.allCases.map(\.rawValue))
      for site in WorkloadNetworkDiagnostic.Site.allCases {
        for result in [Int32.min, -1, 0, 1, 2, Int32.max] {
          for event in [UInt8(0), 1, 2, 255] {
            var diagnostic = WorkloadNetworkDiagnostic()
            diagnostic.bridge(.progress, result: result)
            diagnostic.bridge(.daemon, result: result)
            diagnostic.vm(role: 1, event: event)
            diagnostic.vm(role: 2, event: event)
            let captured = diagnostic.takeLine(fallback: site)
            let bytes = try #require(captured)
            #expect(bytes.count <= 256)
            let line = String(decoding: bytes, as: UTF8.self)
            #expect(line.filter({ $0 == "\n" }).count == 1 && line.hasSuffix("\n"))
            let fields = line.dropLast().split(separator: " ").map(String.init)
            #expect(fields.count == 6 && fields[0] == "workload-network-diagnostic")
            #expect(sites.contains(String(fields[1].dropFirst("first=".count))))
            #expect(bridges.contains(String(fields[2].dropFirst("progress=".count))))
            #expect(bridges.contains(String(fields[3].dropFirst("daemon=".count))))
            #expect(machines.contains(String(fields[4].dropFirst("production=".count))))
            #expect(machines.contains(String(fields[5].dropFirst("service=".count))))
          }
        }
      }
    }

    #if os(macOS)
      @Test func abandonedConnectCompletionDisposesLateOwnership() throws {
        let pending = WorkloadCountingCompletion()
        #expect(throws: (any Error).self) { try pending.wait(deadline: 0, cancelled: { false }) }
        pending.complete(.success(7))
        #expect(pending.disposed == [7])
        let completed = WorkloadCountingCompletion()
        completed.complete(.success(8))
        #expect(throws: (any Error).self) {
          try completed.wait(
            deadline: ProcessInfo.processInfo.systemUptime + 1, cancelled: { true })
        }
        #expect(completed.disposed == [8])
      }
    #endif

    private func frame(_ tag: UInt8, role: UInt8 = 2) -> Data {
      var bytes = Data(repeating: 0x7b, count: 130)
      bytes[0] = tag
      bytes[1] = role
      bytes[10] = role
      return bytes
    }

    private func encode(_ object: [String: Any]) throws -> Data {
      try JSONSerialization.data(
        withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private func object() -> [String: Any] {
      [
        "schemaVersion": 4, "vmID": "00000000-0000-4000-8000-000000000001",
        "generation": 1, "cpuCount": 2, "memoryMiB": 2048, "daemonVsockPort": 7777,
        "runNonce": String(repeating: "9", count: 64),
        "kernel": ["size": 1, "sha256": String(repeating: "a", count: 64)],
        "initialRamdisk": ["size": 1, "sha256": String(repeating: "b", count: 64)],
        "seedDisk": ["size": 4096, "sha256": String(repeating: "c", count: 64)],
        "setupDisk": ["size": 65536, "sha256": String(repeating: "d", count: 64)],
        "serviceInitialRamdisk": ["size": 1, "sha256": String(repeating: "e", count: 64)],
        "serviceBinding": ["size": 4096, "sha256": String(repeating: "f", count: 64)],
        "stateDisk": [
          "size": 268_435_456, "filesystemUUID": "10000000-0000-4000-8000-000000000001",
        ],
        "rootDisk": [
          "size": 268_435_456, "filesystemUUID": "20000000-0000-4000-8000-000000000001",
        ],
      ]
    }
  }

}

private final class WorkloadDescriptorFixture {
  var files: [Int32] = []
  var channels: [[Int32]] = []
  var control: [Int32] = []
  init() throws {
    control = try pair()
    for _ in 0..<2 { channels.append(try pair()) }
    for _ in 0..<8 {
      var path = Array((NSTemporaryDirectory() + "cw-workload-network.XXXXXX").utf8CString)
      let fd = mkstemp(&path)
      try #require(fd >= 0)
      files.append(fd)
      try #require(unlink(path) == 0)
    }
  }
  private func pair() throws -> [Int32] {
    var result: [Int32] = [-1, -1]
    try #require(cw_vz_fixture_socketpair(&result) == 0)
    return result
  }
  deinit { for fd in files + control + channels.flatMap({ $0 }) { _ = close(fd) } }
}

#if os(macOS)
  private final class WorkloadCountingCompletion: FixtureCompletion<Int>, @unchecked Sendable {
    private(set) var disposed: [Int] = []
    override func dispose(_ value: Int) { disposed.append(value) }
  }
#endif
