import CCanarySupport
import Darwin
import Foundation
import SandboxCanaryProtocol
import Testing

private func spawnFixedTrue() -> pid_t {
  let control = open("/dev/null", O_RDONLY | O_CLOEXEC)
  guard control >= 0 else { return -1 }
  defer { _ = close(control) }
  var child: pid_t = 0
  let result = "/usr/bin/true".withCString { executable in
    cw_canary_spawn(executable, control, &child)
  }
  // cw_canary_spawn uses fixed argv/environment, a fresh process group, and
  // POSIX_SPAWN_CLOEXEC_DEFAULT; only this private descriptor is mapped to 3.
  return result == 0 ? child : -1
}

@Suite(.serialized) struct ProtocolTests {
  private let nonce = "0123456789abcdef0123456789abcdef"

  @Test
  func testLaunchCompletionDiagnosticIsExactAndCannotCarryAuthority() throws {
    for observation in ["succeeded", "failed"] {
      let encoded = try encodeMessage(
        WireMessage(kind: "launch-completion", nonce: nonce, observation: observation))
      #expect(try decodeMessage(encoded).observation == observation)
      var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
      for key in ["pid", "sha256", "canaryPath", "terminated", "extra"] {
        var invalid = object
        invalid[key] = "synthetic"
        #expect(throws: (any Error).self) {
          try decodeMessage(JSONSerialization.data(withJSONObject: invalid))
        }
      }
      object["nonce"] = "invalid"
      #expect(throws: (any Error).self) {
        try decodeMessage(JSONSerialization.data(withJSONObject: object))
      }
    }
    for observation in ["denied", "unknown", "not-run", "", "arbitrary"] {
      #expect(throws: (any Error).self) {
        try encodeMessage(
          WireMessage(kind: "launch-completion", nonce: nonce, observation: observation))
      }
    }
  }

  @Test
  func testLaunchCompletionSequenceRejectsContradictionsAndDuplicates() throws {
    let success = WireMessage(kind: "launch-completion", nonce: nonce, observation: "succeeded")
    let failure = WireMessage(kind: "launch-completion", nonce: nonce, observation: "failed")
    let launched = WireMessage(
      kind: "deputy-launch", nonce: nonce, bundleIdentifier: "dev.codewire.fixture",
      pid: 123, bundlePath: "/fixture/Deputy.app",
      executablePath: "/fixture/Deputy.app/Contents/MacOS/deputy", terminated: false)
    let denied = WireMessage(kind: "deputy-launch-failed", nonce: nonce, observation: "denied")
    try validateLaunchCompletion(success, followedBy: launched, nonce: nonce)
    try validateLaunchCompletion(failure, followedBy: denied, nonce: nonce)
    for pair in [(success, denied), (failure, launched), (success, success), (launched, launched)] {
      #expect(throws: (any Error).self) {
        try validateLaunchCompletion(pair.0, followedBy: pair.1, nonce: nonce)
      }
    }
    #expect(throws: (any Error).self) {
      try validateLaunchCompletion(
        success, followedBy: launched, nonce: String(repeating: "a", count: 32))
    }
  }

  @Test
  func testSharedFrameDeadlineRejectsReadyDataAfterExpiry() throws {
    var pair = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
    guard pair[0] >= 0, pair[1] >= 0 else { return }
    defer {
      _ = close(pair[0])
      _ = close(pair[1])
    }
    let frame = WireMessage(kind: "finish", nonce: nonce)
    try writeFrame(frame, to: pair[1])
    try writeFrame(frame, to: pair[1])
    try writeFrame(frame, to: pair[1])
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    #expect(try readFrame(from: pair[0], deadline: deadline).kind == "finish")
    #expect(try readFrame(from: pair[0], deadline: deadline).kind == "finish")
    let expired = ContinuousClock.now.advanced(by: .milliseconds(-1))
    #expect(throws: (any Error).self) { try readFrame(from: pair[0], deadline: expired) }
  }

  @Test
  func testPartialFrameDoesNotRestartDeadline() throws {
    var pair = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
    guard pair[0] >= 0, pair[1] >= 0 else { return }
    let reader = pair[0]
    let writer = pair[1]
    let payload = try encodeMessage(WireMessage(kind: "finish", nonce: nonce))
    var size = UInt32(payload.count).bigEndian
    let header = withUnsafeBytes(of: &size) { Data($0) }
    let finished = DispatchSemaphore(value: 0)
    let deadline = ContinuousClock.now.advanced(by: .milliseconds(60))
    DispatchQueue.global().async {
      defer { finished.signal() }
      for chunk in [Data(header.prefix(2)), Data(header.suffix(2)), payload] {
        let count = chunk.withUnsafeBytes { Darwin.write(writer, $0.baseAddress, $0.count) }
        precondition(count == chunk.count, "synthetic fixture write failed")
        usleep(40_000)
      }
    }
    #expect(throws: (any Error).self) {
      try readFrame(from: reader, deadline: deadline)
    }
    let quiescent = finished.wait(timeout: .now() + .seconds(2)) == .success
    #expect(quiescent)
    // Do not close/reuse descriptors if the synthetic writer's state is unknown.
    if quiescent {
      _ = close(reader)
      _ = close(writer)
    }
  }

  @Test
  func testConfigureRoundTripIsExact() throws {
    let message = WireMessage(
      kind: "configure", nonce: nonce, mode: .candidate,
      canaryPath: "/private/canary",
      deputyBundlePath: "/private/Candidate.app/Contents/Helpers/Deputy.app",
      bundleIdentifier: "dev.codewire.experiment.deputy.fixture")
    let encoded = try encodeMessage(message)
    #expect(try decodeMessage(encoded).mode == .candidate)
  }

  @Test
  func testOwnerConfigurationRequiresAllPinnedHashesAndCheckpoint() throws {
    let configuration = OwnerConfiguration(
      schemaVersion: 1, nonce: nonce, canaryPath: "/private/canary",
      expectedCanarySHA256: String(repeating: "a", count: 64),
      endpointPath: "/private/deputy.sock",
      controlExecutable: "/private/Control.app/Contents/MacOS/sandbox-candidate",
      candidateExecutable: "/private/Candidate.app/Contents/MacOS/sandbox-candidate",
      deputyBundlePath: "/private/Candidate.app/Contents/Helpers/Deputy.app",
      deputyExecutable:
        "/private/Candidate.app/Contents/Helpers/Deputy.app/Contents/MacOS/canary-deputy",
      controlBundleIdentifier: "dev.codewire.experiment.control.fixture",
      candidateBundleIdentifier: "dev.codewire.experiment.candidate.fixture",
      deputyBundleIdentifier: "dev.codewire.experiment.deputy.fixture",
      controlCDHash: String(repeating: "b", count: 40),
      candidateCDHash: String(repeating: "c", count: 40),
      deputyCDHash: String(repeating: "d", count: 40),
      checkpointPath: "/private/checkpoint.json")
    #expect(throws: Never.self) { try configuration.validate() }

    let encoded = try JSONEncoder().encode(configuration)
    var object = try #require(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    object["deputyCDHash"] = String(repeating: "D", count: 40)
    let invalid = try JSONDecoder().decode(
      OwnerConfiguration.self, from: JSONSerialization.data(withJSONObject: object))
    #expect(throws: (any Error).self) { try invalid.validate() }
  }

  @Test
  func testCleanupRefusesAnAlreadyReapedChild() {
    #expect(cw_canary_normalize_sigchld() == 0)
    let child = spawnFixedTrue()
    #expect(child > 1)
    guard child > 1 else { return }
    var status: Int32 = 0
    #expect(waitpid(child, &status, 0) == child)
    #expect(cw_canary_cleanup_child(child) == CW_CANARY_CLEANUP_UNKNOWN)
  }

  @Test
  func testCleanupReportsUnknownForInheritedAutoreap() {
    _ = signal(SIGCHLD, SIG_IGN)
    defer { #expect(cw_canary_normalize_sigchld() == 0) }
    let child = spawnFixedTrue()
    #expect(child > 1)
    guard child > 1 else { return }
    let deadline = Date().addingTimeInterval(2)
    while kill(child, 0) == 0 && Date() < deadline {
      usleep(10_000)
    }
    #expect(cw_canary_cleanup_child(child) == CW_CANARY_CLEANUP_UNKNOWN)
  }

  @Test
  func testCheckpointReplacementIsBoundedAndExact() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "codewire-canary-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let checkpoint = directory.appendingPathComponent("checkpoint.json")
    let initial = Data("initial\n".utf8)
    #expect(
      FileManager.default.createFile(
        atPath: checkpoint.path, contents: initial,
        attributes: [.posixPermissions: 0o600]))
    let replacement = Data("{\"schemaVersion\":1}\n".utf8)
    let result = checkpoint.path.withCString { path in
      replacement.withUnsafeBytes { bytes in
        cw_canary_replace_checkpoint(
          path, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
      }
    }
    #expect(result == 0)
    #expect(try Data(contentsOf: checkpoint) == replacement)
    #expect(!FileManager.default.fileExists(atPath: checkpoint.path + ".next"))

    let oversized = Data(repeating: 0x61, count: 4097)
    let rejected = checkpoint.path.withCString { path in
      oversized.withUnsafeBytes { bytes in
        cw_canary_replace_checkpoint(
          path, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
      }
    }
    #expect(rejected == -1)
    #expect(try Data(contentsOf: checkpoint) == replacement)
  }

  @Test
  func testResultRequiresHashOnlyOnSuccess() throws {
    #expect(throws: Never.self) {
      try decodeMessage(
        encodeMessage(
          WireMessage(
            kind: "deputy-result", nonce: nonce, observation: "succeeded",
            sha256: String(repeating: "b", count: 64))))
    }
    #expect(throws: Never.self) {
      try decodeMessage(
        encodeMessage(
          WireMessage(kind: "deputy-result", nonce: nonce, observation: "denied")))
    }
    #expect(throws: (any Error).self) {
      try encodeMessage(
        WireMessage(kind: "deputy-result", nonce: nonce, observation: "succeeded"))
    }
    #expect(throws: (any Error).self) {
      try encodeMessage(
        WireMessage(
          kind: "deputy-result", nonce: nonce, observation: "denied",
          sha256: String(repeating: "b", count: 64)))
    }
  }

  @Test
  func testUnknownMissingAndTrailingFieldsAreRejected() throws {
    let valid = try encodeMessage(WireMessage(kind: "arm", nonce: nonce))
    var object = try #require(
      JSONSerialization.jsonObject(with: valid) as? [String: Any])
    object["path"] = "/private/unrelated"
    #expect(throws: (any Error).self) {
      try decodeMessage(JSONSerialization.data(withJSONObject: object))
    }

    object.removeValue(forKey: "path")
    object.removeValue(forKey: "nonce")
    #expect(throws: (any Error).self) {
      try decodeMessage(JSONSerialization.data(withJSONObject: object))
    }

    var trailing = valid
    trailing.append(Data("{}".utf8))
    #expect(throws: (any Error).self) { try decodeMessage(trailing) }
  }

  @Test
  func testOversizeAndNoncanonicalNonceAreRejected() {
    #expect(throws: (any Error).self) {
      try decodeMessage(Data(repeating: 0x20, count: maximumFrameBytes + 1))
    }
    #expect(throws: (any Error).self) {
      try encodeMessage(
        WireMessage(
          kind: "arm", nonce: "ABCDEF0123456789ABCDEF0123456789"))
    }
  }

  @Test
  func testOwnerResultKeepsPropertyAndCompletionIndependent() throws {
    let result = OwnerResult(
      property: "falsified", completion: "unknown",
      control: ArmObservation(
        mode: .control, directRead: "succeeded", deputyRead: "succeeded",
        completion: "complete"),
      candidate: ArmObservation(
        mode: .candidate, directRead: "denied", deputyRead: "succeeded",
        completion: "unknown"))
    let object = try #require(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(result)) as? [String: Any])
    #expect(object["property"] as? String == "falsified")
    #expect(object["completion"] as? String == "unknown")
    #expect(object["artifacts"] as? String == "retained")
  }
}
