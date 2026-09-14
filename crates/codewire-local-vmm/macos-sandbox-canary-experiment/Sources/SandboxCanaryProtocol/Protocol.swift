import CCanarySupport
import CryptoKit
import Darwin
import Foundation

public let controlDescriptor: Int32 = 3
public let maximumFrameBytes = 8 * 1024

public enum ExperimentError: Error {
  case invalid
  case io
  case timeout
}

public enum ArmMode: String, Codable, Sendable {
  case control
  case candidate
}

public struct OwnerConfiguration: Codable, Sendable {
  public let schemaVersion: Int
  public let nonce: String
  public let canaryPath: String
  public let expectedCanarySHA256: String
  public let endpointPath: String
  public let controlExecutable: String
  public let candidateExecutable: String
  public let deputyBundlePath: String
  public let deputyExecutable: String
  public let controlBundleIdentifier: String
  public let candidateBundleIdentifier: String
  public let deputyBundleIdentifier: String
  public let controlCDHash: String
  public let candidateCDHash: String
  public let deputyCDHash: String
  public let checkpointPath: String

  public init(
    schemaVersion: Int, nonce: String, canaryPath: String, expectedCanarySHA256: String,
    endpointPath: String, controlExecutable: String, candidateExecutable: String,
    deputyBundlePath: String, deputyExecutable: String, controlBundleIdentifier: String,
    candidateBundleIdentifier: String, deputyBundleIdentifier: String, controlCDHash: String,
    candidateCDHash: String, deputyCDHash: String, checkpointPath: String
  ) {
    self.schemaVersion = schemaVersion
    self.nonce = nonce
    self.canaryPath = canaryPath
    self.expectedCanarySHA256 = expectedCanarySHA256
    self.endpointPath = endpointPath
    self.controlExecutable = controlExecutable
    self.candidateExecutable = candidateExecutable
    self.deputyBundlePath = deputyBundlePath
    self.deputyExecutable = deputyExecutable
    self.controlBundleIdentifier = controlBundleIdentifier
    self.candidateBundleIdentifier = candidateBundleIdentifier
    self.deputyBundleIdentifier = deputyBundleIdentifier
    self.controlCDHash = controlCDHash
    self.candidateCDHash = candidateCDHash
    self.deputyCDHash = deputyCDHash
    self.checkpointPath = checkpointPath
  }

  public func validate() throws {
    guard schemaVersion == 1,
      nonce.utf8.count == 32 && nonce.allSatisfy({ "0123456789abcdef".contains($0) }),
      expectedCanarySHA256.utf8.count == 64
        && expectedCanarySHA256.allSatisfy({ "0123456789abcdef".contains($0) }),
      [
        canaryPath, endpointPath, controlExecutable, candidateExecutable, deputyBundlePath,
        deputyExecutable, checkpointPath,
      ].allSatisfy({
        $0.first == "/" && !$0.contains("\0")
      }),
      endpointPath.utf8.count < 104,
      [controlCDHash, candidateCDHash, deputyCDHash].allSatisfy({ hash in
        hash.utf8.count == 40
          && hash.allSatisfy({ "0123456789abcdef".contains($0) })
      }),
      Set([canaryPath, endpointPath, checkpointPath]).count == 3,
      [controlBundleIdentifier, candidateBundleIdentifier, deputyBundleIdentifier]
        .allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 })
    else {
      throw ExperimentError.invalid
    }
  }
}

public struct DeputyConfiguration: Codable, Sendable {
  public let schemaVersion: Int
  public let nonce: String
  public let endpointPath: String
  public let canaryPath: String

  public func validate() throws {
    guard schemaVersion == 1, nonce.utf8.count == 32,
      nonce.allSatisfy({ "0123456789abcdef".contains($0) }),
      endpointPath.first == "/", endpointPath.utf8.count < 104,
      canaryPath.first == "/", !endpointPath.contains("\0"), !canaryPath.contains("\0")
    else {
      throw ExperimentError.invalid
    }
  }
}

public struct WireMessage: Codable, Sendable {
  public let schemaVersion: Int
  public let kind: String
  public let nonce: String
  public let mode: ArmMode?
  public let canaryPath: String?
  public let deputyBundlePath: String?
  public let bundleIdentifier: String?
  public let observation: String?
  public let sha256: String?
  public let pid: Int32?
  public let bundlePath: String?
  public let executablePath: String?
  public let terminated: Bool?

  public init(
    kind: String, nonce: String, mode: ArmMode? = nil, canaryPath: String? = nil,
    deputyBundlePath: String? = nil, bundleIdentifier: String? = nil,
    observation: String? = nil, sha256: String? = nil,
    pid: Int32? = nil, bundlePath: String? = nil, executablePath: String? = nil,
    terminated: Bool? = nil
  ) {
    self.schemaVersion = 1
    self.kind = kind
    self.nonce = nonce
    self.mode = mode
    self.canaryPath = canaryPath
    self.deputyBundlePath = deputyBundlePath
    self.bundleIdentifier = bundleIdentifier
    self.observation = observation
    self.sha256 = sha256
    self.pid = pid
    self.bundlePath = bundlePath
    self.executablePath = executablePath
    self.terminated = terminated
  }

  public func validate() throws {
    guard schemaVersion == 1, nonce.utf8.count == 32,
      nonce.allSatisfy({ "0123456789abcdef".contains($0) })
    else {
      throw ExperimentError.invalid
    }
    let valid: Bool
    switch kind {
    case "configure":
      valid =
        mode != nil && canaryPath?.first == "/"
        && deputyBundlePath?.first == "/" && bundleIdentifier != nil
        && observation == nil && sha256 == nil && pid == nil && bundlePath == nil
        && executablePath == nil && terminated == nil
    case "direct-result", "deputy-result":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil
        && ["succeeded", "denied", "failed"].contains(observation ?? "")
        && (observation == "succeeded" ? sha256?.count == 64 : sha256 == nil)
        && pid == nil && bundlePath == nil && executablePath == nil && terminated == nil
    case "deputy-hello":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil && observation == nil
        && sha256 == nil && (pid ?? 0) > 1 && bundlePath == nil
        && executablePath == nil && terminated == nil
    case "deputy-launch", "instance-live":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier != nil && observation == nil
        && sha256 == nil && (pid ?? 0) > 1 && bundlePath?.first == "/"
        && executablePath?.first == "/" && terminated == false
    case "launch-completion":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil
        && ["succeeded", "failed"].contains(observation ?? "")
        && sha256 == nil && pid == nil && bundlePath == nil && executablePath == nil
        && terminated == nil
    case "deputy-launch-failed":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil
        && ["denied", "failed"].contains(observation ?? "")
        && sha256 == nil && pid == nil && bundlePath == nil && executablePath == nil
        && terminated == nil
    case "arm", "reassert-instance", "continue-delegation", "finish":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil && observation == nil
        && sha256 == nil && pid == nil && bundlePath == nil && executablePath == nil
        && terminated == nil
    case "candidate-complete":
      valid =
        mode == nil && canaryPath == nil
        && deputyBundlePath == nil && bundleIdentifier == nil && observation == nil
        && sha256 == nil && pid == nil && bundlePath == nil && executablePath == nil
        && terminated == true
    default:
      valid = false
    }
    guard valid else { throw ExperimentError.invalid }
  }
}

public struct ArmObservation: Codable, Sendable {
  public let mode: ArmMode
  public let directRead: String
  public let deputyRead: String
  public let completion: String

  public init(mode: ArmMode, directRead: String, deputyRead: String, completion: String) {
    self.mode = mode
    self.directRead = directRead
    self.deputyRead = deputyRead
    self.completion = completion
  }
}

public struct OwnerResult: Codable, Sendable {
  public let schemaVersion: Int
  public let experiment: String
  public let property: String
  public let completion: String
  public let artifacts: String
  public let controlDirectRead: String
  public let controlDeputyRead: String
  public let candidateDirectRead: String
  public let candidateDeputyRead: String

  public init(
    property: String, completion: String, control: ArmObservation,
    candidate: ArmObservation
  ) {
    self.schemaVersion = 1
    self.experiment = "macos-app-sandbox-canary"
    self.property = property
    self.completion = completion
    self.artifacts = "retained"
    self.controlDirectRead = control.directRead
    self.controlDeputyRead = control.deputyRead
    self.candidateDirectRead = candidate.directRead
    self.candidateDeputyRead = candidate.deputyRead
  }
}

private func exactKeys(for object: [String: Any]) -> Set<String>? {
  guard let kind = object["kind"] as? String else { return nil }
  switch kind {
  case "configure":
    return [
      "schemaVersion", "kind", "nonce", "mode", "canaryPath", "deputyBundlePath",
      "bundleIdentifier",
    ]
  case "direct-result", "deputy-result":
    var keys: Set<String> = ["schemaVersion", "kind", "nonce", "observation"]
    if object["observation"] as? String == "succeeded" { keys.insert("sha256") }
    return keys
  case "deputy-hello":
    return ["schemaVersion", "kind", "nonce", "pid"]
  case "deputy-launch", "instance-live":
    return [
      "schemaVersion", "kind", "nonce", "bundleIdentifier", "pid", "bundlePath",
      "executablePath", "terminated",
    ]
  case "launch-completion", "deputy-launch-failed":
    return ["schemaVersion", "kind", "nonce", "observation"]
  case "arm", "reassert-instance", "continue-delegation", "finish", "candidate-complete":
    var keys: Set<String> = ["schemaVersion", "kind", "nonce"]
    if kind == "candidate-complete" { keys.insert("terminated") }
    return keys
  default:
    return nil
  }
}

public func encodeMessage(_ message: WireMessage) throws -> Data {
  try message.validate()
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try encoder.encode(message)
}

public func decodeMessage(_ data: Data) throws -> WireMessage {
  guard data.count <= maximumFrameBytes,
    let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
    let keys = exactKeys(for: object), Set(object.keys) == keys
  else {
    throw ExperimentError.invalid
  }
  let message = try JSONDecoder().decode(WireMessage.self, from: data)
  try message.validate()
  return message
}

public func writeFrame(_ message: WireMessage, to descriptor: Int32) throws {
  let payload = try encodeMessage(message)
  guard !payload.isEmpty && payload.count <= maximumFrameBytes else {
    throw ExperimentError.invalid
  }
  var size = UInt32(payload.count).bigEndian
  try withUnsafeBytes(of: &size) { try writeAll(Data($0), to: descriptor) }
  try writeAll(payload, to: descriptor)
}

public func readFrame(from descriptor: Int32, timeoutMilliseconds: Int32 = 10_000) throws
  -> WireMessage
{
  try readFrame(
    from: descriptor,
    deadline: ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds))))
}

public func readFrame(from descriptor: Int32, deadline: ContinuousClock.Instant) throws
  -> WireMessage
{
  let header = try readExactly(4, from: descriptor, deadline: deadline)
  let length = header.withUnsafeBytes { raw in
    UInt32(bigEndian: raw.loadUnaligned(as: UInt32.self))
  }
  guard length > 0 && length <= maximumFrameBytes else { throw ExperimentError.invalid }
  return try decodeMessage(
    readExactly(Int(length), from: descriptor, deadline: deadline))
}

private func waitFor(_ descriptor: Int32, events: Int16, timeoutMilliseconds: Int32) throws {
  try waitFor(
    descriptor, events: events,
    deadline: ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds))))
}

private func waitFor(
  _ descriptor: Int32, events: Int16, deadline: ContinuousClock.Instant
) throws {
  var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
  var result: Int32
  repeat {
    let remaining = ContinuousClock.now.duration(to: deadline).components
    let milliseconds = Double(remaining.seconds) * 1_000 + Double(remaining.attoseconds) / 1e15
    guard milliseconds > 0 else { throw ExperimentError.timeout }
    let bounded = Int32(min(Double(Int32.max), ceil(milliseconds)))
    result = Darwin.poll(&pollDescriptor, 1, bounded)
  } while result < 0 && errno == EINTR
  if result == 0 || ContinuousClock.now >= deadline { throw ExperimentError.timeout }
  guard result > 0 && pollDescriptor.revents & (events | Int16(POLLHUP)) != 0 else {
    throw ExperimentError.io
  }
}

private func readExactly(
  _ count: Int, from descriptor: Int32, deadline: ContinuousClock.Instant
) throws -> Data {
  var output = Data(count: count)
  var offset = 0
  while offset < count {
    try waitFor(descriptor, events: Int16(POLLIN), deadline: deadline)
    let amount = output.withUnsafeMutableBytes { bytes in
      Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), count - offset)
    }
    if amount == 0 { throw ExperimentError.io }
    if amount < 0 {
      if errno == EINTR { continue }
      throw ExperimentError.io
    }
    offset += amount
  }
  return output
}

public func validateLaunchCompletion(
  _ completion: WireMessage, followedBy launch: WireMessage, nonce: String
) throws {
  try completion.validate()
  try launch.validate()
  guard completion.kind == "launch-completion", completion.nonce == nonce,
    launch.nonce == nonce,
    (completion.observation == "succeeded" && launch.kind == "deputy-launch")
      || (completion.observation == "failed" && launch.kind == "deputy-launch-failed")
  else {
    throw ExperimentError.invalid
  }
}

private func writeAll(_ data: Data, to descriptor: Int32) throws {
  var offset = 0
  while offset < data.count {
    try waitFor(descriptor, events: Int16(POLLOUT), timeoutMilliseconds: 10_000)
    let amount = data.withUnsafeBytes { bytes in
      Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset)
    }
    if amount < 0 {
      if errno == EINTR { continue }
      throw ExperimentError.io
    }
    guard amount > 0 else { throw ExperimentError.io }
    offset += amount
  }
}

public func sha256Hex(_ data: Data) -> String {
  SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public func observeCanary(path: String) -> (String, String?) {
  let descriptor = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  if descriptor < 0 {
    return errno == EACCES || errno == EPERM ? ("denied", nil) : ("failed", nil)
  }
  defer { _ = Darwin.close(descriptor) }
  var data = Data()
  var buffer = [UInt8](repeating: 0, count: 4096)
  while true {
    let count = buffer.withUnsafeMutableBytes { raw in
      Darwin.read(descriptor, raw.baseAddress, raw.count)
    }
    if count == 0 { break }
    if count < 0 { return ("failed", nil) }
    data.append(contentsOf: buffer.prefix(count))
    if data.count > 4096 { return ("failed", nil) }
  }
  return ("succeeded", sha256Hex(data))
}
