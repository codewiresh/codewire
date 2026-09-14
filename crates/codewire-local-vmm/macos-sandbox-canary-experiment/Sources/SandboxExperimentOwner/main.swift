import CCanarySupport
import Darwin
import Foundation
import SandboxCanaryProtocol

private struct ArmProgress {
  var direct = "unknown"
  var deputy = "not-run"
  var completion = "unknown"
}

// Private, finite diagnostics, deliberately separate from scored observations.
// Never include received payloads, paths, identifiers, hashes or canary bytes.
private enum ArmDiagnosticStage: String {
  case awaitingLaunchCompletion
  case launchCompletionSuccessConsumed
  case launchCompletionFailureConsumed
  case launchIdentityAccepted
  case awaitingDeputyHello
  case deputyPeerVerified
  case awaitingInstanceReassertion
  case instanceReasserted
  case armSent
  case deputyResultReceived
  case deputyEOF
  case instanceTerminationObserved
}

private func diagnose(_ stage: ArmDiagnosticStage, mode: ArmMode) {
  try? FileHandle.standardError.write(contentsOf: Data("\(mode.rawValue):\(stage.rawValue)\n".utf8))
}

private struct CheckpointEnvelope: Encodable {
  let experiment = "macos-app-sandbox-canary"
  let nonce: String
  let result: OwnerResult
  let schemaVersion = 1
}

private final class CheckpointWriter {
  private let nonce: String
  private let path: String
  private var control = ArmProgress(direct: "not-run", deputy: "not-run", completion: "not-run")
  private var candidate = ArmProgress(
    direct: "not-run", deputy: "not-run", completion: "not-run")

  init(nonce: String, path: String) {
    self.nonce = nonce
    self.path = path
  }

  func update(_ progress: ArmProgress, for mode: ArmMode) {
    switch mode {
    case .control: control = progress
    case .candidate: candidate = progress
    }
  }

  func recordPositive(_ progress: ArmProgress, for mode: ArmMode) throws {
    update(progress, for: mode)
    let property =
      candidate.direct == "succeeded" || candidate.deputy == "succeeded"
      ? "falsified" : "inconclusive"
    let result = OwnerResult(
      property: property, completion: "unknown",
      control: ArmObservation(
        mode: .control, directRead: control.direct, deputyRead: control.deputy,
        completion: control.completion),
      candidate: ArmObservation(
        mode: .candidate, directRead: candidate.direct, deputyRead: candidate.deputy,
        completion: candidate.completion))
    let envelope = CheckpointEnvelope(nonce: nonce, result: result)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var bytes = try encoder.encode(envelope)
    bytes.append(0x0A)
    let replaced = path.withCString { checkpointPath in
      bytes.withUnsafeBytes { rawBytes in
        cw_canary_replace_checkpoint(
          checkpointPath, rawBytes.bindMemory(to: UInt8.self).baseAddress, rawBytes.count)
      }
    }
    guard replaced == 0 else { throw ExperimentError.io }
  }
}

@main
enum SandboxExperimentOwner {
  static func main() {
    _ = signal(SIGPIPE, SIG_IGN)
    guard cw_canary_normalize_sigchld() == 0 else { Darwin.exit(70) }
    _ = alarm(75)
    do {
      let result = try run()
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
      var bytes = try encoder.encode(result)
      bytes.append(0x0A)
      try FileHandle.standardOutput.write(contentsOf: bytes)
      _ = alarm(0)
    } catch {
      Darwin.exit(70)
    }
  }

  private static func run() throws -> OwnerResult {
    guard CommandLine.arguments.count == 2 else { throw ExperimentError.invalid }
    let configurationURL = URL(fileURLWithPath: CommandLine.arguments[1])
      .resolvingSymlinksInPath().standardizedFileURL
    let configurationBytes = try Data(contentsOf: configurationURL, options: [.mappedIfSafe])
    guard configurationBytes.count <= maximumFrameBytes,
      let object = try JSONSerialization.jsonObject(with: configurationBytes) as? [String: Any],
      Set(object.keys) == [
        "schemaVersion", "nonce", "canaryPath", "expectedCanarySHA256", "endpointPath",
        "controlExecutable", "candidateExecutable", "deputyBundlePath", "deputyExecutable",
        "controlBundleIdentifier", "candidateBundleIdentifier", "deputyBundleIdentifier",
        "controlCDHash", "candidateCDHash", "deputyCDHash", "checkpointPath",
      ]
    else {
      throw ExperimentError.invalid
    }
    let configuration = try JSONDecoder().decode(
      OwnerConfiguration.self, from: configurationBytes)
    try configuration.validate()
    let initialCanary = observeCanary(path: configuration.canaryPath)
    guard FileManager.default.fileExists(atPath: configuration.canaryPath),
      initialCanary.0 == "succeeded",
      initialCanary.1 == configuration.expectedCanarySHA256
    else {
      throw ExperimentError.invalid
    }

    let listener = configuration.endpointPath.withCString { path in
      cw_canary_listen(path)
    }
    guard listener >= 0 else { throw ExperimentError.io }
    defer { _ = Darwin.close(listener) }

    let checkpoint = CheckpointWriter(
      nonce: configuration.nonce, path: configuration.checkpointPath)
    let control = runArm(
      mode: .control, executable: configuration.controlExecutable,
      configuration: configuration, listener: listener
    ) { progress in
      try checkpoint.recordPositive(progress, for: .control)
    }
    checkpoint.update(control, for: .control)
    guard control.direct == "succeeded", control.deputy == "succeeded",
      control.completion == "complete"
    else {
      return OwnerResult(
        property: "inconclusive", completion: "unknown",
        control: ArmObservation(
          mode: .control, directRead: control.direct, deputyRead: control.deputy,
          completion: control.completion),
        candidate: ArmObservation(
          mode: .candidate, directRead: "not-run", deputyRead: "not-run",
          completion: "not-run"))
    }

    let candidate = runArm(
      mode: .candidate, executable: configuration.candidateExecutable,
      configuration: configuration, listener: listener
    ) { progress in
      try checkpoint.recordPositive(progress, for: .candidate)
    }
    checkpoint.update(candidate, for: .candidate)
    let property: String
    if candidate.direct == "succeeded" || candidate.deputy == "succeeded" {
      property = "falsified"
    } else if candidate.direct == "denied" && candidate.deputy == "denied"
      && candidate.completion == "complete"
    {
      property = "not-falsified"
    } else {
      property = "inconclusive"
    }
    return OwnerResult(
      property: property, completion: candidate.completion,
      control: ArmObservation(
        mode: .control, directRead: control.direct, deputyRead: control.deputy,
        completion: control.completion),
      candidate: ArmObservation(
        mode: .candidate, directRead: candidate.direct, deputyRead: candidate.deputy,
        completion: candidate.completion))
  }

  private static func runArm(
    mode: ArmMode, executable: String, configuration: OwnerConfiguration, listener: Int32,
    onPositive: (ArmProgress) throws -> Void
  ) -> ArmProgress {
    var progress = ArmProgress()
    var pair = [Int32](repeating: -1, count: 2)
    let socketResult = pair.withUnsafeMutableBufferPointer { descriptors in
      socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors.baseAddress)
    }
    guard socketResult == 0 else { return progress }
    let ownerDescriptor = pair[0]
    let childDescriptor = pair[1]
    _ = fcntl(ownerDescriptor, F_SETFD, FD_CLOEXEC)
    _ = fcntl(childDescriptor, F_SETFD, FD_CLOEXEC)
    defer { _ = Darwin.close(ownerDescriptor) }

    var childPID: pid_t = 0
    let spawnResult = executable.withCString { path in
      cw_canary_spawn(path, childDescriptor, &childPID)
    }
    _ = Darwin.close(childDescriptor)
    guard spawnResult == 0, childPID > 1 else { return progress }
    var childReaped = false
    defer {
      if !childReaped {
        _ = cw_canary_cleanup_child(childPID)
      }
    }

    do {
      guard
        verifyDirectChild(
          pid: childPID, mode: mode, executable: executable, configuration: configuration)
      else {
        return progress
      }
      try writeFrame(
        WireMessage(
          kind: "configure", nonce: configuration.nonce, mode: mode,
          canaryPath: configuration.canaryPath,
          deputyBundlePath: configuration.deputyBundlePath,
          bundleIdentifier: configuration.deputyBundleIdentifier),
        to: ownerDescriptor)
      let direct = try readFrame(from: ownerDescriptor)
      guard direct.kind == "direct-result", direct.nonce == configuration.nonce,
        let directObservation = direct.observation
      else {
        return progress
      }
      if directObservation == "succeeded"
        && direct.sha256 != configuration.expectedCanarySHA256
      {
        return progress
      }
      progress.direct = directObservation
      if directObservation == "succeeded" {
        try onPositive(progress)
      }

      let delegationAllowed =
        mode == .control
        ? directObservation == "succeeded" : directObservation == "denied"
      guard delegationAllowed else {
        try writeFrame(
          WireMessage(kind: "finish", nonce: configuration.nonce), to: ownerDescriptor)
        return finishDirectChild(pid: childPID, progress: &progress, reaped: &childReaped)
      }
      try writeFrame(
        WireMessage(kind: "continue-delegation", nonce: configuration.nonce),
        to: ownerDescriptor)

      diagnose(.awaitingLaunchCompletion, mode: mode)
      let launchDeadline = ContinuousClock.now.advanced(by: .seconds(10))
      let completion = try readFrame(from: ownerDescriptor, deadline: launchDeadline)
      guard completion.kind == "launch-completion", completion.nonce == configuration.nonce,
        ["succeeded", "failed"].contains(completion.observation ?? "")
      else {
        return progress
      }
      diagnose(
        completion.observation == "succeeded"
          ? .launchCompletionSuccessConsumed : .launchCompletionFailureConsumed,
        mode: mode)
      let launch = try readFrame(from: ownerDescriptor, deadline: launchDeadline)
      try validateLaunchCompletion(completion, followedBy: launch, nonce: configuration.nonce)
      if launch.kind == "deputy-launch-failed" {
        progress.deputy = launch.observation ?? "unknown"
      } else {
        guard launch.kind == "deputy-launch",
          launch.bundleIdentifier == configuration.deputyBundleIdentifier,
          launch.bundlePath == configuration.deputyBundlePath,
          launch.executablePath == configuration.deputyExecutable,
          let deputyPID = launch.pid, deputyPID > 1, launch.terminated == false,
          cw_canary_child_live(childPID) == 1
        else {
          return progress
        }
        diagnose(.launchIdentityAccepted, mode: mode)
        let deputyDescriptor = cw_canary_accept(listener, 10_000)
        guard deputyDescriptor >= 0 else { return progress }
        defer { _ = Darwin.close(deputyDescriptor) }
        diagnose(.awaitingDeputyHello, mode: mode)
        let hello = try readFrame(from: deputyDescriptor)
        guard hello.kind == "deputy-hello", hello.nonce == configuration.nonce,
          hello.pid == deputyPID,
          verifyDeputyPeer(
            descriptor: deputyDescriptor, pid: deputyPID, configuration: configuration),
          cw_canary_child_live(childPID) == 1
        else {
          return progress
        }
        diagnose(.deputyPeerVerified, mode: mode)
        try writeFrame(
          WireMessage(kind: "reassert-instance", nonce: configuration.nonce),
          to: ownerDescriptor)
        diagnose(.awaitingInstanceReassertion, mode: mode)
        let live = try readFrame(from: ownerDescriptor)
        guard live.kind == "instance-live", live.nonce == configuration.nonce,
          live.bundleIdentifier == configuration.deputyBundleIdentifier,
          live.pid == deputyPID, live.bundlePath == configuration.deputyBundlePath,
          live.executablePath == configuration.deputyExecutable,
          live.terminated == false, cw_canary_child_live(childPID) == 1
        else {
          return progress
        }
        diagnose(.instanceReasserted, mode: mode)
        try writeFrame(
          WireMessage(kind: "arm", nonce: configuration.nonce), to: deputyDescriptor)
        diagnose(.armSent, mode: mode)
        let deputyResult = try readFrame(from: deputyDescriptor)
        guard deputyResult.kind == "deputy-result",
          deputyResult.nonce == configuration.nonce,
          let deputyObservation = deputyResult.observation
        else {
          return progress
        }
        if deputyObservation == "succeeded"
          && deputyResult.sha256 != configuration.expectedCanarySHA256
        {
          return progress
        }
        progress.deputy = deputyObservation
        if deputyObservation == "succeeded" {
          try onPositive(progress)
        }
        diagnose(.deputyResultReceived, mode: mode)
        guard readEOF(from: deputyDescriptor) else { return progress }
        diagnose(.deputyEOF, mode: mode)

        let complete = try readFrame(from: ownerDescriptor)
        guard complete.kind == "candidate-complete",
          complete.nonce == configuration.nonce, complete.terminated == true
        else {
          return progress
        }
        diagnose(.instanceTerminationObserved, mode: mode)
      }

      return finishDirectChild(pid: childPID, progress: &progress, reaped: &childReaped)
    } catch {
      return progress
    }
  }

  private static func finishDirectChild(
    pid: pid_t, progress: inout ArmProgress, reaped: inout Bool
  ) -> ArmProgress {
    var status: Int32 = 0
    guard cw_canary_wait(pid, 5_000, &status) == 0 else { return progress }
    reaped = true
    guard status == 0 else { return progress }
    progress.completion = "complete"
    return progress
  }

  private static func directBundlePath(for executable: String) -> String? {
    let executableURL = URL(fileURLWithPath: executable)
      .resolvingSymlinksInPath().standardizedFileURL
    let macOSDirectory = executableURL.deletingLastPathComponent()
    let contentsDirectory = macOSDirectory.deletingLastPathComponent()
    let bundleURL = contentsDirectory.deletingLastPathComponent()
    guard executableURL.path == executable, macOSDirectory.lastPathComponent == "MacOS",
      contentsDirectory.lastPathComponent == "Contents", bundleURL.pathExtension == "app"
    else {
      return nil
    }
    return bundleURL.path
  }

  private static func verifyDirectChild(
    pid: pid_t, mode: ArmMode, executable: String, configuration: OwnerConfiguration
  ) -> Bool {
    guard let bundlePath = directBundlePath(for: executable) else { return false }
    let identifier =
      mode == .control
      ? configuration.controlBundleIdentifier : configuration.candidateBundleIdentifier
    let cdhash =
      mode == .control
      ? configuration.controlCDHash : configuration.candidateCDHash
    return bundlePath.withCString { bundle in
      executable.withCString { executablePath in
        identifier.withCString { identifierBytes in
          cdhash.withCString { hashBytes in
            cw_canary_verify_direct_child(
              pid, bundle, executablePath, identifierBytes, hashBytes,
              mode == .candidate ? 1 : 0) == CW_CANARY_OK
          }
        }
      }
    }
  }

  private static func readEOF(from descriptor: Int32) -> Bool {
    var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    var pollResult: Int32
    repeat {
      pollResult = Darwin.poll(&pollDescriptor, 1, 5_000)
    } while pollResult < 0 && errno == EINTR
    guard pollResult > 0 else { return false }
    var byte: UInt8 = 0
    return Darwin.read(descriptor, &byte, 1) == 0
  }

  private static func verifyDeputyPeer(
    descriptor: Int32, pid: pid_t, configuration: OwnerConfiguration
  ) -> Bool {
    configuration.deputyBundlePath.withCString { bundlePath in
      configuration.deputyExecutable.withCString { executablePath in
        configuration.deputyBundleIdentifier.withCString { identifier in
          configuration.deputyCDHash.withCString { cdhash in
            cw_canary_verify_connected_peer(
              descriptor, pid, bundlePath, executablePath, identifier, cdhash)
              == CW_CANARY_OK
          }
        }
      }
    }
  }
}
