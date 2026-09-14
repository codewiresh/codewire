@preconcurrency import AppKit
import CoreFoundation
import Darwin
import Foundation
import SandboxCanaryProtocol

private final class LaunchState: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Result<NSRunningApplication, Error>?

  func set(_ newValue: Result<NSRunningApplication, Error>) {
    lock.lock()
    defer { lock.unlock() }
    guard value == nil else { return }
    value = newValue
  }

  func get() -> Result<NSRunningApplication, Error>? {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

private final class TerminationState: @unchecked Sendable {
  private let lock = NSLock()
  private var value = false

  func set(_ terminated: Bool) {
    lock.lock()
    value = value || terminated
    lock.unlock()
  }

  func get() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

@main
enum SandboxCandidate {
  static func main() {
    _ = signal(SIGPIPE, SIG_IGN)
    _ = alarm(30)
    do {
      try run()
    } catch {
      Darwin.exit(70)
    }
  }

  private static func run() throws {
    guard CommandLine.arguments.count == 1 else { throw ExperimentError.invalid }
    let configuration = try readFrame(from: controlDescriptor)
    guard configuration.kind == "configure", let mode = configuration.mode,
      let canaryPath = configuration.canaryPath,
      let deputyBundlePath = configuration.deputyBundlePath,
      let deputyIdentifier = configuration.bundleIdentifier
    else {
      throw ExperimentError.invalid
    }

    let direct = observeCanary(path: canaryPath)
    try writeFrame(
      WireMessage(
        kind: "direct-result", nonce: configuration.nonce,
        observation: direct.0, sha256: direct.1),
      to: controlDescriptor)

    let decision = try readFrame(from: controlDescriptor)
    guard decision.nonce == configuration.nonce else { throw ExperimentError.invalid }
    if decision.kind == "finish" {
      _ = alarm(0)
      _ = Darwin.close(controlDescriptor)
      return
    }
    guard decision.kind == "continue-delegation" else { throw ExperimentError.invalid }

    let bundleURL = URL(fileURLWithPath: deputyBundlePath, isDirectory: true)
      .resolvingSymlinksInPath().standardizedFileURL
    let launch = try launchDeputy(at: bundleURL)
    // Fixed diagnostic only: callback completion is not launch identity,
    // a canary observation, or permission to ARM the deputy.
    let launchObservation: String
    switch launch {
    case .success: launchObservation = "succeeded"
    case .failure: launchObservation = "failed"
    }
    try writeFrame(
      WireMessage(
        kind: "launch-completion", nonce: configuration.nonce,
        observation: launchObservation),
      to: controlDescriptor)
    switch launch {
    case .failure(let error):
      try writeFrame(
        WireMessage(
          kind: "deputy-launch-failed", nonce: configuration.nonce,
          observation: isPermissionDenial(error) ? "denied" : "failed"),
        to: controlDescriptor)
    case .success(let application):
      guard application.bundleIdentifier == deputyIdentifier,
        application.bundleURL?.resolvingSymlinksInPath().standardizedFileURL == bundleURL,
        let executableURL = application.executableURL?.resolvingSymlinksInPath()
          .standardizedFileURL,
        application.processIdentifier > 1, !application.isTerminated
      else {
        throw ExperimentError.invalid
      }
      try writeFrame(
        WireMessage(
          kind: "deputy-launch", nonce: configuration.nonce,
          bundleIdentifier: deputyIdentifier, pid: application.processIdentifier,
          bundlePath: bundleURL.path, executablePath: executableURL.path,
          terminated: false),
        to: controlDescriptor)
      let reassertion = try readFrame(from: controlDescriptor)
      guard reassertion.kind == "reassert-instance",
        reassertion.nonce == configuration.nonce
      else {
        throw ExperimentError.invalid
      }
      _ = CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.01, true)
      guard application.bundleIdentifier == deputyIdentifier,
        application.bundleURL?.resolvingSymlinksInPath().standardizedFileURL == bundleURL,
        application.executableURL?.resolvingSymlinksInPath().standardizedFileURL
          == executableURL,
        application.processIdentifier > 1, !application.isTerminated
      else {
        throw ExperimentError.invalid
      }
      try writeFrame(
        WireMessage(
          kind: "instance-live", nonce: configuration.nonce,
          bundleIdentifier: deputyIdentifier, pid: application.processIdentifier,
          bundlePath: bundleURL.path, executablePath: executableURL.path,
          terminated: false),
        to: controlDescriptor)
      try observeExactTermination(application)
      try writeFrame(
        WireMessage(
          kind: "candidate-complete", nonce: configuration.nonce, terminated: true),
        to: controlDescriptor)
    }
    _ = alarm(0)
    _ = Darwin.close(controlDescriptor)
    _ = mode
  }

  private static func launchDeputy(
    at bundleURL: URL
  ) throws -> Result<NSRunningApplication, Error> {
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = false
    configuration.addsToRecentItems = false
    configuration.allowsRunningApplicationSubstitution = false
    configuration.createsNewApplicationInstance = true
    configuration.hides = false
    configuration.hidesOthers = false
    configuration.promptsUserIfNeeded = false

    let state = LaunchState()
    NSWorkspace.shared.openApplication(at: bundleURL, configuration: configuration) {
      application, error in
      DispatchQueue.main.async {
        if let application {
          state.set(.success(application))
        } else {
          state.set(.failure(error ?? ExperimentError.invalid))
        }
      }
    }
    let deadline = Date().addingTimeInterval(10)
    while state.get() == nil && Date() < deadline {
      _ = CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.05, true)
    }
    guard let result = state.get() else { throw ExperimentError.timeout }
    return result
  }

  private static func observeExactTermination(_ application: NSRunningApplication) throws {
    let state = TerminationState()
    let observation = application.observe(\.isTerminated, options: [.initial, .new]) {
      runningApplication, _ in
      state.set(runningApplication.isTerminated)
    }
    defer { observation.invalidate() }
    let deadline = Date().addingTimeInterval(15)
    while !state.get() && Date() < deadline {
      _ = CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.05, true)
    }
    guard state.get(), application.isTerminated else { throw ExperimentError.timeout }
  }

  private static func isPermissionDenial(_ error: Error) -> Bool {
    let cocoa = error as NSError
    return (cocoa.domain == NSPOSIXErrorDomain && [EACCES, EPERM].contains(Int32(cocoa.code)))
      || (cocoa.domain == NSCocoaErrorDomain
        && cocoa.code == CocoaError.Code.fileReadNoPermission.rawValue)
  }
}
