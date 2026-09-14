import AppKit
import Darwin
import Dispatch
import Foundation

private enum LifecycleFailure: String {
  case notMainThread
  case activationNotProhibited
  case invalidLaunchCallback
}

private func failLifecycle(_ reason: LifecycleFailure) -> Never {
  try? FileHandle.standardError.write(contentsOf: Data("lifecycle:\(reason.rawValue)\n".utf8))
  Darwin.exit(70)
}

final class ApplicationLifecycle: NSObject, NSApplicationDelegate, @unchecked Sendable {
  private let lock = NSLock()
  private let worker: @Sendable () -> Void
  private var finishCount = 0
  private var everyFinishWasOnMainThread = true

  init(worker: @escaping @Sendable () -> Void) {
    self.worker = worker
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    lock.lock()
    finishCount += 1
    everyFinishWasOnMainThread = everyFinishWasOnMainThread && Thread.isMainThread
    let shouldStart = finishCount == 1 && everyFinishWasOnMainThread
    lock.unlock()
    guard shouldStart else { failLifecycle(.invalidLaunchCallback) }
    DispatchQueue.global(qos: .userInitiated).async(execute: worker)
    _ = notification
  }

  func finishObservation() -> (count: Int, everyNotificationWasOnMainThread: Bool) {
    lock.lock()
    defer { lock.unlock() }
    return (finishCount, everyFinishWasOnMainThread)
  }
}

@discardableResult
@MainActor
func runApplicationLifecycle(worker: @escaping @Sendable () -> Void) -> ApplicationLifecycle {
  guard Thread.isMainThread else { failLifecycle(.notMainThread) }
  let application = NSApplication.shared
  // Both the sealed LSBackgroundOnly deputy and the unbundled fixture already
  // require this policy. Verify it without requesting a redundant transition.
  guard application.activationPolicy() == .prohibited else {
    failLifecycle(.activationNotProhibited)
  }
  let lifecycle = ApplicationLifecycle(worker: worker)
  application.delegate = lifecycle
  application.run()
  application.delegate = nil
  withExtendedLifetime(lifecycle) {}
  return lifecycle
}
