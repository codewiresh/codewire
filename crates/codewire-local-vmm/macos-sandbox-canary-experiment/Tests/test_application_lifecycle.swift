@preconcurrency import AppKit
import Darwin
import Dispatch
import Foundation

private final class LifecycleProbe: @unchecked Sendable {
  private let lock = NSLock()
  private var workerCount = 0
  private var workerWasOffMainThread = true
  private var workerWasWaiting = false
  private var callbackCount = 0
  private var callbackWasOnMainThread = true
  private var callbackObservedWaitingWorker = true

  func recordWorkerStart() {
    lock.lock()
    workerCount += 1
    workerWasOffMainThread = workerWasOffMainThread && !Thread.isMainThread
    workerWasWaiting = true
    lock.unlock()
  }

  func recordMainCallback() {
    lock.lock()
    callbackCount += 1
    callbackWasOnMainThread = callbackWasOnMainThread && Thread.isMainThread
    callbackObservedWaitingWorker = callbackObservedWaitingWorker && workerWasWaiting
    lock.unlock()
  }

  func recordWorkerFinish() {
    lock.lock()
    workerWasWaiting = false
    lock.unlock()
  }

  func observation() -> (
    workerCount: Int, workerWasOffMainThread: Bool, callbackCount: Int,
    callbackWasOnMainThread: Bool, callbackObservedWaitingWorker: Bool
  ) {
    lock.lock()
    defer { lock.unlock() }
    return (
      workerCount, workerWasOffMainThread, callbackCount, callbackWasOnMainThread,
      callbackObservedWaitingWorker
    )
  }
}

private func fail(_ message: String) -> Never {
  do {
    try FileHandle.standardError.write(contentsOf: Data("\(message)\n".utf8))
  } catch {}
  Darwin.exit(1)
}

@main
struct ApplicationLifecycleFixture {
  static func main() {
    _ = signal(SIGALRM, SIG_DFL)
    _ = alarm(2)
    guard Thread.isMainThread else {
      fail("application lifecycle fixture did not start on the main thread")
    }
    let probe = LifecycleProbe()
    let callback = DispatchSemaphore(value: 0)
    let workerFinished = DispatchSemaphore(value: 0)
    let deadline = DispatchTime.now() + .seconds(2)
    let lifecycle = runApplicationLifecycle {
      probe.recordWorkerStart()
      DispatchQueue.main.async {
        probe.recordMainCallback()
        callback.signal()
        let application = NSApplication.shared
        application.stop(nil)
        guard
          let wakeEvent = NSEvent.otherEvent(
            with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0)
        else {
          fail("application lifecycle fixture could not create its wake event")
        }
        application.postEvent(wakeEvent, atStart: false)
      }
      guard callback.wait(timeout: deadline) == .success else {
        fail("worker did not observe the main-queue callback")
      }
      probe.recordWorkerFinish()
      workerFinished.signal()
    }
    guard workerFinished.wait(timeout: deadline) == .success else {
      fail("application lifecycle worker did not finish")
    }
    let finish = lifecycle.finishObservation()
    guard finish.count == 1, finish.everyNotificationWasOnMainThread else {
      fail("did-finish-launching was not delivered exactly once on the main thread")
    }
    let observation = probe.observation()
    guard observation.workerCount == 1, observation.workerWasOffMainThread,
      observation.callbackCount == 1, observation.callbackWasOnMainThread,
      observation.callbackObservedWaitingWorker
    else {
      fail("application lifecycle did not preserve the worker/main-queue boundary")
    }
    _ = alarm(0)
  }
}
