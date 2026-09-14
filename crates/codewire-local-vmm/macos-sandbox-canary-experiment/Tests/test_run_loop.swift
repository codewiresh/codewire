import CoreFoundation
import Darwin
import Dispatch
import Foundation

private final class LockedFlag: @unchecked Sendable {
  private let lock = NSLock()
  private var value = false

  func set() {
    lock.lock()
    value = true
    lock.unlock()
  }

  func get() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

private func fail(_ message: String) -> Never {
  do {
    try FileHandle.standardError.write(contentsOf: Data("\(message)\n".utf8))
  } catch {}
  Darwin.exit(1)
}

guard Thread.isMainThread else {
  fail("standalone run-loop fixture did not start on the main thread")
}
private let delivered = LockedFlag()
DispatchQueue.global().async {
  DispatchQueue.main.async { delivered.set() }
}
let deadline = Date().addingTimeInterval(2)
while !delivered.get() && Date() < deadline {
  _ = CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.01, true)
}
guard delivered.get() else {
  fail("default run-loop mode did not deliver the main-queue callback")
}
