/// API request errors are not VM termination observations. This reducer is
/// shared by the native owner and platform-independent transition regressions.
struct ConsolePairLifecycle {
  enum Event {
    case started, startFailed, guestStopped, guestFailed, stopSucceeded, stopFailed
  }

  private(set) var started = false
  private(set) var terminal = false
  private(set) var failed = false
  private var events: [UInt8] = []

  mutating func apply(_ event: Event) {
    guard !terminal else { return }
    switch event {
    case .started:
      started = true
    case .startFailed, .stopFailed:
      failed = true
    case .guestStopped:
      terminal = true
      events.append(0)
    case .guestFailed:
      terminal = true
      failed = true
      events.append(1)
    case .stopSucceeded:
      terminal = true
      events.append(2)
    }
  }

  mutating func drain() -> (state: Self, events: [UInt8]) {
    let records = events
    events.removeAll(keepingCapacity: true)
    return (self, records)
  }
}

struct ConsolePairStreamLiveness {
  enum Failure: Error { case prematureClosure }
  private(set) var statusClosed = false
  private(set) var controlClosed = false

  mutating func statusEOF(isTerminalNow: () -> Bool) throws {
    guard isTerminalNow() else { throw Failure.prematureClosure }
    statusClosed = true
  }

  mutating func controlHUP(isTerminalNow: () -> Bool) throws {
    guard isTerminalNow() else { throw Failure.prematureClosure }
    controlClosed = true
  }
}
