import Testing

@testable import CodewireVZRunnerRuntime

@Suite struct ConsolePairLifecycleTests {
  @Test func failedRequestsNeverProveTermination() {
    for failure in [ConsolePairLifecycle.Event.startFailed, .stopFailed] {
      var lifecycle = ConsolePairLifecycle()
      lifecycle.apply(.started)
      lifecycle.apply(failure)
      let observation = lifecycle.drain()
      #expect(observation.state.failed)
      #expect(!observation.state.terminal)
      #expect(observation.events.isEmpty)
    }
  }

  @Test func terminalStateAndEventAreDeliveredTogetherOnce() {
    for (event, expected) in [
      (ConsolePairLifecycle.Event.guestStopped, UInt8(0)),
      (.guestFailed, 1), (.stopSucceeded, 2),
    ] {
      var lifecycle = ConsolePairLifecycle()
      lifecycle.apply(.started)
      lifecycle.apply(event)
      let observation = lifecycle.drain()
      #expect(observation.state.terminal)
      #expect(observation.events == [expected])
      lifecycle.apply(.stopFailed)
      lifecycle.apply(.guestStopped)
      #expect(lifecycle.drain().events.isEmpty)
      #expect(lifecycle.failed == (expected == 1))
    }
  }

  @Test func laterActualTerminationDoesNotEraseEarlierFailure() {
    var lifecycle = ConsolePairLifecycle()
    lifecycle.apply(.stopFailed)
    #expect(!lifecycle.terminal)
    lifecycle.apply(.guestStopped)
    let observation = lifecycle.drain()
    #expect(observation.state.terminal)
    #expect(observation.state.failed)
    #expect(observation.events == [0])
  }

  @Test func streamClosureUsesCurrentStateWithoutConsumingTerminalEvent() throws {
    var lifecycle = ConsolePairLifecycle()
    lifecycle.apply(.started)
    let beforePoll = lifecycle
    var streams = ConsolePairStreamLiveness()
    #expect(!beforePoll.terminal)
    lifecycle.apply(.guestStopped)
    try streams.statusEOF { lifecycle.terminal }
    try streams.controlHUP { lifecycle.terminal }
    #expect(streams.statusClosed)
    #expect(streams.controlClosed)
    #expect(lifecycle.drain().events == [0])
  }

  @Test func prematureClosureRemainsFailure() {
    var streams = ConsolePairStreamLiveness()
    #expect(throws: ConsolePairStreamLiveness.Failure.self) {
      try streams.statusEOF { false }
    }
    #expect(throws: ConsolePairStreamLiveness.Failure.self) {
      try streams.controlHUP { false }
    }
    #expect(!streams.statusClosed)
    #expect(!streams.controlClosed)
  }
}
