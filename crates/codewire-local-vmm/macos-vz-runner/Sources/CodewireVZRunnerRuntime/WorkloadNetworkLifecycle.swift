import Foundation

/// Native transport state only. Opaque service messages are authenticated by
/// the parent/guest, never interpreted as readiness by this reducer.
struct WorkloadNetworkLifecycle {
  enum Failure: Error { case order, frame, ownership }
  enum Phase { case waiting, connecting, attached, forwarded }
  private(set) var phase: Phase = .waiting
  private(set) var cancelled = false
  private(set) var detached = false
  private(set) var closed = false

  static func serviceFrame(_ payload: Data, tag: UInt8) throws -> Data {
    guard payload.count == 130, payload[0] == tag, payload[1] == 2, payload[10] == 2
    else { throw Failure.frame }
    return Data(payload.dropFirst(2))
  }

  mutating func begin(_ payload: Data, bothStarted: Bool) throws -> Data {
    guard bothStarted, phase == .waiting, !cancelled, !closed else { throw Failure.order }
    let frame = try Self.serviceFrame(payload, tag: 0x41)
    phase = .connecting
    return frame
  }

  mutating func didAttach() throws {
    guard phase == .connecting, !cancelled, !closed else { throw Failure.order }
    phase = .attached
  }

  mutating func didForward() throws {
    guard phase == .attached, !cancelled, !closed else { throw Failure.order }
    phase = .forwarded
  }

  func subsequent(_ payload: Data) throws -> Data {
    guard phase == .forwarded, !cancelled, !closed else { throw Failure.order }
    return try Self.serviceFrame(payload, tag: 0x43)
  }

  mutating func cancel() { cancelled = true }

  mutating func didDetach(consumerTerminal: Bool) throws {
    guard consumerTerminal, !detached, !closed, phase == .attached || phase == .forwarded else {
      throw Failure.ownership
    }
    detached = true
  }

  mutating func claimClose() throws -> Bool {
    guard phase == .waiting || phase == .connecting || detached else { throw Failure.ownership }
    guard !closed else { return false }
    closed = true
    return true
  }

  static func mayComplete(actualStops: Set<UInt8>, daemonDrained: Bool) -> Bool {
    // Actual VM callbacks do not prove the final daemon bytes reached the
    // verifier-owned kernel endpoint. Drain means real guest EOF and empty
    // forwarding buffers, not parsing a post-Hyper tail. Parsed/authenticated
    // poweroff acceptance remains the independent verifier A gate.
    actualStops == [1, 2] && daemonDrained
  }
}

/// Failure evidence only; no field here participates in runtime acceptance.
/// The caller serializes access. Every emitted value belongs to a closed enum.
struct WorkloadNetworkDiagnostic {
  enum Site: String, CaseIterable {
    case packetConnect = "packet-connect"
    case packetAttachStart = "packet-attach-start"
    case packetCompletion = "packet-completion"
    case progressConnect = "progress-connect"
    case daemonConnect = "daemon-connect"
    case bridgeMarker = "bridge-marker"
    case progressBridgeResult = "progress-bridge-result"
    case daemonBridgeResult = "daemon-bridge-result"
    case progressParentControl = "progress-parent-control"
    case runtimeDeadline = "runtime-deadline"
    case vmFailure = "vm-failure"
    case startDeadline = "start-deadline"
    case workerFailure = "worker-failure"
    case eventBounds = "event-bounds"
    case relayPoll = "relay-poll"
    case parentRead = "parent-read"
    case parentFrame = "parent-frame"
    case forcedControl = "forced-control"
    case attachmentOrder = "attachment-order"
    case serviceControlOrder = "service-control-order"
    case serviceStatusRead = "service-status-read"
    case serviceStatusFrame = "service-status-frame"
    case serviceStatusEOF = "service-status-eof"
    case serviceControlWrite = "service-control-write"
    case serviceControlHUP = "service-control-hup"
    case parentWrite = "parent-write"
    case completion = "completion"
    case normalCleanup = "normal-cleanup"
    case runtime = "runtime"
  }

  enum BridgeRole { case progress, daemon }
  enum Bridge: String, CaseIterable {
    case notReturned = "not-returned"
    case cancelled
    case localEOF = "local-eof"
    case guestDrained = "guest-drained"
    case error, unexpected

    init(result: Int32) {
      switch result {
      case 0: self = .cancelled
      case 1: self = .localEOF
      case 2: self = .guestDrained
      case -1: self = .error
      default: self = .unexpected
      }
    }
  }

  enum VM: String, CaseIterable {
    case notObserved = "not-observed"
    case guestStopped = "guest-stopped"
    case guestFailed = "guest-failed"
    case forcedStopped = "forced-stopped"
    case unexpected

    init(event: UInt8) {
      switch event {
      case 0: self = .guestStopped
      case 1: self = .guestFailed
      case 2: self = .forcedStopped
      default: self = .unexpected
      }
    }
  }

  private(set) var first: Site?
  private(set) var progress: Bridge = .notReturned
  private(set) var daemon: Bridge = .notReturned
  private(set) var production: VM = .notObserved
  private(set) var service: VM = .notObserved
  private var emitted = false

  mutating func reject(_ site: Site) {
    if first == nil { first = site }
  }

  mutating func bridge(_ role: BridgeRole, result: Int32) {
    switch role {
    case .progress: progress = Bridge(result: result)
    case .daemon: daemon = Bridge(result: result)
    }
  }

  mutating func vm(role: UInt8, event: UInt8) {
    // Only the first observed terminal event; forced cleanup cannot rewrite it.
    if role == 1, production == .notObserved { production = VM(event: event) }
    if role == 2, service == .notObserved { service = VM(event: event) }
  }

  mutating func takeLine(fallback: Site) -> Data? {
    guard !emitted else { return nil }
    emitted = true
    reject(fallback)
    return Data(
      ("workload-network-diagnostic first=\(first!.rawValue) progress=\(progress.rawValue)"
        + " daemon=\(daemon.rawValue) production=\(production.rawValue) service=\(service.rawValue)\n")
        .utf8)
  }
}
