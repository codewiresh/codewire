import Foundation

/// The runner-to-helper control channel (#4654): one end of an unnamed
/// AF_UNIX stream socketpair that the helper inherits, named by
/// `controlDescriptor` in a schema 3 configuration. Each message is one JSON
/// object on one line of at most `maxLineBytes`.
///
/// A request names an operation and nothing else: no path, descriptor or
/// size. `save` always writes the configuration's `saveState`, so the channel
/// can never point the framework at another file. Replies and the one event
/// carry numbers and the machine identifier only.
public enum ControlError: Error, Equatable {
  case malformed
  case lineTooLong
}

public enum ControlOperation: String, CaseIterable, Sendable {
  case pause, save, resume, stop
}

public struct ControlRequest: Equatable, Sendable {
  public static let maxLineBytes = 4096

  public let id: UInt64
  public let operation: ControlOperation

  public init(id: UInt64, operation: ControlOperation) {
    self.id = id
    self.operation = operation
  }

  /// One request line, without its newline: exactly `{"id": N, "op": "..."}`.
  public static func decode(_ line: Data) throws -> ControlRequest {
    guard line.count <= maxLineBytes,
      let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
      Set(object.keys) == ["id", "op"],
      let number = object["id"] as? NSNumber,
      CFGetTypeID(number) == CFNumberGetTypeID(),
      let id = UInt64(exactly: number.doubleValue),
      number.stringValue == String(id),
      let name = object["op"] as? String,
      let operation = ControlOperation(rawValue: name)
    else { throw ControlError.malformed }
    return ControlRequest(id: id, operation: operation)
  }
}

/// A reply to one request, or the event the helper sends unprompted.
public enum ControlMessage: Equatable, Sendable {
  /// The operation finished, taking `milliseconds`.
  case done(id: UInt64, milliseconds: UInt64)
  /// The framework refused it; `code` is its `VZError.Code`, or 0.
  case failed(id: UInt64, code: Int)
  /// Not allowed in the VM's present state.
  case refused(id: UInt64)
  /// The VM runs (started, or restored and resumed) with this identifier,
  /// base64 of `VZGenericMachineIdentifier.dataRepresentation`.
  case started(machineIdentifier: String)

  /// The message as one line, newline included.
  public func encoded() -> Data {
    let text: String
    switch self {
    case .done(let id, let milliseconds):
      text = #"{"id":\#(id),"result":"done","ms":\#(milliseconds)}"#
    case .failed(let id, let code):
      text = #"{"id":\#(id),"result":"failed","code":\#(code)}"#
    case .refused(let id):
      text = #"{"id":\#(id),"result":"refused"}"#
    case .started(let machineIdentifier):
      text = #"{"event":"started","machineIdentifier":"\#(machineIdentifier)"}"#
    }
    return Data((text + "\n").utf8)
  }
}

/// Splits the channel's bytes into lines, refusing one longer than
/// `ControlRequest.maxLineBytes`.
public struct ControlLineReader: Sendable {
  private var pending = Data()

  public init() {}

  public mutating func append(_ bytes: Data) throws -> [Data] {
    pending.append(bytes)
    var lines: [Data] = []
    while let newline = pending.firstIndex(of: UInt8(ascii: "\n")) {
      let line = pending[pending.startIndex..<newline]
      guard line.count <= ControlRequest.maxLineBytes else { throw ControlError.lineTooLong }
      lines.append(Data(line))
      pending.removeSubrange(pending.startIndex...newline)
    }
    guard pending.count <= ControlRequest.maxLineBytes else { throw ControlError.lineTooLong }
    return lines
  }
}

/// Which operations the VM's state allows. A capture is pause, save, then
/// resume; stop is allowed from any state and ends the VM.
public struct ControlStateMachine: Equatable, Sendable {
  public enum State: Equatable, Sendable {
    case starting, running, paused, stopping
  }

  public private(set) var state: State = .starting

  public init() {}

  /// The VM is running: it started, or it was restored and resumed.
  public mutating func started() {
    if state == .starting { state = .running }
  }

  /// Whether `operation` may run now.
  public func admits(_ operation: ControlOperation) -> Bool {
    switch (operation, state) {
    case (.stop, .stopping): return false
    case (.stop, _): return true
    case (.pause, .running): return true
    case (.save, .paused), (.resume, .paused): return true
    default: return false
    }
  }

  /// Record that `operation` finished successfully.
  public mutating func completed(_ operation: ControlOperation) {
    switch operation {
    case .pause: state = .paused
    case .save: break
    case .resume: state = .running
    case .stop: state = .stopping
    }
  }
}
