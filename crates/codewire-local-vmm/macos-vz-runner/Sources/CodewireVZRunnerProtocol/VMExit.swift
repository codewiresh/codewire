/// How the helper's exit status tells the Rust runner why its VM ended. The
/// helper's standard streams are `/dev/null`, so the status is the only
/// report, and it carries a fixed classification, never an error's text.
public enum VMExit: Equatable, Sendable {
  /// The guest powered off, or a requested stop completed.
  case stopped
  /// The VM stopped with an error, or the helper failed before starting it.
  case failed
  /// Virtualization.framework refused to start the VM, with this
  /// `VZError.Code`, or 0 for an error outside its domain (#4478).
  case startRefused(virtualizationCode: Int)

  /// The first status of a refused start. A refused start exits this plus its
  /// `VZError.Code` when the code is 1...63, and exactly this otherwise.
  public static let startRefusedBase: Int32 = 64

  public var status: Int32 {
    switch self {
    case .stopped: return 0
    case .failed: return 1
    case .startRefused(let code):
      return (1...63).contains(code) ? Self.startRefusedBase + Int32(code) : Self.startRefusedBase
    }
  }
}
