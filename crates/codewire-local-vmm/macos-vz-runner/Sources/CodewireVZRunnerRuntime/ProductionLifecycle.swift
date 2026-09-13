import CodewireVZRunnerProtocol
import Foundation

/// Transport lifecycle only: none of these transitions authenticates a guest.
public final class ProductionFixtureLifecycle: @unchecked Sendable {
  public enum End: Sendable { case parentClosed, guestStopped, failed }
  private let lock = NSLock()
  private var connected: Set<ProductionDescriptorRole> = []
  private var progressEnded = false
  private var terminal: End?

  public init() {}

  public var end: End? {
    lock.lock()
    defer { lock.unlock() }
    return terminal
  }

  @discardableResult public func finish(_ reason: End) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard terminal == nil else { return false }
    terminal = reason
    return true
  }

  public func didConnect(_ role: ProductionDescriptorRole) throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard terminal == nil, let result = role.connectedResult,
      connected.insert(role).inserted
    else { throw IPCError.rejected(-5) }
    return result
  }

  public func progressClosed() throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard terminal == nil, connected.contains(.progress), !progressEnded else {
      throw IPCError.rejected(-5)
    }
    progressEnded = true
    return "progress-closed"
  }
}
