import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  @available(macOS 15.0, *)
  public enum ProductionFixtureRuntime {
    public static func run(request: ProductionFixtureRequest, controlDescriptor: Int32) throws {
      let configuration = try RuntimeAdmission.buildProductionFixtureConfiguration(for: request)
      try send("descriptors-admitted", control: controlDescriptor)
      try PrivateIPC.receiveStart(controlDescriptor: controlDescriptor)
      let context = try FixtureContext(
        request: request, configuration: configuration, control: controlDescriptor
      )
      try context.run()
    }

    static func send(_ result: String, control: Int32) throws {
      // Only fixed call-site classifications; no guest bytes, paths or errors.
      try PrivateIPC.send(
        controlDescriptor: control,
        response: Data("{\"result\":\"\(result)\",\"schemaVersion\":2}".utf8)
      )
    }
  }

  @available(macOS 15.0, *)
  private final class FixtureContext: @unchecked Sendable {
    let lifecycle = ProductionFixtureLifecycle()
    let queue = DispatchQueue(label: "dev.codewire.vz-production-fixture")
    let workers = DispatchGroup()
    let request: ProductionFixtureRequest
    let machine: VZVirtualMachine
    let control: Int32
    let cancellation: [Int32]
    let deadline = fixtureNow() + ProductionFixtureProtocol.runtimeSeconds
    let connectDeadline = fixtureNow() + ProductionFixtureProtocol.connectSeconds
    private let writes = NSLock()
    private let delegate: FixtureDelegate

    init(
      request: ProductionFixtureRequest, configuration: VZVirtualMachineConfiguration,
      control: Int32
    ) throws {
      self.request = request
      self.control = control
      machine = VZVirtualMachine(configuration: configuration, queue: queue)
      delegate = FixtureDelegate(lifecycle: lifecycle)
      var pipeFDs: [Int32] = [-1, -1]
      guard Darwin.pipe(&pipeFDs) == 0 else { throw IPCError.rejected(-4) }
      for fd in pipeFDs {
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 else {
          for owned in pipeFDs { _ = Darwin.close(owned) }
          throw IPCError.rejected(-4)
        }
      }
      cancellation = pipeFDs
      queue.sync { machine.delegate = delegate }
    }

    deinit { for fd in cancellation { _ = Darwin.close(fd) } }

    func run() throws {
      workers.enter()
      DispatchQueue.global().async {
        defer { self.workers.leave() }
        while self.lifecycle.end == nil {
          if fixtureNow() >= self.deadline {
            self.lifecycle.finish(.failed)
            break
          }
          let event = cw_vz_control_event(self.control, 100)
          if event != 0 {
            self.lifecycle.finish(event == 1 ? .parentClosed : .failed)
          }
        }
      }
      do {
        let start = FixtureCompletion<Void>()
        queue.async {
          guard self.lifecycle.end == nil else {
            start.complete(.failure(IPCError.rejected(-4)))
            return
          }
          self.machine.start { start.complete($0) }
        }
        _ = try start.wait(deadline: connectDeadline, cancelled: { self.lifecycle.end != nil })
        for role in [ProductionDescriptorRole.network, .progress, .daemon] {
          workers.enter()
          DispatchQueue.global().async {
            defer { self.workers.leave() }
            do { try self.bridge(role) } catch { self.lifecycle.finish(.failed) }
          }
        }
        while lifecycle.end == nil { Thread.sleep(forTimeInterval: 0.02) }
      } catch {
        lifecycle.finish(.failed)
      }
      // The pipe remains open until every worker releases its borrowed FDs.
      // One unread byte wakes all bridge pollers without consuming cancellation.
      var byte: UInt8 = 1
      _ = Darwin.write(cancellation[1], &byte, 1)
      let stopDeadline = fixtureNow() + ProductionFixtureProtocol.stopSeconds
      let stopped = FixtureCompletion<Void>()
      queue.async {
        if self.machine.state == .stopped {
          stopped.complete(.success(()))
        } else {
          // Parent may already have requested authenticated guest poweroff.
          // This fallback stops only the VZ instance owned by this helper.
          self.machine.stop { error in
            if let error {
              stopped.complete(.failure(error))
            } else {
              stopped.complete(.success(()))
            }
          }
        }
      }
      do { _ = try stopped.wait(deadline: stopDeadline, cancelled: { false }) } catch {
        throw IPCError.rejected(-4)
      }
      guard workers.wait(timeout: .now() + max(0, stopDeadline - fixtureNow())) == .success
      else { throw IPCError.rejected(-4) }
      if case .some(.failed) = lifecycle.end { throw IPCError.rejected(-4) }
      // No helper result claims guest readiness or persistence. Parent-owned
      // progress and daemon authentication remain the only acceptance proof.
    }

    private func bridge(_ role: ProductionDescriptorRole) throws {
      let connection = try connect(role)
      defer { connection.close() }
      writes.lock()
      do {
        try ProductionFixtureRuntime.send(try lifecycle.didConnect(role), control: control)
        writes.unlock()
      } catch {
        writes.unlock()
        throw error
      }
      let local = request.descriptors.descriptor(for: role)
      let remaining = Int32(max(1, min(180, (deadline - fixtureNow()).rounded(.up))))
      let result = cw_vz_bridge_streams(
        local, connection.fileDescriptor, cancellation[0], remaining, role == .progress ? 1 : 0
      )
      if result == 0 { return }
      guard role == .progress, result == 2 else { throw IPCError.rejected(-4) }
      writes.lock()
      do {
        try ProductionFixtureRuntime.send(try lifecycle.progressClosed(), control: control)
        writes.unlock()
      } catch {
        writes.unlock()
        throw error
      }
      // Production progress ends its guest stream after the terminal frame.
      // Keep the fixture alive while the parent independently verifies it.
      while lifecycle.end == nil {
        let event = cw_vz_control_event(local, 100)
        if event != 0 {
          lifecycle.finish(event == 1 ? .parentClosed : .failed)
        }
      }
    }

    private func connect(_ role: ProductionDescriptorRole) throws -> VZVirtioSocketConnection {
      guard let port = role.port else { throw IPCError.rejected(-5) }
      while fixtureNow() < connectDeadline, lifecycle.end == nil {
        let pending = FixtureConnectionCompletion()
        queue.async {
          guard self.lifecycle.end == nil,
            let device = self.machine.socketDevices.first as? VZVirtioSocketDevice
          else {
            pending.complete(.failure(IPCError.rejected(-4)))
            return
          }
          device.connect(toPort: port) { pending.complete($0) }
        }
        do {
          return try pending.wait(
            deadline: connectDeadline, cancelled: { self.lifecycle.end != nil })
        } catch {
          if fixtureNow() >= connectDeadline || lifecycle.end != nil { throw error }
          Thread.sleep(forTimeInterval: 0.05)
        }
      }
      throw IPCError.rejected(-4)
    }
  }

  @available(macOS 15.0, *)
  private final class FixtureDelegate: NSObject, VZVirtualMachineDelegate {
    let lifecycle: ProductionFixtureLifecycle
    init(lifecycle: ProductionFixtureLifecycle) { self.lifecycle = lifecycle }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { lifecycle.finish(.guestStopped) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
      lifecycle.finish(.failed)
    }
  }

  class FixtureCompletion<Value>: @unchecked Sendable {
    let lock = NSLock()
    private let signal = DispatchSemaphore(value: 0)
    private var value: Result<Value, any Error>?
    private var abandoned = false
    func dispose(_ value: Value) {}
    func complete(_ result: Result<Value, any Error>) {
      lock.lock()
      if abandoned || value != nil {
        lock.unlock()
        if case .success(let item) = result { dispose(item) }
        return
      }
      value = result
      lock.unlock()
      signal.signal()
    }
    func wait(deadline: TimeInterval, cancelled: () -> Bool) throws -> Value {
      while fixtureNow() < deadline, !cancelled() {
        if signal.wait(timeout: .now() + 0.05) == .success {
          lock.lock()
          let result = value!
          value = nil
          abandoned = true
          lock.unlock()
          return try result.get()
        }
      }
      lock.lock()
      abandoned = true
      let result = value
      value = nil
      lock.unlock()
      if case .success(let item) = result { dispose(item) }
      throw IPCError.rejected(-4)
    }
  }

  @available(macOS 15.0, *)
  final class FixtureConnectionCompletion: FixtureCompletion<VZVirtioSocketConnection>,
    @unchecked Sendable
  {
    override func dispose(_ value: VZVirtioSocketConnection) { value.close() }
  }

  private func fixtureNow() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
#endif
