import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  @available(macOS 15.0, *)
  public enum WorkloadNetworkRuntime {
    public static func run(request: WorkloadNetworkRequest, controlDescriptor: Int32) throws {
      try request.configuration.validate()
      let production = try RuntimeAdmission.buildProductionBootConfiguration(
        configuration: request.configuration.production,
        descriptors: request.descriptors.productionBootDescriptors)
      let service = try WorkloadNetworkServiceBoot(request: request)
      let context = try WorkloadNetworkContext(
        request: request, production: production, service: service, control: controlDescriptor)
      try PrivateIPC.send(
        controlDescriptor: controlDescriptor, response: workloadMarker("workload-network-admitted"))
      try PrivateIPC.receiveStart(controlDescriptor: controlDescriptor)
      try context.run()
    }
  }

  private func workloadNow() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
  private func workloadMarker(_ result: String) -> Data {
    // Only fixed call-site enums; no guest data, paths or error descriptions.
    Data("{\"result\":\"\(result)\",\"schemaVersion\":4}".utf8)
  }

  /// VZ owns the descriptor. The one wrapper borrows it for both attachment
  /// directions; this object never reads, writes, duplicates or FileHandle-closes it.
  @available(macOS 15.0, *)
  private final class WorkloadNetworkPacket: @unchecked Sendable {
    let connection: VZVirtioSocketConnection
    let handle: FileHandle
    let attachment: VZFileHandleSerialPortAttachment
    init(_ connection: VZVirtioSocketConnection) {
      self.connection = connection
      handle = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
      attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: handle, fileHandleForWriting: handle)
    }
  }

  /// Retain an unresolved exact VM/attachment until process exit. An unknown
  /// stop is never converted into a quiescence observation by releasing objects.
  private final class WorkloadNetworkUnknown: @unchecked Sendable {
    static let shared = WorkloadNetworkUnknown()
    private let lock = NSLock()
    private var retained: AnyObject?
    func retain(_ object: AnyObject) {
      lock.lock()
      defer { lock.unlock() }
      retained = object
    }
  }

  @available(macOS 15.0, *)
  private final class WorkloadNetworkContext: @unchecked Sendable {
    let request: WorkloadNetworkRequest
    let serviceBoot: WorkloadNetworkServiceBoot
    let production: WorkloadNetworkMachine
    let service: WorkloadNetworkMachine
    let control: Int32
    let cancellation: [Int32]
    let workers = DispatchGroup()
    let deadline = workloadNow() + WorkloadNetworkProtocol.runtimeSeconds
    let connectDeadline = workloadNow() + WorkloadNetworkProtocol.connectSeconds
    private let lock = NSLock()
    private var life = WorkloadNetworkLifecycle()
    private var failed = false
    private var daemonDrained = false
    private var diagnostic = WorkloadNetworkDiagnostic()
    private var pendingEvents: [Data] = []
    // Both of these belong exclusively to the service VZ queue.
    private var packet: WorkloadNetworkPacket?
    private var packetPort: VZVirtioConsolePort?

    init(
      request: WorkloadNetworkRequest, production: VZVirtualMachineConfiguration,
      service: WorkloadNetworkServiceBoot, control: Int32
    ) throws {
      self.request = request
      self.serviceBoot = service
      self.production = WorkloadNetworkMachine(role: 1, configuration: production)
      self.service = WorkloadNetworkMachine(role: 2, configuration: try service.configuration())
      self.control = control
      var fds: [Int32] = [-1, -1]
      guard Darwin.pipe(&fds) == 0 else { throw IPCError.rejected(-4) }
      for fd in fds {
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 else {
          for owned in fds { _ = Darwin.close(owned) }
          throw IPCError.rejected(-4)
        }
      }
      cancellation = fds
    }

    deinit { for fd in cancellation { _ = Darwin.close(fd) } }

    private var cancelled: Bool {
      lock.lock()
      defer { lock.unlock() }
      return life.cancelled
    }

    private func fail(_ site: WorkloadNetworkDiagnostic.Site) {
      lock.lock()
      if !life.cancelled {
        diagnostic.reject(site)
        failed = true
      }
      lock.unlock()
      cancel()
    }

    private func recordRejection(_ site: WorkloadNetworkDiagnostic.Site) {
      lock.lock()
      diagnostic.reject(site)
      lock.unlock()
    }

    private func emitDiagnosticBeforeCleanup() {
      // A worker failure may have prevented the relay from sending a terminal
      // event it already drained. Include those and any now-pending events,
      // before requesting a forced stop, without manufacturing a normal event.
      let observed = [production.drain(), service.drain()]
      lock.lock()
      for (index, observation) in observed.enumerated() {
        for event in observation.events { diagnostic.vm(role: UInt8(index + 1), event: event) }
      }
      let line = diagnostic.takeLine(fallback: .runtime)
      lock.unlock()
      if let line { FileHandle.standardError.write(line) }
    }

    private func cancel() {
      lock.lock()
      let first = !life.cancelled
      life.cancel()
      lock.unlock()
      if first {
        // One unread byte wakes every bridge, without competing consumers.
        var byte: UInt8 = 1
        _ = Darwin.write(cancellation[1], &byte, 1)
      }
    }

    private func enqueue(_ marker: String) throws {
      lock.lock()
      defer { lock.unlock() }
      guard !life.cancelled, pendingEvents.count < 8 else { throw IPCError.rejected(-4) }
      pendingEvents.append(workloadMarker(marker))
    }

    func run() throws {
      try nonblocking(control)
      production.start()
      service.start()
      do {
        try relay()
        do { try finish(force: false) } catch {
          recordRejection(.normalCleanup)
          throw error
        }
      } catch {
        emitDiagnosticBeforeCleanup()
        do { try finish(force: true) } catch { WorkloadNetworkUnknown.shared.retain(self) }
        throw IPCError.rejected(-4)
      }
      withExtendedLifetime((request, serviceBoot, production, service)) {}
    }

    private func beginAttachment(_ payload: Data, bothStarted: Bool) throws {
      lock.lock()
      let held: Data
      do { held = try life.begin(payload, bothStarted: bothStarted) } catch {
        lock.unlock()
        throw error
      }
      lock.unlock()
      workers.enter()
      DispatchQueue.global().async {
        defer { self.workers.leave() }
        var site = WorkloadNetworkDiagnostic.Site.packetConnect
        do {
          let connection = try self.connect(port: 7775)
          let writeDeadline = min(self.deadline, workloadNow() + 1)
          let owned = WorkloadNetworkPacket(connection)
          let done = FixtureCompletion<Void>()
          self.service.queue.async {
            do {
              try self.attachAndStart(owned, held: held, writeDeadline: writeDeadline)
              done.complete(.success(()))
            } catch {
              self.fail(.packetAttachStart)
              done.complete(.failure(error))
            }
          }
          site = .packetCompletion
          _ = try done.wait(deadline: self.deadline, cancelled: { self.cancelled })
        } catch { self.fail(site) }
      }
    }

    private func attachAndStart(
      _ owned: WorkloadNetworkPacket, held: Data, writeDeadline: TimeInterval
    ) throws {
      // Called only on the consuming service VM queue. There is no parent
      // round trip between the successful connect and forwarding held Start.
      lock.lock()
      guard !life.cancelled, workloadNow() < writeDeadline, packet == nil,
        !service.snapshot().terminal,
        let device = service.machine.consoleDevices.first as? VZVirtioConsoleDevice,
        let port = device.ports[0], port.name == ConsolePairProtocol.packetPort,
        port.attachment == nil
      else {
        lock.unlock()
        owned.connection.close()  // Never attached: no consumer can use it.
        throw IPCError.rejected(-4)
      }
      do { try life.didAttach() } catch {
        lock.unlock()
        owned.connection.close()
        throw error
      }
      packet = owned
      packetPort = port
      port.attachment = owned.attachment
      lock.unlock()

      var bytes = held
      while !bytes.isEmpty {
        guard !cancelled, workloadNow() < writeDeadline else { throw IPCError.rejected(-4) }
        try writeAvailable(serviceBoot.control.fileHandleForWriting.fileDescriptor, buffer: &bytes)
        if !bytes.isEmpty {
          var polls = [
            pollfd(fd: cancellation[0], events: Int16(POLLIN), revents: 0),
            pollfd(
              fd: serviceBoot.control.fileHandleForWriting.fileDescriptor,
              events: Int16(POLLOUT), revents: 0),
          ]
          let result = poll(&polls, 2, 10)
          guard result >= 0 || errno == EINTR else { throw IPCError.rejected(-4) }
        }
      }
      lock.lock()
      defer { lock.unlock() }
      guard workloadNow() < writeDeadline else { throw IPCError.rejected(-4) }
      try life.didForward()
      guard pendingEvents.count < 8 else { throw IPCError.rejected(-4) }
      pendingEvents.append(workloadMarker("packet-attached"))
    }

    private func connect(port: UInt32) throws -> VZVirtioSocketConnection {
      while workloadNow() < connectDeadline, !cancelled {
        let pending = FixtureConnectionCompletion()
        production.queue.async {
          guard !self.cancelled, !self.production.snapshot().terminal,
            let device = self.production.machine.socketDevices.first as? VZVirtioSocketDevice
          else {
            pending.complete(.failure(IPCError.rejected(-4)))
            return
          }
          device.connect(toPort: port) { pending.complete($0) }
        }
        do {
          return try pending.wait(deadline: connectDeadline, cancelled: { self.cancelled })
        } catch {
          guard !cancelled, workloadNow() < connectDeadline else { throw error }
          Thread.sleep(forTimeInterval: 0.05)
        }
      }
      throw IPCError.rejected(-4)
    }

    private func startBridges() {
      for role in [WorkloadNetworkDescriptorRole.progress, .daemon] {
        workers.enter()
        DispatchQueue.global().async {
          defer { self.workers.leave() }
          var site: WorkloadNetworkDiagnostic.Site =
            role == .progress ? .progressConnect : .daemonConnect
          do { try self.bridge(role, site: &site) } catch { self.fail(site) }
        }
      }
    }

    private func bridge(
      _ role: WorkloadNetworkDescriptorRole, site: inout WorkloadNetworkDiagnostic.Site
    ) throws {
      let progress = role == .progress
      let connection = try connect(port: progress ? 7776 : 7777)
      defer { connection.close() }
      site = .bridgeMarker
      try enqueue(progress ? "progress-connected" : "daemon-connected")
      let local = request.descriptors.descriptor(for: role)
      let seconds = Int32(max(1, min(180, (deadline - workloadNow()).rounded(.up))))
      let result =
        progress
        ? cw_vz_bridge_streams(local, connection.fileDescriptor, cancellation[0], seconds, 1)
        : cw_vz_bridge_daemon_streams(local, connection.fileDescriptor, cancellation[0], seconds)
      lock.lock()
      diagnostic.bridge(progress ? .progress : .daemon, result: result)
      lock.unlock()
      site = progress ? .progressBridgeResult : .daemonBridgeResult
      if result == 0 { return }
      guard result == 2 else { throw IPCError.rejected(-4) }
      if progress {
        site = .bridgeMarker
        try enqueue("progress-closed")
        site = .progressParentControl
        while !cancelled {
          guard cw_vz_control_event(local, 100) == 0 else { throw IPCError.rejected(-4) }
        }
      } else {
        // Real guest EOF plus all bridge-buffered bytes delivered to the
        // verifier-owned kernel endpoint. Hyper may have ended its own read;
        // this does not claim it parsed that transport tail. The verifier's A
        // remains the separately parsed/authenticated poweroff acceptance.
        lock.lock()
        daemonDrained = true
        lock.unlock()
        // Daemon EOF precedes PID 1's workspace/network cleanup and sync/reboot.
        // The central relay still joins this fact with both actual VM stops
        // under its runtime deadline, and the parent bounds poweroff separately.
        // Do not borrow the forced-cleanup budget for normal guest shutdown.
        // This drained connection can close; EOF alone never completes the run.
      }
    }

    private func relay() throws {
      var site = WorkloadNetworkDiagnostic.Site.runtime
      do { try relayObservations(site: &site) } catch {
        recordRejection(site)
        throw error
      }
    }

    private func relayObservations(site: inout WorkloadNetworkDiagnostic.Site) throws {
      var wire = WorkloadNetworkWire()
      var output = Data()
      var controls = Data()
      var liveness = ConsolePairStreamLiveness()
      var started = false
      var bridgesStarted = false
      var actualStops = Set<UInt8>()
      let startDeadline = workloadNow() + 10
      while true {
        site = .runtimeDeadline
        guard workloadNow() < deadline else { throw IPCError.rejected(-4) }
        let states = [production.drain(), service.drain()]
        for (index, state) in states.enumerated() {
          for event in state.events {
            let role = UInt8(index + 1)
            lock.lock()
            diagnostic.vm(role: role, event: event)
            lock.unlock()
            if event == 0 { actualStops.insert(role) }
            site = .eventBounds
            output.append(try wire.event(Data([0x56, role, event])))
          }
        }
        site = .vmFailure
        guard !states.contains(where: { $0.state.failed }) else { throw IPCError.rejected(-4) }
        if !bridgesStarted, states[0].state.started {
          bridgesStarted = true
          startBridges()
        }
        if !started, states.allSatisfy({ $0.state.started }) {
          started = true
          site = .eventBounds
          output.append(try wire.event(workloadMarker("workload-network-started")))
        }
        site = .startDeadline
        guard started || workloadNow() < startDeadline else { throw IPCError.rejected(-4) }
        lock.lock()
        let failedNow = failed
        let daemonDrainedNow = daemonDrained
        let forwarded = life.phase == .forwarded
        let markers = pendingEvents
        pendingEvents.removeAll(keepingCapacity: true)
        lock.unlock()
        site = .workerFailure
        guard !failedNow, !cancelled else { throw IPCError.rejected(-4) }
        site = .eventBounds
        for marker in markers { output.append(try wire.event(marker)) }
        guard output.count <= 16 * 1024, controls.count <= 1024 else { throw IPCError.rejected(-4) }
        var polls = [
          pollfd(
            fd: control, events: Int16(POLLIN) | (output.isEmpty ? 0 : Int16(POLLOUT)), revents: 0),
          pollfd(
            fd: liveness.statusClosed ? -1 : serviceBoot.status.fileHandleForReading.fileDescriptor,
            events: Int16(POLLIN), revents: 0),
          pollfd(
            fd: liveness.controlClosed
              ? -1 : serviceBoot.control.fileHandleForWriting.fileDescriptor,
            events: controls.isEmpty ? 0 : Int16(POLLOUT), revents: 0),
        ]
        site = .relayPoll
        let result = poll(&polls, 3, 20)
        if result < 0 && errno == EINTR { continue }
        guard result >= 0 else { throw IPCError.rejected(-4) }
        if polls[0].revents & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL) != 0 {
          site = .parentRead
          guard let bytes = try readAvailable(control, maximum: 1024) else {
            throw IPCError.rejected(-4)
          }
          site = .parentFrame
          for frame in try wire.controls(bytes) {
            if frame == Data([0x51]) {
              site = .forcedControl
              throw IPCError.rejected(-4)
            }
            if frame[0] == 0x41 {
              site = .attachmentOrder
              try beginAttachment(frame, bothStarted: started)
            } else {
              site = .serviceControlOrder
              lock.lock()
              do {
                let next = try life.subsequent(frame)
                guard controls.count + next.count <= 1024 else { throw IPCError.rejected(-4) }
                controls.append(next)
                lock.unlock()
              } catch {
                lock.unlock()
                throw error
              }
            }
          }
        }
        if polls[1].revents & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL) != 0 {
          site = .serviceStatusRead
          if let bytes = try readAvailable(polls[1].fd, maximum: 1024) {
            // Prepared/status delivery is independent of both-VM start ordering.
            site = .serviceStatusFrame
            for frame in try wire.statuses(bytes) { output.append(frame) }
          } else {
            site = .serviceStatusEOF
            try liveness.statusEOF { service.snapshot().terminal }
          }
        }
        if polls[2].revents & Int16(POLLOUT) != 0 {
          site = .serviceControlWrite
          try writeAvailable(polls[2].fd, buffer: &controls)
        }
        if polls[2].revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 {
          site = .serviceControlHUP
          try liveness.controlHUP { service.snapshot().terminal }
        }
        if polls[0].revents & Int16(POLLOUT) != 0 {
          site = .parentWrite
          try writeAvailable(control, buffer: &output)
        }
        // Once VZ reports both terminals, still drain already-readable status
        // bytes before helper EOF. A partial/trailing frame cannot vanish at exit.
        if states.allSatisfy({ $0.state.terminal }),
          WorkloadNetworkLifecycle.mayComplete(
            actualStops: actualStops, daemonDrained: daemonDrainedNow),
          output.isEmpty,
          polls[1].revents == 0 || liveness.statusClosed
        {
          site = .completion
          guard actualStops == [1, 2], forwarded, wire.input.isEmpty, wire.status.isEmpty,
            controls.isEmpty
          else { throw IPCError.rejected(-4) }
          return
        }
      }
    }

    private func finish(force: Bool) throws {
      cancel()
      let stopDeadline = workloadNow() + WorkloadNetworkProtocol.stopSeconds
      if force {
        production.requestStop()
        service.requestStop()
      }
      while !(production.snapshot().terminal && service.snapshot().terminal),
        workloadNow() < stopDeadline
      {
        Thread.sleep(forTimeInterval: 0.01)
      }
      guard production.snapshot().terminal, service.snapshot().terminal else {
        throw IPCError.rejected(-4)
      }
      let detached = FixtureCompletion<Void>()
      service.queue.async {
        do {
          self.lock.lock()
          defer { self.lock.unlock() }
          if let packet = self.packet {
            guard let port = self.packetPort, port.attachment === packet.attachment else {
              throw IPCError.rejected(-4)
            }
            port.attachment = nil
            try self.life.didDetach(consumerTerminal: self.service.snapshot().terminal)
            if try self.life.claimClose() { packet.connection.close() }
            self.packet = nil
            self.packetPort = nil
          }
          detached.complete(.success(()))
        } catch { detached.complete(.failure(error)) }
      }
      _ = try detached.wait(deadline: stopDeadline, cancelled: { false })
      guard workers.wait(timeout: .now() + max(0, stopDeadline - workloadNow())) == .success else {
        throw IPCError.rejected(-4)
      }
      lock.lock()
      let failedNow = failed
      lock.unlock()
      if !force, failedNow { throw IPCError.rejected(-4) }
    }
  }
#endif
