import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  private enum ConsolePairError: Error {
    case admission, io, protocolViolation, deadline, machine
  }

  /// Developer-only two-VM fixture. The packet socketpair is attached directly
  /// to Virtualization.framework; no code here reads, writes or parses it.
  @available(macOS 15.0, *)
  public enum ConsolePairRuntime {
    public static func run(request: ConsolePairRequest, controlDescriptor: Int32) throws {
      try RuntimeAdmission.validateHost()
      let deadline = ContinuousClock.now.advanced(by: .seconds(110))
      let artifacts = try ConsolePairBootCopies(request: request)
      let packetPair = try makePacketPair()
      let machines = try [
        ConsolePairMachine(role: 1, packet: packetPair.0, artifacts: artifacts),
        ConsolePairMachine(role: 2, packet: packetPair.1, artifacts: artifacts),
      ]
      // Every input and copy remains retained, including on failure. The parent
      // owns the private TMPDIR and decides whether evidence can be removed.
      try PrivateIPC.send(
        controlDescriptor: controlDescriptor,
        response: Data("{\"result\":\"console-pair-admitted\",\"schemaVersion\":3}".utf8))
      try PrivateIPC.receiveStart(controlDescriptor: controlDescriptor)
      try nonblocking(controlDescriptor)
      for machine in machines { machine.start() }
      do {
        try relay(
          machines: machines, control: controlDescriptor,
          deadline: deadline, startDeadline: .now.advanced(by: .seconds(10)))
      } catch {
        for machine in machines { machine.requestStop() }
        let stopDeadline = ContinuousClock.now.advanced(by: .seconds(5))
        while machines.contains(where: { !$0.snapshot().terminal }),
          ContinuousClock.now < stopDeadline
        {
          // Only the exact retained VM objects are asked to stop. Failure or
          // timeout is not a stopped observation, even though this helper exits.
          Thread.sleep(forTimeInterval: 0.01)
        }
        throw error
      }
      withExtendedLifetime((request, artifacts, machines, packetPair)) {}
    }

    private static func relay(
      machines: [ConsolePairMachine], control: Int32,
      deadline: ContinuousClock.Instant, startDeadline: ContinuousClock.Instant
    ) throws {
      var input = Data()
      var output = Data()
      var statusBuffers = [Data(), Data()]
      var streamLiveness = [ConsolePairStreamLiveness(), ConsolePairStreamLiveness()]
      var controlQueues = [Data(), Data()]
      var eventCount = 0
      var startedSent = false
      var stopRequested = false
      var stopDeadline: ContinuousClock.Instant?

      func framed(_ payload: Data) -> Data {
        let count = UInt32(payload.count)
        return Data([
          UInt8(count >> 24), UInt8((count >> 16) & 255),
          UInt8((count >> 8) & 255), UInt8(count & 255),
        ]) + payload
      }

      while true {
        guard ContinuousClock.now < deadline else { throw ConsolePairError.deadline }
        let drained = machines.map { $0.drain() }
        let observations = drained.map(\.state)
        for (index, machine) in machines.enumerated() {
          for event in drained[index].events {
            eventCount += 1
            guard eventCount <= 64 else { throw ConsolePairError.protocolViolation }
            output.append(framed(Data([0x56, machine.role, event])))
          }
        }
        if observations.contains(where: { $0.failed }), !stopRequested {
          stopRequested = true
          stopDeadline = .now.advanced(by: .seconds(5))
          for machine in machines { machine.requestStop() }
        }
        if !startedSent && observations.allSatisfy(\.started) {
          output.append(
            framed(Data("{\"result\":\"console-pair-started\",\"schemaVersion\":3}".utf8)))
          startedSent = true
        }
        if !startedSent && !stopRequested && ContinuousClock.now >= startDeadline {
          throw ConsolePairError.deadline
        }
        if let stopDeadline, ContinuousClock.now >= stopDeadline,
          observations.contains(where: { !$0.terminal })
        {
          throw ConsolePairError.deadline
        }
        guard output.count <= 16 * 1024,
          controlQueues.allSatisfy({ $0.count <= 1024 })
        else { throw ConsolePairError.protocolViolation }

        var descriptors = [
          pollfd(
            fd: control, events: Int16(POLLIN) | (output.isEmpty ? 0 : Int16(POLLOUT)), revents: 0),
          pollfd(
            fd: streamLiveness[0].statusClosed ? -1 : machines[0].statusReader.fileDescriptor,
            events: Int16(POLLIN), revents: 0),
          pollfd(
            fd: streamLiveness[1].statusClosed ? -1 : machines[1].statusReader.fileDescriptor,
            events: Int16(POLLIN), revents: 0),
          pollfd(
            fd: streamLiveness[0].controlClosed ? -1 : machines[0].controlWriter.fileDescriptor,
            events: controlQueues[0].isEmpty ? 0 : Int16(POLLOUT), revents: 0),
          pollfd(
            fd: streamLiveness[1].controlClosed ? -1 : machines[1].controlWriter.fileDescriptor,
            events: controlQueues[1].isEmpty ? 0 : Int16(POLLOUT), revents: 0),
        ]
        let polled = poll(&descriptors, nfds_t(descriptors.count), 50)
        if polled < 0 && errno == EINTR { continue }
        guard polled >= 0 else { throw ConsolePairError.io }

        if descriptors[0].revents & Int16(POLLIN | POLLHUP | POLLERR) != 0 {
          let bytes = try readAvailable(control, maximum: 1024)
          guard let bytes else { throw ConsolePairError.io }
          input.append(bytes)
          guard input.count <= 2048 else { throw ConsolePairError.protocolViolation }
          while input.count >= 4 {
            let length = input.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            guard length == 1 || length == 130 else { throw ConsolePairError.protocolViolation }
            guard input.count >= 4 + length else { break }
            let payload = Data(input.dropFirst(4).prefix(length))
            input.removeFirst(4 + length)
            if payload == Data([0x51]) {
              if !stopRequested {
                stopRequested = true
                stopDeadline = .now.advanced(by: .seconds(5))
                for machine in machines { machine.requestStop() }
              }
            } else {
              guard !stopRequested, startedSent, payload.count == 130,
                payload[0] == 0x43, (1...2).contains(payload[1]),
                payload[10] == payload[1]
              else { throw ConsolePairError.protocolViolation }
              controlQueues[Int(payload[1]) - 1].append(payload.dropFirst(2))
            }
          }
        }
        for index in 0..<2 {
          if descriptors[index + 1].revents & Int16(POLLIN | POLLHUP | POLLERR) != 0 {
            if let bytes = try readAvailable(descriptors[index + 1].fd, maximum: 1024) {
              statusBuffers[index].append(bytes)
              guard statusBuffers[index].count <= 2048 else {
                throw ConsolePairError.protocolViolation
              }
              while statusBuffers[index].count >= ConsolePairProtocol.roleFrameBytes {
                let frame = Data(statusBuffers[index].prefix(ConsolePairProtocol.roleFrameBytes))
                statusBuffers[index].removeFirst(ConsolePairProtocol.roleFrameBytes)
                guard frame[8] == machines[index].role else {
                  throw ConsolePairError.protocolViolation
                }
                eventCount += 1
                guard eventCount <= 64 else { throw ConsolePairError.protocolViolation }
                output.append(framed(Data([0x52, machines[index].role]) + frame))
              }
            } else {
              try streamLiveness[index].statusEOF { machines[index].snapshot().terminal }
            }
          }
          if descriptors[index + 3].revents & Int16(POLLOUT) != 0 {
            try writeAvailable(descriptors[index + 3].fd, buffer: &controlQueues[index])
          }
          if descriptors[index + 3].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
            try streamLiveness[index].controlHUP { machines[index].snapshot().terminal }
          }
        }
        if descriptors[0].revents & Int16(POLLOUT) != 0 {
          try writeAvailable(control, buffer: &output)
        }
        if observations.allSatisfy(\.terminal), output.isEmpty {
          guard input.isEmpty, statusBuffers.allSatisfy(\.isEmpty),
            controlQueues.allSatisfy(\.isEmpty)
          else {
            throw ConsolePairError.protocolViolation
          }
          if observations.contains(where: { $0.failed }) { throw ConsolePairError.machine }
          return
        }
      }
    }
  }

  @available(macOS 15.0, *)
  private final class ConsolePairBootCopies {
    let directory: URL
    let files: [URL]

    init(request: ConsolePairRequest) throws {
      let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        "codewire-console-pair-\(UUID().uuidString)", isDirectory: true)
      guard mkdir(directory.path, 0o700) == 0 else { throw ConsolePairError.admission }
      self.directory = directory
      var copies: [URL] = []
      for role in ConsolePairArtifactRole.allCases {
        let descriptor = request.descriptors.descriptor(for: role)
        let identity = request.configuration.artifact(for: role)
        var status = stat()
        let flags = fcntl(descriptor, F_GETFL)
        guard fstat(descriptor, &status) == 0,
          status.st_mode & S_IFMT == S_IFREG, status.st_uid == geteuid(),
          status.st_nlink == 1, status.st_mode & 0o077 == 0,
          status.st_size > 0, UInt64(status.st_size) == identity.size,
          flags >= 0, flags & O_ACCMODE == O_RDONLY
        else { throw ConsolePairError.admission }
        copies.append(
          try PathBackedBootControl.copyVerified(
            sourceDescriptor: descriptor, identity: identity,
            destination: directory.appendingPathComponent("artifact-\(role.rawValue)")))
      }
      files = copies
    }
  }

  @available(macOS 15.0, *)
  private final class ConsolePairMachine: NSObject, VZVirtualMachineDelegate, @unchecked Sendable {
    // VZ operations are queue-confined. Only small observations/events cross
    // queues, under lock; the unchecked conformance does not make VZ thread-safe.
    let role: UInt8
    let statusReader: FileHandle
    let controlWriter: FileHandle
    private let queue: DispatchQueue
    private let machine: VZVirtualMachine
    private let lock = NSLock()
    private var observation = ConsolePairLifecycle()
    private var stopRequested = false

    init(role: UInt8, packet: FileHandle, artifacts: ConsolePairBootCopies) throws {
      self.role = role
      let queue = DispatchQueue(label: "dev.codewire.console-pair.\(role)")
      self.queue = queue
      let status = Pipe()
      let control = Pipe()
      statusReader = status.fileHandleForReading
      controlWriter = control.fileHandleForWriting
      try nonblocking(statusReader.fileDescriptor)
      try nonblocking(controlWriter.fileDescriptor)
      let configuration = VZVirtualMachineConfiguration()
      let loader = VZLinuxBootLoader(kernelURL: artifacts.files[0])
      loader.initialRamdiskURL = artifacts.files[1]
      loader.commandLine = "rdinit=/init panic=-1 -- \(role == 1 ? "guest" : "service")"
      configuration.bootLoader = loader
      configuration.platform = VZGenericPlatformConfiguration()
      configuration.cpuCount = ConsolePairProtocol.cpuCount
      configuration.memorySize = ConsolePairProtocol.memoryMiB * 1024 * 1024
      let binding = VZVirtioBlockDeviceConfiguration(
        attachment: try VZDiskImageStorageDeviceAttachment(
          url: artifacts.files[role == 1 ? 2 : 3], readOnly: true,
          cachingMode: .automatic, synchronizationMode: .full))
      binding.blockDeviceIdentifier = ConsolePairProtocol.bindingSerial
      configuration.storageDevices = [binding]
      configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      let console = VZVirtioConsoleDeviceConfiguration()
      let packetPort = VZVirtioConsolePortConfiguration()
      packetPort.name = ConsolePairProtocol.packetPort
      packetPort.isConsole = false
      packetPort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: packet, fileHandleForWriting: packet)
      let statusPort = VZVirtioConsolePortConfiguration()
      statusPort.name = ConsolePairProtocol.statusPort
      statusPort.isConsole = false
      statusPort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: nil, fileHandleForWriting: status.fileHandleForWriting)
      let controlPort = VZVirtioConsolePortConfiguration()
      controlPort.name = ConsolePairProtocol.controlPort
      controlPort.isConsole = false
      controlPort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: control.fileHandleForReading, fileHandleForWriting: nil)
      console.ports[0] = packetPort
      console.ports[1] = statusPort
      console.ports[2] = controlPort
      configuration.consoleDevices = [console]
      configuration.socketDevices = []
      configuration.networkDevices = []
      configuration.directorySharingDevices = []
      configuration.graphicsDevices = []
      configuration.audioDevices = []
      configuration.keyboards = []
      configuration.pointingDevices = []
      configuration.usbControllers = []
      configuration.serialPorts = []
      configuration.memoryBalloonDevices = []
      try configuration.validate()
      machine = VZVirtualMachine(configuration: configuration, queue: queue)
      super.init()
      queue.sync { machine.delegate = self }
    }

    func snapshot() -> ConsolePairLifecycle {
      lock.lock()
      defer { lock.unlock() }
      return observation
    }

    func drain() -> (state: ConsolePairLifecycle, events: [UInt8]) {
      lock.lock()
      defer { lock.unlock() }
      return observation.drain()
    }

    func start() {
      queue.async { [self] in
        machine.start { [self] result in
          switch result {
          case .success:
            record(.started)
            if stopRequested { stopOnQueue() }
          case .failure:
            record(.startFailed)
          }
        }
      }
    }

    func requestStop() {
      queue.async { [self] in
        guard !stopRequested else { return }
        stopRequested = true
        if snapshot().started { stopOnQueue() }
      }
    }

    private func stopOnQueue() {
      guard !snapshot().terminal else { return }
      guard machine.canStop else {
        record(.stopFailed)
        return
      }
      machine.stop { [self] error in
        record(error == nil ? .stopSucceeded : .stopFailed)
      }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
      guard virtualMachine === machine else { return }
      record(.guestStopped)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
      guard virtualMachine === machine else { return }
      record(.guestFailed)
    }

    private func record(_ event: ConsolePairLifecycle.Event) {
      lock.lock()
      defer { lock.unlock() }
      observation.apply(event)
    }
  }

  private func makePacketPair() throws -> (FileHandle, FileHandle) {
    var descriptors: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw ConsolePairError.io }
    let first = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
    let second = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
    for descriptor in descriptors {
      let flags = fcntl(descriptor, F_GETFD)
      guard flags >= 0, fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
        throw ConsolePairError.io
      }
    }
    return (first, second)
  }

  private func nonblocking(_ descriptor: Int32) throws {
    let flags = fcntl(descriptor, F_GETFL)
    guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
      throw ConsolePairError.io
    }
    var enabled: Int32 = 1
    // SO_NOSIGPIPE is socket-only; pipes use the standalone helper's SIGPIPE
    // disposition established before any VM is constructed.
    _ = setsockopt(
      descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
  }

  private func readAvailable(_ descriptor: Int32, maximum: Int) throws -> Data? {
    var bytes = [UInt8](repeating: 0, count: maximum)
    let count = Darwin.read(descriptor, &bytes, bytes.count)
    if count < 0 && (errno == EAGAIN || errno == EINTR) { return Data() }
    guard count >= 0 else { throw ConsolePairError.io }
    return count == 0 ? nil : Data(bytes.prefix(count))
  }

  private func writeAvailable(_ descriptor: Int32, buffer: inout Data) throws {
    guard !buffer.isEmpty else { return }
    let count = buffer.withUnsafeBytes { raw in Darwin.write(descriptor, raw.baseAddress, raw.count)
    }
    if count < 0 && (errno == EAGAIN || errno == EINTR) { return }
    guard count > 0 else { throw ConsolePairError.io }
    buffer.removeFirst(count)
  }
#endif
