import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  /// The product VM process: the macOS counterpart of the Cloud Hypervisor
  /// process the Linux runner owns. It boots one guest, serves the guest's
  /// vsock ports on one hybrid-vsock Unix socket, stops the VM on SIGTERM or
  /// SIGINT, and exits once the VM has stopped.
  @available(macOS 15.0, *)
  public enum VMRuntime {
    public enum Exit: Int32 {
      /// The guest powered off, or a requested stop completed.
      case stopped = 0
      /// The VM failed to start or stopped with an error.
      case failed = 1
    }

    public static func run(configuration: VMConfiguration) throws -> Exit {
      try RuntimeAdmission.validateHost()
      let vmConfiguration = try buildConfiguration(configuration)
      let listener = cw_vz_listen_unix(configuration.vsockSocket)
      guard listener >= 0 else { throw RuntimeError.descriptorInvalid }
      // A socket descriptor's fstat does not name the filesystem node, so
      // record the path's identity right after this process bound it.
      var identity = stat()
      guard lstat(configuration.vsockSocket, &identity) == 0 else {
        throw RuntimeError.descriptorInvalid
      }
      defer { removeSocket(configuration.vsockSocket, bound: identity) }

      let machine = VMMachine(configuration: vmConfiguration)
      for signalNumber in [SIGTERM, SIGINT] {
        signal(signalNumber, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: machine.queue)
        source.setEventHandler { machine.stop() }
        source.resume()
        machine.retain(source)
      }
      signal(SIGPIPE, SIG_IGN)
      // macOS has no PDEATHSIG: stop with the runner that spawned this helper,
      // so a crashed runner never leaves a VM holding its disks.
      let parent = getppid()
      let parentExit = DispatchSource.makeProcessSource(
        identifier: parent, eventMask: .exit, queue: machine.queue)
      parentExit.setEventHandler { machine.stop() }
      parentExit.resume()
      machine.retain(parentExit)
      if getppid() != parent { machine.queue.async { machine.stop() } }
      machine.start()
      let acceptor = Thread { acceptConnections(listener: listener, machine: machine) }
      acceptor.start()
      // The acceptor and any live bridges end with this process.
      return machine.waitForExit()
    }

    static func buildConfiguration(_ request: VMConfiguration) throws
      -> VZVirtualMachineConfiguration
    {
      let result = VZVirtualMachineConfiguration()
      let loader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: request.kernel))
      loader.initialRamdiskURL = URL(fileURLWithPath: request.initialRamdisk)
      loader.commandLine = request.commandLine
      result.bootLoader = loader
      guard request.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
        request.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount
      else { throw ConfigurationError.invalidCPUCount }
      let memory = try RuntimeAdmission.multiplied(request.memoryMiB, by: 1024 * 1024)
      guard memory >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        memory <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
      else { throw ConfigurationError.invalidMemory }
      result.cpuCount = request.cpuCount
      result.memorySize = memory
      result.platform = VZGenericPlatformConfiguration()
      result.storageDevices = try request.disks.map { disk in
        let attachment = try VZDiskImageStorageDeviceAttachment(
          url: URL(fileURLWithPath: disk.path), readOnly: disk.readOnly,
          cachingMode: .automatic, synchronizationMode: .full)
        let device = VZVirtioBlockDeviceConfiguration(attachment: attachment)
        device.blockDeviceIdentifier = disk.serial
        return device
      }
      result.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      result.socketDevices = [VZVirtioSocketDeviceConfiguration()]
      do { try result.validate() } catch { throw RuntimeError.virtualMachineConfigurationInvalid }
      return result
    }

    private static func acceptConnections(listener: Int32, machine: VMMachine) {
      while true {
        let connection = Darwin.accept(listener, nil, nil)
        if connection < 0 {
          if errno == EINTR || errno == ECONNABORTED { continue }
          return
        }
        let flags = fcntl(connection, F_GETFD)
        guard flags >= 0, fcntl(connection, F_SETFD, flags | FD_CLOEXEC) == 0 else {
          Darwin.close(connection)
          continue
        }
        Thread.detachNewThread { bridge(connection, machine: machine) }
      }
    }

    /// One hybrid-vsock client: a refused or unreachable guest port closes
    /// the connection without an acknowledgement, as Cloud Hypervisor does.
    private static func bridge(_ client: Int32, machine: VMMachine) {
      defer { Darwin.close(client) }
      var port: UInt32 = 0
      guard cw_vz_read_connect(client, &port) == 0, port != 0,
        let guest = machine.connect(toPort: port)
      else { return }
      withExtendedLifetime(guest) {
        let acknowledgement = Array("OK \(max(guest.sourcePort, 1))\n".utf8)
        guard cw_vz_write_all(client, acknowledgement, acknowledgement.count) == 0 else { return }
        _ = cw_vz_splice(client, guest.fileDescriptor)
        guest.close()
      }
    }

    /// Remove only the socket this process bound, never a replacement.
    private static func removeSocket(_ path: String, bound: stat) {
      var current = stat()
      guard lstat(path, &current) == 0, current.st_dev == bound.st_dev,
        current.st_ino == bound.st_ino
      else { return }
      unlink(path)
    }
  }

  @available(macOS 15.0, *)
  final class VMMachine: NSObject, VZVirtualMachineDelegate, @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.codewire.vz-vm")
    private let machine: VZVirtualMachine
    private let exited = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var exit: VMRuntime.Exit?
    private var retained: [AnyObject] = []

    init(configuration: VZVirtualMachineConfiguration) {
      machine = VZVirtualMachine(configuration: configuration, queue: queue)
      super.init()
      queue.sync { machine.delegate = self }
    }

    func retain(_ object: AnyObject) { retained.append(object) }

    /// Read and written only on `queue`.
    private var stopRequested = false

    func start() {
      queue.async {
        self.machine.start { result in
          if case .failure = result {
            self.finish(.failed)
          } else if self.stopRequested {
            self.stop()
          }
        }
      }
    }

    /// A forced stop of this helper's own VM, called on `queue`. The Rust
    /// runner first asks the guest to power off through its daemon, as it does
    /// on Linux. A stop requested while the VM is starting applies once it has.
    func stop() {
      stopRequested = true
      if machine.state == .stopped {
        finish(.stopped)
      } else if machine.canStop {
        machine.stop { error in self.finish(error == nil ? .stopped : .failed) }
      }
    }

    func connect(toPort port: UInt32) -> VZVirtioSocketConnection? {
      let pending = FixtureConnectionCompletion()
      queue.async {
        guard self.machine.state == .running,
          let device = self.machine.socketDevices.first as? VZVirtioSocketDevice
        else {
          pending.complete(.failure(RuntimeError.descriptorInvalid))
          return
        }
        device.connect(toPort: port) { pending.complete($0) }
      }
      let deadline = ProcessInfo.processInfo.systemUptime + 2
      return try? pending.wait(deadline: deadline, cancelled: { false })
    }

    func waitForExit() -> VMRuntime.Exit {
      exited.wait()
      lock.lock()
      defer { lock.unlock() }
      return exit ?? .failed
    }

    private func finish(_ value: VMRuntime.Exit) {
      lock.lock()
      let first = exit == nil
      if first { exit = value }
      lock.unlock()
      if first { exited.signal() }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) { finish(.stopped) }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
      finish(.failed)
    }
  }
#endif
