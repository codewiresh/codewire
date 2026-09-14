import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  /// Two concrete fixture roles, not a public VMM backend abstraction.
  @available(macOS 15.0, *)
  final class WorkloadNetworkMachine: NSObject, VZVirtualMachineDelegate, @unchecked Sendable {
    let role: UInt8
    let queue: DispatchQueue
    let machine: VZVirtualMachine
    private let lock = NSLock()
    private var life = ConsolePairLifecycle()
    private var stopRequested = false

    init(role: UInt8, configuration: VZVirtualMachineConfiguration) {
      self.role = role
      queue = DispatchQueue(label: "dev.codewire.workload-network.\(role)")
      machine = VZVirtualMachine(configuration: configuration, queue: queue)
      super.init()
      queue.sync { machine.delegate = self }
    }

    func snapshot() -> ConsolePairLifecycle {
      lock.lock()
      defer { lock.unlock() }
      return life
    }

    func drain() -> (state: ConsolePairLifecycle, events: [UInt8]) {
      lock.lock()
      defer { lock.unlock() }
      return life.drain()
    }

    private func record(_ event: ConsolePairLifecycle.Event) {
      lock.lock()
      defer { lock.unlock() }
      life.apply(event)
    }

    func start() {
      queue.async { [self] in
        guard !stopRequested else {
          record(.startFailed)
          return
        }
        machine.start { [self] result in
          switch result {
          case .success:
            record(.started)
            if stopRequested { stopOnQueue() }
          case .failure: record(.startFailed)
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
      machine.stop { [self] error in record(error == nil ? .stopSucceeded : .stopFailed) }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
      guard virtualMachine === machine else { return }
      record(.guestStopped)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: any Error) {
      guard virtualMachine === machine else { return }
      record(.guestFailed)
    }
  }

  /// Service boot copies use the already-proved immutable path-backed route;
  /// production boot retains its independently proved /dev/fd disk/boot inputs.
  @available(macOS 15.0, *)
  final class WorkloadNetworkServiceBoot {
    let files: [URL]
    let status = Pipe()
    let control = Pipe()

    init(request: WorkloadNetworkRequest) throws {
      let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        "codewire-workload-network-\(UUID().uuidString)", isDirectory: true)
      guard mkdir(directory.path, 0o700) == 0 else { throw IPCError.rejected(-4) }
      var copies: [URL] = []
      for (role, identity) in [
        (WorkloadNetworkDescriptorRole.kernel, request.configuration.kernel),
        (.serviceInitialRamdisk, request.configuration.serviceInitialRamdisk),
        (.serviceBinding, request.configuration.serviceBinding),
      ] {
        let descriptor = request.descriptors.descriptor(for: role)
        try RuntimeAdmission.validateImmutable(descriptor, identity: identity)
        copies.append(
          try PathBackedBootControl.copyVerified(
            sourceDescriptor: descriptor, identity: identity,
            destination: directory.appendingPathComponent("artifact-\(role.rawValue)")))
      }
      files = copies
      for handle in [status.fileHandleForReading, control.fileHandleForWriting] {
        let flags = fcntl(handle.fileDescriptor, F_GETFL)
        guard flags >= 0,
          fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0
        else { throw IPCError.rejected(-4) }
      }
    }

    func configuration() throws -> VZVirtualMachineConfiguration {
      let configuration = VZVirtualMachineConfiguration()
      let loader = VZLinuxBootLoader(kernelURL: files[0])
      loader.initialRamdiskURL = files[1]
      loader.commandLine = "rdinit=/init panic=-1 -- service"
      configuration.bootLoader = loader
      configuration.platform = VZGenericPlatformConfiguration()
      configuration.cpuCount = ConsolePairProtocol.cpuCount
      configuration.memorySize = ConsolePairProtocol.memoryMiB * 1024 * 1024
      let binding = VZVirtioBlockDeviceConfiguration(
        attachment: try VZDiskImageStorageDeviceAttachment(
          url: files[2], readOnly: true, cachingMode: .automatic, synchronizationMode: .full))
      binding.blockDeviceIdentifier = ConsolePairProtocol.bindingSerial
      configuration.storageDevices = [binding]
      configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      let device = VZVirtioConsoleDeviceConfiguration()
      for (index, name, attachment) in [
        (0, ConsolePairProtocol.packetPort, nil as VZSerialPortAttachment?),
        (
          1, ConsolePairProtocol.statusPort,
          VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil, fileHandleForWriting: status.fileHandleForWriting)
        ),
        (
          2, ConsolePairProtocol.controlPort,
          VZFileHandleSerialPortAttachment(
            fileHandleForReading: control.fileHandleForReading, fileHandleForWriting: nil)
        ),
      ] {
        let port = VZVirtioConsolePortConfiguration()
        port.name = name
        port.isConsole = false
        port.attachment = attachment
        device.ports[index] = port
      }
      configuration.consoleDevices = [device]
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
      return configuration
    }
  }
#endif
