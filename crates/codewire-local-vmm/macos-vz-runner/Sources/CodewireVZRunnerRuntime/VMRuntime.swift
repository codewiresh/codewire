import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Darwin
  import Virtualization

  enum RuntimeError: Error, Equatable {
    case unsupportedHost
    case listenerFailed
    case virtualMachineConfigurationInvalid
    case sharedDirectoryChanged
    case sandboxNotApplied
    case controlInvalid
    case machineIdentifierInvalid
  }

  /// The product VM process: the macOS counterpart of the Cloud Hypervisor
  /// process the Linux runner owns. It boots one guest, serves the guest's
  /// vsock ports on one hybrid-vsock Unix socket, serves each admitted host
  /// directory through virtio-fs (Linux's virtiofsd), stops the VM on SIGTERM
  /// or SIGINT, and exits once the VM has stopped.
  public enum VMRuntime {
    public typealias Exit = VMExit

    public static func run(configuration: VMConfiguration) throws -> Exit {
      try validateHost()
      let vmConfiguration = try buildConfiguration(configuration)
      let listener = cw_vz_listen_unix(configuration.vsockSocket)
      guard listener >= 0 else { throw RuntimeError.listenerFailed }
      // A socket descriptor's fstat does not name the filesystem node, so
      // record the path's identity right after this process bound it.
      var identity = stat()
      guard lstat(configuration.vsockSocket, &identity) == 0 else {
        throw RuntimeError.listenerFailed
      }
      defer { removeSocket(configuration.vsockSocket, bound: identity) }

      // Schema 3's control socket must be exactly the unnamed AF_UNIX stream
      // the runner passed (cw-security, condition 2, #4654), checked before
      // anything starts.
      let checkpointing = configuration.checkpointing
      if let checkpointing, cw_vz_check_control(checkpointing.controlDescriptor) != 0 {
        throw RuntimeError.controlInvalid
      }

      // Since macOS 27, Virtualization.framework looks up the user's cache
      // directory as a VM starts. Confined, it can reach neither
      // opendirectoryd nor dirhelper for it, and the start fails with "Failed
      // to retrieve cache directory" (#4478). Resolved here first, the
      // framework's own lookup needs only the metadata of `/var`.
      resolveUserCacheDirectory()

      // From here on the helper handles bytes a guest can influence, so it
      // keeps only this VM's own files. A profile that cannot be applied stops
      // the helper before the VM starts (#1905).
      guard cw_vz_apply_sandbox(configuration.sandboxProfile()) == 0 else {
        throw RuntimeError.sandboxNotApplied
      }

      // Virtualization.framework shares a directory by path, so require the
      // admitted directory again once the VM has started; a replacement in
      // between stops the VM.
      let shares = configuration.shares
      let machine = VMMachine(
        configuration: vmConfiguration,
        startedCheck: { (try? verifySharedDirectories(shares)) != nil })
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
      if let checkpointing {
        let identifier =
          (vmConfiguration.platform as? VZGenericPlatformConfiguration)?.machineIdentifier
          .dataRepresentation.base64EncodedString() ?? ""
        let control = VMControl(
          descriptor: checkpointing.controlDescriptor, saveState: checkpointing.saveState,
          machineIdentifier: identifier, machine: machine)
        machine.retain(control)
        machine.queue.sync { machine.onStarted = { control.started() } }
        control.startReading()
      }
      if let restoreState = checkpointing?.restoreState {
        machine.restore(from: restoreState)
      } else {
        machine.start()
      }
      let acceptor = Thread { acceptConnections(listener: listener, machine: machine) }
      acceptor.start()
      // The acceptor and any live bridges end with this process.
      return machine.waitForExit()
    }

    static func validateHost() throws {
      #if arch(arm64)
        guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 26,
          VZVirtualMachine.isSupported
        else {
          throw RuntimeError.unsupportedHost
        }
      #else
        throw RuntimeError.unsupportedHost
      #endif
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
      let (memory, overflow) = request.memoryMiB.multipliedReportingOverflow(by: 1024 * 1024)
      guard !overflow, memory >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        memory <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
      else { throw ConfigurationError.invalidMemory }
      result.cpuCount = request.cpuCount
      result.memorySize = memory
      // Schema 3 keeps one machine identifier per VM; a restore needs the
      // one its state was saved with (#4654). Without one, the framework
      // makes a new identifier, which the helper reports in `started`.
      let platform = VZGenericPlatformConfiguration()
      if let machineIdentifier = request.machineIdentifier {
        guard let data = Data(base64Encoded: machineIdentifier),
          let identifier = VZGenericMachineIdentifier(dataRepresentation: data)
        else { throw RuntimeError.machineIdentifierInvalid }
        platform.machineIdentifier = identifier
      }
      result.platform = platform
      result.storageDevices = try request.disks.map { disk in
        let attachment = try VZDiskImageStorageDeviceAttachment(
          url: URL(fileURLWithPath: disk.path), readOnly: disk.readOnly,
          cachingMode: .automatic, synchronizationMode: .full)
        let device = VZVirtioBlockDeviceConfiguration(attachment: attachment)
        device.blockDeviceIdentifier = disk.serial
        return device
      }
      try verifySharedDirectories(request.shares)
      result.directorySharingDevices = try request.shares.map { share in
        do { try VZVirtioFileSystemDeviceConfiguration.validateTag(share.tag) } catch {
          throw ConfigurationError.invalidShare
        }
        let device = VZVirtioFileSystemDeviceConfiguration(tag: share.tag)
        device.share = VZSingleDirectoryShare(
          directory: VZSharedDirectory(
            url: URL(fileURLWithPath: share.path, isDirectory: true), readOnly: share.readOnly))
        return device
      }
      result.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      result.socketDevices = [VZVirtioSocketDeviceConfiguration()]
      do { try result.validate() } catch { throw RuntimeError.virtualMachineConfigurationInvalid }
      return result
    }

    /// The answer stays with this process. A failure here is not fatal: a
    /// start that then fails reports the framework's error code.
    private static func resolveUserCacheDirectory() {
      var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
      _ = confstr(_CS_DARWIN_USER_CACHE_DIR, &buffer, buffer.count)
    }

    /// Each share must still be the admitted directory: same device and inode,
    /// owned by this user, reached without a symlink and named by its path.
    static func verifySharedDirectories(_ shares: [VMConfiguration.Share]) throws {
      for share in shares
      where cw_vz_verify_shared_directory(share.path, share.device, share.inode) != 0 {
        throw RuntimeError.sharedDirectoryChanged
      }
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

  /// One guest connection attempt. A connection that completes after its
  /// waiter gave up is closed, never leaked.
  final class ConnectionCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private let signal = DispatchSemaphore(value: 0)
    private var connection: VZVirtioSocketConnection?
    private var finished = false

    func complete(_ result: Result<VZVirtioSocketConnection, any Error>) {
      lock.lock()
      if finished {
        lock.unlock()
        if case .success(let late) = result { late.close() }
        return
      }
      finished = true
      if case .success(let connected) = result { connection = connected }
      lock.unlock()
      signal.signal()
    }

    func wait(seconds: TimeInterval) -> VZVirtioSocketConnection? {
      _ = signal.wait(timeout: .now() + seconds)
      lock.lock()
      defer { lock.unlock() }
      finished = true
      return connection
    }
  }

  final class VMMachine: NSObject, VZVirtualMachineDelegate, @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.codewire.vz-vm")
    private let machine: VZVirtualMachine
    private let exited = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var exit: VMRuntime.Exit?
    private var retained: [AnyObject] = []
    private let startedCheck: @Sendable () -> Bool

    init(
      configuration: VZVirtualMachineConfiguration, startedCheck: @escaping @Sendable () -> Bool
    ) {
      machine = VZVirtualMachine(configuration: configuration, queue: queue)
      self.startedCheck = startedCheck
      super.init()
      queue.sync { machine.delegate = self }
    }

    func retain(_ object: AnyObject) { retained.append(object) }

    /// Read and written only on `queue`: told when the VM runs.
    var onStarted: (() -> Void)?
    /// Read and written only on `queue`.
    private var stopRequested = false
    /// Read and written only on `queue`: the started VM failed its check and
    /// is stopping, so its stop reports failure.
    private var startCheckFailed = false

    func start() {
      queue.async {
        self.machine.start { result in
          if case .failure(let error) = result {
            self.finish(.startRefused(virtualizationCode: (error as? VZError)?.code.rawValue ?? 0))
          } else if !self.startedCheck() {
            self.startCheckFailed = true
            self.stop()
          } else if self.stopRequested {
            self.stop()
          } else {
            self.onStarted?()
          }
        }
      }
    }

    /// Restore `path`, a state saved from this VM's exact configuration and
    /// machine identifier, instead of starting; then resume it.
    func restore(from path: String) {
      queue.async {
        self.machine.restoreMachineStateFrom(url: URL(fileURLWithPath: path)) { error in
          if let error {
            self.finish(.startRefused(virtualizationCode: (error as? VZError)?.code.rawValue ?? 0))
            return
          }
          self.machine.resume { result in
            if case .failure(let error) = result {
              self.finish(
                .startRefused(virtualizationCode: (error as? VZError)?.code.rawValue ?? 0))
            } else if !self.startedCheck() {
              self.startCheckFailed = true
              self.stop()
            } else if self.stopRequested {
              self.stop()
            } else {
              self.onStarted?()
            }
          }
        }
      }
    }

    /// On `queue`: pause the vCPUs and devices.
    func pause(_ done: @escaping ((any Error)?) -> Void) {
      machine.pause { result in
        if case .failure(let error) = result { done(error) } else { done(nil) }
      }
    }

    /// On `queue`: write the paused VM's state to the new file `url`.
    func save(to url: URL, _ done: @escaping ((any Error)?) -> Void) {
      machine.saveMachineStateTo(url: url) { done($0) }
    }

    /// On `queue`: resume a paused VM.
    func resume(_ done: @escaping ((any Error)?) -> Void) {
      machine.resume { result in
        if case .failure(let error) = result { done(error) } else { done(nil) }
      }
    }

    /// A forced stop of this helper's own VM, called on `queue`. The Rust
    /// runner first asks the guest to power off through its daemon, as it does
    /// on Linux. A stop requested while the VM is starting applies once it has.
    func stop() {
      stopRequested = true
      let stopped: VMRuntime.Exit = startCheckFailed ? .failed : .stopped
      if machine.state == .stopped {
        finish(stopped)
      } else if machine.canStop {
        machine.stop { error in self.finish(error == nil ? stopped : .failed) }
      }
    }

    func connect(toPort port: UInt32) -> VZVirtioSocketConnection? {
      let pending = ConnectionCompletion()
      queue.async {
        guard self.machine.state == .running,
          let device = self.machine.socketDevices.first as? VZVirtioSocketDevice
        else {
          pending.complete(.failure(RuntimeError.listenerFailed))
          return
        }
        device.connect(toPort: port) { pending.complete($0) }
      }
      return pending.wait(seconds: 2)
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
