import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Virtualization

  @available(macOS 15.0, *)
  extension RuntimeAdmission {
    static func buildProductionFixtureConfiguration(for request: ProductionFixtureRequest) throws
      -> VZVirtualMachineConfiguration
    {
      try validateHost()
      try request.configuration.validate()
      let config = request.configuration
      let files = request.descriptors
      for (role, identity) in [
        (ProductionDescriptorRole.kernel, config.kernel), (.initialRamdisk, config.initialRamdisk),
        (.seedDisk, config.seedDisk), (.setupDisk, config.setupDisk),
      ] {
        try validateImmutable(files.descriptor(for: role), identity: identity)
      }
      try validateMutable(files.descriptor(for: .stateDisk), identity: config.stateDisk)
      try validateMutable(files.descriptor(for: .rootDisk), identity: config.rootDisk)

      let result = VZVirtualMachineConfiguration()
      guard config.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
        config.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount
      else { throw ConfigurationError.invalidCPUCount }
      let memory = try multiplied(config.memoryMiB, by: 1024 * 1024)
      guard memory >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        memory <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
      else { throw ConfigurationError.invalidMemory }
      let loader = VZLinuxBootLoader(kernelURL: descriptorURL(files.descriptor(for: .kernel)))
      loader.initialRamdiskURL = descriptorURL(files.descriptor(for: .initialRamdisk))
      // The real guest PID 1, not the synthetic inode-probe branch.
      loader.commandLine = RunnerProtocol.guestKernelCommandLine
      result.bootLoader = loader
      result.cpuCount = config.cpuCount
      result.memorySize = memory
      result.platform = VZGenericPlatformConfiguration()
      result.storageDevices = try [
        (ProductionDescriptorRole.stateDisk, "CWSTATE1", false),
        (.rootDisk, "CWROOT1", false), (.seedDisk, "CWSEED1", true),
        (.setupDisk, "CWSETUP1", true),
      ].map { role, serial, readOnly in
        let attachment = try VZDiskImageStorageDeviceAttachment(
          url: descriptorURL(files.descriptor(for: role)), readOnly: readOnly,
          cachingMode: .automatic, synchronizationMode: .full
        )
        let disk = VZVirtioBlockDeviceConfiguration(attachment: attachment)
        disk.blockDeviceIdentifier = serial
        return disk
      }
      result.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      result.socketDevices = [VZVirtioSocketDeviceConfiguration()]
      result.networkDevices = []
      result.directorySharingDevices = []
      result.graphicsDevices = []
      result.audioDevices = []
      result.keyboards = []
      result.pointingDevices = []
      result.usbControllers = []
      result.serialPorts = []
      result.consoleDevices = []
      result.memoryBalloonDevices = []
      do { try result.validate() } catch { throw RuntimeError.virtualMachineConfigurationInvalid }
      return result
    }
  }
#endif
