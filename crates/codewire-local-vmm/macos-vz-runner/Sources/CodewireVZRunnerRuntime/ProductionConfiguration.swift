import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Virtualization

  @available(macOS 15.0, *)
  extension RuntimeAdmission {
    static func buildProductionFixtureConfiguration(for request: ProductionFixtureRequest) throws
      -> VZVirtualMachineConfiguration
    {
      try buildProductionBootConfiguration(
        configuration: request.configuration,
        descriptors: ProductionDescriptorRole.allCases.prefix(6).map {
          request.descriptors.descriptor(for: $0)
        })
    }

    /// Only the six validated production boot roles are shared. The combined
    /// fixture has no host network channel and cannot construct a schema-2 request.
    static func buildProductionBootConfiguration(
      configuration config: ProductionFixtureConfiguration, descriptors: [Int32]
    ) throws -> VZVirtualMachineConfiguration {
      guard descriptors.count == 6 else { throw RuntimeError.descriptorInvalid }
      func descriptor(_ role: ProductionDescriptorRole) -> Int32 { descriptors[role.rawValue] }
      try validateHost()
      try config.validate()
      for (role, identity) in [
        (ProductionDescriptorRole.kernel, config.kernel), (.initialRamdisk, config.initialRamdisk),
        (.seedDisk, config.seedDisk), (.setupDisk, config.setupDisk),
      ] {
        try validateImmutable(descriptor(role), identity: identity)
      }
      try validateMutable(descriptor(.stateDisk), identity: config.stateDisk)
      try validateMutable(descriptor(.rootDisk), identity: config.rootDisk)

      let result = VZVirtualMachineConfiguration()
      guard config.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
        config.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount
      else { throw ConfigurationError.invalidCPUCount }
      let memory = try multiplied(config.memoryMiB, by: 1024 * 1024)
      guard memory >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        memory <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
      else { throw ConfigurationError.invalidMemory }
      let loader = VZLinuxBootLoader(kernelURL: descriptorURL(descriptor(.kernel)))
      loader.initialRamdiskURL = descriptorURL(descriptor(.initialRamdisk))
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
          url: descriptorURL(descriptor(role)), readOnly: readOnly,
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
