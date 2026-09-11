import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import CryptoKit
  import Darwin
  import Virtualization

  enum RuntimeError: Error, Equatable, CustomStringConvertible {
    case unsupportedHost
    case descriptorInvalid
    case descriptorAccessInvalid
    case descriptorSizeMismatch
    case artifactDigestMismatch
    case dataDiskFormatInvalid
    case dataDiskIdentityMismatch
    case bootControlCopyFailed
    case virtualMachineConfigurationInvalid

    var description: String {
      switch self {
      case .unsupportedHost: "Virtualization.framework requires macOS 26+ on Apple Silicon"
      case .descriptorInvalid: "an admitted descriptor is not a private regular file"
      case .descriptorAccessInvalid: "an admitted descriptor has the wrong access mode"
      case .descriptorSizeMismatch: "an admitted descriptor size changed"
      case .artifactDigestMismatch: "an admitted immutable artifact digest changed"
      case .dataDiskFormatInvalid: "the admitted data disk is not ext4"
      case .dataDiskIdentityMismatch: "the admitted data disk identity changed"
      case .bootControlCopyFailed: "the path-backed boot control copy failed"
      case .virtualMachineConfigurationInvalid:
        "Virtualization.framework rejected the fixed topology"
      }
    }
  }

  @available(macOS 15.0, *)
  public struct RuntimeAdmission {
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

    public static func validateConfiguration(for request: ReceivedRequest) throws {
      _ = try buildConfiguration(for: request)
    }

    static func buildConfiguration(for request: ReceivedRequest) throws
      -> VZVirtualMachineConfiguration
    {
      try buildConfiguration(
        for: request, commandLine: RunnerProtocol.guestKernelCommandLine
      )
    }

    static func buildInodeProbeConfiguration(for request: ReceivedRequest) throws
      -> VZVirtualMachineConfiguration
    {
      try buildConfiguration(
        for: request, commandLine: RunnerProtocol.inodeProbeKernelCommandLine,
        bootArtifacts: nil
      )
    }

    static func buildInodeProbeConfiguration(
      for request: ReceivedRequest, bootArtifacts: InodeProbeBootArtifacts
    ) throws -> VZVirtualMachineConfiguration {
      try buildConfiguration(
        for: request, commandLine: RunnerProtocol.inodeProbeKernelCommandLine,
        bootArtifacts: bootArtifacts
      )
    }

    private static func buildConfiguration(
      for request: ReceivedRequest, commandLine: String,
      bootArtifacts: InodeProbeBootArtifacts? = nil
    ) throws -> VZVirtualMachineConfiguration {
      try validateHost()
      let configuration = request.configuration
      let descriptors = request.descriptors

      try validateInodeProbeBootArtifacts(for: request)
      try validateImmutable(
        descriptors.descriptor(for: .seedDisk), identity: configuration.seedDisk
      )
      try validateMutable(
        descriptors.descriptor(for: .dataDisk), identity: configuration.dataDisk
      )

      let result = VZVirtualMachineConfiguration()
      guard configuration.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
        configuration.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount
      else { throw ConfigurationError.invalidCPUCount }
      let memoryBytes = try multiplied(configuration.memoryMiB, by: 1024 * 1024)
      guard memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
      else { throw ConfigurationError.invalidMemory }

      let bootLoader = VZLinuxBootLoader(
        kernelURL: bootArtifacts?.kernel
          ?? descriptorURL(descriptors.descriptor(for: .kernel))
      )
      bootLoader.initialRamdiskURL =
        bootArtifacts?.initialRamdisk
        ?? descriptorURL(descriptors.descriptor(for: .initialRamdisk))
      bootLoader.commandLine = commandLine
      result.bootLoader = bootLoader
      result.cpuCount = configuration.cpuCount
      result.memorySize = memoryBytes
      result.platform = VZGenericPlatformConfiguration()

      let seedAttachment = try VZDiskImageStorageDeviceAttachment(
        url: descriptorURL(descriptors.descriptor(for: .seedDisk)),
        readOnly: true,
        cachingMode: .automatic,
        synchronizationMode: .full
      )
      let dataAttachment = try VZDiskImageStorageDeviceAttachment(
        url: descriptorURL(descriptors.descriptor(for: .dataDisk)),
        readOnly: false,
        cachingMode: .automatic,
        synchronizationMode: .full
      )
      let seed = VZVirtioBlockDeviceConfiguration(attachment: seedAttachment)
      seed.blockDeviceIdentifier = "CWSEED1"
      let data = VZVirtioBlockDeviceConfiguration(attachment: dataAttachment)
      data.blockDeviceIdentifier = "CWSTATE1"
      result.storageDevices = [seed, data]
      result.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
      result.socketDevices = [VZVirtioSocketDeviceConfiguration()]

      // Explicit empty arrays make prohibited device classes reviewable and
      // prevent a future default from silently granting host access.
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

      do {
        try result.validate()
      } catch {
        throw RuntimeError.virtualMachineConfigurationInvalid
      }
      return result
    }

    static func validateInodeProbeBootArtifacts(for request: ReceivedRequest) throws {
      try validateImmutable(
        request.descriptors.descriptor(for: .kernel), identity: request.configuration.kernel
      )
      try validateImmutable(
        request.descriptors.descriptor(for: .initialRamdisk),
        identity: request.configuration.initialRamdisk
      )
    }

    private static func descriptorURL(_ descriptor: Int32) -> URL {
      // This feasibility slice deliberately has no pathname fallback. Apple
      // documents URL-only APIs for Linux boot and regular disk images; an
      // exact-inode hardware kill test must prove /dev/fd before VM start is admitted.
      URL(fileURLWithPath: "/dev/fd/\(descriptor)", isDirectory: false)
    }

    private static func validateImmutable(
      _ descriptor: Int32,
      identity: ImmutableArtifact
    ) throws {
      try validateRegular(descriptor, expectedSize: identity.size, writable: false)
      guard try sha256(descriptor: descriptor, size: identity.size) == identity.sha256 else {
        throw RuntimeError.artifactDigestMismatch
      }
    }

    private static func validateMutable(
      _ descriptor: Int32,
      identity: MutableDataDisk
    ) throws {
      try validateRegular(descriptor, expectedSize: identity.size, writable: true)
      guard try readExt4FilesystemUUID(descriptor: descriptor) == identity.filesystemUUID else {
        throw RuntimeError.dataDiskIdentityMismatch
      }
    }

    private static func readExt4FilesystemUUID(descriptor: Int32) throws -> String {
      let superblockOffset = 1024
      let magicOffset = 0x38
      let uuidOffset = 0x68
      var superblock = [UInt8](repeating: 0, count: 0x78)
      var consumed = 0
      while consumed < superblock.count {
        let remaining = superblock.count - consumed
        let count = superblock.withUnsafeMutableBytes { raw in
          pread(
            descriptor,
            raw.baseAddress?.advanced(by: consumed),
            remaining,
            off_t(superblockOffset + consumed)
          )
        }
        guard count > 0 else { throw RuntimeError.dataDiskFormatInvalid }
        consumed += count
      }
      guard superblock[magicOffset..<(magicOffset + 2)].elementsEqual([0x53, 0xef]) else {
        throw RuntimeError.dataDiskFormatInvalid
      }
      let uuid = Array(superblock[uuidOffset..<(uuidOffset + 16)])
      guard uuid.contains(where: { $0 != 0 }) else {
        throw RuntimeError.dataDiskFormatInvalid
      }
      return [0..<4, 4..<6, 6..<8, 8..<10, 10..<16]
        .map { range in uuid[range].map { String(format: "%02x", $0) }.joined() }
        .joined(separator: "-")
    }

    static func inodeProbeSeed(for request: ReceivedRequest) throws -> Data {
      let descriptor = request.descriptors.descriptor(for: .seedDisk)
      return try readExact(descriptor: descriptor, size: Int(request.configuration.seedDisk.size))
    }

    static func inodeProbeFilesystemUUID(for request: ReceivedRequest) throws -> [UInt8] {
      let value = try readExt4FilesystemUUID(
        descriptor: request.descriptors.descriptor(for: .dataDisk)
      )
      let compact = value.replacingOccurrences(of: "-", with: "")
      guard compact.count == 32 else { throw RuntimeError.dataDiskFormatInvalid }
      return try stride(from: 0, to: compact.count, by: 2).map { offset in
        let start = compact.index(compact.startIndex, offsetBy: offset)
        let end = compact.index(start, offsetBy: 2)
        guard let byte = UInt8(compact[start..<end], radix: 16) else {
          throw RuntimeError.dataDiskFormatInvalid
        }
        return byte
      }
    }

    private static func readExact(descriptor: Int32, size: Int) throws -> Data {
      var bytes = [UInt8](repeating: 0, count: size)
      var consumed = 0
      while consumed < bytes.count {
        let requested = bytes.count - consumed
        let count = bytes.withUnsafeMutableBytes { raw in
          pread(
            descriptor, raw.baseAddress?.advanced(by: consumed), requested,
            off_t(consumed)
          )
        }
        guard count > 0 else { throw RuntimeError.descriptorInvalid }
        consumed += count
      }
      return Data(bytes)
    }

    private static func validateRegular(
      _ descriptor: Int32,
      expectedSize: UInt64,
      writable: Bool
    ) throws {
      var status = stat()
      guard fstat(descriptor, &status) == 0,
        (status.st_mode & S_IFMT) == S_IFREG,
        status.st_uid == geteuid(),
        status.st_nlink == 1,
        (status.st_mode & 0o077) == 0
      else { throw RuntimeError.descriptorInvalid }
      guard status.st_size >= 0, UInt64(status.st_size) == expectedSize else {
        throw RuntimeError.descriptorSizeMismatch
      }
      let flags = fcntl(descriptor, F_GETFL)
      let access = flags & O_ACCMODE
      guard flags >= 0,
        writable ? access == O_RDWR : access == O_RDONLY
      else { throw RuntimeError.descriptorAccessInvalid }
    }

    private static func sha256(descriptor: Int32, size: UInt64) throws -> String {
      var digest = SHA256()
      var offset: UInt64 = 0
      var buffer = [UInt8](repeating: 0, count: 64 * 1024)
      while offset < size {
        let requested = min(UInt64(buffer.count), size - offset)
        let count = buffer.withUnsafeMutableBytes { raw in
          pread(descriptor, raw.baseAddress, Int(requested), off_t(offset))
        }
        guard count > 0 else { throw RuntimeError.descriptorInvalid }
        digest.update(data: Data(buffer.prefix(Int(count))))
        offset += UInt64(count)
      }
      return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func multiplied(_ value: UInt64, by multiplier: UInt64) throws -> UInt64 {
      let (result, overflow) = value.multipliedReportingOverflow(by: multiplier)
      guard !overflow else { throw ConfigurationError.invalidMemory }
      return result
    }
  }

  struct InodeProbeBootArtifacts {
    let kernel: URL
    let initialRamdisk: URL
  }
#endif
