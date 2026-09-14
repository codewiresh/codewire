import CVZRunnerIPC
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

/// An unreachable developer fixture, not a second product launch protocol.
public enum ProductionFixtureProtocol {
  public static let schemaVersion = 2
  public static let descriptorCount = 9
  public static let setupAlignment: UInt64 = 4096
  public static let maximumSetupBytes: UInt64 = 65 * 1024 * 1024 * 1024
  public static let runtimeSeconds: Double = 180
  public static let connectSeconds: Double = 120
  public static let stopSeconds: Double = 5
}

public struct ProductionFixtureConfiguration: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let vmID: String
  public let generation: UInt64
  public let cpuCount: Int
  public let memoryMiB: UInt64
  public let daemonVsockPort: UInt32
  public let kernel: ImmutableArtifact
  public let initialRamdisk: ImmutableArtifact
  public let seedDisk: ImmutableArtifact
  public let stateDisk: MutableDataDisk
  public let rootDisk: MutableDataDisk
  public let setupDisk: ImmutableArtifact

  public static func decode(_ bytes: Data) throws -> Self {
    guard !bytes.isEmpty, bytes.count <= RunnerProtocol.maxFrameBytes else {
      throw ConfigurationError.malformed
    }
    guard let root = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any],
      Set(root.keys) == [
        "schemaVersion", "vmID", "generation", "cpuCount", "memoryMiB", "daemonVsockPort",
        "kernel", "initialRamdisk", "seedDisk", "stateDisk", "rootDisk", "setupDisk",
      ]
    else { throw ConfigurationError.unknownFields }
    for name in ["kernel", "initialRamdisk", "seedDisk", "setupDisk"] {
      guard let artifact = root[name] as? [String: Any], Set(artifact.keys) == ["size", "sha256"]
      else { throw ConfigurationError.unknownFields }
    }
    for name in ["stateDisk", "rootDisk"] {
      guard let disk = root[name] as? [String: Any],
        Set(disk.keys) == ["size", "filesystemUUID"]
      else { throw ConfigurationError.unknownFields }
    }
    let value: Self
    do { value = try JSONDecoder().decode(Self.self, from: bytes) } catch {
      throw ConfigurationError.malformed
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard try encoder.encode(value) == bytes else { throw ConfigurationError.nonCanonical }
    try value.validate()
    return value
  }

  public func validate() throws {
    guard schemaVersion == ProductionFixtureProtocol.schemaVersion else {
      throw ConfigurationError.unsupportedSchema
    }
    // Reuse schema-1 value validation without admitting its descriptor topology.
    try RunnerConfiguration(
      schemaVersion: RunnerProtocol.schemaVersion, vmID: vmID, generation: generation,
      cpuCount: cpuCount, memoryMiB: memoryMiB, daemonVsockPort: daemonVsockPort,
      kernel: kernel, initialRamdisk: initialRamdisk, seedDisk: seedDisk, dataDisk: stateDisk
    ).validate()
    try RunnerConfiguration(
      schemaVersion: RunnerProtocol.schemaVersion, vmID: vmID, generation: generation,
      cpuCount: cpuCount, memoryMiB: memoryMiB, daemonVsockPort: daemonVsockPort,
      kernel: kernel, initialRamdisk: initialRamdisk, seedDisk: seedDisk, dataDisk: rootDisk
    ).validate()
    guard rootDisk.filesystemUUID != stateDisk.filesystemUUID else {
      throw ConfigurationError.invalidDataDisk
    }
    guard setupDisk.size >= 64 * 1024,
      setupDisk.size <= ProductionFixtureProtocol.maximumSetupBytes,
      setupDisk.size.isMultiple(of: ProductionFixtureProtocol.setupAlignment),
      setupDisk.sha256.count == 64,
      setupDisk.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else { throw ConfigurationError.invalidArtifact }
  }
}

public enum ProductionDescriptorRole: Int, CaseIterable, Sendable {
  case kernel, initialRamdisk, seedDisk, stateDisk, rootDisk, setupDisk
  case network, progress, daemon

  public var port: UInt32? {
    switch self {
    case .network: 7775
    case .progress: 7776
    case .daemon: 7777
    default: nil
    }
  }

  public var connectedResult: String? {
    switch self {
    case .network: "network-connected"
    case .progress: "progress-connected"
    case .daemon: "daemon-connected"
    default: nil
    }
  }
}

public struct ProductionFixtureRequest {
  public let configuration: ProductionFixtureConfiguration
  public let descriptors: ProductionDescriptorSet
}

public final class ProductionDescriptorSet: @unchecked Sendable {
  private let owned: [Int32]

  init(_ descriptors: [Int32], control: Int32) throws {
    guard descriptors.count == ProductionFixtureProtocol.descriptorCount,
      Set(descriptors).count == descriptors.count,
      descriptors.withUnsafeBufferPointer({
        cw_vz_validate_production_descriptors(control, $0.baseAddress) == 1
      })
    else {
      for fd in Set(descriptors) where fd >= 0 { _ = close(fd) }
      throw IPCError.rejected(Int(CW_VZ_IPC_DESCRIPTOR_SET_INVALID.rawValue))
    }
    owned = descriptors
  }

  deinit { for fd in owned { _ = close(fd) } }

  public func descriptor(for role: ProductionDescriptorRole) -> Int32 { owned[role.rawValue] }
}

extension PrivateIPC {
  public static func receiveProductionFixture(controlDescriptor: Int32) throws
    -> ProductionFixtureRequest
  {
    guard controlDescriptor >= 3 else { throw IPCError.invalidControlDescriptor }
    var bytes = [UInt8](repeating: 0, count: RunnerProtocol.maxFrameBytes)
    var descriptors = [Int32](repeating: -1, count: ProductionFixtureProtocol.descriptorCount)
    let count = cw_vz_receive_production_request(
      controlDescriptor, &bytes, bytes.count, &descriptors
    )
    guard count > 0 else { throw IPCError.rejected(Int(count)) }
    let owned = try ProductionDescriptorSet(descriptors, control: controlDescriptor)
    let configuration = try ProductionFixtureConfiguration.decode(Data(bytes.prefix(Int(count))))
    return ProductionFixtureRequest(configuration: configuration, descriptors: owned)
  }
}
