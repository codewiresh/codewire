import CVZRunnerIPC
import Foundation

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

/// Fixed combined developer topology, never another interpretation of schema 2/3.
public enum WorkloadNetworkProtocol {
  public static let schemaVersion = 4
  public static let descriptorCount = 10
  public static let runtimeSeconds: Double = 180
  public static let connectSeconds: Double = 120
  public static let stopSeconds: Double = 5
}

public struct WorkloadNetworkConfiguration: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let vmID: String
  public let generation: UInt64
  public let cpuCount: Int
  public let memoryMiB: UInt64
  public let daemonVsockPort: UInt32
  public let runNonce: String
  public let kernel: ImmutableArtifact
  public let initialRamdisk: ImmutableArtifact
  public let seedDisk: ImmutableArtifact
  public let stateDisk: MutableDataDisk
  public let rootDisk: MutableDataDisk
  public let setupDisk: ImmutableArtifact
  public let serviceInitialRamdisk: ImmutableArtifact
  public let serviceBinding: ImmutableArtifact

  public var production: ProductionFixtureConfiguration {
    ProductionFixtureConfiguration(
      schemaVersion: 2, vmID: vmID, generation: generation, cpuCount: cpuCount,
      memoryMiB: memoryMiB, daemonVsockPort: daemonVsockPort, kernel: kernel,
      initialRamdisk: initialRamdisk, seedDisk: seedDisk, stateDisk: stateDisk,
      rootDisk: rootDisk, setupDisk: setupDisk)
  }

  public static func decode(_ bytes: Data) throws -> Self {
    guard !bytes.isEmpty, bytes.count <= RunnerProtocol.maxFrameBytes,
      let root = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any],
      Set(root.keys) == [
        "schemaVersion", "vmID", "generation", "cpuCount", "memoryMiB", "daemonVsockPort",
        "runNonce", "kernel", "initialRamdisk", "seedDisk", "stateDisk", "rootDisk", "setupDisk",
        "serviceInitialRamdisk", "serviceBinding",
      ]
    else { throw ConfigurationError.malformed }
    for name in [
      "kernel", "initialRamdisk", "seedDisk", "setupDisk", "serviceInitialRamdisk",
      "serviceBinding",
    ] {
      guard let value = root[name] as? [String: Any], Set(value.keys) == ["size", "sha256"]
      else { throw ConfigurationError.unknownFields }
    }
    for name in ["stateDisk", "rootDisk"] {
      guard let value = root[name] as? [String: Any], Set(value.keys) == ["size", "filesystemUUID"]
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
    guard schemaVersion == 4, cpuCount == 2, memoryMiB == 2048,
      runNonce.utf8.count == 64,
      runNonce.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
      runNonce != String(repeating: "0", count: 64)
    else { throw ConfigurationError.invalidIdentity }
    try production.validate()
    for artifact in [serviceInitialRamdisk, serviceBinding] {
      guard artifact.size > 0, artifact.size <= 1024 * 1024 * 1024,
        artifact.sha256.utf8.count == 64,
        artifact.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
      else { throw ConfigurationError.invalidArtifact }
    }
    guard serviceBinding.size == 4096 else { throw ConfigurationError.invalidArtifact }
  }
}

public enum WorkloadNetworkDescriptorRole: Int, CaseIterable, Sendable {
  case kernel, initialRamdisk, seedDisk, stateDisk, rootDisk, setupDisk
  case serviceInitialRamdisk, serviceBinding, progress, daemon
}

public final class WorkloadNetworkDescriptors: @unchecked Sendable {
  private let owned: [Int32]

  init(_ descriptors: [Int32], control: Int32) throws {
    guard descriptors.count == WorkloadNetworkProtocol.descriptorCount,
      Set(descriptors).count == descriptors.count,
      descriptors.withUnsafeBufferPointer({
        cw_vz_validate_workload_network_descriptors(control, $0.baseAddress) == 1
      })
    else {
      for fd in Set(descriptors) where fd >= 0 { _ = close(fd) }
      throw IPCError.rejected(Int(CW_VZ_IPC_DESCRIPTOR_SET_INVALID.rawValue))
    }
    owned = descriptors
  }

  deinit { for fd in owned { _ = close(fd) } }

  public var productionBootDescriptors: [Int32] { Array(owned.prefix(6)) }
  public func descriptor(for role: WorkloadNetworkDescriptorRole) -> Int32 { owned[role.rawValue] }
}

public struct WorkloadNetworkRequest {
  public let configuration: WorkloadNetworkConfiguration
  public let descriptors: WorkloadNetworkDescriptors
}

extension PrivateIPC {
  public static func receiveWorkloadNetwork(controlDescriptor: Int32) throws
    -> WorkloadNetworkRequest
  {
    guard controlDescriptor >= 3 else { throw IPCError.invalidControlDescriptor }
    var bytes = [UInt8](repeating: 0, count: RunnerProtocol.maxFrameBytes)
    var descriptors = [Int32](repeating: -1, count: WorkloadNetworkProtocol.descriptorCount)
    let count = cw_vz_receive_workload_network_request(
      controlDescriptor, &bytes, bytes.count, &descriptors)
    guard count > 0 else { throw IPCError.rejected(Int(count)) }
    let owned = try WorkloadNetworkDescriptors(descriptors, control: controlDescriptor)
    return WorkloadNetworkRequest(
      configuration: try WorkloadNetworkConfiguration.decode(Data(bytes.prefix(Int(count)))),
      descriptors: owned)
  }
}
