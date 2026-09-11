import Foundation

public enum RunnerProtocol {
  public static let schemaVersion = 1
  public static let descriptorCount = 4
  public static let maxFrameBytes = 16 * 1024
  public static let guestDaemonVsockPort: UInt32 = 7_777
  public static let inodeProbeVsockPort: UInt32 = 7_775
  public static let guestKernelCommandLine = "console=ttyS0 rdinit=/init panic=-1"
  public static let inodeProbeKernelCommandLine =
    "console=ttyS0 rdinit=/init panic=-1 -- vz-inode-probe"
}

public enum ConfigurationError: Error, Equatable, CustomStringConvertible {
  case malformed
  case unknownFields
  case nonCanonical
  case unsupportedSchema
  case invalidIdentity
  case invalidGeneration
  case invalidCPUCount
  case invalidMemory
  case invalidVsockPort
  case invalidArtifact
  case invalidDataDisk

  public var description: String {
    switch self {
    case .malformed: "configuration is malformed"
    case .unknownFields: "configuration contains unknown fields"
    case .nonCanonical: "configuration is not canonical JSON"
    case .unsupportedSchema: "configuration schema is unsupported"
    case .invalidIdentity: "VM identity is invalid"
    case .invalidGeneration: "VM generation is invalid"
    case .invalidCPUCount: "CPU count is invalid"
    case .invalidMemory: "memory size is invalid"
    case .invalidVsockPort: "daemon vsock port is invalid"
    case .invalidArtifact: "immutable artifact identity is invalid"
    case .invalidDataDisk: "data disk identity is invalid"
    }
  }
}

public struct ImmutableArtifact: Codable, Equatable, Sendable {
  public let size: UInt64
  public let sha256: String
}

public struct MutableDataDisk: Codable, Equatable, Sendable {
  public let size: UInt64
  public let filesystemUUID: String
}

public struct RunnerConfiguration: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let vmID: String
  public let generation: UInt64
  public let cpuCount: Int
  public let memoryMiB: UInt64
  public let daemonVsockPort: UInt32
  public let kernel: ImmutableArtifact
  public let initialRamdisk: ImmutableArtifact
  public let seedDisk: ImmutableArtifact
  public let dataDisk: MutableDataDisk

  public static func decode(_ bytes: Data) throws -> Self {
    guard !bytes.isEmpty, bytes.count <= RunnerProtocol.maxFrameBytes else {
      throw ConfigurationError.malformed
    }
    let object: Any
    do {
      object = try JSONSerialization.jsonObject(with: bytes, options: [])
    } catch {
      throw ConfigurationError.malformed
    }
    guard let root = object as? [String: Any],
      Set(root.keys) == [
        "schemaVersion", "vmID", "generation", "cpuCount", "memoryMiB",
        "daemonVsockPort", "kernel", "initialRamdisk", "seedDisk", "dataDisk",
      ],
      hasExactKeys(root["kernel"], ["size", "sha256"]),
      hasExactKeys(root["initialRamdisk"], ["size", "sha256"]),
      hasExactKeys(root["seedDisk"], ["size", "sha256"]),
      hasExactKeys(root["dataDisk"], ["size", "filesystemUUID"])
    else {
      throw ConfigurationError.unknownFields
    }
    let configuration: Self
    do {
      configuration = try JSONDecoder().decode(Self.self, from: bytes)
    } catch {
      throw ConfigurationError.malformed
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard try encoder.encode(configuration) == bytes else {
      throw ConfigurationError.nonCanonical
    }
    try configuration.validate()
    return configuration
  }

  public func validate() throws {
    guard schemaVersion == RunnerProtocol.schemaVersion else {
      throw ConfigurationError.unsupportedSchema
    }
    guard let uuid = UUID(uuidString: vmID), uuid.uuidString.lowercased() == vmID else {
      throw ConfigurationError.invalidIdentity
    }
    guard generation > 0 else { throw ConfigurationError.invalidGeneration }
    guard (1...32).contains(cpuCount) else { throw ConfigurationError.invalidCPUCount }
    guard (128...65_536).contains(memoryMiB) else {
      throw ConfigurationError.invalidMemory
    }
    guard daemonVsockPort == RunnerProtocol.guestDaemonVsockPort else {
      throw ConfigurationError.invalidVsockPort
    }
    guard validArtifact(kernel, maximum: 1024 * 1024 * 1024),
      validArtifact(initialRamdisk, maximum: 4 * 1024 * 1024 * 1024),
      seedDisk.size == 4096,
      validArtifact(seedDisk, maximum: 4096)
    else {
      throw ConfigurationError.invalidArtifact
    }
    guard dataDisk.size >= 256 * 1024 * 1024,
      dataDisk.size <= 1024 * 1024 * 1024 * 1024,
      dataDisk.size.isMultiple(of: 1024 * 1024),
      let diskUUID = UUID(uuidString: dataDisk.filesystemUUID),
      dataDisk.filesystemUUID != "00000000-0000-0000-0000-000000000000",
      diskUUID.uuidString.lowercased() == dataDisk.filesystemUUID
    else {
      throw ConfigurationError.invalidDataDisk
    }
  }
}

private func hasExactKeys(_ value: Any?, _ keys: Set<String>) -> Bool {
  guard let dictionary = value as? [String: Any] else { return false }
  return Set(dictionary.keys) == keys
}

private func validArtifact(_ artifact: ImmutableArtifact, maximum: UInt64) -> Bool {
  artifact.size > 0 && artifact.size <= maximum && artifact.sha256.count == 64
    && artifact.sha256.utf8.allSatisfy {
      ($0 >= Character("0").asciiValue! && $0 <= Character("9").asciiValue!)
        || ($0 >= Character("a").asciiValue! && $0 <= Character("f").asciiValue!)
    }
}
