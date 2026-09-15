import CVZRunnerIPC
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

/// Isolated functional fixture; this schema grants no product runtime mode.
public enum ConsolePairProtocol {
  public static let schemaVersion = 3
  public static let cpuCount = 1
  public static let memoryMiB: UInt64 = 512
  public static let bindingBytes: UInt64 = 4096
  public static let roleFrameBytes = 128
  public static let packetPort = "org.codewire.console-pair.packet"
  public static let statusPort = "org.codewire.console-pair.status"
  public static let controlPort = "org.codewire.console-pair.control"
  public static let bindingSerial = "CWCONSOLEPAIR1"
}

public enum ConsolePairArtifactRole: Int, CaseIterable, Sendable {
  case kernel = 0
  case initialRamdisk = 1
  case guestBinding = 2
  case serviceBinding = 3
}

public struct ConsolePairConfiguration: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let vmID: String
  public let generation: UInt64
  public let runNonce: String
  public let kernel: ImmutableArtifact
  public let initialRamdisk: ImmutableArtifact
  public let guestBinding: ImmutableArtifact
  public let serviceBinding: ImmutableArtifact

  public static func decode(_ bytes: Data) throws -> Self {
    guard !bytes.isEmpty, bytes.count <= RunnerProtocol.maxFrameBytes else {
      throw ConfigurationError.malformed
    }
    let object: Any
    do {
      object = try JSONSerialization.jsonObject(with: bytes)
    } catch {
      throw ConfigurationError.malformed
    }
    guard let root = object as? [String: Any],
      Set(root.keys) == [
        "schemaVersion", "vmID", "generation", "runNonce", "kernel", "initialRamdisk",
        "guestBinding", "serviceBinding",
      ],
      ["kernel", "initialRamdisk", "guestBinding", "serviceBinding"].allSatisfy({ key in
        guard let identity = root[key] as? [String: Any] else { return false }
        return Set(identity.keys) == ["size", "sha256"]
      })
    else { throw ConfigurationError.unknownFields }
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
    guard configuration.schemaVersion == ConsolePairProtocol.schemaVersion else {
      throw ConfigurationError.unsupportedSchema
    }
    guard let identity = UUID(uuidString: configuration.vmID),
      identity.uuidString.lowercased() == configuration.vmID,
      configuration.vmID != "00000000-0000-0000-0000-000000000000"
    else { throw ConfigurationError.invalidIdentity }
    guard configuration.generation > 0 else { throw ConfigurationError.invalidGeneration }
    guard lowercaseDigest(configuration.runNonce),
      configuration.runNonce != String(repeating: "0", count: 64)
    else { throw ConfigurationError.invalidIdentity }
    guard validArtifact(configuration.kernel, maximum: 1024 * 1024 * 1024),
      validArtifact(configuration.initialRamdisk, maximum: 1024 * 1024 * 1024),
      validArtifact(configuration.guestBinding, maximum: ConsolePairProtocol.bindingBytes),
      validArtifact(configuration.serviceBinding, maximum: ConsolePairProtocol.bindingBytes),
      configuration.guestBinding.size == ConsolePairProtocol.bindingBytes,
      configuration.serviceBinding.size == ConsolePairProtocol.bindingBytes,
      configuration.guestBinding.sha256 != configuration.serviceBinding.sha256
    else { throw ConfigurationError.invalidArtifact }
    return configuration
  }

  public func artifact(for role: ConsolePairArtifactRole) -> ImmutableArtifact {
    switch role {
    case .kernel: kernel
    case .initialRamdisk: initialRamdisk
    case .guestBinding: guestBinding
    case .serviceBinding: serviceBinding
    }
  }
}

private func lowercaseDigest(_ value: String) -> Bool {
  value.utf8.count == 64
    && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

private func validArtifact(_ value: ImmutableArtifact, maximum: UInt64) -> Bool {
  value.size > 0 && value.size <= maximum && lowercaseDigest(value.sha256)
}

public final class ConsolePairDescriptors: @unchecked Sendable {
  private let owned: [Int32]

  init(_ descriptors: [Int32]) throws {
    guard descriptors.count == ConsolePairArtifactRole.allCases.count,
      Set(descriptors).count == descriptors.count,
      descriptors.allSatisfy({ $0 >= 0 }),
      descriptors.withUnsafeBufferPointer({
        cw_vz_descriptors_are_distinct_files($0.baseAddress) == 1
      })
    else {
      for descriptor in Set(descriptors) where descriptor >= 0 { _ = close(descriptor) }
      throw IPCError.rejected(Int(CW_VZ_IPC_DESCRIPTOR_SET_INVALID.rawValue))
    }
    owned = descriptors
  }

  deinit {
    for descriptor in owned { _ = close(descriptor) }
  }

  public func descriptor(for role: ConsolePairArtifactRole) -> Int32 { owned[role.rawValue] }
}

public struct ConsolePairRequest {
  public let configuration: ConsolePairConfiguration
  public let descriptors: ConsolePairDescriptors
}

extension PrivateIPC {
  public static func receiveConsolePair(controlDescriptor: Int32) throws -> ConsolePairRequest {
    guard controlDescriptor >= 0 else { throw IPCError.invalidControlDescriptor }
    var bytes = [UInt8](repeating: 0, count: RunnerProtocol.maxFrameBytes)
    var descriptors = [Int32](repeating: -1, count: ConsolePairArtifactRole.allCases.count)
    let count = cw_vz_receive_request(controlDescriptor, &bytes, bytes.count, &descriptors)
    guard count > 0 else { throw IPCError.rejected(Int(count)) }
    let owned = try ConsolePairDescriptors(descriptors)
    let configuration = try ConsolePairConfiguration.decode(Data(bytes.prefix(Int(count))))
    return ConsolePairRequest(configuration: configuration, descriptors: owned)
  }
}
