import CVZRunnerIPC
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

public enum DescriptorRole: Int, CaseIterable, Sendable {
  case kernel = 0
  case initialRamdisk = 1
  case seedDisk = 2
  case dataDisk = 3
}

public enum IPCError: Error, Equatable, CustomStringConvertible {
  case invalidControlDescriptor
  case rejected(Int)

  public var description: String {
    switch self {
    case .invalidControlDescriptor: "control descriptor is invalid"
    case .rejected(let code): "private IPC request was rejected (\(code))"
    }
  }
}

public struct ReceivedRequest {
  public let configuration: RunnerConfiguration
  public let descriptors: DescriptorSet
}

public final class DescriptorSet: @unchecked Sendable {
  private let owned: [Int32]

  init(_ descriptors: [Int32]) throws {
    guard descriptors.count == RunnerProtocol.descriptorCount,
      Set(descriptors).count == descriptors.count,
      descriptors.allSatisfy({ $0 >= 0 })
    else {
      closeUnique(descriptors)
      throw IPCError.rejected(Int(CW_VZ_IPC_DESCRIPTOR_SET_INVALID.rawValue))
    }
    let distinctFiles = descriptors.withUnsafeBufferPointer {
      cw_vz_descriptors_are_distinct_files($0.baseAddress) == 1
    }
    guard distinctFiles else {
      closeUnique(descriptors)
      throw IPCError.rejected(Int(CW_VZ_IPC_DESCRIPTOR_SET_INVALID.rawValue))
    }
    owned = descriptors
  }

  deinit {
    for descriptor in owned where descriptor >= 0 { _ = close(descriptor) }
  }

  public func descriptor(for role: DescriptorRole) -> Int32 {
    owned[role.rawValue]
  }
}

private func closeUnique(_ descriptors: [Int32]) {
  for descriptor in Set(descriptors) where descriptor >= 0 {
    _ = close(descriptor)
  }
}

public enum PrivateIPC {
  public static func receive(controlDescriptor: Int32) throws -> ReceivedRequest {
    guard controlDescriptor >= 0 else { throw IPCError.invalidControlDescriptor }
    var bytes = [UInt8](repeating: 0, count: RunnerProtocol.maxFrameBytes)
    var descriptors = [Int32](repeating: -1, count: RunnerProtocol.descriptorCount)
    let count = cw_vz_receive_request(
      controlDescriptor,
      &bytes,
      bytes.count,
      &descriptors
    )
    guard count > 0 else { throw IPCError.rejected(Int(count)) }
    let descriptorSet = try DescriptorSet(descriptors)
    let configuration = try RunnerConfiguration.decode(Data(bytes.prefix(Int(count))))
    return ReceivedRequest(configuration: configuration, descriptors: descriptorSet)
  }

  public static func send(controlDescriptor: Int32, response: Data) throws {
    guard controlDescriptor >= 0 else { throw IPCError.invalidControlDescriptor }
    let result = response.withUnsafeBytes { raw -> Int32 in
      guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
        return CW_VZ_IPC_INVALID_ARGUMENT.rawValue
      }
      return cw_vz_send_response(controlDescriptor, base, response.count)
    }
    guard result == 0 else { throw IPCError.rejected(Int(result)) }
  }

  public static func receiveStart(controlDescriptor: Int32) throws {
    guard controlDescriptor >= 0 else { throw IPCError.invalidControlDescriptor }
    let result = cw_vz_receive_start(controlDescriptor)
    guard result == 0 else { throw IPCError.rejected(Int(result)) }
  }
}
