import Foundation

/// Product VM request for `codewire-vz-runner vm --config FILE`.
///
/// It carries what the Linux runner passes on the Cloud Hypervisor command
/// line: boot artifacts and disks by path, one hybrid-vsock socket, CPU and
/// memory. The Rust runner admits every path under its private state root
/// before it writes this file.
public struct VMConfiguration: Codable, Equatable, Sendable {
  public static let schemaVersion = 1
  public static let maxConfigurationBytes = 64 * 1024
  public static let maxDisks = 8
  /// virtio-blk serial numbers hold at most 20 bytes.
  public static let maxSerialBytes = 20
  /// `sockaddr_un.sun_path` is 104 bytes on Darwin, including the NUL.
  public static let maxSocketPathBytes = 103
  public static let maxCommandLineBytes = 2048

  public struct Disk: Codable, Equatable, Sendable {
    public var path: String
    public var serial: String
    public var readOnly: Bool

    public init(path: String, serial: String, readOnly: Bool) {
      self.path = path
      self.serial = serial
      self.readOnly = readOnly
    }
  }

  public var schemaVersion: Int
  public var kernel: String
  public var initialRamdisk: String
  public var commandLine: String
  public var cpuCount: Int
  public var memoryMiB: UInt64
  public var disks: [Disk]
  public var vsockSocket: String

  public init(
    kernel: String, initialRamdisk: String, commandLine: String, cpuCount: Int,
    memoryMiB: UInt64, disks: [Disk], vsockSocket: String
  ) {
    schemaVersion = Self.schemaVersion
    self.kernel = kernel
    self.initialRamdisk = initialRamdisk
    self.commandLine = commandLine
    self.cpuCount = cpuCount
    self.memoryMiB = memoryMiB
    self.disks = disks
    self.vsockSocket = vsockSocket
  }

  /// Decodes one configuration and refuses unknown or missing fields, so a
  /// newer runner cannot silently ask for something this helper ignores.
  public static func decode(_ data: Data) throws -> VMConfiguration {
    guard data.count <= maxConfigurationBytes,
      let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw ConfigurationError.malformed }
    guard Set(root.keys) == Set(CodingKeys.allNames) else { throw ConfigurationError.unknownFields }
    guard let disks = root["disks"] as? [[String: Any]],
      disks.allSatisfy({ Set($0.keys) == ["path", "serial", "readOnly"] })
    else { throw ConfigurationError.unknownFields }
    guard let configuration = try? JSONDecoder().decode(VMConfiguration.self, from: data) else {
      throw ConfigurationError.malformed
    }
    try configuration.validate()
    return configuration
  }

  public func validate() throws {
    guard schemaVersion == Self.schemaVersion else { throw ConfigurationError.unsupportedSchema }
    guard Self.isAbsolute(kernel), Self.isAbsolute(initialRamdisk) else {
      throw ConfigurationError.invalidArtifact
    }
    guard !commandLine.isEmpty, commandLine.utf8.count <= Self.maxCommandLineBytes,
      commandLine.utf8.allSatisfy({ (0x20...0x7e).contains($0) })
    else { throw ConfigurationError.invalidArtifact }
    guard cpuCount >= 1, cpuCount <= 64 else { throw ConfigurationError.invalidCPUCount }
    guard memoryMiB >= 128, memoryMiB <= 1024 * 1024 else { throw ConfigurationError.invalidMemory }
    guard !disks.isEmpty, disks.count <= Self.maxDisks,
      Set(disks.map(\.serial)).count == disks.count,
      Set(disks.map(\.path)).count == disks.count,
      disks.allSatisfy({ disk in
        Self.isAbsolute(disk.path) && !disk.serial.isEmpty
          && disk.serial.utf8.count <= Self.maxSerialBytes
          && disk.serial.utf8.allSatisfy({ (0x21...0x7e).contains($0) })
      })
    else { throw ConfigurationError.invalidDataDisk }
    guard Self.isAbsolute(vsockSocket), vsockSocket.utf8.count <= Self.maxSocketPathBytes else {
      throw ConfigurationError.invalidVsockPort
    }
  }

  private static func isAbsolute(_ value: String) -> Bool {
    value.hasPrefix("/") && !value.utf8.contains(0)
      && !value.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
  }

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion, kernel, initialRamdisk, commandLine, cpuCount, memoryMiB, disks,
      vsockSocket

    static var allNames: [String] { allCases.map(\.rawValue) }
  }
}
