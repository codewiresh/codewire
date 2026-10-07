import Foundation

/// Product VM request for `codewire-vz-runner vm --config FILE`.
///
/// It carries what the Linux runner passes on the Cloud Hypervisor command
/// line: boot artifacts and disks by path, one hybrid-vsock socket, CPU and
/// memory, and the admitted host directories it serves through virtiofsd.
/// The Rust runner admits every disk under its private state root and every
/// shared directory before it writes this file. Schema 2 added `shares`.
public struct VMConfiguration: Codable, Equatable, Sendable {
  public static let schemaVersion = 2
  public static let maxConfigurationBytes = 64 * 1024
  public static let maxDisks = 8
  /// virtio-blk serial numbers hold at most 20 bytes.
  public static let maxSerialBytes = 20
  /// `sockaddr_un.sun_path` is 104 bytes on Darwin, including the NUL.
  public static let maxSocketPathBytes = 103
  public static let maxCommandLineBytes = 2048
  /// The guest mounts at most this many direct shares.
  public static let maxShares = 16
  /// Share paths are absolute Darwin paths (`MAXPATHLEN`, including the NUL).
  public static let maxSharePathBytes = 1023
  /// The guest mounts share `index` by the virtio-fs tag `cw-direct-NN`.
  public static let shareTagPrefix = "cw-direct-"

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

  /// One admitted host directory: the guest mounts it by `tag`. The helper
  /// opens `path` without following any symlink and requires the exact
  /// directory `device`/`inode` (its raw `st_dev` and `st_ino`).
  public struct Share: Codable, Equatable, Sendable {
    public var tag: String
    public var path: String
    public var readOnly: Bool
    public var device: UInt32
    public var inode: UInt64

    public init(tag: String, path: String, readOnly: Bool, device: UInt32, inode: UInt64) {
      self.tag = tag
      self.path = path
      self.readOnly = readOnly
      self.device = device
      self.inode = inode
    }
  }

  public var schemaVersion: Int
  public var kernel: String
  public var initialRamdisk: String
  public var commandLine: String
  public var cpuCount: Int
  public var memoryMiB: UInt64
  public var disks: [Disk]
  public var shares: [Share]
  public var vsockSocket: String

  public init(
    kernel: String, initialRamdisk: String, commandLine: String, cpuCount: Int,
    memoryMiB: UInt64, disks: [Disk], shares: [Share], vsockSocket: String
  ) {
    schemaVersion = Self.schemaVersion
    self.kernel = kernel
    self.initialRamdisk = initialRamdisk
    self.commandLine = commandLine
    self.cpuCount = cpuCount
    self.memoryMiB = memoryMiB
    self.disks = disks
    self.shares = shares
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
    guard let shares = root["shares"] as? [[String: Any]],
      shares.allSatisfy({ Set($0.keys) == ["tag", "path", "readOnly", "device", "inode"] })
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
    guard shares.count <= Self.maxShares,
      shares.enumerated().allSatisfy({ index, share in
        share.tag == Self.shareTag(index) && Self.isAbsolute(share.path) && share.path != "/"
          && share.path.utf8.count <= Self.maxSharePathBytes && share.inode != 0
      }),
      Set(shares.map(\.path)).count == shares.count
    else { throw ConfigurationError.invalidShare }
    guard Self.isAbsolute(vsockSocket), vsockSocket.utf8.count <= Self.maxSocketPathBytes else {
      throw ConfigurationError.invalidVsockPort
    }
  }

  /// The guest's virtio-fs tag for share `index`, in plan order.
  public static func shareTag(_ index: Int) -> String {
    shareTagPrefix + (index < 10 ? "0\(index)" : "\(index)")
  }

  private static func isAbsolute(_ value: String) -> Bool {
    value.hasPrefix("/") && !value.utf8.contains(0)
      && !value.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
  }

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion, kernel, initialRamdisk, commandLine, cpuCount, memoryMiB, disks, shares,
      vsockSocket

    static var allNames: [String] { allCases.map(\.rawValue) }
  }
}
