import Foundation

public enum ConfigurationError: Error, Equatable {
  case malformed
  case unknownFields
  case unsupportedSchema
  case invalidCPUCount
  case invalidMemory
  case invalidVsockPort
  case invalidArtifact
  case invalidDataDisk
  case invalidShare
  case invalidControl
  case invalidStatePath
  case invalidMachineIdentifier
}

/// Product VM request for `codewire-vz-runner vm --config FILE`.
///
/// It carries what the Linux runner passes on the Cloud Hypervisor command
/// line: boot artifacts and disks by path, one hybrid-vsock socket, CPU and
/// memory, and the admitted host directories it serves through virtiofsd.
/// The Rust runner admits every disk under its private state root and every
/// shared directory before it writes this file. Schema 2 added `shares`.
/// Schema 3 (#4654) adds the control channel and the checkpoint files:
/// `machineIdentifier`, `saveState`, `restoreState` and `controlDescriptor`.
/// The helper accepts both, so a runner that writes schema 2 keeps working.
public struct VMConfiguration: Codable, Equatable, Sendable {
  public static let schemaVersion = 3
  public static let supportedSchemaVersions = [2, 3]
  /// A machine identifier's data representation is a small property list.
  public static let maxMachineIdentifierBytes = 1024
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
  /// Schema 3: base64 of `VZGenericMachineIdentifier.dataRepresentation`;
  /// `nil` on a VM's first start, when the helper makes one and reports it.
  public var machineIdentifier: String?
  /// Schema 3: the one file a `save` writes, inside the VM's directory.
  public var saveState: String?
  /// Schema 3: a saved state to restore instead of starting, inside the VM's
  /// directory.
  public var restoreState: String?
  /// Schema 3: the inherited control socket.
  public var controlDescriptor: Int32?

  /// What schema 3 adds, together.
  public struct Checkpointing: Equatable, Sendable {
    public var machineIdentifier: String?
    public var saveState: String
    public var restoreState: String?
    public var controlDescriptor: Int32

    public init(
      machineIdentifier: String?, saveState: String, restoreState: String?, controlDescriptor: Int32
    ) {
      self.machineIdentifier = machineIdentifier
      self.saveState = saveState
      self.restoreState = restoreState
      self.controlDescriptor = controlDescriptor
    }
  }

  /// A schema 3 configuration with `checkpointing`, or schema 2 without it.
  public init(
    kernel: String, initialRamdisk: String, commandLine: String, cpuCount: Int,
    memoryMiB: UInt64, disks: [Disk], shares: [Share], vsockSocket: String,
    checkpointing: Checkpointing? = nil
  ) {
    schemaVersion = checkpointing == nil ? 2 : Self.schemaVersion
    self.kernel = kernel
    self.initialRamdisk = initialRamdisk
    self.commandLine = commandLine
    self.cpuCount = cpuCount
    self.memoryMiB = memoryMiB
    self.disks = disks
    self.shares = shares
    self.vsockSocket = vsockSocket
    machineIdentifier = checkpointing?.machineIdentifier
    saveState = checkpointing?.saveState
    restoreState = checkpointing?.restoreState
    controlDescriptor = checkpointing?.controlDescriptor
  }

  /// Schema 3's fields, or `nil` for schema 2.
  public var checkpointing: Checkpointing? {
    guard schemaVersion >= 3, let saveState, let controlDescriptor else { return nil }
    return Checkpointing(
      machineIdentifier: machineIdentifier, saveState: saveState, restoreState: restoreState,
      controlDescriptor: controlDescriptor)
  }

  /// Decodes one configuration and refuses unknown or missing fields, so a
  /// newer runner cannot silently ask for something this helper ignores.
  /// `directory` is the VM's private directory, the one holding the
  /// configuration file; schema 3's two state files must lie inside it.
  public static func decode(_ data: Data, directory: String) throws -> VMConfiguration {
    guard data.count <= maxConfigurationBytes,
      let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw ConfigurationError.malformed }
    let version = (root["schemaVersion"] as? Int) ?? 0
    guard supportedSchemaVersions.contains(version) else {
      throw ConfigurationError.unsupportedSchema
    }
    let names = version >= 3 ? CodingKeys.allNames : CodingKeys.schema2Names
    guard Set(root.keys) == Set(names) else { throw ConfigurationError.unknownFields }
    guard let disks = root["disks"] as? [[String: Any]],
      disks.allSatisfy({ Set($0.keys) == ["path", "serial", "readOnly"] })
    else { throw ConfigurationError.unknownFields }
    guard let shares = root["shares"] as? [[String: Any]],
      shares.allSatisfy({ Set($0.keys) == ["tag", "path", "readOnly", "device", "inode"] })
    else { throw ConfigurationError.unknownFields }
    guard let configuration = try? JSONDecoder().decode(VMConfiguration.self, from: data) else {
      throw ConfigurationError.malformed
    }
    try configuration.validate(directory: directory)
    return configuration
  }

  public func validate(directory: String) throws {
    guard Self.supportedSchemaVersions.contains(schemaVersion) else {
      throw ConfigurationError.unsupportedSchema
    }
    try validateCheckpointing(directory: directory)
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

  /// Schema 3's fields: all present together, or none for schema 2.
  private func validateCheckpointing(directory: String) throws {
    guard schemaVersion >= 3 else {
      guard
        machineIdentifier == nil, saveState == nil, restoreState == nil, controlDescriptor == nil
      else { throw ConfigurationError.unknownFields }
      return
    }
    guard let controlDescriptor, controlDescriptor >= 3, controlDescriptor < 1024 else {
      throw ConfigurationError.invalidControl
    }
    guard let saveState, Self.isProfileLiteral(saveState, inside: directory) else {
      throw ConfigurationError.invalidStatePath
    }
    if let restoreState {
      guard Self.isProfileLiteral(restoreState, inside: directory), restoreState != saveState else {
        throw ConfigurationError.invalidStatePath
      }
    }
    if let machineIdentifier {
      guard let bytes = Data(base64Encoded: machineIdentifier), !bytes.isEmpty,
        bytes.count <= Self.maxMachineIdentifierBytes
      else { throw ConfigurationError.invalidMachineIdentifier }
    }
  }

  /// Whether the sandbox profile may embed `path` as a literal. It is refused,
  /// never escaped, unless it is absolute, normalized, strictly inside
  /// `directory` (itself such a path) and uses only `[A-Za-z0-9._/-]`
  /// (cw-security, condition 5, #4654).
  public static func isProfileLiteral(_ path: String, inside directory: String) -> Bool {
    isNormalizedLiteral(path) && isNormalizedLiteral(directory) && path.hasPrefix(directory + "/")
  }

  private static func isNormalizedLiteral(_ value: String) -> Bool {
    let allowed = value.utf8.allSatisfy { byte in
      (0x30...0x39).contains(byte) || (0x41...0x5a).contains(byte) || (0x61...0x7a).contains(byte)
        || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "/")
        || byte == UInt8(ascii: "-")
    }
    let components = value.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
    return allowed && value.count > 1 && value.hasPrefix("/")
      && value.utf8.count <= maxSharePathBytes
      && !components.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." })
  }

  /// Schema 3 writes all four of its keys, `null` included, because the
  /// helper refuses a missing one; schema 2 writes none of them.
  public func encode(to encoder: any Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(schemaVersion, forKey: .schemaVersion)
    try container.encode(kernel, forKey: .kernel)
    try container.encode(initialRamdisk, forKey: .initialRamdisk)
    try container.encode(commandLine, forKey: .commandLine)
    try container.encode(cpuCount, forKey: .cpuCount)
    try container.encode(memoryMiB, forKey: .memoryMiB)
    try container.encode(disks, forKey: .disks)
    try container.encode(shares, forKey: .shares)
    try container.encode(vsockSocket, forKey: .vsockSocket)
    if schemaVersion >= 3 {
      try container.encode(machineIdentifier, forKey: .machineIdentifier)
      try container.encode(saveState, forKey: .saveState)
      try container.encode(restoreState, forKey: .restoreState)
      try container.encode(controlDescriptor, forKey: .controlDescriptor)
    }
  }

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion, kernel, initialRamdisk, commandLine, cpuCount, memoryMiB, disks, shares,
      vsockSocket, machineIdentifier, saveState, restoreState, controlDescriptor

    static var allNames: [String] { allCases.map(\.rawValue) }
    static var schema2Names: [String] {
      allNames.filter {
        !["machineIdentifier", "saveState", "restoreState", "controlDescriptor"].contains($0)
      }
    }
  }
}
