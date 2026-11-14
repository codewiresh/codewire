import Foundation

extension VMConfiguration {
  /// The Seatbelt profile the product helper applies to itself once its
  /// listener is bound and before the VM starts (#1905): everything is denied
  /// except the exact files this one VM was admitted to use. Built only from
  /// the validated configuration.
  public func sandboxProfile() -> String {
    var rules = [
      "(version 1)", "(deny default)",
      // Virtualization.framework and what it loads read the OS's own files,
      // which hold no user data.
      "(allow file-read* (subpath \"/System\") (subpath \"/usr/lib\") (literal \"/dev/null\"))",
      "(allow sysctl-read)",
      // Since macOS 27 the framework looks up the user's cache directory as
      // the VM starts. The helper resolves it before confinement, and the
      // lookup then needs only the `/var` symlink's own metadata (#4478).
      "(allow file-read-metadata (literal \"/var\"))",
      // The XPC service that runs the VM; nothing else in the Mach namespace.
      "(allow mach-lookup (xpc-service-name \"com.apple.Virtualization.VirtualMachine\"))",
    ]
    let readOnly = [kernel, initialRamdisk] + disks.filter(\.readOnly).map(\.path)
    for path in readOnly {
      rules.append("(allow file-read* (literal \(Self.profileString(path))))")
    }
    for disk in disks where !disk.readOnly {
      rules.append("(allow file-read* file-write* (literal \(Self.profileString(disk.path))))")
    }
    // Schema 3 (#4654): a save writes exactly `saveState` and a restore reads
    // exactly `restoreState`. Decoding admitted both as safe literals inside
    // the VM's directory, so nothing here is escaped into a wider rule.
    if let saveState {
      rules.append("(allow file-read* file-write* (literal \(Self.profileString(saveState))))")
    }
    if let restoreState {
      rules.append("(allow file-read* (literal \(Self.profileString(restoreState))))")
    }
    for share in shares {
      let rights = share.readOnly ? "file-read*" : "file-read* file-write*"
      let path = Self.profileString(share.path)
      // Virtualization.framework gives its VM service each share with a file
      // extension. Without this the VM boots and the guest gets EPERM.
      rules.append("(allow \(rights) file-issue-extension (subpath \(path)))")
    }
    if !shares.isEmpty {
      // The one extension class that lets the VM service serve virtio-fs.
      rules.append(
        "(allow generic-issue-extension (extension-class \"com.apple.virtualization.extension.fuse\"))"
      )
    }
    // The helper removes the socket it bound when it exits.
    let socket = Self.profileString(vsockSocket)
    rules.append("(allow file-read-metadata file-write-unlink (literal \(socket)))")
    return rules.joined(separator: "\n") + "\n"
  }

  /// A profile string literal. Validation already refused NUL, and every other
  /// byte of a path, control characters included, stands for itself there.
  static func profileString(_ value: String) -> String {
    let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
      .replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
  }
}
