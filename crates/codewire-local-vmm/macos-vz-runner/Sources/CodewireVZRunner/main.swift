import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import CodewireVZRunnerRuntime
#endif

private func usage() -> Never {
  FileHandle.standardError.write(
    Data("usage: codewire-vz-runner vm --config FILE | protocol\n".utf8))
  exit(2)
}

/// The product VM: runs until the guest stops and exits with its result.
private func runVM(configurationPath: String) throws -> Never {
  #if canImport(Virtualization) && os(macOS)
    guard
      let handle = FileHandle(forReadingAtPath: configurationPath),
      let data = try handle.read(upToCount: VMConfiguration.maxConfigurationBytes + 1)
    else { throw ConfigurationError.malformed }
    // The VM's private directory is the one holding its configuration.
    guard let slash = configurationPath.lastIndex(of: "/") else {
      throw ConfigurationError.malformed
    }
    let directory = String(configurationPath[..<slash])
    let configuration = try VMConfiguration.decode(data, directory: directory)
    exit(try VMRuntime.run(configuration: configuration).status)
  #else
    throw ConfigurationError.unsupportedSchema
  #endif
}

let arguments = CommandLine.arguments
// The newest configuration schema this helper accepts, for the runner's
// admission probe (#4654). A helper from before schema 3 has no such command
// and exits 2 with its usage, which the runner reads as schema 2.
if arguments.count == 2, arguments[1] == "protocol" {
  FileHandle.standardOutput.write(Data("\(VMConfiguration.schemaVersion)\n".utf8))
  exit(0)
}
guard arguments.count == 4, arguments[1] == "vm", arguments[2] == "--config" else { usage() }
do {
  try runVM(configurationPath: arguments[3])
} catch {
  // Errors are fixed classifications only; no paths, provider material,
  // configuration payloads, NSError descriptions, or ambient values escape.
  FileHandle.standardError.write(Data("codewire-vz-runner: request rejected\n".utf8))
  exit(1)
}
