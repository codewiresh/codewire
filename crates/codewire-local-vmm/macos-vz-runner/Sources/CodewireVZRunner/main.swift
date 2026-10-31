import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import CodewireVZRunnerRuntime
#endif

private func usage() -> Never {
  FileHandle.standardError.write(Data("usage: codewire-vz-runner vm --config FILE\n".utf8))
  exit(2)
}

/// The product VM: runs until the guest stops and exits with its result.
private func runVM(configurationPath: String) throws -> Never {
  #if canImport(Virtualization) && os(macOS)
    guard
      let handle = FileHandle(forReadingAtPath: configurationPath),
      let data = try handle.read(upToCount: VMConfiguration.maxConfigurationBytes + 1)
    else { throw ConfigurationError.malformed }
    let configuration = try VMConfiguration.decode(data)
    exit(try VMRuntime.run(configuration: configuration).rawValue)
  #else
    throw ConfigurationError.unsupportedSchema
  #endif
}

let arguments = CommandLine.arguments
guard arguments.count == 4, arguments[1] == "vm", arguments[2] == "--config" else { usage() }
do {
  try runVM(configurationPath: arguments[3])
} catch {
  // Errors are fixed classifications only; no paths, provider material,
  // configuration payloads, NSError descriptions, or ambient values escape.
  FileHandle.standardError.write(Data("codewire-vz-runner: request rejected\n".utf8))
  exit(1)
}
