import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import CodewireVZRunnerRuntime
#endif

private struct Response: Encodable {
  let schemaVersion = RunnerProtocol.schemaVersion
  let result: String
}

private func usage() -> Never {
  FileHandle.standardError.write(
    Data("usage: codewire-vz-runner validate --control-fd FD\n".utf8)
  )
  exit(2)
}

private func run() throws {
  let arguments = CommandLine.arguments
  guard arguments.count == 4,
    arguments[1] == "validate",
    arguments[2] == "--control-fd",
    let controlDescriptor = Int32(arguments[3]),
    controlDescriptor >= 3
  else { usage() }

  #if canImport(Virtualization) && os(macOS)
    let request = try PrivateIPC.receive(controlDescriptor: controlDescriptor)
    try RuntimeAdmission.validateConfiguration(for: request)
    let response = try JSONEncoder().encode(Response(result: "configuration-valid"))
    try PrivateIPC.send(controlDescriptor: controlDescriptor, response: response)
  #else
    throw ConfigurationError.unsupportedSchema
  #endif
}

do {
  try run()
} catch {
  // Errors are fixed classifications only; no paths, provider material,
  // configuration payloads, NSError descriptions, or ambient values escape.
  FileHandle.standardError.write(Data("codewire-vz-runner: request rejected\n".utf8))
  exit(1)
}
