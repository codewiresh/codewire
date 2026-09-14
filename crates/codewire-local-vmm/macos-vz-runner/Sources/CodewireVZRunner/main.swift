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
    Data(
      "usage: codewire-vz-runner (validate|inode-probe|inode-probe-path-control|console-pair-fixture) --control-fd FD\n"
        .utf8
    )
  )
  exit(2)
}

private func run() throws {
  let arguments = CommandLine.arguments
  guard arguments.count == 4,
    ["validate", "inode-probe", "inode-probe-path-control", "console-pair-fixture"].contains(
      arguments[1]),
    arguments[2] == "--control-fd",
    let controlDescriptor = Int32(arguments[3]),
    controlDescriptor >= 3
  else { usage() }

  #if canImport(Virtualization) && os(macOS)
    if arguments[1] == "console-pair-fixture" {
      signal(SIGPIPE, SIG_IGN)
      signal(SIGALRM, SIG_DFL)
      alarm(120)
      let request = try PrivateIPC.receiveConsolePair(controlDescriptor: controlDescriptor)
      try ConsolePairRuntime.run(request: request, controlDescriptor: controlDescriptor)
      alarm(0)
      return
    }
    let request = try PrivateIPC.receive(controlDescriptor: controlDescriptor)
    if arguments[1] == "validate" {
      try RuntimeAdmission.validateConfiguration(for: request)
      try sendResponse("configuration-valid", to: controlDescriptor)
    } else {
      try InodeProbeRuntime.run(
        request: request,
        controlDescriptor: controlDescriptor,
        mode: arguments[1] == "inode-probe" ? .exactInode : .pathBackedBootControl
      )
    }
  #else
    throw ConfigurationError.unsupportedSchema
  #endif
}

private func sendResponse(_ result: String, to descriptor: Int32) throws {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  try PrivateIPC.send(
    controlDescriptor: descriptor,
    response: try encoder.encode(Response(result: result))
  )
}

do {
  try run()
} catch {
  // Errors are fixed classifications only; no paths, provider material,
  // configuration payloads, NSError descriptions, or ambient values escape.
  FileHandle.standardError.write(Data("codewire-vz-runner: request rejected\n".utf8))
  exit(1)
}
