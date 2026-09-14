import CCanarySupport
import Darwin
import Foundation
import SandboxCanaryProtocol

@main
enum CanaryDeputy {
  static func main() {
    _ = signal(SIGPIPE, SIG_IGN)
    _ = alarm(20)
    _ = runApplicationLifecycle {
      do {
        try run()
        Darwin.exit(0)
      } catch {
        Darwin.exit(70)
      }
    }
    Darwin.exit(70)
  }

  private static func run() throws {
    guard CommandLine.arguments.count == 1,
      let resource = Bundle.main.url(forResource: "run-config", withExtension: "json")
    else {
      throw ExperimentError.invalid
    }
    let bytes = try Data(contentsOf: resource, options: [.mappedIfSafe])
    guard bytes.count <= maximumFrameBytes,
      let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      Set(object.keys) == ["schemaVersion", "nonce", "endpointPath", "canaryPath"]
    else {
      throw ExperimentError.invalid
    }
    let configuration = try JSONDecoder().decode(DeputyConfiguration.self, from: bytes)
    try configuration.validate()

    let descriptor = configuration.endpointPath.withCString { path in
      cw_canary_connect(path)
    }
    guard descriptor >= 0 else { throw ExperimentError.io }
    defer { _ = Darwin.close(descriptor) }
    try writeFrame(
      WireMessage(kind: "deputy-hello", nonce: configuration.nonce, pid: getpid()),
      to: descriptor)
    let arm = try readFrame(from: descriptor)
    guard arm.kind == "arm", arm.nonce == configuration.nonce else {
      throw ExperimentError.invalid
    }

    let result = observeCanary(path: configuration.canaryPath)
    try writeFrame(
      WireMessage(
        kind: "deputy-result", nonce: configuration.nonce,
        observation: result.0, sha256: result.1),
      to: descriptor)
    guard Darwin.shutdown(descriptor, SHUT_WR) == 0 else { throw ExperimentError.io }
    _ = alarm(0)
  }
}
