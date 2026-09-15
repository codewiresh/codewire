import CodewireVZRunnerProtocol
import Foundation
import Testing

@Suite struct ConsolePairTests {
  @Test func fixedTopologyAndExactRoleMapping() throws {
    let configuration = try ConsolePairConfiguration.decode(canonical())
    #expect(ConsolePairProtocol.cpuCount == 1)
    #expect(ConsolePairProtocol.memoryMiB == 512)
    #expect(ConsolePairProtocol.roleFrameBytes == 128)
    #expect(configuration.artifact(for: .guestBinding).sha256 == String(repeating: "c", count: 64))
    #expect(
      configuration.artifact(for: .serviceBinding).sha256 == String(repeating: "d", count: 64))
    #expect(ConsolePairArtifactRole.allCases.map(\.rawValue) == [0, 1, 2, 3])
    #expect(
      Set([
        ConsolePairProtocol.packetPort, ConsolePairProtocol.statusPort,
        ConsolePairProtocol.controlPort,
      ]).count == 3)
  }

  @Test func unknownAndDuplicateFieldsFailClosed() throws {
    let base = String(decoding: canonical(), as: UTF8.self)
    for bytes in [
      Data(
        base.replacingOccurrences(
          of: "\"schemaVersion\":3", with: "\"extra\":0,\"schemaVersion\":3"
        ).utf8),
      Data(
        base.replacingOccurrences(
          of: "\"schemaVersion\":3", with: "\"schemaVersion\":3,\"schemaVersion\":3"
        ).utf8),
      Data(
        base.replacingOccurrences(of: "\"size\":4096", with: "\"size\":4096,\"size\":4096").utf8),
      Data(base.replacingOccurrences(of: "\"size\":4096", with: "\"extra\":0,\"size\":4096").utf8),
      Data((" " + base).utf8),
      Data("{}".utf8), Data("[]".utf8), Data(), Data(repeating: 0x61, count: 16385),
    ] {
      #expect(throws: (any Error).self) { try ConsolePairConfiguration.decode(bytes) }
    }
  }

  @Test func identityAndArtifactBounds() throws {
    let base = String(decoding: canonical(), as: UTF8.self)
    for (needle, replacement) in [
      ("\"schemaVersion\":3", "\"schemaVersion\":1"),
      ("\"generation\":1", "\"generation\":0"),
      ("\"generation\":1", "\"generation\":-1"),
      ("10000000-0000-4000-8000-000000000001", "00000000-0000-0000-0000-000000000000"),
      ("10000000-0000-4000-8000-000000000001", "not-an-identity"),
      (String(repeating: "e", count: 64), String(repeating: "0", count: 64)),
      (String(repeating: "e", count: 64), String(repeating: "E", count: 64)),
      (String(repeating: "c", count: 64), String(repeating: "d", count: 64)),
      ("\"size\":4096", "\"size\":4095"),
      ("\"size\":4096", "\"size\":4097"),
      ("\"size\":1", "\"size\":0"),
      ("\"size\":1", "\"size\":1073741825"),
      (String(repeating: "a", count: 64), String(repeating: "a", count: 63)),
    ] {
      let bytes = Data(base.replacingOccurrences(of: needle, with: replacement).utf8)
      #expect(throws: (any Error).self) { try ConsolePairConfiguration.decode(bytes) }
    }
  }

  private func canonical() -> Data {
    Data(
      """
      {"generation":1,"guestBinding":{"sha256":"\(String(repeating: "c", count: 64))","size":4096},"initialRamdisk":{"sha256":"\(String(repeating: "b", count: 64))","size":1},"kernel":{"sha256":"\(String(repeating: "a", count: 64))","size":1},"runNonce":"\(String(repeating: "e", count: 64))","schemaVersion":3,"serviceBinding":{"sha256":"\(String(repeating: "d", count: 64))","size":4096},"vmID":"10000000-0000-4000-8000-000000000001"}
      """.utf8)
  }
}
