import CodewireVZRunnerProtocol
import Foundation
import Testing

extension CodewireVZRunnerTests {
  /// The runner-to-helper control channel's codec and state rules
  /// (cw-security, condition 3, #4654).
  @Suite struct ControlProtocolTests {
    static func decode(_ text: String) throws -> ControlRequest {
      try ControlRequest.decode(Data(text.utf8))
    }

    @Test
    func testARequestIsExactlyAnIdAndAnOperation() throws {
      #expect(try Self.decode(#"{"id":1,"op":"pause"}"#) == .init(id: 1, operation: .pause))
      #expect(try Self.decode(#"{"op":"save","id":7}"#) == .init(id: 7, operation: .save))
      #expect(try Self.decode(#"{"id":0,"op":"resume"}"#) == .init(id: 0, operation: .resume))
      #expect(try Self.decode(#"{"id":2,"op":"stop"}"#) == .init(id: 2, operation: .stop))
    }

    @Test
    func testARequestCarriesNoPathDescriptorOrSize() {
      for line in [
        #"{"id":1,"op":"save","path":"/tmp/elsewhere"}"#,
        #"{"id":1,"op":"save","fd":5}"#,
        #"{"id":1,"op":"save","size":4096}"#,
        #"{"id":1}"#,
        #"{"op":"pause"}"#,
        #"{"id":1,"op":"snapshot"}"#,
        #"{"id":1,"op":"PAUSE"}"#,
        #"{"id":"1","op":"pause"}"#,
        #"{"id":true,"op":"pause"}"#,
        #"{"id":1.5,"op":"pause"}"#,
        #"{"id":-1,"op":"pause"}"#,
        #"{"id":1,"op":null}"#,
        #"["pause"]"#,
        "pause",
        "",
      ] {
        #expect(throws: ControlError.malformed, "\(line)") { _ = try Self.decode(line) }
      }
    }

    @Test
    func testLinesAreBoundedAndSplit() throws {
      var reader = ControlLineReader()
      let two = Data((#"{"id":1,"op":"pause"}"# + "\n" + #"{"id":2,"op":"sa"#).utf8)
      #expect(try reader.append(two) == [Data(#"{"id":1,"op":"pause"}"#.utf8)])
      #expect(try reader.append(Data("ve\"}\n".utf8)) == [Data(#"{"id":2,"op":"save"}"#.utf8)])

      var long = ControlLineReader()
      let tooLong = Data(repeating: UInt8(ascii: "a"), count: ControlRequest.maxLineBytes + 1)
      #expect(throws: ControlError.lineTooLong) { _ = try long.append(tooLong) }

      var longWithNewline = ControlLineReader()
      #expect(throws: ControlError.lineTooLong) {
        _ = try longWithNewline.append(tooLong + Data("\n".utf8))
      }

      var exact = ControlLineReader()
      let fits = Data(repeating: UInt8(ascii: "a"), count: ControlRequest.maxLineBytes)
      #expect(try exact.append(fits + Data("\n".utf8)) == [fits])
    }

    @Test
    func testRepliesAndTheEventAreNumbersAndTheIdentifierOnly() {
      #expect(
        ControlMessage.done(id: 3, milliseconds: 1104).encoded()
          == Data(#"{"id":3,"result":"done","ms":1104}"#.utf8 + [UInt8(ascii: "\n")]))
      #expect(
        ControlMessage.failed(id: 4, code: 11).encoded()
          == Data(#"{"id":4,"result":"failed","code":11}"#.utf8 + [UInt8(ascii: "\n")]))
      #expect(
        ControlMessage.refused(id: 5).encoded()
          == Data(#"{"id":5,"result":"refused"}"#.utf8 + [UInt8(ascii: "\n")]))
      #expect(
        ControlMessage.started(machineIdentifier: "YnBsaXN0MDA=").encoded()
          == Data(
            #"{"event":"started","machineIdentifier":"YnBsaXN0MDA="}"#.utf8 + [UInt8(ascii: "\n")]))
    }

    @Test
    func testACaptureIsPauseSaveResumeAndStopEndsEverything() {
      var states = ControlStateMachine()
      // Nothing but stop before the VM runs.
      #expect(!states.admits(.pause) && !states.admits(.save) && !states.admits(.resume))
      #expect(states.admits(.stop))

      states.started()
      #expect(states.admits(.pause))
      #expect(!states.admits(.save) && !states.admits(.resume))

      states.completed(.pause)
      #expect(states.state == .paused)
      #expect(states.admits(.save) && states.admits(.resume) && states.admits(.stop))
      #expect(!states.admits(.pause))

      states.completed(.save)
      #expect(states.state == .paused)
      states.completed(.resume)
      #expect(states.state == .running)

      states.completed(.stop)
      #expect(states.state == .stopping)
      for operation in ControlOperation.allCases {
        #expect(!states.admits(operation), "\(operation)")
      }
      // A late `started` never revives a stopping VM.
      states.started()
      #expect(states.state == .stopping)
    }
  }
}
