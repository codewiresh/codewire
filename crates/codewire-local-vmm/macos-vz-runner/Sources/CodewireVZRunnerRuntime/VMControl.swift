import CVZRunnerIPC
import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import Virtualization

  /// The helper's end of the runner's control channel (#4654). Requests
  /// arrive on their own thread and run on the VM's queue, one at a time;
  /// replies and the `started` event are written from that queue only.
  ///
  /// Anything but a well-formed request stops the VM: EOF from the runner,
  /// a read error, ancillary data, an over-long or malformed line.
  final class VMControl: @unchecked Sendable {
    private let descriptor: Int32
    private let saveState: URL
    private let machineIdentifier: String
    private unowned let machine: VMMachine
    /// Read and written only on the VM's queue.
    private var states = ControlStateMachine()

    init(descriptor: Int32, saveState: String, machineIdentifier: String, machine: VMMachine) {
      self.descriptor = descriptor
      self.saveState = URL(fileURLWithPath: saveState)
      self.machineIdentifier = machineIdentifier
      self.machine = machine
    }

    /// Called on the VM's queue once the VM runs: started, or restored and
    /// resumed.
    func started() {
      states.started()
      send(.started(machineIdentifier: machineIdentifier))
    }

    func startReading() {
      let reader = Thread { [self] in readRequests() }
      reader.start()
    }

    private func readRequests() {
      var lines = ControlLineReader()
      var buffer = [UInt8](repeating: 0, count: ControlRequest.maxLineBytes)
      while true {
        let count = buffer.withUnsafeMutableBufferPointer { bytes in
          cw_vz_control_read(descriptor, bytes.baseAddress, bytes.count)
        }
        guard count > 0 else { break }
        guard let received = try? lines.append(Data(buffer[0..<count])) else { break }
        for line in received {
          guard let request = try? ControlRequest.decode(line) else {
            machine.queue.async { self.machine.stop() }
            return
          }
          machine.queue.async { self.handle(request) }
        }
      }
      machine.queue.async { self.machine.stop() }
    }

    /// On the VM's queue.
    private func handle(_ request: ControlRequest) {
      guard states.admits(request.operation) else {
        send(.refused(id: request.id))
        return
      }
      let begun = DispatchTime.now()
      let finish = { (error: (any Error)?) in
        if let error {
          self.send(.failed(id: request.id, code: (error as? VZError)?.code.rawValue ?? 0))
        } else {
          self.states.completed(request.operation)
          self.send(.done(id: request.id, milliseconds: Self.milliseconds(since: begun)))
        }
      }
      switch request.operation {
      case .pause:
        machine.pause { finish($0) }
      case .save:
        machine.save(to: saveState) { finish($0) }
      case .resume:
        machine.resume { finish($0) }
      case .stop:
        states.completed(.stop)
        send(.done(id: request.id, milliseconds: 0))
        machine.stop()
      }
    }

    /// On the VM's queue, so lines never interleave.
    private func send(_ message: ControlMessage) {
      let line = message.encoded()
      // A failed write means the runner is gone; its EOF stops the VM.
      _ = line.withUnsafeBytes { bytes in
        cw_vz_write_all(descriptor, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
      }
    }

    private static func milliseconds(since begun: DispatchTime) -> UInt64 {
      (DispatchTime.now().uptimeNanoseconds - begun.uptimeNanoseconds) / 1_000_000
    }
  }
#endif
