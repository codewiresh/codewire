import CodewireVZRunnerProtocol
import Foundation

#if canImport(Virtualization) && os(macOS)
  import CryptoKit
  import Darwin
  import Security
  import Virtualization

  @available(macOS 15.0, *)
  public enum InodeProbeRuntime {
    private static let challengeBytes = 32
    private static let frameBytes = 88
    private static let frameBodyBytes = 56
    private static let readyDeadlineSeconds: TimeInterval = 30
    private static let frameMagic = Data("CWVINOD1".utf8)
    private static let stageFrameMagic = Data("CWVSTG1\0".utf8)
    private static let domain = Data("codewire-vz-exact-inode-probe-v1\0".utf8)

    public static func run(request: ReceivedRequest, controlDescriptor: Int32) throws {
      let configuration = try RuntimeAdmission.buildInodeProbeConfiguration(for: request)
      let seed = try RuntimeAdmission.inodeProbeSeed(for: request)
      let filesystemUUID = try RuntimeAdmission.inodeProbeFilesystemUUID(for: request)
      try sendResponse("descriptors-admitted", to: controlDescriptor)
      try PrivateIPC.receiveStart(controlDescriptor: controlDescriptor)

      let challenge: Data
      do {
        challenge = try randomChallenge()
      } catch {
        try? sendResponse(ProbeError.randomFailed.controlResult, to: controlDescriptor)
        throw error
      }

      let queue = DispatchQueue(label: "dev.codewire.vz-inode-probe")
      let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
      let binding: InodeProbeListenerBinding
      do {
        binding = try installListener(on: virtualMachine, queue: queue)
      } catch {
        try? sendResponse(ProbeError.helperSocketUnavailable.controlResult, to: controlDescriptor)
        throw error
      }
      do {
        try start(virtualMachine, on: queue)
      } catch {
        binding.receiver.cancel()
        try? sendResponse(ProbeError.virtualMachineStartFailed.controlResult, to: controlDescriptor)
        throw error
      }

      let connection: VZVirtioSocketConnection
      do {
        connection = try receiveReadiness(
          from: binding.receiver,
          seed: seed,
          filesystemUUID: filesystemUUID,
          challenge: challenge
        )
      } catch let error as ProbeError {
        binding.receiver.cancel()
        try? sendResponse(error.controlResult, to: controlDescriptor)
        throw error
      } catch {
        binding.receiver.cancel()
        try? sendResponse(ProbeError.invalidReadiness.controlResult, to: controlDescriptor)
        throw error
      }
      try sendResponse("guest-ready", to: controlDescriptor)

      // The fixture owner deliberately SIGKILLs this helper. Retain the
      // accepted listener, delegate and authenticated guest connection until
      // then. EOF is the only accepted terminal control event and destroys the
      // in-process VZVirtualMachine by exiting through the fixed error path.
      try withExtendedLifetime(binding) {
        try withExtendedLifetime(connection) {
          var byte: UInt8 = 0
          while true {
            let count = Darwin.read(controlDescriptor, &byte, 1)
            if count == 0 { throw IPCError.rejected(-5) }
            if count < 0 && errno == EINTR { continue }
            throw IPCError.rejected(-5)
          }
        }
      }
    }

    private static func sendResponse(_ result: String, to descriptor: Int32) throws {
      let bytes = Data("{\"result\":\"\(result)\",\"schemaVersion\":1}".utf8)
      try PrivateIPC.send(controlDescriptor: descriptor, response: bytes)
    }

    private static func installListener(
      on virtualMachine: VZVirtualMachine,
      queue: DispatchQueue
    ) throws -> InodeProbeListenerBinding {
      let receiver = InodeProbeConnectionReceiver()
      let listener = VZVirtioSocketListener()
      listener.delegate = receiver
      let completion = CompletionBox<VZVirtioSocketDevice>()
      let machine = UncheckedSendableBox(virtualMachine)
      let listenerBox = UncheckedSendableBox(listener)
      queue.async {
        guard let device = machine.value.socketDevices.first as? VZVirtioSocketDevice else {
          completion.complete(.failure(ProbeError.helperSocketUnavailable))
          return
        }
        device.setSocketListener(
          listenerBox.value,
          forPort: RunnerProtocol.inodeProbeVsockPort
        )
        completion.complete(.success(device))
      }
      let device = try completion.wait(seconds: readyDeadlineSeconds)
      return InodeProbeListenerBinding(device: device, listener: listener, receiver: receiver)
    }

    private static func start(_ virtualMachine: VZVirtualMachine, on queue: DispatchQueue) throws {
      let completion = CompletionBox<Void>()
      let machine = UncheckedSendableBox(virtualMachine)
      queue.async {
        machine.value.start { result in completion.complete(result) }
      }
      try completion.wait(seconds: readyDeadlineSeconds)
    }

    private static func receiveReadiness(
      from receiver: InodeProbeConnectionReceiver,
      seed: Data,
      filesystemUUID: [UInt8],
      challenge: Data
    ) throws -> VZVirtioSocketConnection {
      let deadline = Date().addingTimeInterval(readyDeadlineSeconds)
      let connection: VZVirtioSocketConnection
      do {
        connection = try receiver.wait(deadline: deadline)
      } catch {
        throw ProbeError.readinessFailed(.beforeConnection)
      }
      var retainConnection = false
      defer {
        if !retainConnection { connection.close() }
      }

      var lastStage: DiagnosticStage?
      do {
        try writeExact(challenge, to: connection.fileDescriptor, deadline: deadline)
        while true {
          switch try readReadinessRecord(
            from: connection.fileDescriptor,
            after: lastStage,
            deadline: deadline
          ) {
          case .diagnostic(let stage):
            lastStage = stage
          case .authenticated(let readiness):
            try verifyReadiness(
              readiness,
              seed: seed,
              filesystemUUID: filesystemUUID,
              challenge: challenge
            )
            retainConnection = true
            return connection
          }
        }
      } catch ProbeError.timedOut {
        throw ProbeError.readinessFailed(ReadinessPhase(lastStage))
      } catch ProbeError.socketUnavailable {
        throw ProbeError.readinessFailed(ReadinessPhase(lastStage))
      }
    }

    static func readReadinessRecord(
      from descriptor: Int32,
      after lastStage: DiagnosticStage?,
      deadline: Date
    ) throws -> ReadinessRecord {
      try parseReadinessRecord(
        readExact(frameBytes, from: descriptor, deadline: deadline),
        after: lastStage
      )
    }

    enum DiagnosticStage: UInt8, CaseIterable, Sendable {
      case started = 1
      case filesystemsMounted = 2
      case seedRead = 3
      case dataIdentified = 4
    }

    enum ReadinessRecord: Equatable {
      case diagnostic(DiagnosticStage)
      case authenticated(Data)
    }

    static func parseReadinessRecord(_ frame: Data, after lastStage: DiagnosticStage?) throws
      -> ReadinessRecord
    {
      guard frame.count == frameBytes else { throw ProbeError.invalidReadiness }
      if frame.prefix(8) == frameMagic {
        guard lastStage == .dataIdentified else { throw ProbeError.invalidReadiness }
        return .authenticated(frame)
      }
      guard frame.prefix(8) == stageFrameMagic,
        let stage = DiagnosticStage(rawValue: frame[8]),
        frame.dropFirst(9).allSatisfy({ $0 == 0 }),
        stage.rawValue == (lastStage?.rawValue ?? 0) + 1
      else { throw ProbeError.invalidReadiness }
      return .diagnostic(stage)
    }

    static func diagnosticFrame(_ stage: DiagnosticStage) -> Data {
      var frame = Data(repeating: 0, count: frameBytes)
      frame.replaceSubrange(0..<8, with: stageFrameMagic)
      frame[8] = stage.rawValue
      return frame
    }

    static func verifyReadiness(
      _ frame: Data, seed: Data, filesystemUUID: [UInt8], challenge: Data
    ) throws {
      guard frame.count == frameBytes,
        frame.prefix(8) == frameMagic,
        Data(frame[8..<40]) == Data(SHA256.hash(data: seed)),
        Data(frame[40..<56]) == Data(filesystemUUID)
      else { throw ProbeError.invalidReadiness }
      let body = frame.prefix(frameBodyBytes)
      var authenticated = Data()
      authenticated.append(domain)
      authenticated.append(challenge)
      authenticated.append(body)
      let key = SymmetricKey(data: seed)
      guard
        HMAC<SHA256>.isValidAuthenticationCode(
          frame.suffix(from: frameBodyBytes),
          authenticating: authenticated,
          using: key
        )
      else { throw ProbeError.invalidReadiness }
    }

    private static func randomChallenge() throws -> Data {
      var bytes = [UInt8](repeating: 0, count: challengeBytes)
      guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess,
        bytes.contains(where: { $0 != 0 })
      else { throw ProbeError.randomFailed }
      return Data(bytes)
    }

    private static func writeExact(_ data: Data, to descriptor: Int32, deadline: Date) throws {
      try data.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { throw ProbeError.socketUnavailable }
        var written = 0
        while written < data.count {
          try waitFor(descriptor, events: Int16(POLLOUT), deadline: deadline)
          let count = Darwin.write(descriptor, base.advanced(by: written), data.count - written)
          if count < 0 && errno == EINTR { continue }
          guard count > 0 else { throw ProbeError.socketUnavailable }
          written += count
        }
      }
    }

    private static func readExact(_ count: Int, from descriptor: Int32, deadline: Date) throws
      -> Data
    {
      var bytes = [UInt8](repeating: 0, count: count)
      var consumed = 0
      while consumed < bytes.count {
        try waitFor(descriptor, events: Int16(POLLIN), deadline: deadline)
        let requested = bytes.count - consumed
        let readCount = bytes.withUnsafeMutableBytes { raw in
          Darwin.read(descriptor, raw.baseAddress?.advanced(by: consumed), requested)
        }
        if readCount < 0 && errno == EINTR { continue }
        guard readCount > 0 else { throw ProbeError.socketUnavailable }
        consumed += readCount
      }
      return Data(bytes)
    }

    private static func waitFor(_ descriptor: Int32, events: Int16, deadline: Date) throws {
      let remaining = deadline.timeIntervalSinceNow
      guard remaining > 0 else { throw ProbeError.timedOut }
      var item = pollfd(fd: descriptor, events: events, revents: 0)
      let milliseconds = Int32(min(remaining * 1_000, Double(Int32.max)))
      let result = Darwin.poll(&item, 1, milliseconds)
      if result < 0 && errno == EINTR {
        return try waitFor(descriptor, events: events, deadline: deadline)
      }
      if result == 0 { throw ProbeError.timedOut }
      guard result == 1, item.revents & events != 0 else { throw ProbeError.socketUnavailable }
    }
  }

  private enum ReadinessPhase: String {
    case beforeConnection = "no-connection"
    case connected
    case started
    case filesystemsMounted = "filesystems-mounted"
    case seedRead = "seed-read"
    case dataIdentified = "data-identified"

    init(_ stage: InodeProbeRuntime.DiagnosticStage?) {
      switch stage {
      case nil: self = .connected
      case .started: self = .started
      case .filesystemsMounted: self = .filesystemsMounted
      case .seedRead: self = .seedRead
      case .dataIdentified: self = .dataIdentified
      }
    }
  }

  private enum ProbeError: Error {
    case helperSocketUnavailable
    case invalidReadiness
    case randomFailed
    case readinessFailed(ReadinessPhase)
    case socketUnavailable
    case timedOut
    case virtualMachineStartFailed

    var controlResult: String {
      switch self {
      case .helperSocketUnavailable: "guest-readiness-helper-socket-unavailable"
      case .invalidReadiness: "guest-readiness-invalid"
      case .randomFailed: "guest-readiness-challenge-failed"
      case .readinessFailed(let phase): "guest-readiness-failed-\(phase.rawValue)"
      case .socketUnavailable: "guest-readiness-socket-failed"
      case .timedOut: "guest-readiness-timeout"
      case .virtualMachineStartFailed: "guest-start-failed"
      }
    }
  }

  @available(macOS 15.0, *)
  private final class InodeProbeListenerBinding: @unchecked Sendable {
    let device: VZVirtioSocketDevice
    let listener: VZVirtioSocketListener
    let receiver: InodeProbeConnectionReceiver

    init(
      device: VZVirtioSocketDevice,
      listener: VZVirtioSocketListener,
      receiver: InodeProbeConnectionReceiver
    ) {
      self.device = device
      self.listener = listener
      self.receiver = receiver
    }
  }

  final class OneShotAdmissionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var open = true

    func admit() -> Bool {
      lock.lock()
      defer { lock.unlock() }
      guard open else { return false }
      open = false
      return true
    }

    func cancel() {
      lock.lock()
      open = false
      lock.unlock()
    }
  }

  @available(macOS 15.0, *)
  private final class InodeProbeConnectionReceiver: NSObject,
    VZVirtioSocketListenerDelegate, @unchecked Sendable
  {
    private let admission = OneShotAdmissionGate()
    private let completion = CompletionBox<VZVirtioSocketConnection>()

    func listener(
      _ listener: VZVirtioSocketListener,
      shouldAcceptNewConnection connection: VZVirtioSocketConnection,
      from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
      guard admission.admit() else { return false }
      completion.complete(.success(connection))
      return true
    }

    func wait(deadline: Date) throws -> VZVirtioSocketConnection {
      let remaining = deadline.timeIntervalSinceNow
      guard remaining > 0 else {
        cancel()
        throw ProbeError.timedOut
      }
      do {
        return try completion.wait(seconds: remaining)
      } catch {
        cancel()
        throw error
      }
    }

    func cancel() {
      admission.cancel()
    }
  }

  private final class CompletionBox<Value>: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Result<Value, Error>?

    func complete(_ value: Result<Value, Error>) {
      lock.lock()
      guard result == nil else {
        lock.unlock()
        return
      }
      result = value
      lock.unlock()
      semaphore.signal()
    }

    func wait(seconds: TimeInterval) throws -> Value {
      guard semaphore.wait(timeout: .now() + seconds) == .success else {
        throw ProbeError.timedOut
      }
      lock.lock()
      let value = result
      lock.unlock()
      return try value!.get()
    }
  }

  private final class UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
      self.value = value
    }
  }
#endif
