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
    private static let domain = Data("codewire-vz-exact-inode-probe-v1\0".utf8)

    public static func run(request: ReceivedRequest, controlDescriptor: Int32) throws {
      let configuration = try RuntimeAdmission.buildInodeProbeConfiguration(for: request)
      let seed = try RuntimeAdmission.inodeProbeSeed(for: request)
      let filesystemUUID = try RuntimeAdmission.inodeProbeFilesystemUUID(for: request)
      try sendResponse("descriptors-admitted", to: controlDescriptor)
      try PrivateIPC.receiveStart(controlDescriptor: controlDescriptor)

      let queue = DispatchQueue(label: "dev.codewire.vz-inode-probe")
      let virtualMachine = VZVirtualMachine(configuration: configuration, queue: queue)
      try start(virtualMachine, on: queue)
      let challenge = try randomChallenge()
      let frame = try receiveReadiness(
        from: virtualMachine, on: queue, challenge: challenge
      )
      try verifyReadiness(
        frame, seed: seed, filesystemUUID: filesystemUUID, challenge: challenge
      )
      try sendResponse("guest-ready", to: controlDescriptor)

      // The fixture owner deliberately SIGKILLs this helper. Until then, EOF
      // is the only accepted terminal control event and destroys the in-process
      // VZVirtualMachine by exiting through the fixed error path.
      var byte: UInt8 = 0
      while true {
        let count = Darwin.read(controlDescriptor, &byte, 1)
        if count == 0 { throw IPCError.rejected(-5) }
        if count < 0 && errno == EINTR { continue }
        throw IPCError.rejected(-5)
      }
    }

    private static func sendResponse(_ result: String, to descriptor: Int32) throws {
      let bytes = Data("{\"result\":\"\(result)\",\"schemaVersion\":1}".utf8)
      try PrivateIPC.send(controlDescriptor: descriptor, response: bytes)
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
      from virtualMachine: VZVirtualMachine,
      on queue: DispatchQueue,
      challenge: Data
    ) throws -> Data {
      let deadline = Date().addingTimeInterval(readyDeadlineSeconds)
      let machine = UncheckedSendableBox(virtualMachine)
      while Date() < deadline {
        let completion = CompletionBox<VZVirtioSocketConnection>()
        queue.async {
          guard let device = machine.value.socketDevices.first as? VZVirtioSocketDevice else {
            completion.complete(.failure(ProbeError.socketUnavailable))
            return
          }
          device.connect(toPort: RunnerProtocol.inodeProbeVsockPort) { result in
            completion.complete(result)
          }
        }
        if let connection = try? completion.wait(seconds: 1) {
          defer { connection.close() }
          try writeExact(challenge, to: connection.fileDescriptor, deadline: deadline)
          return try readExact(frameBytes, from: connection.fileDescriptor, deadline: deadline)
        }
        Thread.sleep(forTimeInterval: 0.05)
      }
      throw ProbeError.timedOut
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
      guard result == 1, item.revents & events != 0 else { throw ProbeError.socketUnavailable }
    }
  }

  private enum ProbeError: Error {
    case invalidReadiness
    case randomFailed
    case socketUnavailable
    case timedOut
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
