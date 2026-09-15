import Foundation

/// Fixed control/status carrier only: no packet or authentication codec.
struct WorkloadNetworkWire {
  enum Failure: Error { case bounds, frame }
  private(set) var input = Data()
  private(set) var status = Data()
  private(set) var eventCount = 0

  static func framed(_ payload: Data) -> Data {
    let count = UInt32(payload.count)
    return Data([
      UInt8(count >> 24), UInt8((count >> 16) & 255),
      UInt8((count >> 8) & 255), UInt8(count & 255),
    ]) + payload
  }

  mutating func controls(_ bytes: Data) throws -> [Data] {
    guard bytes.count <= 1024, input.count + bytes.count <= 2048 else { throw Failure.bounds }
    input.append(bytes)
    var frames: [Data] = []
    while input.count >= 4 {
      let size = input.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
      guard size == 1 || size == 130 else { throw Failure.frame }
      guard input.count >= 4 + size else { break }
      let frame = Data(input.dropFirst(4).prefix(size))
      input.removeFirst(4 + size)
      guard frame == Data([0x51]) || (size == 130 && [0x41, 0x43].contains(frame[0]))
      else { throw Failure.frame }
      frames.append(frame)
    }
    return frames
  }

  mutating func statuses(_ bytes: Data) throws -> [Data] {
    guard bytes.count <= 1024, status.count + bytes.count <= 2048 else { throw Failure.bounds }
    status.append(bytes)
    var frames: [Data] = []
    while status.count >= 128 {
      let frame = Data(status.prefix(128))
      status.removeFirst(128)
      guard frame[8] == 2 else { throw Failure.frame }
      frames.append(try event(Data([0x52, 2]) + frame))
    }
    return frames
  }

  mutating func event(_ payload: Data) throws -> Data {
    guard eventCount < 64 else { throw Failure.bounds }
    eventCount += 1
    return Self.framed(payload)
  }
}
