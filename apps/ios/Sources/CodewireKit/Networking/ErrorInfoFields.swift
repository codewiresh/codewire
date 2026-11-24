import Foundation

/// The reason and domain of a `google.rpc.ErrorInfo` a Connect error carries
/// as a base64 protobuf detail: fields 1 and 2, both strings. Every other
/// field, such as its metadata, is skipped.
struct ErrorInfoFields: Equatable {
    var reason = ""
    var domain = ""

    init(reason: String, domain: String) {
        self.reason = reason
        self.domain = domain
    }

    init?(base64 value: String) {
        // Connect may leave out the padding.
        let padded = value + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: padded) else { return nil }
        let bytes = [UInt8](data)
        var index = 0
        func varint() -> UInt64? {
            var result: UInt64 = 0
            var shift: UInt64 = 0
            while index < bytes.count, shift < 64 {
                let byte = bytes[index]
                index += 1
                result |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 { return result }
                shift += 7
            }
            return nil
        }
        while index < bytes.count {
            guard let key = varint() else { return nil }
            switch key & 0x7 {
            case 0:
                guard varint() != nil else { return nil }
            case 1:
                index += 8
            case 2:
                guard let length = varint(), length <= UInt64(bytes.count - index) else { return nil }
                let end = index + Int(length)
                if key >> 3 == 1 || key >> 3 == 2 {
                    guard let text = String(bytes: bytes[index..<end], encoding: .utf8) else { return nil }
                    if key >> 3 == 1 { reason = text } else { domain = text }
                }
                index = end
            case 5:
                index += 4
            default:
                return nil
            }
        }
        guard index == bytes.count else { return nil }
    }
}
