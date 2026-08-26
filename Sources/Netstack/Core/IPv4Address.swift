/// A 32-bit IPv4 address, stored in host byte order.
///
/// Host order throughout the stack, converted at the wire boundary. Doing it
/// the other way round means every comparison and every subnet test carries a
/// byte-swap, and the swaps get forgotten.
public struct IPv4Address: Hashable, Sendable, CustomStringConvertible {
    public let raw: UInt32

    public init(_ raw: UInt32) {
        self.raw = raw
    }

    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        self.raw = UInt32(a) << 24 | UInt32(b) << 16 | UInt32(c) << 8 | UInt32(d)
    }

    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for part in parts {
            // Reject "01", "+1", and anything else Int would tolerate but a
            // dotted quad does not.
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isASCII), part.allSatisfy(\.isNumber),
                let value = UInt16(part), value <= 255
            else { return nil }
            octets.append(UInt8(value))
        }
        self.init(octets[0], octets[1], octets[2], octets[3])
    }

    public var bytes: [UInt8] {
        [UInt8(raw >> 24), UInt8((raw >> 16) & 0xff), UInt8((raw >> 8) & 0xff), UInt8(raw & 0xff)]
    }

    public var description: String {
        bytes.map(String.init).joined(separator: ".")
    }

    public static let any = IPv4Address(0)
    public static let broadcast = IPv4Address(0xffff_ffff)
}
