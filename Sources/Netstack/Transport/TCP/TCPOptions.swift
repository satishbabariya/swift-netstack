import NIOCore

/// A single TCP option, decoded from (or to be encoded into) the options
/// area that follows a `TCPHeader`'s fixed 20 bytes. Kind numbers are IANA
/// TCP option kind numbers.
///
/// `.unknown(kind:)` captures an option kind this stack does not implement.
/// Per RFC 793 §3.1, an option kind we do not recognize is not an error — a
/// peer is free to send options we know nothing about — so parsing records
/// that one was there (by kind) rather than aborting or silently dropping
/// it.
enum TCPOption: Equatable, Sendable {
    case maximumSegmentSize(UInt16)
    case windowScale(UInt8)
    case sackPermitted
    case timestamps(value: UInt32, echo: UInt32)
    case unknown(kind: UInt8)
}

/// Encoding and decoding for the options area of a TCP header.
///
/// Deliberately independent of `Tests/NetstackTests/Support/VectorFrames.swift`'s
/// own TCP option encoder — see that file's doc comment for why a second,
/// unrelated implementation of the same wire format is the point.
enum TCPOptionCodec {
    private static let endOfOptionList: UInt8 = 0
    private static let noOperation: UInt8 = 1
    private static let maximumSegmentSizeKind: UInt8 = 2
    private static let windowScaleKind: UInt8 = 3
    private static let sackPermittedKind: UInt8 = 4
    private static let timestampsKind: UInt8 = 8

    /// Decode the options area of a TCP header. `bytes` must hold exactly
    /// the options bytes (`dataOffset * 4 - TCPHeader.minimumLength` of
    /// them) — nothing before or after; the caller is responsible for
    /// slicing that span out first.
    ///
    /// Returns nil for anything malformed. In particular, an option whose
    /// declared length is below 2 is rejected outright rather than skipped:
    /// the length byte is defined to cover the kind and length bytes
    /// themselves, so a declared length of 0 or 1 can never be advanced
    /// past. A parser that blindly does `index += length` spins forever on
    /// such a value — re-reading the same kind byte on every iteration —
    /// which turns one malformed segment from a remote peer into a hang.
    /// Every path through this loop either returns nil immediately or
    /// consumes at least one byte from `bytes` before looping again, so it
    /// always terminates.
    static func parse(_ bytes: inout ByteBuffer) -> [TCPOption]? {
        var options: [TCPOption] = []
        while bytes.readableBytes > 0 {
            guard let kind = bytes.readInteger(as: UInt8.self) else { return nil }
            if kind == endOfOptionList { break }
            if kind == noOperation { continue }  // no length byte follows a NOP

            guard let length = bytes.readInteger(as: UInt8.self), length >= 2 else { return nil }
            let valueLength = Int(length) - 2
            guard valueLength <= bytes.readableBytes else { return nil }

            switch kind {
            case maximumSegmentSizeKind:
                guard valueLength == 2, let value = bytes.readInteger(endianness: .big, as: UInt16.self) else { return nil }
                options.append(.maximumSegmentSize(value))
            case windowScaleKind:
                guard valueLength == 1, let shift = bytes.readInteger(as: UInt8.self) else { return nil }
                options.append(.windowScale(shift))
            case sackPermittedKind:
                guard valueLength == 0 else { return nil }
                options.append(.sackPermitted)
            case timestampsKind:
                guard valueLength == 8,
                    let value = bytes.readInteger(endianness: .big, as: UInt32.self),
                    let echo = bytes.readInteger(endianness: .big, as: UInt32.self)
                else { return nil }
                options.append(.timestamps(value: value, echo: echo))
            default:
                // An option kind we don't implement: skip its declared value
                // bytes rather than treating the option, or the segment, as
                // an error.
                guard bytes.readSlice(length: valueLength) != nil else { return nil }
                options.append(.unknown(kind: kind))
            }
        }
        return options
    }

    /// Encode options to wire bytes, padded with NOP (kind 1) to a 4-byte
    /// boundary — the header's data offset is in 32-bit words, so the
    /// options area must land on one. `.unknown` cannot be re-encoded (this
    /// stack never produces an option it does not itself understand), so it
    /// is dropped rather than serialized.
    static func encode(_ options: [TCPOption]) -> [UInt8] {
        var bytes: [UInt8] = []
        for option in options {
            switch option {
            case .maximumSegmentSize(let value):
                bytes += [maximumSegmentSizeKind, 4, UInt8(value >> 8), UInt8(value & 0xff)]
            case .windowScale(let shift):
                bytes += [windowScaleKind, 3, shift]
            case .sackPermitted:
                bytes += [sackPermittedKind, 2]
            case .timestamps(let value, let echo):
                bytes += [timestampsKind, 10]
                bytes += [UInt8(value >> 24), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
                bytes += [UInt8(echo >> 24), UInt8((echo >> 16) & 0xff), UInt8((echo >> 8) & 0xff), UInt8(echo & 0xff)]
            case .unknown:
                continue
            }
        }
        while bytes.count % 4 != 0 {
            bytes.append(noOperation)
        }
        return bytes
    }
}
