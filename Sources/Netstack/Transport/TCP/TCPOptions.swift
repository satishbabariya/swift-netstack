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
/// One selectively acknowledged range, half-open: `right` is the sequence
/// number just past the last byte, exactly as it goes on the wire.
struct SACKBlock: Equatable, Sendable {
    var left: SequenceNumber
    var right: SequenceNumber

    var length: Int { right - left }
}

enum TCPOption: Equatable, Sendable {
    case maximumSegmentSize(UInt16)
    /// Shift count. When this comes from `TCPOptionCodec.parse` it is at
    /// most 14 — see `TCPOptionCodec.maximumWindowScale` for why a peer does
    /// not get to choose a larger one.
    case windowScale(UInt8)
    case sackPermitted
    /// Selectively acknowledged ranges, each `[left, right)`. RFC 2018 §3
    /// allows at most four in a 40-byte options area, and fewer once anything
    /// else is present -- `TCPOptionCodec.maximumSackBlocks(alongside:)` is
    /// what decides, rather than a constant that would be wrong the day a
    /// timestamp joined them.
    case selectiveAcknowledgement([SACKBlock])
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
    private static let sackKind: UInt8 = 5
    private static let timestampsKind: UInt8 = 8

    /// The largest window scale this stack will honour from a peer. RFC 7323
    /// §2.3: "If a Window Scale option is received with a shift.cnt value
    /// larger than 14, the TCP SHOULD log the error but MUST use 14 instead
    /// of the specified value." So a larger shift is clamped, not rejected —
    /// the option stays present and negotiated, only its shift is bounded.
    /// (The RFC's SHOULD-log has no receiver here: the codec is a pure
    /// decoder with no logger, so the clamp is silent.)
    ///
    /// 14 is not arbitrary, and the arithmetic is worth spelling out because
    /// the next reader will ask why not 15. Serial-number comparison —
    /// `SequenceNumber`, and the `isInRange` family built on it — is only
    /// meaningful over less than half the sequence space. The sender's and
    /// receiver's windows can be out of phase by as much as a full window,
    /// so RFC 7323 §2.3 derives its bound from *twice* the maximum window
    /// having to stay under 2^31, i.e. a maximum window below 2^30. A shift
    /// of 14 gives 65535 << 14 = 1,073,725,440 bytes, just under
    /// 2^30 = 1,073,741,824. A shift of 15 gives 2,147,450,880, which is
    /// itself just under 2^31 — the reason 15 is excluded is not that one
    /// window overruns the half-space but that two out-of-phase ones do,
    /// which is exactly when a comparison stops meaning anything.
    ///
    /// `TCB.negotiateWindowScale(fromSynOptions:)` **depends on this clamp** and
    /// re-checks nothing: it records whatever shift reaches it as
    /// `TCB.sndWindScale`, on the guarantee that it is at most 14. Moving or
    /// relaxing the bound here changes what a peer can make this stack
    /// left-shift a window by.
    private static let maximumWindowScale: UInt8 = 14

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
                // Bounded per `maximumWindowScale` above. The option's shape
                // is validated first, so a malformed one is still rejected
                // rather than clamped into looking well-formed.
                options.append(.windowScale(min(shift, maximumWindowScale)))
            case sackPermittedKind:
                guard valueLength == 0 else { return nil }
                options.append(.sackPermitted)
            case sackKind:
                // Two 32-bit edges per block, so anything not a multiple of
                // eight is malformed rather than truncatable. A zero-block
                // option is malformed too: the option exists to carry blocks.
                guard valueLength > 0, valueLength % 8 == 0 else { return nil }
                var blocks: [SACKBlock] = []
                for _ in 0..<(valueLength / 8) {
                    guard let left = bytes.readInteger(endianness: .big, as: UInt32.self),
                        let right = bytes.readInteger(endianness: .big, as: UInt32.self)
                    else { return nil }
                    blocks.append(SACKBlock(left: SequenceNumber(left), right: SequenceNumber(right)))
                }
                options.append(.selectiveAcknowledgement(blocks))
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

    /// How many SACK blocks still fit once `others` have taken their space.
    ///
    /// Derived rather than fixed. RFC 2018 §3's "four blocks" is the figure for
    /// an otherwise empty options area; a timestamp takes twelve bytes with its
    /// own padding and drops it to three, and a constant would have been
    /// silently wrong from the moment timestamps were negotiated. The
    /// arithmetic: the area is 40 bytes, and the option costs `2 + 2 + 8n` --
    /// two NOPs to align its 32-bit edges, then its kind and length.
    static func maximumSackBlocks(alongside others: [TCPOption]) -> Int {
        // `encode` pads its result to a word, so `used` can overstate the room
        // the other options really take by up to three bytes. That direction is
        // safe -- it can only reserve one block fewer than would have fit -- and
        // the alternative is an unpadded encoder that exists solely to be
        // measured.
        let used = encode(others).count
        let aligned = used + (2 + 4 - used % 4) % 4
        let available = maximumOptionsBytes - aligned - 2 /* kind and length */
        return max(0, min(4, available / 8))
    }

    /// The options area is what a header's four-bit data offset can address
    /// beyond the fixed twenty bytes: (15 - 5) words.
    static let maximumOptionsBytes = 40

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
            case .selectiveAcknowledgement(let blocks):
                guard !blocks.isEmpty else { continue }
                // NOPs first, and they are alignment rather than padding. The
                // option's payload is 32-bit sequence numbers behind a two-byte
                // kind and length, so the edges land on a word boundary only if
                // the option itself starts two bytes short of one. RFC 2018 §3
                // lays it out this way and every real stack emits it so.
                //
                // Written as "pad until two bytes short of a boundary" rather
                // than the customary literal `NOP NOP`, because the literal is
                // only correct from an already-aligned position. Beside a
                // timestamp -- ten bytes, which this encoder does not pad
                // individually -- two NOPs would leave the edges at byte 14. The
                // first version did exactly that, and a test asserting the
                // boundary is what caught it.
                while bytes.count % 4 != 2 { bytes.append(noOperation) }
                bytes += [sackKind, UInt8(2 + blocks.count * 8)]
                for block in blocks {
                    for edge in [block.left.value, block.right.value] {
                        bytes += [
                            UInt8(edge >> 24), UInt8((edge >> 16) & 0xff), UInt8((edge >> 8) & 0xff),
                            UInt8(edge & 0xff),
                        ]
                    }
                }
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
