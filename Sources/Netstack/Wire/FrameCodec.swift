import NIOCore

/// How a stream wire says where one frame ends and the next begins.
///
/// There are two, and they are not compatible: reading one as the other gives a
/// length that is not a length, so the first frame is wrong and every byte after
/// it is garbage. Upstream picks between them by the `--listen` URL scheme, and
/// a client that guesses wrong sees a connection that closes immediately with a
/// framing error rather than anything that names the mismatch -- which is worth
/// knowing before debugging one.
public enum StreamFraming: Sendable {
    /// Four bytes, big-endian. qemu's `-netdev socket`, and with it bess and
    /// stdio.
    case qemu
    /// Two bytes, little-endian. hyperkit and vpnkit, and the default upstream
    /// uses for a guest that joins over its own `/connect` endpoint.
    case hyperkit

    var lengthBytes: Int {
        switch self {
        case .qemu: return 4
        case .hyperkit: return 2
        }
    }

    /// The largest length the prefix itself can express. Two bytes cannot say
    /// more than 65535 whatever the link's MTU is, so the frame bound is the
    /// smaller of this and the wire's.
    var greatestExpressibleLength: Int {
        switch self {
        case .qemu: return Int(UInt32.max)
        case .hyperkit: return Int(UInt16.max)
        }
    }

    func length(from buffer: ByteBuffer, at index: Int) -> Int? {
        switch self {
        case .qemu:
            return buffer.getInteger(at: index, endianness: .big, as: UInt32.self).map(Int.init)
        case .hyperkit:
            return buffer.getInteger(at: index, endianness: .little, as: UInt16.self).map(Int.init)
        }
    }

    func write(_ length: Int, to buffer: inout ByteBuffer) {
        switch self {
        case .qemu: buffer.writeInteger(UInt32(length), endianness: .big)
        case .hyperkit: buffer.writeInteger(UInt16(length), endianness: .little)
        }
    }
}

/// The framing qemu's `-netdev socket` uses, and with it bess and stdio: a
/// four-byte big-endian length, then that many bytes of ethernet frame.
///
/// ## Why a stream transport needs framing at all, and a datagram one does not
///
/// The premise the whole gateway rests on is that one datagram is one ethernet
/// frame. A datagram socket preserves that for free — the kernel keeps the
/// boundaries. A stream socket does not: it delivers bytes, and something has to
/// say where one frame ends. The length prefix is that something, and it is
/// **guest-controlled**, which makes this the first place a hostile guest can
/// reach with a number of its own choosing.
///
/// ## The bound is the point
///
/// A length is checked against `maximumFrame` before a single byte is reserved
/// for it. Without that check a guest sends `0xFFFFFFFF` and the decoder waits
/// for four gigabytes -- either allocating them or, in NIO's case, holding
/// everything that arrives in the cumulation buffer forever while the connection
/// looks merely slow. Neither is a crash to point at afterwards; both are a
/// guest deciding how much of the host's memory it would like to occupy.
///
/// A frame that claims more than the link can carry is not truncated to fit,
/// because there is no honest way to interpret it: the sender and this decoder
/// disagree about where the next frame starts, so every byte after it is
/// garbage. The connection is failed instead, which is what a framing error
/// means.
struct FrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer

    /// The largest frame this decoder will assemble. Anything claiming more is
    /// a framing error, not a large frame.
    let maximumFrame: Int
    let framing: StreamFraming

    init(maximumFrame: Int, framing: StreamFraming = .qemu) {
        // A two-byte prefix cannot describe a frame longer than 65535 however
        // large the MTU is, so the bound is the smaller of the two. Taking the
        // MTU alone would leave a decoder willing to accept a length its own
        // prefix could not have written.
        self.maximumFrame = max(1, min(maximumFrame, framing.greatestExpressibleLength))
        self.framing = framing
    }

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = framing.length(from: buffer, at: buffer.readerIndex) else {
            return .needMoreData
        }
        // Checked BEFORE the readable-bytes test, so an impossible length is
        // rejected on the four bytes that carry it rather than after waiting for
        // data that is never coming. The order is the whole difference between
        // bounding the guest and merely noticing afterwards.
        guard length > 0, length <= maximumFrame else {
            throw FrameCodecError.frameTooLarge(claimed: UInt32(length), maximum: maximumFrame)
        }
        guard buffer.readableBytes >= framing.lengthBytes + length else { return .needMoreData }

        buffer.moveReaderIndex(forwardBy: framing.lengthBytes)
        // `readSlice` cannot fail here -- the guard above is exactly its
        // precondition -- but the failure branch throws rather than
        // force-unwrapping, because "cannot fail" is a claim about today's
        // guard and the crash would be the guest's to trigger.
        guard let frame = buffer.readSlice(length: length) else {
            throw FrameCodecError.frameTooLarge(claimed: UInt32(length), maximum: maximumFrame)
        }
        context.fireChannelRead(wrapInboundOut(frame))
        return .continue
    }

    mutating func decodeLast(
        context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool
    ) throws -> DecodingState {
        // A trailing partial frame is discarded rather than delivered. Half a
        // frame is not a frame, and the peer that would have finished it is
        // gone.
        try decode(context: context, buffer: &buffer)
    }
}

/// The encoder half. Refuses rather than truncates, for the same reason
/// `Sender.write` does: a truncated frame is a frame the peer will
/// misinterpret, and it takes the next one down with it.
struct FrameEncoder: MessageToByteEncoder {
    typealias OutboundIn = ByteBuffer

    let maximumFrame: Int
    let framing: StreamFraming

    init(maximumFrame: Int, framing: StreamFraming = .qemu) {
        self.maximumFrame = max(1, min(maximumFrame, framing.greatestExpressibleLength))
        self.framing = framing
    }

    func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        guard data.readableBytes > 0, data.readableBytes <= maximumFrame else {
            throw FrameCodecError.frameTooLarge(claimed: UInt32(data.readableBytes), maximum: maximumFrame)
        }
        framing.write(data.readableBytes, to: &out)
        out.writeImmutableBuffer(data)
    }
}

public enum FrameCodecError: Error, Equatable, CustomStringConvertible {
    /// A length prefix claimed more than the wire can carry.
    case frameTooLarge(claimed: UInt32, maximum: Int)

    public var description: String {
        switch self {
        case .frameTooLarge(let claimed, let maximum):
            return "a frame claiming \(claimed) bytes arrived on a wire carrying at most \(maximum)"
        }
    }
}
