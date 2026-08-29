import NIOCore

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

    private static let lengthBytes = 4

    init(maximumFrame: Int) {
        self.maximumFrame = max(1, maximumFrame)
    }

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, endianness: .big, as: UInt32.self) else {
            return .needMoreData
        }
        // Checked BEFORE the readable-bytes test, so an impossible length is
        // rejected on the four bytes that carry it rather than after waiting for
        // data that is never coming. The order is the whole difference between
        // bounding the guest and merely noticing afterwards.
        guard length > 0, length <= UInt32(maximumFrame) else {
            throw FrameCodecError.frameTooLarge(claimed: length, maximum: maximumFrame)
        }
        guard buffer.readableBytes >= Self.lengthBytes + Int(length) else { return .needMoreData }

        buffer.moveReaderIndex(forwardBy: Self.lengthBytes)
        // `readSlice` cannot fail here -- the guard above is exactly its
        // precondition -- but the failure branch throws rather than
        // force-unwrapping, because "cannot fail" is a claim about today's
        // guard and the crash would be the guest's to trigger.
        guard let frame = buffer.readSlice(length: Int(length)) else {
            throw FrameCodecError.frameTooLarge(claimed: length, maximum: maximumFrame)
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

    func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        guard data.readableBytes > 0, data.readableBytes <= maximumFrame else {
            throw FrameCodecError.frameTooLarge(claimed: UInt32(data.readableBytes), maximum: maximumFrame)
        }
        out.writeInteger(UInt32(data.readableBytes), endianness: .big)
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
