import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// The framing a stream transport needs and a datagram one does not. This is the
// first place a hostile guest reaches with a number of its own choosing, so the
// tests that matter are the ones about the number rather than the ones about
// the frames.

private func decodingChannel(maximumFrame: Int = 1514) throws -> EmbeddedChannel {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
        ByteToMessageHandler(FrameDecoder(maximumFrame: maximumFrame)))
    return channel
}

private func framed(_ bytes: [UInt8]) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt32(bytes.count), endianness: .big)
    buffer.writeBytes(bytes)
    return buffer
}

@Test func aFrameArrivesWholeOnceItsLengthIsSatisfied() throws {
    let channel = try decodingChannel()
    try channel.writeInbound(framed([1, 2, 3, 4, 5]))
    let frame = try #require(try channel.readInbound(as: ByteBuffer.self))
    #expect(Array(frame.readableBytesView) == [1, 2, 3, 4, 5])
    _ = try channel.finish()
}

@Test func twoFramesInOneReadAreBothDelivered() throws {
    // The property that makes this a *stream* decoder rather than a datagram
    // one: a single read can carry any number of frames, including a fraction
    // of the last.
    let channel = try decodingChannel()
    var buffer = framed([1, 2, 3])
    buffer.writeImmutableBuffer(framed([4, 5]))
    try channel.writeInbound(buffer)

    let first = try #require(try channel.readInbound(as: ByteBuffer.self))
    let second = try #require(try channel.readInbound(as: ByteBuffer.self))
    #expect(Array(first.readableBytesView) == [1, 2, 3])
    #expect(Array(second.readableBytesView) == [4, 5])
    _ = try channel.finish()
}

@Test func aFrameSplitAcrossReadsIsHeldUntilItIsWhole() throws {
    let channel = try decodingChannel()
    var buffer = framed([1, 2, 3, 4])
    let tail = buffer.readSlice(length: buffer.readableBytes - 2)!
    try channel.writeInbound(tail)
    #expect(try channel.readInbound(as: ByteBuffer.self) == nil, "half a frame was delivered as a frame")
    try channel.writeInbound(buffer)
    let frame = try #require(try channel.readInbound(as: ByteBuffer.self))
    #expect(Array(frame.readableBytesView) == [1, 2, 3, 4])
    _ = try channel.finish()
}

@Test func aLengthLargerThanTheWireCanCarryFailsOnTheLengthAlone() throws {
    // The bound, and the reason it is checked before the readable-bytes test.
    //
    // A guest sends four bytes claiming four gigabytes and then stops. With the
    // check in the other order the decoder returns `.needMoreData` and NIO holds
    // everything that arrives in its cumulation buffer, waiting for data that is
    // never coming — a guest deciding how much of the host's memory to occupy,
    // and a connection that looks merely slow while it does.
    let channel = try decodingChannel(maximumFrame: 1514)
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt32.max, endianness: .big)

    #expect(throws: FrameCodecError.self) {
        try channel.writeInbound(buffer)
    }
    _ = try? channel.finish()
}

@Test func aLengthOneByteOverTheMaximumIsRejected() throws {
    // The boundary, checked on both sides. A test that only tries 4 GB passes
    // against a decoder whose bound is off by a thousand.
    let channel = try decodingChannel(maximumFrame: 1514)
    var overLarge = ByteBuffer()
    overLarge.writeInteger(UInt32(1515), endianness: .big)
    #expect(throws: FrameCodecError.self) { try channel.writeInbound(overLarge) }
    _ = try? channel.finish()

    let allowed = try decodingChannel(maximumFrame: 1514)
    try allowed.writeInbound(framed([UInt8](repeating: 0, count: 1514)))
    let frame = try #require(try allowed.readInbound(as: ByteBuffer.self))
    #expect(frame.readableBytes == 1514, "the largest legal frame was rejected")
    _ = try allowed.finish()
}

@Test func aZeroLengthFrameIsAFramingErrorRatherThanAnEmptyFrame() throws {
    // Not pedantry: a zero-length frame consumes four bytes and produces
    // nothing, so a guest sending them in a loop drives the decoder without ever
    // being noticed as sending anything. There is also no such thing as an
    // ethernet frame of zero bytes, so nothing legitimate is being refused.
    let channel = try decodingChannel()
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt32(0), endianness: .big)
    #expect(throws: FrameCodecError.self) { try channel.writeInbound(buffer) }
    _ = try? channel.finish()
}

@Test func aTrailingPartialFrameIsDiscardedAtEndOfStream() throws {
    let channel = try decodingChannel()
    var buffer = framed([1, 2, 3, 4])
    let head = buffer.readSlice(length: 5)!
    try channel.writeInbound(head)
    _ = try channel.finish()
    #expect(try channel.readInbound(as: ByteBuffer.self) == nil, "half a frame survived the end of the stream")
}

@Test func theEncoderRefusesAFrameTheWireCannotCarry() throws {
    // Refuses rather than truncates, for the reason `Sender.write` does: a
    // truncated frame is one the peer will misinterpret, and because the length
    // prefix would then be wrong it takes every frame after it down too.
    var encoder = FrameEncoder(maximumFrame: 1514)
    var out = ByteBuffer()
    #expect(throws: FrameCodecError.self) {
        try encoder.encode(data: ByteBuffer(bytes: [UInt8](repeating: 0, count: 1515)), out: &out)
    }
    #expect(out.readableBytes == 0, "a refused frame still wrote something")
}

@Test func whatTheEncoderWritesIsWhatTheDecoderReads() throws {
    // The round trip, which is the only thing that checks the two halves agree
    // about byte order. A decoder and encoder that both used little-endian would
    // pass every test above and fail against qemu.
    var encoder = FrameEncoder(maximumFrame: 1514)
    var wire = ByteBuffer()
    let payload = ByteBuffer(bytes: [0xde, 0xad, 0xbe, 0xef])
    try encoder.encode(data: payload, out: &wire)
    #expect(Array(wire.readableBytesView.prefix(4)) == [0, 0, 0, 4], "the length is not four bytes big-endian")

    let channel = try decodingChannel()
    try channel.writeInbound(wire)
    let frame = try #require(try channel.readInbound(as: ByteBuffer.self))
    #expect(frame == payload)
    _ = try channel.finish()
}
