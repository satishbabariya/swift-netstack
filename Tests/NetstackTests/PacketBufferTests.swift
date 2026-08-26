import NIOCore
import Testing

@testable import Netstack

@Test func prependingHeadersDoesNotReallocate() {
    let allocator = ByteBufferAllocator()
    var packet = PacketBuffer(allocator: allocator, payload: ByteBuffer(bytes: [0xaa, 0xbb]))
    let capacityBefore = packet.frame.capacity

    packet.prepend([0x01, 0x02, 0x03, 0x04])  // transport
    packet.prepend([0x05, 0x06])  // network
    packet.prepend([0x07])  // link

    #expect(packet.frame.capacity == capacityBefore)
    #expect(Array(packet.frame.readableBytesView) == [0x07, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb])
}

@Test func consumingHeadersWalksDownTheLayers() {
    var packet = PacketBuffer(received: ByteBuffer(bytes: [0x07, 0x05, 0x06, 0xaa, 0xbb]))
    let link = packet.consumeHeader(1)
    #expect(link.map { Array($0.readableBytesView) } == [0x07])
    let network = packet.consumeHeader(2)
    #expect(network.map { Array($0.readableBytesView) } == [0x05, 0x06])
    #expect(Array(packet.payload.readableBytesView) == [0xaa, 0xbb])
    #expect(packet.readableBytes == 2)
}

@Test func consumingMoreThanIsPresentFails() {
    var packet = PacketBuffer(received: ByteBuffer(bytes: [0x01, 0x02]))
    #expect(packet.consumeHeader(3) == nil)
    // The failed consume must not have advanced anything.
    #expect(packet.readableBytes == 2)
}

@Test func cloneIsIndependent() {
    var original = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0x01]))
    var copy = original.clone()
    copy.prepend([0xff])
    #expect(Array(original.frame.readableBytesView) == [0x01])
    #expect(Array(copy.frame.readableBytesView) == [0xff, 0x01])
}

@Test func prependWithWriterFillsInPlace() {
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0x99]))
    packet.prepend(count: 4) { buffer, index in
        buffer.setInteger(UInt32(0xdead_beef), at: index, endianness: .big)
    }
    #expect(Array(packet.frame.readableBytesView) == [0xde, 0xad, 0xbe, 0xef, 0x99])
}

@Test func receivedBufferHasNoHeadroomButStillClones() {
    let packet = PacketBuffer(received: ByteBuffer(bytes: [0x01, 0x02, 0x03]))
    #expect(packet.readableBytes == 3)
    #expect(Array(packet.clone().frame.readableBytesView) == [0x01, 0x02, 0x03])
}

@Test func headroomFitsTheWorstCaseTCPSegment() {
    // ethernet 14 + IPv4 20 + TCP 60 = 94 bytes of headers. This is the
    // largest stack of headers this package will ever prepend, and the
    // default headroom must absorb it without growing the buffer.
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0xaa]))
    let capacityBefore = packet.frame.capacity
    packet.prepend(Array(repeating: UInt8(0x01), count: 60))  // TCP with full options
    packet.prepend(Array(repeating: UInt8(0x02), count: 20))  // IPv4, no options
    packet.prepend(Array(repeating: UInt8(0x03), count: 14))  // ethernet
    #expect(packet.frame.capacity == capacityBefore)
    #expect(packet.readableBytes == 95)
    #expect(packet.transportHeaderLength == 60)
    #expect(packet.networkHeaderLength == 20)
    #expect(packet.linkHeaderLength == 14)
}
