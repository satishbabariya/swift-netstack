import NIOCore
import Testing

@testable import Netstack

private func template() -> IPv4Header {
    var header = IPv4Header(
        source: IPv4Address("192.168.127.1")!,
        destination: IPv4Address("192.168.127.2")!,
        protocolNumber: .udp,
        payloadLength: 0
    )
    header.identification = 0x1234
    return header
}

@Test func aPayloadThatFitsIsNotFragmented() {
    let payload = ByteBuffer(bytes: Array(repeating: UInt8(0xaa), count: 100))
    let fragments = Fragmenter.fragment(payload: payload, template: template(), mtu: 1500, allocator: ByteBufferAllocator())

    #expect(fragments.count == 1)
    var packet = PacketBuffer(received: fragments[0].frame)
    let header = IPv4Header.parse(&packet)
    #expect(header?.flags.contains(.moreFragments) == false)
    #expect(header?.fragmentOffset == 0)
    #expect(packet.readableBytes == 100)
}

@Test func splitsOnEightByteBoundaries() {
    // MTU 1500 leaves 1480 payload bytes, already a multiple of 8.
    let payload = ByteBuffer(bytes: Array(repeating: UInt8(0xbb), count: 3000))
    let fragments = Fragmenter.fragment(payload: payload, template: template(), mtu: 1500, allocator: ByteBufferAllocator())

    #expect(fragments.count == 3)
    var offsets: [Int] = []
    var moreFlags: [Bool] = []
    var lengths: [Int] = []
    for fragment in fragments {
        var packet = PacketBuffer(received: fragment.frame)
        let header = IPv4Header.parse(&packet)!
        offsets.append(header.fragmentOffset)
        moreFlags.append(header.flags.contains(.moreFragments))
        lengths.append(packet.readableBytes)
    }
    #expect(offsets == [0, 1480, 2960])
    #expect(moreFlags == [true, true, false])
    #expect(lengths == [1480, 1480, 40])
    #expect(lengths.reduce(0, +) == 3000)
}

@Test func roundsTheFragmentSizeDownToAMultipleOfEight() {
    // MTU 1005 leaves 985 payload bytes, which rounds down to 984.
    let payload = ByteBuffer(bytes: Array(repeating: UInt8(0xcc), count: 2000))
    let fragments = Fragmenter.fragment(payload: payload, template: template(), mtu: 1005, allocator: ByteBufferAllocator())

    var packet = PacketBuffer(received: fragments[0].frame)
    _ = IPv4Header.parse(&packet)
    #expect(packet.readableBytes == 984)
    #expect(packet.readableBytes % 8 == 0)
}

@Test func everyFragmentSharesTheIdentification() {
    let payload = ByteBuffer(bytes: Array(repeating: UInt8(0xdd), count: 3000))
    let fragments = Fragmenter.fragment(payload: payload, template: template(), mtu: 1500, allocator: ByteBufferAllocator())

    let ids = fragments.map { fragment -> UInt16 in
        var packet = PacketBuffer(received: fragment.frame)
        return IPv4Header.parse(&packet)!.identification
    }
    #expect(ids == [0x1234, 0x1234, 0x1234])
}

@Test func aDontFragmentPayloadThatDoesNotFitProducesNothing() {
    var header = template()
    header.flags = [.dontFragment]
    let payload = ByteBuffer(bytes: Array(repeating: UInt8(0xee), count: 3000))
    #expect(Fragmenter.fragment(payload: payload, template: header, mtu: 1500, allocator: ByteBufferAllocator()).isEmpty)
}
