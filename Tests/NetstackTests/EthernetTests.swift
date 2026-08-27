import NIOCore
import Testing

@testable import Netstack

@Test func parsesAnEthernetHeader() {
    let frame = ByteBuffer(bytes: [
        0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee,  // destination
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,  // source
        0x08, 0x00,  // IPv4
        0xde, 0xad,  // payload
    ])
    var packet = PacketBuffer(received: frame)
    let header = EthernetHeader.parse(&packet)

    #expect(header?.destination == MACAddress("5a:94:ef:e4:0c:ee"))
    #expect(header?.source == MACAddress("0a:0b:0c:0d:0e:0f"))
    #expect(header?.etherType == .ipv4)
    #expect(Array(packet.payload.readableBytesView) == [0xde, 0xad])
    #expect(packet.linkHeaderLength == 14)
}

@Test func rejectsARunt() {
    var packet = PacketBuffer(received: ByteBuffer(bytes: [0x01, 0x02, 0x03]))
    let parsed = EthernetHeader.parse(&packet)
    #expect(parsed == nil)
}

@Test func prependsAnEthernetHeader() {
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0xde, 0xad]))
    let header = EthernetHeader(
        destination: MACAddress("5a:94:ef:e4:0c:ee")!,
        source: MACAddress("0a:0b:0c:0d:0e:0f")!,
        etherType: .arp
    )
    header.prepend(to: &packet)

    #expect(Array(packet.frame.readableBytesView) == [
        0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x08, 0x06,
        0xde, 0xad,
    ])
}

@Test func headerRoundTrips() {
    var outgoing = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0x01]))
    let original = EthernetHeader(
        destination: MACAddress.broadcast,
        source: MACAddress("0a:0b:0c:0d:0e:0f")!,
        etherType: .ipv4
    )
    original.prepend(to: &outgoing)

    var incoming = PacketBuffer(received: outgoing.frame)
    let parsed = EthernetHeader.parse(&incoming)
    #expect(parsed?.destination == original.destination)
    #expect(parsed?.source == original.source)
    #expect(parsed?.etherType == original.etherType)
}
