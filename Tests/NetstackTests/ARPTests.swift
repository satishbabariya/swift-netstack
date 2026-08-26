import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func arpFrame(operation: UInt16, senderMAC: String, senderIP: String, targetMAC: String, targetIP: String) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt16(1), endianness: .big)        // hardware: ethernet
    buffer.writeInteger(UInt16(0x0800), endianness: .big)   // protocol: IPv4
    buffer.writeInteger(UInt8(6))                           // hardware length
    buffer.writeInteger(UInt8(4))                           // protocol length
    buffer.writeInteger(operation, endianness: .big)
    buffer.writeBytes(MACAddress(senderMAC)!.bytes)
    buffer.writeBytes(IPv4Address(senderIP)!.bytes)
    buffer.writeBytes(MACAddress(targetMAC)!.bytes)
    buffer.writeBytes(IPv4Address(targetIP)!.bytes)
    return buffer
}

@Test func parsesAnARPRequest() {
    var packet = PacketBuffer(received: arpFrame(
        operation: 1, senderMAC: "0a:0b:0c:0d:0e:0f", senderIP: "192.168.127.2",
        targetMAC: "00:00:00:00:00:00", targetIP: "192.168.127.1"))
    let arp = ARPPacket.parse(&packet)

    #expect(arp?.operation == .request)
    #expect(arp?.senderIP == IPv4Address("192.168.127.2"))
    #expect(arp?.targetIP == IPv4Address("192.168.127.1"))
    #expect(arp?.senderMAC == MACAddress("0a:0b:0c:0d:0e:0f"))
}

@Test func rejectsNonEthernetOrNonIPv4ARP() {
    var wrongHardware = PacketBuffer(received: {
        var b = arpFrame(operation: 1, senderMAC: "0a:0b:0c:0d:0e:0f", senderIP: "1.2.3.4",
                         targetMAC: "00:00:00:00:00:00", targetIP: "1.2.3.5")
        b.setInteger(UInt16(6), at: 0, endianness: .big)  // not ethernet
        return b
    }())
    #expect(ARPPacket.parse(&wrongHardware) == nil)

    var truncated = PacketBuffer(received: ByteBuffer(bytes: [0x00, 0x01, 0x08, 0x00]))
    #expect(ARPPacket.parse(&truncated) == nil)
}

@Test func cacheExpiresEntries() {
    let clock = ManualClock()
    let cache = ARPCache(clock: clock, ttl: .seconds(60))
    cache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    #expect(cache.lookup(IPv4Address("192.168.127.2")!) == MACAddress("0a:0b:0c:0d:0e:0f"))

    clock.advance(by: .seconds(59))
    #expect(cache.lookup(IPv4Address("192.168.127.2")!) != nil)
    clock.advance(by: .seconds(2))
    #expect(cache.lookup(IPv4Address("192.168.127.2")!) == nil)
}

@Test func cacheRefreshesOnRecord() {
    let clock = ManualClock()
    let cache = ARPCache(clock: clock, ttl: .seconds(60))
    cache.record(IPv4Address("10.0.0.1")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    clock.advance(by: .seconds(50))
    cache.record(IPv4Address("10.0.0.1")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    clock.advance(by: .seconds(50))
    #expect(cache.lookup(IPv4Address("10.0.0.1")!) != nil)
}

@Test func respondsToARequestForOurAddress() {
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    let cache = ARPCache(clock: ManualClock(), ttl: .seconds(60))
    let responder = ARPResponder(nic: nic, cache: cache, allocator: ByteBufferAllocator())
    nic.setHandler(for: .arp) { packet, ethernet in responder.handle(packet, ethernet) }

    var request = ByteBuffer()
    request.writeBytes(MACAddress.broadcast.bytes)
    request.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    request.writeInteger(UInt16(0x0806), endianness: .big)
    var payload = arpFrame(operation: 1, senderMAC: "0a:0b:0c:0d:0e:0f", senderIP: "192.168.127.2",
                           targetMAC: "00:00:00:00:00:00", targetIP: "192.168.127.1")
    request.writeBuffer(&payload)
    link.inject(request)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var reply = PacketBuffer(received: frames[0])
    let ethernet = EthernetHeader.parse(&reply)
    #expect(ethernet?.etherType == .arp)
    #expect(ethernet?.destination == MACAddress("0a:0b:0c:0d:0e:0f"))
    let arp = ARPPacket.parse(&reply)
    #expect(arp?.operation == .reply)
    #expect(arp?.senderIP == IPv4Address("192.168.127.1"))
    #expect(arp?.senderMAC == MACAddress("5a:94:ef:e4:0c:ee"))
    // The requester's binding is learned from the request itself.
    #expect(cache.lookup(IPv4Address("192.168.127.2")!) == MACAddress("0a:0b:0c:0d:0e:0f"))
}

@Test func ignoresRequestsForAddressesWeDoNotOwn() {
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    let cache = ARPCache(clock: ManualClock(), ttl: .seconds(60))
    let responder = ARPResponder(nic: nic, cache: cache, allocator: ByteBufferAllocator())

    var packet = PacketBuffer(received: arpFrame(
        operation: 1, senderMAC: "0a:0b:0c:0d:0e:0f", senderIP: "192.168.127.2",
        targetMAC: "00:00:00:00:00:00", targetIP: "192.168.127.99"))
    let ethernet = EthernetHeader(destination: .broadcast, source: MACAddress("0a:0b:0c:0d:0e:0f")!, etherType: .arp)
    responder.handle(packet, ethernet)
    #expect(link.drainTransmitted().isEmpty)
}

@Test func learnsFromReplies() {
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    let cache = ARPCache(clock: ManualClock(), ttl: .seconds(60))
    let responder = ARPResponder(nic: nic, cache: cache, allocator: ByteBufferAllocator())

    let packet = PacketBuffer(received: arpFrame(
        operation: 2, senderMAC: "0a:0b:0c:0d:0e:0f", senderIP: "192.168.127.2",
        targetMAC: "5a:94:ef:e4:0c:ee", targetIP: "192.168.127.1"))
    responder.handle(packet, EthernetHeader(destination: link.linkAddress, source: MACAddress("0a:0b:0c:0d:0e:0f")!, etherType: .arp))

    #expect(cache.lookup(IPv4Address("192.168.127.2")!) == MACAddress("0a:0b:0c:0d:0e:0f"))
    #expect(link.drainTransmitted().isEmpty)  // a reply is not answered
}
