import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func makeNIC(promiscuous: Bool = false) -> (NIC, RecordingEndpoint) {
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.acceptsAnyDestination = promiscuous
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    return (nic, link)
}

private func frame(to destination: String, etherType: UInt16, payload: [UInt8]) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeBytes(MACAddress(destination)!.bytes)
    buffer.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    buffer.writeInteger(etherType, endianness: .big)
    buffer.writeBytes(payload)
    return buffer
}

@Test func deliversFramesAddressedToUs() {
    let (nic, link) = makeNIC()
    var seen: [UInt8] = []
    nic.setHandler(for: .ipv4) { packet, _ in seen = Array(packet.payload.readableBytesView) }

    link.inject(frame(to: "5a:94:ef:e4:0c:ee", etherType: 0x0800, payload: [0xaa]))
    #expect(seen == [0xaa])
}

@Test func deliversBroadcastFrames() {
    let (nic, link) = makeNIC()
    var count = 0
    nic.setHandler(for: .arp) { _, _ in count += 1 }

    link.inject(frame(to: "ff:ff:ff:ff:ff:ff", etherType: 0x0806, payload: [0xaa]))
    #expect(count == 1)
}

@Test func dropsFramesForOtherHostsUnlessPromiscuous() {
    let (nic, link) = makeNIC(promiscuous: false)
    var count = 0
    nic.setHandler(for: .ipv4) { _, _ in count += 1 }
    link.inject(frame(to: "aa:bb:cc:dd:ee:ff", etherType: 0x0800, payload: [0xaa]))
    #expect(count == 0)

    let (promiscuousNIC, promiscuousLink) = makeNIC(promiscuous: true)
    var promiscuousCount = 0
    promiscuousNIC.setHandler(for: .ipv4) { _, _ in promiscuousCount += 1 }
    promiscuousLink.inject(frame(to: "aa:bb:cc:dd:ee:ff", etherType: 0x0800, payload: [0xaa]))
    #expect(promiscuousCount == 1)
}

@Test func dropsFramesWithNoHandlerForTheirEtherType() {
    let (nic, link) = makeNIC()
    // A handler exists for IPv4. An IPv6 frame must not reach it, and must
    // not trap. Asserting "nothing was transmitted" would prove nothing:
    // the receive path never transmits, so that is true either way.
    var ipv4Deliveries = 0
    nic.setHandler(for: .ipv4) { _, _ in ipv4Deliveries += 1 }

    link.inject(frame(to: "5a:94:ef:e4:0c:ee", etherType: 0x86dd, payload: [0xaa]))
    #expect(ipv4Deliveries == 0)

    // And the NIC still works afterwards, so the drop was selective rather
    // than the handler table being broken outright.
    link.inject(frame(to: "5a:94:ef:e4:0c:ee", etherType: 0x0800, payload: [0xbb]))
    #expect(ipv4Deliveries == 1)
}

@Test func dropsRuntFrames() {
    let (nic, link) = makeNIC()
    var count = 0
    nic.setHandler(for: .ipv4) { _, _ in count += 1 }
    link.inject(ByteBuffer(bytes: [0x01, 0x02, 0x03]))
    #expect(count == 0)
}

@Test func sendPrependsEthernetAndWrites() {
    let (nic, link) = makeNIC()
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0x99]))
    nic.send(&packet, to: MACAddress("0a:0b:0c:0d:0e:0f")!, etherType: .ipv4)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    #expect(
        Array(frames[0].readableBytesView) == [
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee,
            0x08, 0x00,
            0x99,
        ])
}

@Test func tracksItsAddresses() {
    let (nic, _) = makeNIC()
    #expect(nic.hasAddress(IPv4Address("192.168.127.1")!))
    #expect(!nic.hasAddress(IPv4Address("192.168.127.2")!))
    #expect(nic.primaryAddress == IPv4Address("192.168.127.1"))
}

@Test func aNICNamesTheSubnetAnAddressOfItsBelongsTo() {
    // The one public function in this package that nothing called and nothing
    // tested, found by sweeping the public surface for symbols with no
    // reference in `Sources` or `Tests`. Six others came up and all six are
    // NIO protocol requirements -- `getOption`, `localAddress`,
    // `triggerUserOutboundEvent` and the rest -- which NIO calls rather than
    // this package, so they are reached even though nothing here names them.
    //
    // Untested public API on a library is a commitment nobody has checked.
    // This one turned out to be right, which is worth knowing rather than
    // assuming: the answer is the NETWORK, not the address that was asked
    // about, and it is `IPv4Subnet`'s initialiser that masks it rather than
    // anything here. A version that kept the host bits would have been wrong in
    // a way no caller existed to notice.
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    nic.addAddress(IPv4Address("10.1.2.3")!, prefixLength: 8)

    #expect(nic.subnet(for: IPv4Address("192.168.127.1")!) == IPv4Subnet(cidr: "192.168.127.0/24"))
    #expect(nic.subnet(for: IPv4Address("10.1.2.3")!) == IPv4Subnet(cidr: "10.0.0.0/8"))
    #expect(
        nic.subnet(for: IPv4Address("192.168.127.2")!) == nil,
        "an address this NIC does not hold has no subnet here to name")
}
