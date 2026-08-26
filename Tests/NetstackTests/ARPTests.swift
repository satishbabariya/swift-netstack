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

@Test func cacheIsBoundedUnderAFloodOfSpoofedSources() {
    // `IPv4Protocol.handleInbound` calls `arpCache.record` on EVERY accepted
    // IPv4 packet, so a guest — or anything it forwards for, under
    // promiscuous mode — can grow this table by simply varying the claimed
    // source address, no valid ARP or checksum required. Unbounded, that is
    // an OOM of the host process. 50,000 distinct sources, capped table.
    let clock = ManualClock()
    let cache = ARPCache(clock: clock, ttl: .seconds(60), capacity: 512)
    for i in 0..<50_000 {
        let ip = IPv4Address(UInt8((i >> 24) & 0xff), UInt8((i >> 16) & 0xff), UInt8((i >> 8) & 0xff), UInt8(i & 0xff))
        cache.record(ip, MACAddress(bytes: [0x02, 0, 0, 0, UInt8((i >> 8) & 0xff), UInt8(i & 0xff)])!)
    }
    #expect(cache.count == 512)
}

@Test func refreshingAnExistingEntryDoesNotScanTheWholeCache() {
    // `touch` used to do `order.firstIndex(of:)` + `order.remove(at:)` on
    // every refresh -- an O(capacity) scan replacing what should be a
    // single dictionary store -- on the hottest path in the stack:
    // `IPv4Protocol.handleInbound` calls `record` on EVERY accepted IPv4
    // packet, and `lookup` touches too. The reviewer measured 100,000
    // refreshes at capacity 512 taking 1.611s versus 0.075s at capacity 8,
    // a ~21x cost that scales with capacity rather than staying constant.
    //
    // A wall-clock ceiling (the same style used for the reassembler's own
    // analogous O(n)-scan fix, `evictionUnderTheByteCapDoesNotScanEveryPendingEntry`)
    // was tried here first and dropped: reliably separating the O(1) and
    // O(capacity) implementations on this hardware needed a cache large
    // enough (tens of thousands of live entries) that holding them for the
    // duration measurably perturbed OTHER tests' own real-memory
    // measurements running concurrently in the same process (see
    // `ReassemblerTests`). `orderScanStepsForTesting` sidesteps that: it is
    // a direct, timing-independent count of how much scanning
    // `compactOrderIfNeeded` actually does, and the invariant under test —
    // that touching an entry does constant, not capacity-proportional, work
    // — holds at any scale, including one small enough to be memory-cheap.
    let clock = ManualClock()
    let capacity = 64
    let cache = ARPCache(clock: clock, ttl: .seconds(3600), capacity: capacity)
    let ip: (Int) -> IPv4Address = { IPv4Address(10, 0, 0, UInt8($0)) }
    let mac: (Int) -> MACAddress = { MACAddress(bytes: [0x02, 0, 0, 0, 0, UInt8($0)])! }

    for i in 0..<capacity {
        cache.record(ip(i), mac(i))
    }
    #expect(cache.count == capacity)

    let touches = 100_000
    for i in 0..<touches {
        // Refreshes an EXISTING entry every time -- this is the
        // `entries[ip] != nil` path in `record`, i.e. exactly the touch
        // this test is regression-guarding. Cycling through all 64 keys
        // (rather than hammering one) exercises `compactOrderIfNeeded`
        // against a full, constantly-churning table, not a degenerate
        // single-key case.
        cache.record(ip(i % capacity), mac(i % capacity))
    }

    // Each of the `touches` calls to `record` triggers exactly one call to
    // `compactOrderIfNeeded`. Over the table's lifetime, an appearance in
    // `order` is scanned past as "stale" at most once ever, and a call
    // scans at most one further "live" appearance before breaking -- so
    // total scan steps across every call is bounded by roughly twice the
    // number of touches, not by touches times capacity (which for this
    // input would be 6,400,000, two orders of magnitude more). `+ capacity`
    // covers the initial fill's own appends.
    #expect(cache.orderScanStepsForTesting <= 2 * touches + capacity)
    // Refreshing must never evict: every key touched was already present.
    #expect(cache.count == capacity)
}

@Test func cacheEvictsOldestButKeepsARecentlyTouchedEntry() {
    let clock = ManualClock()
    let cache = ARPCache(clock: clock, ttl: .seconds(3600), capacity: 4)
    let mac: (Int) -> MACAddress = { MACAddress(bytes: [0x02, 0, 0, 0, 0, UInt8($0)])! }
    let ip: (Int) -> IPv4Address = { IPv4Address(10, 0, 0, UInt8($0)) }

    cache.record(ip(1), mac(1))
    cache.record(ip(2), mac(2))
    cache.record(ip(3), mac(3))
    cache.record(ip(4), mac(4))
    // Touch the oldest entry so it is no longer the least-recently-used one.
    #expect(cache.lookup(ip(1)) == mac(1))

    // A fifth distinct source must evict the actual least-recently-used
    // entry (2), not the one that was merely inserted first (1).
    cache.record(ip(5), mac(5))

    #expect(cache.count == 4)
    #expect(cache.lookup(ip(1)) == mac(1))   // recently touched: survives
    #expect(cache.lookup(ip(2)) == nil)      // least-recently-used: evicted
    #expect(cache.lookup(ip(3)) == mac(3))
    #expect(cache.lookup(ip(4)) == mac(4))
    #expect(cache.lookup(ip(5)) == mac(5))
}

@Test func cacheReapsExpiredEntriesOnMaintenance() {
    let clock = ManualClock()
    let cache = ARPCache(clock: clock, ttl: .seconds(60))
    cache.record(IPv4Address("10.0.0.1")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    cache.record(IPv4Address("10.0.0.2")!, MACAddress("0a:0b:0c:0d:0e:10")!)
    #expect(cache.count == 2)

    clock.advance(by: .seconds(61))
    cache.reapExpired()
    #expect(cache.count == 0)
    #expect(cache.lookup(IPv4Address("10.0.0.1")!) == nil)
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
