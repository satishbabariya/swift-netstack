import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// One gateway, several guests. Upstream's `pkg/tap.Switch` is what makes a
// gvisor-tap-vsock network a network rather than a point-to-point link, and
// these are its forwarding rules.

private let swGateway = MACAddress("5a:94:ef:e4:0c:ee")!
private let swGuestA = MACAddress("0a:00:00:00:00:01")!
private let swGuestB = MACAddress("0a:00:00:00:00:02")!

/// Collects what the stack above the switch was given.
private final class RecordingDispatcher: LinkDispatcher {
    var frames: [ByteBuffer] = []
    func deliverInbound(_ frame: PacketBuffer) {
        frames.append(frame.frame)
    }
}

private func ethernetFrame(
    to destination: MACAddress, from source: MACAddress, payload: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeBytes(destination.bytes)
    buffer.writeBytes(source.bytes)
    buffer.writeInteger(UInt16(0x0800), endianness: .big)
    buffer.writeBytes(payload)
    return buffer
}

/// A switch with `count` ports on one loop, and the frames each port has been
/// written, readable as they arrive.
private struct SwitchFixture {
    let loop: EmbeddedEventLoop
    let netSwitch: NetworkSwitch
    let channels: [EmbeddedChannel]
    let ids: [Int]
    let upstream: RecordingDispatcher

    /// What port `index` has been sent, draining the channel each time.
    func written(_ index: Int) throws -> [ByteBuffer] {
        var out: [ByteBuffer] = []
        while let frame = try channels[index].readOutbound(as: ByteBuffer.self) {
            out.append(frame)
        }
        return out
    }

    func deliver(_ frame: ByteBuffer, toPort index: Int) throws {
        try channels[index].writeInbound(frame)
    }
}

private func makeSwitch(ports count: Int, addressesPerPort: Int = 16) throws -> SwitchFixture {
    let loop = EmbeddedEventLoop()
    let netSwitch = NetworkSwitch(
        linkAddress: swGateway, eventLoop: loop, maximumAddressesPerPort: addressesPerPort)
    let upstream = RecordingDispatcher()
    netSwitch.attach(upstream)

    var channels: [EmbeddedChannel] = []
    var ids: [Int] = []
    for _ in 0..<count {
        let channel = EmbeddedChannel(loop: loop)
        let link = WireLinkEndpoint(channel: channel, linkAddress: swGateway, mtu: 1500)
        ids.append(netSwitch.addPort(link))
        try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
        channels.append(channel)
    }
    return SwitchFixture(
        loop: loop, netSwitch: netSwitch, channels: channels, ids: ids, upstream: upstream)
}

@Test func aFrameFromOneGuestToAnotherIsForwardedAndNeverReachesTheStack() throws {
    let fixture = try makeSwitch(ports: 2)

    // B speaks first, so the switch knows where it is. On this network every
    // station does: it has to ask for an address by DHCP before it can use one.
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestB), toPort: 1)
    _ = try fixture.written(0)
    _ = try fixture.written(1)
    fixture.upstream.frames.removeAll()

    try fixture.deliver(ethernetFrame(to: swGuestB, from: swGuestA), toPort: 0)

    let toB = try fixture.written(1)
    #expect(toB.count == 1, "the frame did not reach the other guest")
    // Not "the stack saw fewer frames" -- none at all. A gateway that sees guest
    // to guest traffic is one that could answer it, and answering traffic that
    // was not addressed to you is the bug this rule prevents.
    #expect(fixture.upstream.frames.isEmpty, "the stack was given a frame addressed to a guest")
    #expect(try fixture.written(0).isEmpty, "the frame was echoed back at its sender")
}

@Test func aBroadcastReachesTheOtherGuestsAndTheStackBoth() throws {
    let fixture = try makeSwitch(ports: 3)
    fixture.upstream.frames.removeAll()

    try fixture.deliver(ethernetFrame(to: .broadcast, from: swGuestA), toPort: 0)

    // Both halves of the rule run for a broadcast, and this is the case that
    // makes the network work: an ARP request has to reach the other guests, and
    // a DHCP DISCOVER has to reach the server.
    #expect(try fixture.written(1).count == 1)
    #expect(try fixture.written(2).count == 1)
    #expect(fixture.upstream.frames.count == 1, "the gateway did not see the broadcast")
    #expect(try fixture.written(0).isEmpty, "the broadcast was flooded back at its sender")
}

@Test func aFrameForTheGatewayGoesUpAndNotAcross() throws {
    let fixture = try makeSwitch(ports: 2)
    fixture.upstream.frames.removeAll()

    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 0)

    #expect(fixture.upstream.frames.count == 1)
    #expect(try fixture.written(1).isEmpty, "a frame for the gateway was put on the fabric")
}

@Test func anUnknownUnicastIsDroppedRatherThanFlooded() throws {
    let fixture = try makeSwitch(ports: 3)

    try fixture.deliver(ethernetFrame(to: swGuestB, from: swGuestA), toPort: 0)

    // A real switch floods this. A real switch is also on a network whose
    // stations are not assumed hostile: flooding lets any guest make the switch
    // replicate a frame to every port by naming an address nobody owns, which is
    // a multiplier the guest picks and nothing bounds.
    #expect(try fixture.written(1).isEmpty)
    #expect(try fixture.written(2).isEmpty)
    #expect(fixture.netSwitch.unknownUnicastDropped == 1)
}

@Test func theGatewayCanReachAGuestItHasHeardFromAndNoOther() throws {
    let fixture = try makeSwitch(ports: 2)
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 0)
    _ = try fixture.written(0)
    _ = try fixture.written(1)

    var reply = PacketBuffer(received: ethernetFrame(to: swGuestA, from: swGateway))
    fixture.netSwitch.write([reply])
    reply = PacketBuffer(received: ethernetFrame(to: swGuestB, from: swGateway))
    fixture.netSwitch.write([reply])

    #expect(try fixture.written(0).count == 1, "the gateway could not answer the guest it heard from")
    #expect(try fixture.written(1).isEmpty)
    #expect(fixture.netSwitch.unknownUnicastDropped == 1, "the unheard-of address was not counted")
}

@Test func oneGuestFloodingAddressesCannotStopAnotherFromBeingLearned() throws {
    // The bound upstream does not have, and the reason it is per port rather
    // than global. Upstream's CAM is a map that grows by an entry for every
    // source address it sees, and the source address is a field the guest
    // writes -- so a guest emitting random ones at line rate grows it without
    // limit. A global cap would fix that and introduce a worse bug: the flooding
    // guest fills the table and locks every other guest out of it.
    let fixture = try makeSwitch(ports: 2, addressesPerPort: 4)

    for index in 0..<64 {
        let spoofed = MACAddress(bytes: [0x0a, 0x00, 0x00, 0x00, 0x01, UInt8(index)])!
        try fixture.deliver(ethernetFrame(to: .broadcast, from: spoofed), toPort: 0)
    }

    #expect(fixture.netSwitch.addressesRefused == 60, "the per-port limit did not hold")
    // The whole point: port 1 is unaffected and can still be learned.
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestB), toPort: 1)
    _ = try fixture.written(0)
    _ = try fixture.written(1)

    let table = fixture.netSwitch.addressTable
    #expect(table[swGuestB] == fixture.ids[1], "a flood on one port stopped another port being learned")
    #expect(table.count == 5, "the table is not bounded by ports x limit: \(table.count)")

    // And the gateway can still reach the guest behind the flood.
    fixture.netSwitch.write([PacketBuffer(received: ethernetFrame(to: swGuestB, from: swGateway))])
    #expect(try fixture.written(1).count == 1)
}

@Test func removingAPortForgetsWhatWasLearnedOnIt() throws {
    let fixture = try makeSwitch(ports: 2)
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 0)
    #expect(fixture.netSwitch.addressTable[swGuestA] == fixture.ids[0])

    _ = fixture.netSwitch.removePort(fixture.ids[0])

    // Not tidiness. An entry left behind names a port that is gone, so frames
    // for that address are delivered nowhere and silently -- and stay that way
    // until the next guest to connect is given the same port id.
    #expect(fixture.netSwitch.addressTable[swGuestA] == nil)
    #expect(fixture.netSwitch.portCount == 1)
}

@Test func anAddressThatMovesPortsIsFollowedAndCounted() throws {
    let fixture = try makeSwitch(ports: 2)
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 0)
    #expect(fixture.netSwitch.addressesMoved == 0)

    // The same address, now arriving on the other port: a guest that reconnected,
    // or a guest claiming another's address. Nothing here can tell which, so the
    // switch follows it -- as a switch must, or a reconnecting guest is
    // unreachable forever -- and counts it so an operator can see it happen.
    try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 1)

    #expect(fixture.netSwitch.addressTable[swGuestA] == fixture.ids[1])
    #expect(fixture.netSwitch.addressesMoved == 1)

    fixture.netSwitch.write([PacketBuffer(received: ethernetFrame(to: swGuestA, from: swGateway))])
    #expect(try fixture.written(1).count == 1, "the gateway did not follow the address to its new port")
    #expect(try fixture.written(0).isEmpty)
}

@Test func aGuestRepeatingItsOwnAddressDoesNotSpendItsPortsBudget() throws {
    // The floor under the flood test: if re-learning an address a port already
    // owns counted against the limit, an ordinary guest would exhaust its budget
    // in four frames and stop being reachable.
    let fixture = try makeSwitch(ports: 1, addressesPerPort: 4)

    for _ in 0..<50 {
        try fixture.deliver(ethernetFrame(to: swGateway, from: swGuestA), toPort: 0)
    }

    #expect(fixture.netSwitch.addressesRefused == 0)
    #expect(fixture.netSwitch.addressTable[swGuestA] == fixture.ids[0])
}

@Test func aFrameBetweenTwoAddressesOnOnePortIsNotSentBackOutOfIt() throws {
    // The guard against echoing a frame out of the port it arrived on, which
    // every other test in this file reaches and none of them can see: a frame
    // from A to B leaves by a different port than it entered whether or not the
    // guard is there.
    //
    // It is only exercised when the CAM says the destination is on the *same*
    // port as the source, and that is not an odd case -- one port is one wire,
    // and a guest can have a bridge behind it with several addresses on the far
    // side. Those two stations share a segment and have already heard each
    // other directly; sending the frame back would deliver it twice.
    let fixture = try makeSwitch(ports: 2)
    let behindTheSamePort = MACAddress("0a:00:00:00:00:99")!

    // Both addresses announce themselves on port 0.
    try fixture.deliver(ethernetFrame(to: .broadcast, from: swGuestA), toPort: 0)
    try fixture.deliver(ethernetFrame(to: .broadcast, from: behindTheSamePort), toPort: 0)
    #expect(fixture.netSwitch.addressTable[behindTheSamePort] == fixture.ids[0])
    _ = try fixture.written(0)
    _ = try fixture.written(1)

    try fixture.deliver(ethernetFrame(to: behindTheSamePort, from: swGuestA), toPort: 0)

    #expect(try fixture.written(0).isEmpty, "the frame was sent back out of the port it came in on")
    #expect(try fixture.written(1).isEmpty)
}
