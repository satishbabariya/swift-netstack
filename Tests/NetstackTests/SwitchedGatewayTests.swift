import Foundation
import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// A whole network, not a link: several guests on one gateway, reaching the
// host through it and each other across it. This is the shape upstream has and
// the single-wire entry points do not cover.

private let swgGateway = IPv4Address("192.168.127.1")!
private let swgGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private func swgTemporaryPath(_ tag: String) -> String {
    "/tmp/netstack-switched-\(tag)-\(UInt32.random(in: 0...UInt32.max)).sock"
}

private func swgDial(_ path: String) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    #expect(fd >= 0)
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    _ = withUnsafeMutablePointer(to: &address.sun_path) { raw in
        path.withCString { source in
            raw.withMemoryRebound(to: CChar.self, capacity: 104) { destination in
                strncpy(destination, source, 103)
            }
        }
    }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    #expect(connected == 0, "could not dial \(path): \(String(cString: strerror(errno)))")
    return fd
}

/// One frame, with the four-byte big-endian length this wire puts in front.
private func swgSend(_ fd: Int32, _ frame: [UInt8]) {
    var out = [UInt8]()
    let length = UInt32(frame.count)
    out.append(contentsOf: [
        UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
        UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length),
    ])
    out.append(contentsOf: frame)
    _ = out.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
}

/// Read frames until `predicate` is satisfied or the wait runs out.
private func swgAwaitFrame(_ fd: Int32, matching predicate: ([UInt8]) -> Bool) async -> [UInt8]? {
    var pending = [UInt8]()
    for _ in 0..<400 {
        var chunk = [UInt8](repeating: 0, count: 65536)
        let read = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            pending.append(contentsOf: chunk[0..<read])
            while pending.count >= 4 {
                let length =
                    Int(pending[0]) << 24 | Int(pending[1]) << 16 | Int(pending[2]) << 8 | Int(pending[3])
                guard pending.count >= 4 + length else { break }
                let frame = Array(pending[4..<(4 + length)])
                pending.removeFirst(4 + length)
                if predicate(frame) { return frame }
            }
        } else {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
    return nil
}

private func swgArpRequest(from hardware: MACAddress, sender: IPv4Address, target: IPv4Address) -> [UInt8] {
    var frame = [UInt8]()
    frame.append(contentsOf: MACAddress.broadcast.bytes)
    frame.append(contentsOf: hardware.bytes)
    frame.append(contentsOf: [0x08, 0x06])
    frame.append(contentsOf: [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01])
    frame.append(contentsOf: hardware.bytes)
    frame.append(contentsOf: sender.bytes)
    frame.append(contentsOf: [UInt8](repeating: 0, count: 6))
    frame.append(contentsOf: target.bytes)
    return frame
}

@Test func twoGuestsOnOneSwitchEachGetTheirOwnLeaseAndCanReachEachOther() async throws {
    // The whole point of the switch, end to end on real sockets. Two guests,
    // one gateway: each is addressed independently, and traffic between them
    // crosses the fabric without the gateway's stack being involved at all.
    let path = swgTemporaryPath("pair")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).get()

    let macA = MACAddress("0a:00:00:00:aa:01")!
    let macB = MACAddress("0a:00:00:00:bb:02")!
    let guestA = swgDial(path)
    let guestB = swgDial(path)
    defer {
        close(guestA)
        close(guestB)
    }

    // Each guest asks for an address of its own. DHCP already leases per
    // hardware address, so this needed nothing new -- but it is the property
    // that makes a switch worth having, so it is checked rather than assumed.
    var leases: [MACAddress: IPv4Address] = [:]
    for (fd, mac, transaction) in [(guestA, macA, UInt32(21)), (guestB, macB, UInt32(22))] {
        let discover = frame(
            from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
            destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: mac, transaction: transaction),
            // The ethernet source has to be this guest's own address, not just
            // the hardware address inside the DHCP payload. They are different
            // fields and the switch learns from the former: two guests sharing
            // one ethernet source are, as far as a switch is concerned, one
            // guest that keeps moving between ports.
            destinationMAC: .broadcast, sourceMAC: mac)
        swgSend(fd, Array(discover))
        // Matched on the transaction and the message type, not merely "a UDP
        // frame". The other guest's DISCOVER is a broadcast and the switch
        // floods it here, correctly -- so the first datagram waiting on this
        // socket is frequently somebody else's, and a looser predicate reads it
        // and calls the test failed. That is the switch working.
        let offer = await swgAwaitFrame(fd) { candidate in
            guard candidate.count > 42, candidate[12] == 0x08, candidate[13] == 0x00,
                candidate[23] == 17,
                let message = DHCPCodec.parse(ByteBuffer(bytes: Array(candidate[42...])))
            else { return false }
            return message.messageType == .offer && message.transaction == transaction
        }
        let bytes = try #require(offer, "guest got no DHCP offer")
        let parsed = try #require(
            DHCPCodec.parse(ByteBuffer(bytes: Array(bytes[42...]))), "the offer did not parse")
        leases[mac] = parsed.yourAddress
    }

    let addressA = try #require(leases[macA])
    let addressB = try #require(leases[macB])
    #expect(addressA != addressB, "two guests were handed the same address: \(addressA)")

    // B has spoken, so the switch knows where it is. A now asks for it by ARP,
    // which is a broadcast: it must reach B, and B must be the one to answer.
    let request = swgArpRequest(from: macA, sender: addressA, target: addressB)
    swgSend(guestA, request)

    let seenByB = await swgAwaitFrame(guestB) { $0.count >= 14 && $0[12] == 0x08 && $0[13] == 0x06 }
    let arp = try #require(seenByB, "the ARP request never crossed the switch to the other guest")
    // ARP from offset 14: htype, ptype, hlen, plen, op, then sender hardware (22)
    // and sender protocol (28), then target hardware (32) and target protocol
    // (38). Both are checked, because "an ARP frame arrived" is also true of the
    // gateway's own traffic and of anything else flooded onto this port.
    #expect(Array(arp[20..<22]) == [0x00, 0x01], "the frame that arrived was not a request")
    #expect(Array(arp[28..<32]) == addressA.bytes, "the request did not come from the other guest")
    #expect(Array(arp[38..<42]) == addressB.bytes, "the request was asking for someone else")

    // And the gateway did not answer for B. It answers ARP for its own address
    // and no other -- a gateway that replied here would be claiming to be a
    // guest it is merely carrying traffic for.
    let strayReply = await swgAwaitFrame(guestA) { candidate in
        candidate.count >= 22 && candidate[12] == 0x08 && candidate[13] == 0x06
            && candidate[20] == 0x00 && candidate[21] == 0x02
    }
    #expect(strayReply == nil, "the gateway answered ARP on another guest's behalf")

    let stats = try await gateway.statistics().get()
    #expect(stats.switchPorts == 2)
    #expect(stats.dhcpLeases == 2)

    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
}

@Test func aGuestLeavingTakesItsPortAndEverythingLearnedOnItAway() async throws {
    let path = swgTemporaryPath("leave")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).get()

    let mac = MACAddress("0a:00:00:00:cc:03")!
    let guest = swgDial(path)
    swgSend(guest, swgArpRequest(from: mac, sender: IPv4Address("192.168.127.9")!, target: swgGateway))
    // The reply proves the frame reached the stack, which means the port is up
    // and the address is learned -- without waiting on a timer to say so.
    _ = await swgAwaitFrame(guest) { $0.count >= 22 && $0[12] == 0x08 && $0[13] == 0x06 && $0[21] == 0x02 }

    let netSwitch = try #require(gateway.networkSwitch)
    let learned = try await gateway.eventLoop.submit { netSwitch.addressTable[mac] }.get()
    #expect(learned != nil, "the guest's address was never learned")

    close(guest)

    // Polled rather than slept on: the close travels to the switch's loop and
    // a fixed wait is either flaky or slow, depending on the machine.
    var ports = 1
    for _ in 0..<200 where ports != 0 {
        ports = try await gateway.eventLoop.submit { netSwitch.portCount }.get()
        if ports != 0 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(ports == 0, "the port outlived the guest")
    let afterwards = try await gateway.eventLoop.submit { netSwitch.addressTable[mac] }.get()
    #expect(afterwards == nil, "the switch still thinks the guest is on a port that is gone")

    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
}

@Test func theAddressTableAndLeasesAreServedOverTheControlApi() async throws {
    // The read an operator actually makes: which guests are here, where each one
    // is, and what address each was given.
    let path = swgTemporaryPath("api")
    let controlPath = swgTemporaryPath("api-control")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).get()
    let control = ControlPlane(gateway: gateway)
    try await control.listen(unixSocketPath: controlPath).get()

    let mac = MACAddress("0a:00:00:00:dd:04")!
    let guest = swgDial(path)
    defer { close(guest) }
    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: mac, transaction: 31),
        destinationMAC: .broadcast, sourceMAC: mac)
    swgSend(guest, Array(discover))
    let offer = await swgAwaitFrame(guest) { candidate in
        guard candidate.count > 42, let message = DHCPCodec.parse(ByteBuffer(bytes: Array(candidate[42...])))
        else { return false }
        return message.messageType == .offer
    }
    // Hoisted: `#require` captures its operand, so nesting one inside another
    // expands the macro recursively and does not compile.
    let offerFrame = try #require(offer, "the guest got no DHCP offer")
    let message = try #require(
        DHCPCodec.parse(ByteBuffer(bytes: Array(offerFrame[42...]))), "the offer did not parse")
    let leased = message.yourAddress

    let cam = try swgRequest("GET", "/cam", to: controlPath)
    #expect(cam.contains(mac.description), "the switch's table does not name the guest: \(cam)")

    let leases = try swgRequest("GET", "/leases", to: controlPath)
    #expect(leases.contains(leased.description), "the lease is not reported: \(leases)")
    #expect(leases.contains(mac.description))

    let stats = try swgRequest("GET", "/stats", to: controlPath)
    #expect(stats.contains("\"switch_ports\":1"), "unexpected stats: \(stats)")

    control.close()
    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.removeItem(atPath: controlPath)
}

/// A control-plane request over a unix socket, returning the body.
private func swgRequest(_ method: String, _ path: String, to socketPath: String) throws -> String {
    let fd = swgDial(socketPath)
    defer { close(fd) }
    let request = "\(method) \(path) HTTP/1.1\r\nHost: netstack\r\nConnection: close\r\n\r\n"
    _ = Array(request.utf8).withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
    var response = [UInt8]()
    while true {
        var chunk = [UInt8](repeating: 0, count: 8192)
        let read = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        if read <= 0 { break }
        response.append(contentsOf: chunk[0..<read])
    }
    let text = String(decoding: response, as: UTF8.self)
    guard let separator = text.range(of: "\r\n\r\n") else { return "" }
    return String(text[separator.upperBound...])
}
