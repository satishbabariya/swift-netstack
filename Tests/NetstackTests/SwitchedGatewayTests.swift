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

func swgDial(_ path: String) -> Int32 {
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
func swgSend(_ fd: Int32, _ frame: [UInt8]) {
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
private func swgAwaitFrame(
    _ fd: Int32, framing: StreamFraming = .qemu, matching predicate: ([UInt8]) -> Bool
) async -> [UInt8]? {
    var pending = [UInt8]()
    for _ in 0..<400 {
        var chunk = [UInt8](repeating: 0, count: 65536)
        let read = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            pending.append(contentsOf: chunk[0..<read])
            let prefix = framing == .qemu ? 4 : 2
            while pending.count >= prefix {
                let length =
                    framing == .qemu
                    ? Int(pending[0]) << 24 | Int(pending[1]) << 16 | Int(pending[2]) << 8 | Int(pending[3])
                    : Int(pending[0]) | Int(pending[1]) << 8
                guard pending.count >= prefix + length else { break }
                let frame = Array(pending[prefix..<(prefix + length)])
                pending.removeFirst(prefix + length)
                if predicate(frame) { return frame }
            }
        } else {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
    return nil
}

func swgArpRequest(from hardware: MACAddress, sender: IPv4Address, target: IPv4Address) -> [UInt8] {
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

@Test func aGuestCanJoinTheSwitchOverTheControlSocket() async throws {
    // Upstream's /connect: a guest that can reach the control socket and nothing
    // else joins the network over it. `cmd/vm` does exactly this. The connection
    // stops being HTTP the moment the request ends and carries ethernet frames
    // afterwards, which is why it cannot be a request and a response.
    let path = swgTemporaryPath("connect")
    let controlPath = swgTemporaryPath("connect-control")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).get()
    let control = ControlPlane(gateway: gateway)
    try await control.listen(unixSocketPath: controlPath).get()

    let joined = swgDial(controlPath)
    defer { close(joined) }
    let request = "POST /connect HTTP/1.1\r\nHost: netstack\r\n\r\n"
    _ = Array(request.utf8).withUnsafeBytes { send(joined, $0.baseAddress, $0.count, 0) }

    let netSwitch = try #require(gateway.networkSwitch)
    var ports = 0
    for _ in 0..<200 where ports == 0 {
        ports = try await gateway.eventLoop.submit { netSwitch.portCount }.get()
        if ports == 0 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(ports == 1, "the hijacked connection did not become a switch port")

    // And it is a working port, not merely a counted one: a DHCP DISCOVER over
    // it comes back with an offer. `/connect` speaks hyperkit's two-byte
    // little-endian framing by default, which is upstream's default and not the
    // one the switch's own listening socket uses.
    let mac = MACAddress("0a:00:00:00:ee:05")!
    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: mac, transaction: 41),
        destinationMAC: .broadcast, sourceMAC: mac)
    var framed = [UInt8]()
    framed.append(UInt8(truncatingIfNeeded: discover.count))
    framed.append(UInt8(truncatingIfNeeded: discover.count >> 8))
    framed.append(contentsOf: discover)
    _ = framed.withUnsafeBytes { send(joined, $0.baseAddress, $0.count, 0) }

    let offer = await swgAwaitFrame(joined, framing: .hyperkit) { candidate in
        guard candidate.count > 42, let message = DHCPCodec.parse(ByteBuffer(bytes: Array(candidate[42...])))
        else { return false }
        return message.messageType == .offer
    }
    #expect(offer != nil, "the guest that joined over /connect got no address")

    control.close()
    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.removeItem(atPath: controlPath)
}

@Test func theTunnelRouteCarriesAConnectionToAGuestPort() async throws {
    // Upstream's /tunnel: a port forward for one connection and with no
    // listener. `expose` publishes a host port and leaves it published; this is
    // for a caller that already has a connection and wants it carried, which is
    // how upstream's ssh client reaches a guest.
    let path = swgTemporaryPath("tunnel")
    let controlPath = swgTemporaryPath("tunnel-control")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).get()
    let control = ControlPlane(gateway: gateway)
    try await control.listen(unixSocketPath: controlPath).get()

    // A guest that answers on port 80 -- driven by hand, because the point is
    // the tunnel rather than anything the guest runs.
    let mac = MACAddress("0a:00:00:00:ff:06")!
    let guestAddress = IPv4Address("192.168.127.5")!
    let guest = swgDial(path)
    defer { close(guest) }
    swgSend(guest, swgArpRequest(from: mac, sender: guestAddress, target: swgGateway))
    _ = await swgAwaitFrame(guest) { $0.count >= 22 && $0[12] == 0x08 && $0[13] == 0x06 && $0[21] == 0x02 }

    let tunnel = swgDial(controlPath)
    defer { close(tunnel) }
    let request = "GET /tunnel?ip=\(guestAddress)&port=80 HTTP/1.1\r\nHost: netstack\r\n\r\n"
    _ = Array(request.utf8).withUnsafeBytes { send(tunnel, $0.baseAddress, $0.count, 0) }

    // Upstream answers a bare `OK`, not an HTTP response: the connection stopped
    // being HTTP a moment earlier. A client waits for it before sending.
    var acknowledgement = [UInt8](repeating: 0, count: 2)
    var read = 0
    for _ in 0..<400 where read < 2 {
        let got = acknowledgement.withUnsafeMutableBytes {
            recv(tunnel, $0.baseAddress!.advanced(by: read), 2 - read, MSG_DONTWAIT)
        }
        if got > 0 { read += got } else { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(String(decoding: acknowledgement, as: UTF8.self) == "OK", "the tunnel was not acknowledged")

    // The SYN reaches the guest, addressed to the port that was asked for.
    let syn = await swgAwaitFrame(guest) { candidate in
        candidate.count >= 54 && candidate[12] == 0x08 && candidate[13] == 0x00 && candidate[23] == 6
            && Int(candidate[36]) << 8 | Int(candidate[37]) == 80
    }
    #expect(syn != nil, "no connection was opened to the guest's port")

    control.close()
    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.removeItem(atPath: controlPath)
}

@Test func aGuestThatSendsItsFirstFrameWithTheConnectRequestDoesNotLoseIt() throws {
    // The reason the HTTP decoder is built with `leftOverBytesStrategy:
    // .forwardBytes`, and a case the test above cannot see: it waits for the
    // port to appear before sending, so nothing is ever pipelined.
    //
    // A client with no reason to wait writes the request and its first frame in
    // one call, and both arrive in one read. The decoder has then already taken
    // those frame bytes off the socket, and with the default strategy they are
    // dropped when it is removed -- so the guest has sent a DISCOVER that never
    // arrived and, DHCP being what it is, will sit for seconds before trying
    // again. Nothing errors; the network is just slow to come up, once.
    let path = swgTemporaryPath("pipelined")
    let controlPath = swgTemporaryPath("pipelined-control")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try Gateway.start(
        switchListeningOnStreamSocketAt: path, group: group, configuration: .init()
    ).wait()
    let control = ControlPlane(gateway: gateway)
    try control.listen(unixSocketPath: controlPath).wait()

    let joined = swgDial(controlPath)
    defer { close(joined) }

    let mac = MACAddress("0a:00:00:00:11:07")!
    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: mac, transaction: 51),
        destinationMAC: .broadcast, sourceMAC: mac)

    // One write: the request and the frame, back to back.
    var combined = Array("POST /connect HTTP/1.1\r\nHost: netstack\r\n\r\n".utf8)
    combined.append(UInt8(truncatingIfNeeded: discover.count))
    combined.append(UInt8(truncatingIfNeeded: discover.count >> 8))
    combined.append(contentsOf: discover)
    _ = combined.withUnsafeBytes { send(joined, $0.baseAddress, $0.count, 0) }

    let offer = swgAwaitFrameSync(joined, framing: .hyperkit) { candidate in
        guard candidate.count > 42, let message = DHCPCodec.parse(ByteBuffer(bytes: Array(candidate[42...])))
        else { return false }
        return message.messageType == .offer && message.transaction == 51
    }
    #expect(offer != nil, "the frame sent with the request was dropped when HTTP was removed")

    control.close()
    _ = try? gateway.close().wait()
    try? group.syncShutdownGracefully()
    try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.removeItem(atPath: controlPath)
}

/// `swgAwaitFrame` without the concurrency, for a test that cannot be `async`:
/// it must not give the event loop a chance to run between the write and the
/// read, or the race it is about does not happen.
private func swgAwaitFrameSync(
    _ fd: Int32, framing: StreamFraming, matching predicate: ([UInt8]) -> Bool
) -> [UInt8]? {
    var pending = [UInt8]()
    let prefix = framing == .qemu ? 4 : 2
    for _ in 0..<400 {
        var chunk = [UInt8](repeating: 0, count: 65536)
        let read = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            pending.append(contentsOf: chunk[0..<read])
            while pending.count >= prefix {
                let length =
                    framing == .qemu
                    ? Int(pending[0]) << 24 | Int(pending[1]) << 16 | Int(pending[2]) << 8 | Int(pending[3])
                    : Int(pending[0]) | Int(pending[1]) << 8
                guard pending.count >= prefix + length else { break }
                let candidate = Array(pending[prefix..<(prefix + length)])
                pending.removeFirst(prefix + length)
                if predicate(candidate) { return candidate }
            }
        } else {
            usleep(5000)
        }
    }
    return nil
}
