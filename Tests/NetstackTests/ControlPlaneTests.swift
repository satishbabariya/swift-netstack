import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// Upstream's API for managing port forwards while the gateway runs, so a tool
// written against `gvproxy` works here unchanged. Anything that can reach it can
// publish any guest port on the host, which is why the interesting tests are
// about what it refuses.

private final class CPHolder: @unchecked Sendable {
    var gateway: Gateway?
    var plane: ControlPlane?
}

private func controlPlaneFixture(
    group: EventLoopGroup, guestSide: inout Int32, guestForwards: Int = 64
) async throws -> CPHolder {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    guestSide = pair[1]
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group,
        configuration: .init(maximumGuestForwards: guestForwards)
    ).get()
    let plane = ControlPlane(gateway: gateway)
    try await plane.listen(port: 0).get()
    let holder = CPHolder()
    holder.gateway = gateway
    holder.plane = plane
    return holder
}

/// One request, one response, over a real socket.
private func request(
    _ method: String, _ path: String, body: String?, to address: SocketAddress
) throws -> (status: Int, body: String) {
    let fd = makeSocket(AF_INET, .stream)
    #expect(fd >= 0)
    defer { close(fd) }
    let connected = connectTo(fd, loopbackAddress(port: UInt16(address.port!)))
    #expect(connected == 0, "could not reach the control plane")

    // A read deadline, because without one a route that answers nothing makes
    // this block forever: the test does not fail, it hangs, and the only signal
    // is the whole job timing out with nothing to point at. Found by mutating
    // `HTTPMessageFramer` to swallow the request body -- the request then never
    // completed and the suite stopped rather than reporting anything.
    var deadline = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))

    var text = "\(method) \(path) HTTP/1.1\r\nHost: localhost\r\n"
    if let body {
        text += "Content-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
    } else {
        text += "Content-Length: 0\r\n\r\n"
    }
    let out = Array(text.utf8)
    #expect(out.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) } == out.count)

    var response = ""
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let received: Int = buffer.withUnsafeMutableBytes { raw in
            recv(fd, raw.baseAddress, raw.count, 0)
        }
        if received <= 0 { break }
        response += String(decoding: buffer[0..<received], as: UTF8.self)
    }
    #expect(!response.isEmpty, "the control plane did not answer \(method) \(path) within five seconds")
    let statusLine = response.split(separator: "\r\n").first ?? ""
    let status = Int(statusLine.split(separator: " ").dropFirst().first ?? "0") ?? 0
    let payload = response.components(separatedBy: "\r\n\r\n").dropFirst().joined(separator: "\r\n\r\n")
    return (status, payload)
}

@Test func theGuestsListingLeavesOutTheHostsFilesystem() async throws {
    // The path podman publishes is
    // /Users/<name>/.local/share/containers/podman/machine/podman.sock, so
    // listing it tells a guest the operator's name and where their things live.
    // Measured before this:
    //
    //     PROBE: the guest sees the host's unix path: true
    //
    // For no use the guest has: every other route that touches a unix forward
    // refuses it now. The tcp and udp entries stay, because they are port
    // numbers on a host the guest can already dial.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!
    let gateway = try #require(holder.gateway)

    let path = NSTemporaryDirectory() + "netstack-host-\(UInt32.random(in: 0..<UInt32.max)).sock"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let onDisk = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"\(path)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}",
        to: api)
    try #require(onDisk.status == 200, "the host could not publish it: \(onDisk.body)")
    let overTcp = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    let port = boundPort(in: overTcp.body) ?? 0

    let seen = try await gateway.eventLoop.submit {
        holder.plane!.handleForTesting(
            method: .GET, path: "/services/forwarder/all", body: nil, fromGuest: true)
    }.get().get()
    #expect(!seen.body.contains(path), "the guest was shown a host path: \(seen.body)")
    #expect(
        seen.body.contains(":\(port)"),
        "the guest was not shown the tcp forwards it can use: \(seen.body)")

    // And the host still sees everything, or this would have hidden the forward
    // rather than hidden it from the guest.
    let hostSees = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(hostSees.body.contains(path), "the host cannot see its own forward: \(hostSees.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aGuestPublishesOnLoopbackAndNowhereElse() async throws {
    // `local` carries the interface to bind and the transport to bind it with,
    // and a guest choosing either goes past what this endpoint is for.
    // Measured before this, both answered 200:
    //
    //     guest asking for 0.0.0.0 -> {"local":":51883","protocol":"tcp"}
    //     guest choosing a host filesystem path -> file created: true
    //
    // The first publishes the guest to the host's whole network rather than to
    // the host. The second creates a socket wherever the gateway can write.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!
    let gateway = try #require(holder.gateway)

    func askAsGuest(_ body: String) async throws -> (status: HTTPResponseStatus, body: String) {
        try await gateway.eventLoop.submit {
            holder.plane!.handleForTesting(
                method: .POST, path: "/services/forwarder/expose", body: body, fromGuest: true)
        }.get().get()
    }

    let everywhere = try await askAsGuest(
        "{\"local\":\"0.0.0.0:0\",\"remote\":\"192.168.127.2:80\"}")
    #expect(
        everywhere.status == .forbidden,
        "a guest published on every interface and was answered \(everywhere.status)")

    let path = NSTemporaryDirectory() + "netstack-guest-\(UInt32.random(in: 0..<UInt32.max)).sock"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let onDisk = try await askAsGuest(
        "{\"local\":\"\(path)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}")
    #expect(
        onDisk.status == .forbidden,
        "a guest chose a host path and was answered \(onDisk.status)")
    #expect(
        !FileManager.default.fileExists(atPath: path),
        "the refused request created the socket anyway")

    // What it is for still works, and the host is not held to either rule.
    let ordinary = try await askAsGuest(
        "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}")
    #expect(ordinary.status == .ok, "a guest could not publish on loopback: \(ordinary.body)")
    let fromHost = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"0.0.0.0:0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(fromHost.status == 200, "the host was refused an interface it is allowed")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aGuestCannotWithdrawWhatTheHostPublished() async throws {
    // Upstream serves this route to the guest with the same handler the host
    // gets, so a guest there can withdraw a forward the operator published.
    // Measured here before this:
    //
    //     PROBE: guest unexpose of a host forward answered 200 OK; still listed: false
    //
    // That is not a bounded resource being exhausted, it is the host's own
    // configuration taken apart by something this package's threat model calls
    // hostile -- and it costs a legitimate guest nothing to be told no, because
    // a container withdraws what it published.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!
    let gateway = try #require(holder.gateway)

    let published = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    let hostPort = boundPort(in: published.body) ?? 0
    try #require(hostPort > 0, "the host forward was not published: \(published.body)")

    let refused = try await gateway.eventLoop.submit {
        holder.plane!.handleForTesting(
            method: .POST, path: "/services/forwarder/unexpose",
            body: "{\"local\":\":\(hostPort)\"}", fromGuest: true)
    }.get().get()
    #expect(
        refused.status == .notFound,
        "a guest withdrew the host's forward and was answered \(refused.status)")
    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(
        listed.body.contains(":\(hostPort)"),
        "the host's forward is gone: \(listed.body)")

    // And a guest still withdraws its own, or the endpoint would be useless.
    let mine = try await gateway.eventLoop.submit {
        holder.plane!.handleForTesting(
            method: .POST, path: "/services/forwarder/expose",
            body: "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}",
            fromGuest: true)
    }.get().get()
    let guestPort = boundPort(in: mine.body) ?? 0
    try #require(guestPort > 0, "the guest could not publish one: \(mine.body)")
    let withdrawn = try await gateway.eventLoop.submit {
        holder.plane!.handleForTesting(
            method: .POST, path: "/services/forwarder/unexpose",
            body: "{\"local\":\":\(guestPort)\"}", fromGuest: true)
    }.get().get()
    #expect(
        withdrawn.status == .ok,
        "a guest could not withdraw its own forward: \(withdrawn.status)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aGuestCannotPublishForwardsWithoutLimit() async throws {
    // Publishing a host port was the host's alone until the forwarding routes
    // were served to guests as well. Each forward is a bound listening socket:
    // measured through the executable, two hundred of them cost two hundred
    // descriptors, and a guest looping on this takes the gateway's descriptors
    // until it cannot accept anything from anybody.
    //
    // The host is not bounded here. It reaches this over a unix socket, which is
    // behind the filesystem where an operator decides who may use it -- which is
    // the reason the README gives for the control API being a unix socket at
    // all.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide, guestForwards: 4)
    let api = holder.plane!.listeningAddress!
    let gateway = try #require(holder.gateway)

    // As the guest: the plane serves it through the forwarder, so the requests
    // that count are the ones marked as having come from there.
    var refused = 0
    var published = 0
    for _ in 0..<12 {
        let answer = try await gateway.eventLoop.submit {
            holder.plane!.handleForTesting(
                method: .POST, path: "/services/forwarder/expose",
                body: "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}",
                fromGuest: true)
        }.get().get()
        if answer.status == .tooManyRequests {
            refused += 1
        } else if answer.status == .ok {
            published += 1
        }
    }
    #expect(published == 4, "a guest published \(published) forwards against a limit of 4")
    #expect(refused == 8, "\(refused) of twelve were refused")

    // The host is not held to it.
    var fromHost = 0
    for _ in 0..<6 {
        let answer = try request(
            "POST", "/services/forwarder/expose",
            body: "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}", to: api)
        if answer.status == 200 { fromHost += 1 }
    }
    #expect(fromHost == 6, "the host was refused \(6 - fromHost) forwards it should have got")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func servingGuestsDoesNotNarrowTheEndpointTheHostIsUsing() async throws {
    // The guest endpoint answers three routes and nothing else. That restriction
    // was a property of the plane, and a plane can have more than one listener:
    // asking one that was already serving the host to serve guests as well
    // turned `/stats` on the host socket into a 404.
    //
    //     PROBE: /stats over the host socket answered 404
    //
    // Silently, and for a caller who had asked for something else entirely. The
    // restriction belongs to the endpoint a request arrived on, so it travels
    // with the connection now.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let before = try request("GET", "/stats", body: nil, to: api)
    try #require(before.status == 200, "the host endpoint did not answer to begin with")

    _ = try await holder.plane!.listenForGuests().get()

    let after = try request("GET", "/stats", body: nil, to: api)
    #expect(
        after.status == 200,
        "serving guests took /stats away from the host endpoint: \(after.status)")
    let leases = try request("GET", "/leases", body: nil, to: api)
    #expect(leases.status == 200, "serving guests took /leases away from the host endpoint")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func exposingTheSameUnixPathTwiceIsRefusedRatherThanReplacingTheFirst() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!
    let path = NSTemporaryDirectory() + "netstack-dup-\(UInt32.random(in: 0..<UInt32.max)).sock"
    defer { try? FileManager.default.removeItem(atPath: path) }

    let body = "{\"local\":\"\(path)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}"
    let first = try request("POST", "/services/forwarder/expose", body: body, to: api)
    #expect(first.status == 200, "the first unix forward was refused: \(first.body)")

    // The tcp half refuses this by accident -- its bind fails with EADDRINUSE --
    // and this half could not, because listening on a path unlinks whatever is
    // already there. Both answered 200, the first forwarder's listener was left
    // with no path pointing at it, and the dictionary `stopForwarding` looks in
    // held the second, so nothing could reach the first again.
    let second = try request("POST", "/services/forwarder/expose", body: body, to: api)
    #expect(
        second.status == 409,
        "exposing the same unix path twice was answered \(second.status): \(second.body)")

    // Still exactly one, and it is still the first: a refusal that took the
    // forward down with it would be worse than the leak.
    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    let entries = listed.body.components(separatedBy: "{\"local\"").count - 1
    #expect(entries == 1, "the refused expose changed the table: \(listed.body)")

    // And the path is usable again once it is given up, so this refuses a
    // duplicate rather than burning the name.
    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose",
        body: "{\"local\":\"\(path)\",\"protocol\":\"unix\"}", to: api)
    #expect(withdrawn.status == 200, "the unix forward could not be withdrawn: \(withdrawn.body)")
    let again = try request("POST", "/services/forwarder/expose", body: body, to: api)
    #expect(again.status == 200, "the path could not be reused after unexpose: \(again.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aZoneFieldThatIsPresentAndUnusableIsRefusedRatherThanDropped() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    // Each of these parsed to nil, and nil is how this parser spells "not
    // given", so each was accepted as a zone the operator did not write.

    // Records of the wrong type became no records, and the defaultIP then
    // answered every name under the zone. The zone works; it just answers the
    // wrong thing, everywhere.
    let wrongShape = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"a.test\",\"records\":\"api\",\"defaultIP\":\"10.1.2.3\"}", to: api)
    #expect(
        wrongShape.status == 400,
        "records given as a string was answered \(wrongShape.status): \(wrongShape.body)")

    // An ip that is not an address, on a record that also carries a regexp: the
    // address was dropped and the record kept.
    let badAddress = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"b.test\",\"records\":[{\"name\":\"api\",\"ip\":\"10.1.2.999\",\"regexp\":\"^api$\"}]}",
        to: api)
    #expect(
        badAddress.status == 400,
        "an ip of 10.1.2.999 was answered \(badAddress.status): \(badAddress.body)")

    // A defaultIP that is not an address, on a zone whose records are fine.
    let badDefault = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"c.test\",\"records\":[{\"name\":\"api\",\"ip\":\"10.1.2.3\"}],\"defaultIP\":\"nonsense\"}",
        to: api)
    #expect(
        badDefault.status == 400,
        "a defaultIP of nonsense was answered \(badDefault.status): \(badDefault.body)")

    // None of the three left anything behind.
    let listed = try request("GET", "/services/dns/all", body: nil, to: api)
    #expect(!listed.body.contains("a.test"), "a refused zone was added anyway: \(listed.body)")
    #expect(!listed.body.contains("b.test"), "a refused zone was added anyway: \(listed.body)")
    #expect(!listed.body.contains("c.test"), "a refused zone was added anyway: \(listed.body)")

    // And a zone that is entirely well formed is still taken, so this did not
    // become a parser that refuses everything.
    let good = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"d.test\",\"records\":[{\"name\":\"api\",\"ip\":\"10.1.2.3\"}]}", to: api)
    #expect(good.status == 200, "a well formed zone was refused: \(good.body)")
    let afterwards = try request("GET", "/services/dns/all", body: nil, to: api)
    #expect(afterwards.body.contains("d.test"), "the good zone is not listed: \(afterwards.body)")

    // The shape upstream's client actually sends. Go serialises a nil `net.IP`
    // as "" rather than as null, so every zone gvproxy's client sends without a
    // default carries `"DefaultIP":""` -- empty is how it says absent, and the
    // first version of the strictness above refused all of them. The interop
    // check caught that; this pins it, because a check that fails in another
    // script does not say why.
    let upstreamShape = try request(
        "POST", "/services/dns/add",
        body:
            "{\"Name\":\"e.test.\",\"Records\":[{\"Name\":\"api\",\"IP\":\"10.1.2.3\",\"Regexp\":null}],\"DefaultIP\":\"\"}",
        to: api)
    #expect(
        upstreamShape.status == 200,
        "the shape upstream's client sends was refused: \(upstreamShape.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aProtocolFieldThatIsNotAStringIsRefusedRatherThanTakenAsTcp() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    // Both parsers read this field as `(… as? String) ?? "tcp"`, so a value that
    // was present and not a string failed the cast and took the default. The
    // caller asked for something the gateway does not offer and was given TCP.
    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\",\"protocol\":42}", to: api)
    #expect(
        exposed.status == 400,
        "a protocol of 42 was answered \(exposed.status), not refused: \(exposed.body)")

    // And nothing was published by the request that was refused.
    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(listed.body == "[]", "the refused request published a forward anyway: \(listed.body)")

    // Unexpose is the same parser and the worse half. A host port is unique only
    // within a protocol -- 8080/tcp and 8080/udp are two forwards and both can
    // be published at once -- so falling back to tcp there does not fail, it
    // removes the tcp forward on that port. The caller named a protocol this
    // gateway could not read, and a working forward disappeared.
    let tcp = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(tcp.status == 200)
    let bound = boundPort(in: tcp.body) ?? 0
    let udp = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":\(bound)\",\"remote\":\"192.168.127.2:53\",\"protocol\":\"udp\"}",
        to: api)
    #expect(udp.status == 200, "the same port could not carry a udp forward too: \(udp.body)")

    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose",
        body: "{\"local\":\":\(bound)\",\"protocol\":42}", to: api)
    #expect(
        withdrawn.status == 400,
        "a protocol of 42 was answered \(withdrawn.status), not refused")

    // Both are still there. Read as tcp, that request would have taken the tcp
    // one and answered 200, and the caller would have been told it worked.
    //
    // Named exactly, not by protocol. Written as `contains("tcp")` this passed
    // against the broken parser -- the forward the refused expose had already
    // leaked is a tcp one too, so the check was true whatever happened to the
    // forward it was about.
    let after = try request("GET", "/services/forwarder/all", body: nil, to: api)
    let tcpEntry = "{\"local\":\":\(bound)\",\"protocol\":\"tcp\"}"
    let udpEntry = "{\"local\":\":\(bound)\",\"protocol\":\"udp\"}"
    #expect(
        after.body.contains(tcpEntry),
        "the tcp forward on that port was removed by a protocol that is not a string: \(after.body)")
    #expect(after.body.contains(udpEntry), "the udp forward on that port is gone: \(after.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aPortCanBeExposedListedAndWithdrawnOverTheApi() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let empty = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(empty.status == 200)
    #expect(empty.body == "[]")

    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(exposed.status == 200)
    // Port zero means "anything free", so the answer has to name what was
    // actually bound: a caller told ":0" has no way to address it later.
    let bound = boundPort(in: exposed.body) ?? 0
    #expect(bound > 0, "the answer did not name the port that was bound: \(exposed.body)")

    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(listed.body.contains(":\(bound)"), "the forward is not listed: \(listed.body)")

    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose", body: "{\"local\":\":\(bound)\"}", to: api)
    #expect(withdrawn.status == 200)

    let afterwards = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(afterwards.body == "[]", "the withdrawn forward is still listed: \(afterwards.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func withdrawingAPortThatWasNeverExposedIsAnError() async throws {
    // Not silently fine. A tool that unexposes a port and is told "ok" has no
    // way to notice it was managing a forward that had already gone.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let answer = try request(
        "POST", "/services/forwarder/unexpose", body: "{\"local\":\":9999\"}", to: api)
    #expect(answer.status == 404)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aMalformedRequestIsRefusedRatherThanGuessedAt() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    for body in ["", "{}", "not json", "{\"local\":\":8080\"}", "{\"local\":\"x\",\"remote\":\"y\"}"] {
        let answer = try request("POST", "/services/forwarder/expose", body: body, to: api)
        #expect(answer.status == 400, "body \(body) was accepted with status \(answer.status)")
    }

    let unknown = try request("GET", "/nothing/here", body: nil, to: api)
    #expect(unknown.status == 404)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func anOverlongBodyIsRefusedRatherThanAccumulated() async throws {
    // A request body is chosen by whatever can reach the socket, and a handler
    // that accumulates until the end of a request will accumulate whatever it is
    // sent. The cap has to be checked while reading, not after: after is the
    // failure it exists to prevent.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let huge = String(repeating: "a", count: ControlPlane.maximumBodyBytes + 1)
    let answer = try request("POST", "/services/forwarder/expose", body: huge, to: api)
    #expect(answer.status == 413, "an oversized body was accepted with status \(answer.status)")

    // And the plane still works afterwards: a refusal must not wedge it.
    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(listed.status == 200)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func exposingWithoutAHostPublishesToLoopbackRatherThanEverywhere() async throws {
    // `":8080"` is upstream's spelling for "this machine", and it is also the
    // safe reading. Mapping the empty host to the wildcard would publish a
    // guest's port to the whole network the moment somebody forwarded one, which
    // is not what the request says and is not a mistake the user would see.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(exposed.status == 200)

    let address = try await holder.gateway!.eventLoop.submit {
        holder.gateway!.forwardedPorts.first
    }.get()
    #expect(address != nil)

    // The listener is on loopback, so a connection to it from another address on
    // this machine is refused. Checked by the address the forwarder reports
    // rather than by trying to reach it from elsewhere, which a test cannot
    // arrange portably.
    let bound = try await holder.gateway!.eventLoop.submit { () -> String? in
        holder.gateway!.forwarderForTesting(hostPort: address!)?.listeningAddress?.ipAddress
    }.get()
    #expect(bound == "127.0.0.1", "the forward was published on \(bound ?? "nothing")")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func statisticsAreReadableOverTheApiAndMoveWhenSomethingHappens() async throws {
    // A gauge that never moves is indistinguishable from a gauge that is not
    // wired to anything, so this reads the same field twice with a real change
    // in between rather than asserting a shape once. Checking only that the
    // JSON parses would pass for a handler returning a constant.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let before = try request("GET", "/stats", body: nil, to: api)
    #expect(before.status == 200)
    #expect(before.body.contains("\"forwarded_ports\":0"), "unexpected stats: \(before.body)")
    // The keys are an operator's dashboard, so their spelling is part of the
    // interface rather than an accident of Swift property names.
    #expect(before.body.contains("\"tcp_refused_by_limit\":0"))
    #expect(before.body.contains("\"dns_refused_no_upstream\":0"))

    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(exposed.status == 200)

    let after = try request("GET", "/stats", body: nil, to: api)
    #expect(after.body.contains("\"forwarded_ports\":1"), "the forward did not reach stats: \(after.body)")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func theLeaseAndAddressTableRoutesAnswerEvenWithNothingToReport() async throws {
    // Upstream serves both. An empty object rather than a 404 is the point of
    // this test: a gateway on a single wire has no switch and no address table,
    // and a tool polling /cam should not have to tell "no switch" apart from
    // "nothing learned yet" -- especially since the second becomes the first
    // every time it restarts.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let cam = try request("GET", "/cam", body: nil, to: api)
    #expect(cam.status == 200)
    #expect(cam.body == "{}")

    let leases = try request("GET", "/leases", body: nil, to: api)
    #expect(leases.status == 200)
    #expect(leases.body == "{}")

    // And a route that does not exist still says so, so the two answers above
    // are the route working rather than the fallback answering everything.
    let missing = try request("GET", "/no-such-thing", body: nil, to: api)
    #expect(missing.status == 404)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aZoneCanBeAddedOverTheApiAndProtectedOnesRefused() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let before = try request("GET", "/services/dns/all", body: nil, to: api)
    #expect(before.status == 200)
    // The gateway's own configuration made this zone, and it is protected.
    #expect(before.body.contains("containers.internal"), "unexpected zones: \(before.body)")
    #expect(before.body.contains("\"protected\":true"))

    let added = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"svc.test.\",\"records\":[{\"name\":\"api\",\"ip\":\"10.1.2.3\"}]}", to: api)
    #expect(added.status == 200, "adding a zone failed: \(added.body)")

    let after = try request("GET", "/services/dns/all", body: nil, to: api)
    #expect(after.body.contains("svc.test"), "the zone is not listed: \(after.body)")
    #expect(after.body.contains("10.1.2.3"))

    // The trailing dot is upstream's spelling and must not survive into the
    // name this gateway compares against, or nothing ever matches it.
    #expect(!after.body.contains("svc.test."), "the zone name kept its trailing dot")

    let hijack = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"containers.internal.\",\"defaultIP\":\"6.6.6.6\"}", to: api)
    #expect(hijack.status == 409, "a protected zone was replaced over the API")

    // A zone with neither records nor a default answers NXDOMAIN for everything
    // under it, which is a way to break resolution that looks like a way to
    // configure it. Upstream refuses it and so does this.
    let empty = try request("POST", "/services/dns/add", body: "{\"name\":\"empty.test.\"}", to: api)
    #expect(empty.status == 400)

    let root = try request(
        "POST", "/services/dns/add", body: "{\"name\":\".\",\"defaultIP\":\"6.6.6.6\"}", to: api)
    #expect(root.status == 400, "the root zone was accepted")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func connectIsRefusedOnAGatewayWithNoSwitch() async throws {
    // A gateway on a single wire has one guest already and nowhere to put a
    // second. Refused with a status rather than by hijacking and then failing,
    // because a client that has been hijacked has no way to be told anything.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let refused = try request("POST", "/connect", body: nil, to: api)
    #expect(refused.status == 409, "connect was accepted on a gateway with no switch")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

/// The port named by `{"local":":8080",...}`, parsed rather than string-stripped.
///
/// The first version of this stripped a known prefix and suffix, so adding a
/// field to the response broke it in four places at once and said nothing about
/// which change caused it.
private func boundPort(in body: String) -> Int? {
    guard let object = try? JSONSerialization.jsonObject(with: Data(body.utf8)),
        let fields = object as? [String: Any], let local = fields["local"] as? String,
        let colon = local.lastIndex(of: ":")
    else { return nil }
    return Int(local[local.index(after: colon)...])
}

@Test func aUdpPortCanBeExposedAlongsideATcpOneOnTheSameNumber() async throws {
    // A host port is only unique within a protocol. 8080/tcp and 8080/udp are
    // two different forwards and both may be published at once -- so keying the
    // table by port alone makes exposing the second silently displace the
    // first, and unexposing either take down whichever happens to be there.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let tcp = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(tcp.status == 200, "tcp expose failed: \(tcp.body)")
    let tcpPort = try #require(boundPort(in: tcp.body))

    // The same number, as UDP. Bound explicitly rather than with :0, because
    // the point is that the number collides.
    let udp = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":\(tcpPort)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"udp\"}", to: api)
    #expect(udp.status == 200, "udp expose on the same port failed: \(udp.body)")

    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(listed.body.contains("\"protocol\":\"tcp\""), "the tcp forward is gone: \(listed.body)")
    #expect(listed.body.contains("\"protocol\":\"udp\""), "the udp forward is not listed: \(listed.body)")

    // Withdrawing the UDP one leaves the TCP one alone.
    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose",
        body: "{\"local\":\":\(tcpPort)\",\"protocol\":\"udp\"}", to: api)
    #expect(withdrawn.status == 200)
    let after = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(after.body.contains("\"protocol\":\"tcp\""), "withdrawing udp took the tcp forward with it")
    #expect(!after.body.contains("\"protocol\":\"udp\""))

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aForwardOnAUnixSocketIsPublishedAtItsPath() async throws {
    // Upstream's `unix` protocol. Who may reach the guest is then decided by
    // filesystem permissions rather than by whoever can open a connection to a
    // port on this machine, which is a stronger and a more visible answer.
    let path = "/tmp/netstack-unix-forward-\(UInt32.random(in: 0...UInt32.max)).sock"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"\(path)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}", to: api)
    #expect(exposed.status == 200, "unix expose failed: \(exposed.body)")
    #expect(FileManager.default.fileExists(atPath: path), "no socket was created at \(path)")

    let listed = try request("GET", "/services/forwarder/all", body: nil, to: api)
    #expect(listed.body.contains(path), "the unix forward is not listed: \(listed.body)")

    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose",
        body: "{\"local\":\"\(path)\",\"protocol\":\"unix\"}", to: api)
    #expect(withdrawn.status == 200)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aRelativeUnixPathIsRefusedRatherThanResolvedAgainstTheWorkingDirectory() async throws {
    // Where a relative path lands depends on whichever directory this process
    // happens to be in, which the caller has no way to know -- so the socket
    // appears somewhere neither of them expected, and a caller that asked twice
    // could get two different sockets.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let refused = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"relative.sock\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}", to: api)
    #expect(refused.status == 400, "a relative socket path was accepted")

    // The floor: an absolute one is fine, so this is the path check rather than
    // unix forwarding being refused outright.
    let path = "/tmp/netstack-abs-\(UInt32.random(in: 0...UInt32.max)).sock"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let accepted = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\"\(path)\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"unix\"}", to: api)
    #expect(accepted.status == 200)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func anUnknownProtocolIsRefusedRatherThanTreatedAsTcp() async throws {
    // Defaulting an unrecognised value to TCP would publish a port the caller
    // did not ask for, on a protocol it did not ask for, and report success.
    // An absent `protocol` still means TCP -- that is upstream's default and
    // keeps every request written before this existed working.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    let refused = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\",\"protocol\":\"sctp\"}", to: api)
    #expect(refused.status == 400, "an unknown protocol was accepted")

    let defaulted = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}", to: api)
    #expect(defaulted.status == 200, "an absent protocol was not treated as tcp")
    #expect(defaulted.body.contains("\"protocol\":\"tcp\""))

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

/// A raw request, written verbatim, so a test can send something no well-behaved
/// client would.
private func rawRequest(_ text: String, to address: SocketAddress) throws -> String {
    let fd = makeSocket(AF_INET, .stream)
    #expect(fd >= 0)
    defer { close(fd) }
    _ = connectTo(fd, loopbackAddress(port: UInt16(address.port!)))
    var deadline = timeval(tv_sec: 3, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
    let out = Array(text.utf8)
    _ = out.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    var response = ""
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let received: Int = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        if received <= 0 { break }
        response += String(decoding: buffer[0..<received], as: UTF8.self)
    }
    return response
}

@Test func theControlPlaneAnswersRequestsNoWellBehavedClientWouldSend() async throws {
    // The framer in front of NIO's HTTP decoder is hand-written, and it decides
    // where one message ends. Anything it disagrees with the decoder about is a
    // desync: the framer holds bytes the decoder is waiting for, or forwards
    // bytes the decoder reads as a second request.
    //
    // Every case here must produce an answer. A hang is the failure mode that
    // matters -- the framer holding a body nobody will ever complete -- and it
    // is why these use a read deadline rather than blocking.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    // Chunked, which carries no Content-Length at all.
    let chunked = try rawRequest(
        "POST /services/forwarder/all HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        to: api)
    #expect(!chunked.isEmpty, "a chunked request was never answered")

    // Two Content-Lengths that disagree: the classic smuggling primitive, where
    // one parser believes the first and another the second.
    let conflicting = try rawRequest(
        "POST /services/forwarder/all HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 100\r\n\r\nhello",
        to: api)
    #expect(!conflicting.isEmpty, "a request with two Content-Lengths was never answered")

    // A length that is not a number, and one that is negative.
    let garbage = try rawRequest(
        "POST /services/forwarder/all HTTP/1.1\r\nHost: h\r\nContent-Length: nonsense\r\n\r\n", to: api)
    #expect(!garbage.isEmpty, "a request with a non-numeric Content-Length was never answered")

    let negative = try rawRequest(
        "POST /services/forwarder/all HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n", to: api)
    #expect(!negative.isEmpty, "a request with a negative Content-Length was never answered")

    // A body shorter than it claims: the connection ends before the framer has
    // what it is waiting for.
    let short = try rawRequest(
        "POST /services/forwarder/all HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\nshort", to: api)
    #expect(short.isEmpty || short.contains("HTTP/1.1"), "a truncated body produced something odd")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

/// Send raw bytes and report what the server did: answered, closed, or neither.
private enum RawOutcome { case answered, closed, hung }

private func rawProbe(_ bytes: [UInt8], to address: SocketAddress) -> RawOutcome {
    let fd = makeSocket(AF_INET, .stream)
    guard fd >= 0 else { return .closed }
    defer { close(fd) }
    guard connectTo(fd, loopbackAddress(port: UInt16(address.port!))) == 0 else { return .closed }
    var deadline = timeval(tv_sec: 3, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
    _ = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    var buffer = [UInt8](repeating: 0, count: 4096)
    let received: Int = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
    if received > 0 { return .answered }
    if received == 0 { return .closed }
    return .hung
}

@Test func everyMutatedRequestIsAnsweredOrClosedRatherThanHeld() async throws {
    // The property that matters for a hand-written framer sitting in front of
    // somebody else's parser: whatever arrives, the connection ends. A request
    // the framer holds and the decoder is waiting for produces neither an answer
    // nor a close, and the peer waits forever -- which is what four ordinary
    // malformed requests did before this, and what makes a framing disagreement
    // a denial of service rather than a parse error.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    // A short timeout so the test does not spend the default ten seconds on
    // every truncated request. The mechanism is what is under test; the default
    // value is a separate choice, documented where it is set.
    holder.plane?.requestTimeout = .milliseconds(120)
    let api = holder.plane!.listeningAddress!

    let corpus: [String] = [
        "GET /stats HTTP/1.1\r\nHost: h\r\n\r\n",
        "POST /services/forwarder/expose HTTP/1.1\r\nHost: h\r\nContent-Length: 44\r\n\r\n"
            + "{\"local\":\":0\",\"remote\":\"192.168.127.2:80\"}",
        "POST /services/dns/add HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "GET /services/forwarder/all HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
    ]

    var state: UInt64 = 0xA11CE
    func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }

    var hung = 0
    for _ in 0..<120 {
        var bytes = Array(corpus[Int(next() % UInt64(corpus.count))].utf8)
        for _ in 0...(next() % 3) {
            guard !bytes.isEmpty else { break }
            switch next() % 4 {
            case 0: bytes[Int(next() % UInt64(bytes.count))] = UInt8(truncatingIfNeeded: next())
            case 1: bytes = Array(bytes.prefix(Int(next() % UInt64(bytes.count))))
            case 2: bytes += (0..<Int(next() % 32)).map { _ in UInt8(truncatingIfNeeded: next()) }
            default:
                // Splice in a second request, which is the smuggling shape: the
                // framer must hold it rather than let the decoder read it.
                bytes += Array("GET /stats HTTP/1.1\r\nHost: h\r\n\r\n".utf8)
            }
        }
        if rawProbe(bytes, to: api) == .hung { hung += 1 }
    }

    #expect(hung == 0, "\(hung) of 120 mutated requests were neither answered nor closed")

    // The floor: a well-formed request is still answered, so the above is not
    // satisfied by a server that closes everything.
    #expect(rawProbe(Array(corpus[0].utf8), to: api) == .answered)

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func upstreamsOwnClientLibraryWouldWorkAgainstThisGateway() async throws {
    // Every route `pkg/client` calls, in the spelling it calls it, with the
    // capitalisation Go's encoder produces. That is a narrow and very concrete
    // definition of being a port: upstream's own client can drive this.
    //
    // Two things failed it. `/services/dhcp/leases` did not exist -- upstream
    // serves leases at two paths and its client uses the one this did not have.
    // And `types.Zone` carries no json tags, so Go emits `Name`, `Records`,
    // `IP`, `DefaultIP`, while this read only lowercase keys: the client could
    // read zones from this gateway and not write them.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    for path in ["/services/forwarder/all", "/services/dns/all", "/services/dhcp/leases"] {
        let answer = try request("GET", path, body: nil, to: api)
        #expect(answer.status == 200, "\(path) answered \(answer.status)")
    }

    // Go's field names, which is what the client sends.
    let exposed = try request(
        "POST", "/services/forwarder/expose",
        body: "{\"Local\":\":0\",\"Remote\":\"192.168.127.2:80\",\"Protocol\":\"tcp\"}", to: api)
    #expect(exposed.status == 200, "an expose in Go's capitalisation failed: \(exposed.body)")
    let bound = try #require(boundPort(in: exposed.body))

    let zone = try request(
        "POST", "/services/dns/add",
        body: "{\"Name\":\"client.test.\",\"Records\":[{\"Name\":\"api\",\"IP\":\"10.4.5.6\"}]}", to: api)
    #expect(zone.status == 200, "a zone in Go's capitalisation failed: \(zone.body)")
    let zones = try request("GET", "/services/dns/all", body: nil, to: api)
    #expect(zones.body.contains("10.4.5.6"), "the zone was accepted but not stored: \(zones.body)")

    let withdrawn = try request(
        "POST", "/services/forwarder/unexpose", body: "{\"Local\":\":\(bound)\"}", to: api)
    #expect(withdrawn.status == 200)

    // The floor: lowercase still works, so this is leniency added rather than
    // one spelling swapped for another. Both are the same request to upstream.
    let lower = try request(
        "POST", "/services/dns/add",
        body: "{\"name\":\"lower.test.\",\"records\":[{\"name\":\"api\",\"ip\":\"10.7.8.9\"}]}", to: api)
    #expect(lower.status == 200, "the documented lowercase spelling stopped working")

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

// MARK: - The parser a hostile guest can reach

/// SplitMix64, written out here rather than shared with `FuzzTests`: one
/// generator's worth of arithmetic is cheaper than a dependency between two
/// test files that otherwise have nothing to do with each other.
private struct PlaneRandom {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// The request asked after each mutated one, to see whether the plane is still
/// there. `Connection: close` on purpose: `rawRequest` reads until the server
/// hangs up, so a kept-alive connection costs its full read deadline every
/// time. With it the check is immediate when the plane behaves and slow only
/// when it does not, which is the way round that matters -- the first version
/// of this test took a hundred and fifty seconds to say nothing was wrong.
private let planeProbe = "GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

/// Requests that are meant to work, before anything is done to them.
private let planeSeeds = [
    "GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    "GET /leases HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    "GET /services/forwarder/all HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    "POST /services/forwarder/expose HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 48\r\n\r\n"
        + "{\"local\":\"127.0.0.1:0\",\"remote\":\"192.168.127.2:80\"}",
    "POST /services/dns/add HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 30\r\n\r\n"
        + "{\"name\":\"z.\",\"records\":[]}",
]

/// One mutation. Each is a shape that breaks a hand-written framer rather than
/// random noise -- a length that disagrees with the body, a header that ends
/// where the parser did not expect, a NUL in the middle of a token.
private func mutatePlaneRequest(_ text: String, _ rng: inout PlaneRandom) -> String {
    var bytes = Array(text.utf8)
    guard !bytes.isEmpty else { return text }
    switch rng.next() % 8 {
    case 0:
        bytes[Int(rng.next() % UInt64(bytes.count))] ^= UInt8(1 << (rng.next() % 8))
    case 1:
        bytes = Array(bytes.prefix(Int(rng.next() % UInt64(bytes.count))))
    case 2:
        return text.replacingOccurrences(of: "Content-Length:", with: "Content-Length: 99999 ;")
    case 3:
        return text + text
    case 4:
        bytes.insert(0, at: Int(rng.next() % UInt64(bytes.count)))
    case 5:
        return text.replacingOccurrences(of: "\r\n\r\n", with: "\r\n")
    case 6:
        return String(repeating: "X", count: 1 + Int(rng.next() % 4096)) + text
    default:
        return text.replacingOccurrences(of: "HTTP/1.1", with: "HTTP/9.9")
    }
    return String(decoding: bytes, as: UTF8.self)
}

/// Send and hang up, without waiting for an answer.
///
/// The mutated requests do not need one: what is being checked is the probe
/// after them, and most of them should be refused or left incomplete anyway. A
/// truncated request legitimately leaves the server waiting for the rest, so
/// reading its reply means waiting out the read deadline every time -- which is
/// what made the first version of this test take a hundred and fifty seconds.
///
/// Hanging up mid-request is also the more realistic shape. A guest that sends
/// half a body and disappears is exactly the case a hand-written framer gets
/// wrong.
private func sendAndHangUp(_ text: String, to address: SocketAddress) {
    let fd = makeSocket(AF_INET, .stream)
    guard fd >= 0 else { return }
    defer { close(fd) }
    _ = connectTo(fd, loopbackAddress(port: UInt16(address.port!)))
    let out = Array(text.utf8)
    _ = out.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
}

@Test func theControlPlaneKeepsServingWhateverAGuestSendsIt() async throws {
    // The frame fuzzer covers every parser a guest can reach with a datagram --
    // ARP, DHCP, DNS, ICMP, TCP options, fragments. It does not reach this one,
    // and a guest can: the forwarding routes are served to it at the gateway's
    // own address on port 80, so its HTTP framer and JSON parsing are as
    // exposed as anything under `Network/`.
    //
    // What is checked is not that a mutated request is answered sensibly --
    // most should be refused -- but that the NEXT well-formed one still is. A
    // framer that holds a body nobody will complete, or that forwards bytes the
    // decoder reads as a second request, wedges the connection after it rather
    // than the one that did it. That is why the check is a good request after
    // each bad one rather than an assertion about the bad one's answer.
    let iterations = Int(ProcessInfo.processInfo.environment["NETSTACK_PLANE_FUZZ_ITERATIONS"] ?? "") ?? 120
    let seed = UInt64(ProcessInfo.processInfo.environment["NETSTACK_PLANE_FUZZ_SEED"] ?? "") ?? 0x5EED
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await controlPlaneFixture(group: group, guestSide: &guestSide)
    let api = holder.plane!.listeningAddress!

    // The floor, so a failure below is the fuzzing rather than a fixture that
    // never worked.
    #expect(
        try rawRequest(planeProbe, to: api).contains("200"),
        "the plane did not answer before any of this began")

    var rng = PlaneRandom(seed: seed)
    for iteration in 0..<iterations {
        var request = planeSeeds[Int(rng.next() % UInt64(planeSeeds.count))]
        for _ in 0...(rng.next() % 3) {
            request = mutatePlaneRequest(request, &rng)
        }
        sendAndHangUp(request, to: api)

        let answer = try rawRequest(planeProbe, to: api)
        guard answer.contains("200") else {
            Issue.record("the plane stopped answering after iteration \(iteration)")
            break
        }
    }

    holder.plane?.close()
    _ = try? await holder.gateway?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.gateway
}

@Test func mutatedRequestsActuallyReachTheFramer() throws {
    // The floor under the test above, and what makes it worth running. Sending
    // bytes at a socket and finding the plane still alive proves nothing if the
    // bytes were rejected at the first character -- the fuzzer would pass while
    // exercising the front door rather than the framer behind it.
    //
    // `FuzzTests` has the same companion for the same reason, and the reason it
    // exists is that the socket-level check could not be falsified on its own:
    // poisoning the plane's error path left the fuzz test green, because
    // nothing established that its corpus got that far.
    //
    // So this drives the framer directly and counts. What it wants is not that
    // every mutation parses -- most should not -- but that enough do to be
    // reaching the code under test.
    var rng = PlaneRandom(seed: 0xBEEF)
    var complete = 0
    let attempts = 400

    for _ in 0..<attempts {
        var request = planeSeeds[Int(rng.next() % UInt64(planeSeeds.count))]
        for _ in 0...(rng.next() % 3) {
            request = mutatePlaneRequest(request, &rng)
        }
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(HTTPMessageFramer())
        _ = try? channel.writeInbound(ByteBuffer(string: request))
        while let framed = ((try? channel.readInbound(as: ByteBuffer.self)) ?? nil) {
            _ = framed
            complete += 1
        }
        _ = try? channel.finish()
    }

    // One expression, because `#expect`'s message is a `Comment` and a `+`
    // between two strings is not one.
    #expect(
        complete > attempts / 10,
        "\(complete) of \(attempts) mutated requests reached the framer as a message, which is too few to be exercising it")
}
