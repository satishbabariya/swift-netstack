import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// Upstream's API for managing port forwards while the gateway runs, so a tool
// written against `gvproxy` works here unchanged. Anything that can reach it can
// publish any guest port on the host, which is why the interesting tests are
// about what it refuses.

private final class CPHolder: @unchecked Sendable {
    var gateway: Gateway?
    var plane: ControlPlane?
}

private func controlPlaneFixture(group: EventLoopGroup, guestSide: inout Int32) async throws -> CPHolder {
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    guestSide = pair[1]
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
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
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    #expect(fd >= 0)
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_port = UInt16(address.port!).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
    let connected = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    #expect(connected == 0, "could not reach the control plane")

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
    let statusLine = response.split(separator: "\r\n").first ?? ""
    let status = Int(statusLine.split(separator: " ").dropFirst().first ?? "0") ?? 0
    let payload = response.components(separatedBy: "\r\n\r\n").dropFirst().joined(separator: "\r\n\r\n")
    return (status, payload)
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
    let bound = Int(exposed.body.replacingOccurrences(of: "{\"local\":\":", with: "")
        .replacingOccurrences(of: "\"}", with: "")) ?? 0
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
