import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

// What happens when the guest stops reading.
//
// It is not a hypothetical: a VM that is paused, migrating, or simply slow stops
// draining its side of the socket, and the gateway keeps answering into a queue
// that is already full. A unix datagram queue holds about forty frames --
// `net.local.dgram.recvspace` is 4096 on macOS -- so it does not take long.

private let backpressureMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

@Test func aGuestThatStopsReadingDoesNotTakeTheGatewaysWireWithIt() async throws {
    // Before this, it did. A full unix datagram queue reports ENOBUFS on BSD
    // where Linux reports EAGAIN; NIO retries the second and treats the first as
    // an unrecoverable write error, so it closed the channel. The gateway was
    // then permanently off the network -- not slow, not backed up, closed -- and
    // nothing above it noticed: `outboundDropped` was still zero.
    //
    // Upstream has the same failure and the same fix. `pkg/tap/switch.go`
    // retries on ENOBUFS and cites gvisor-tap-vsock#367.
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()

    // The guest asks two hundred times and reads nothing back, which fills the
    // return queue several times over.
    for transaction in 0..<200 {
        let discover = frame(
            from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
            destinationPort: DHCPServer.serverPort,
            payload: dhcpDiscover(hardware: backpressureMAC, transaction: UInt32(transaction)),
            destinationMAC: .broadcast)
        _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        try await Task.sleep(nanoseconds: 1_000_000)
    }

    let wire = try await gateway.eventLoop.submit {
        (
            open: (gateway.link as? WireLinkEndpoint)?.isActiveForTesting ?? false,
            read: gateway.link.bytesReceived
        )
    }.get()
    #expect(wire.open, "the wire closed because the guest stopped reading")
    // And it kept working while the guest was not reading, rather than stopping
    // at the first refused write.
    #expect(wire.read > 10_000, "the gateway stopped reading after only \(wire.read) bytes")

    // The guest starts reading again.
    for _ in 0..<4000 {
        var back = [UInt8](repeating: 0, count: 4096)
        if back.withUnsafeMutableBytes({ recv(pair[1], $0.baseAddress, $0.count, dontWait) }) <= 0 {
            break
        }
    }

    // And is served again. This is the assertion that matters: a link may drop
    // while its peer is not listening -- that is what a link does -- but it has
    // to come back when the peer does.
    var recovered = false
    for transaction in 900..<960 where !recovered {
        let discover = frame(
            from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
            destinationPort: DHCPServer.serverPort,
            payload: dhcpDiscover(hardware: backpressureMAC, transaction: UInt32(transaction)),
            destinationMAC: .broadcast)
        _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        for _ in 0..<50 where !recovered {
            var back = [UInt8](repeating: 0, count: 4096)
            let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
            if read > 42 { recovered = true } else { try await Task.sleep(nanoseconds: 2_000_000) }
        }
    }
    #expect(recovered, "the gateway never answered again after the guest resumed reading")

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}
