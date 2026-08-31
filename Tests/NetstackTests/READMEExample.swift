import Foundation
import NIOCore
import NIOPosix

@testable import Netstack

// The README's examples, compiled.
//
// They are the first thing anybody runs, and nothing checked that they still
// say something true: every symbol in them has been renamed or re-typed at some
// point in this project's life, and a `Gateway.start` that changed shape would
// leave the page wrong with nothing failing.
//
// Never called. Compiling is the whole claim -- these open sockets and would be
// a poor test -- and `scripts/conventions.sh` checks that the text below is what
// the README actually says, so the copy cannot drift from the page it stands in
// for.
//
// Darwin only, and the example says why itself: `pair[1]` goes to
// `VZFileHandleNetworkDeviceAttachment`, which is Virtualization.framework. The
// README asks for macOS 14+ for the same reason.
//
// It took compiling to find out. `SOCK_DGRAM` is `Int32` on Darwin and
// `__socket_type` on Glibc -- the split this library guards in the two files
// that touch a raw socket -- so the example built here and failed on the Linux
// job the first time this file existed. Nothing had said the example was
// platform-specific because nothing had ever built it anywhere else.
#if canImport(Darwin)

    // EXAMPLE BEGINS
    func readmeExample(guestMAC: MACAddress) async throws {

        // The host keeps one end of the pair and hands the other to the VM.
        var pair: [Int32] = [0, 0]
        socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let gateway = try await Gateway.start(
            adoptingDatagramSocket: pair[0],
            group: group,
            configuration: .init(upstreamResolvers: [try .init(ipAddress: "1.1.1.1", port: 53)])
        ).get()

        // pair[1] goes to VZFileHandleNetworkDeviceAttachment.
        let leased = gateway.leasedAddress(for: guestMAC)!
        _ = try await gateway.forward(hostPort: 8080, toGuest: leased, port: 80).get()
        let control = ControlPlane(gateway: gateway)
        try await control.listen(unixSocketPath: "/tmp/netstack.sock").get()
    }
// EXAMPLE ENDS

#endif
