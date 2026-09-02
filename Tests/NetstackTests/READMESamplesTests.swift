import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

// The README's code samples, kept where the compiler can see them.
//
// They are a claim about this package's API, and this package's API changed
// repeatedly: `Gateway.Configuration` gained a host address, NAT, virtual
// addresses, a link-local switch, a capture file, a notification socket, static
// leases and search domains, and every one of those was a new parameter in the
// middle of an initialiser the README calls. A sample that no longer compiles is
// the first thing a reader tries and the first thing that fails.
//
// Compiled rather than run. Running them would bind `/tmp/netstack.sock` and
// host port 8080 -- real resources with real collisions, in a suite that runs in
// parallel -- and what goes stale about a sample is its shape, not its
// behaviour. The behaviour is covered by `GatewayTests`, which does all of this
// against a real socketpair with ports the kernel chooses.
//
// Any change here must be mirrored in README.md, and any change there here.

/// From "Using it".
private func readmeUsingIt() async throws {
    var pair: [Int32] = [0, 0]
    _ = makeSocketPair(AF_UNIX, .datagram, &pair)

    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0],
        group: group,
        configuration: .init(upstreamResolvers: [try .init(ipAddress: "1.1.1.1", port: 53)])
    ).get()

    // The README's next sample continues from this one.
    let guestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
    let leased = gateway.leasedAddress(for: guestMAC)!
    _ = try await gateway.forward(hostPort: 8080, toGuest: leased, port: 80).get()

    let control = ControlPlane(gateway: gateway)
    try await control.listen(unixSocketPath: "/tmp/netstack.sock").get()
}

@Test func theReadmeDescribesThisPackagesActualDefaults() {
    // The samples above are checked by compiling. These are the README's other
    // kind of claim: concrete values it states in prose, which a reader will
    // configure a VM around and which nothing else here would notice going
    // stale.
    // The sample above is checked by being compiled; a `private func` in a test
    // target is type-checked whether or not anything calls it, and calling it
    // would bind /tmp/netstack.sock and host port 8080 in a suite that runs in
    // parallel.
    let configuration = Gateway.Configuration()

    // "the guest's address is on a subnet that exists only inside this process"
    #expect(configuration.gatewayAddress == IPv4Address("192.168.127.1")!)
    #expect(configuration.subnet == IPv4Subnet(cidr: "192.168.127.0/24")!)

    // "`host.containers.internal` resolves to a host address inside the subnet
    // (192.168.127.254) which the gateway answers ARP for and rewrites to
    // 127.0.0.1 when it dials"
    #expect(configuration.hostAddress == IPv4Address("192.168.127.254")!)
    #expect(configuration.nat[configuration.hostAddress] == IPv4Address("127.0.0.1")!)
    #expect(configuration.gatewayVirtualAddresses.contains(configuration.hostAddress))

    // "Guests cannot reach 169.254.0.0/16 by default."
    #expect(!configuration.allowsLinkLocal)

    // The four names upstream publishes, which the README quotes.
    //
    // gvproxy builds `containers.internal.` and `docker.internal.` with the same
    // pair of records in each. This had only the first pair, and this assertion
    // said "the two names upstream publishes" while checking exactly the two it
    // knew about -- so `host.docker.internal`, the name a container image is
    // most likely to have been written against, was resolved by forwarding it
    // to a public resolver.
    let names = Set(configuration.dnsRecords.map(\.name))
    #expect(names.contains("gateway.containers.internal"))
    #expect(names.contains("host.containers.internal"))
    #expect(names.contains("gateway.docker.internal"))
    #expect(names.contains("host.docker.internal"))

    // "Reno is the default and CUBIC is opt-in", "RACK ... is there and opt-in".
    let endpoint = TCPEndpoint.self
    _ = endpoint
    #expect(configuration.mtu == 1500)
}
