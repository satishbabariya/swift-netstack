import Testing

@testable import Netstack

@Test func ipv4RoundTripsThroughText() {
    let a = IPv4Address("192.168.127.2")
    #expect(a != nil)
    #expect(a?.raw == 0xc0a8_7f02)
    #expect(a?.description == "192.168.127.2")
    #expect(a?.bytes == [192, 168, 127, 2])
}

@Test func ipv4RejectsMalformedText() {
    #expect(IPv4Address("192.168.1") == nil)
    #expect(IPv4Address("192.168.1.256") == nil)
    #expect(IPv4Address("192.168.1.1.1") == nil)
    #expect(IPv4Address("") == nil)
    #expect(IPv4Address("::1") == nil)
    #expect(IPv4Address("192.168.001.001") == nil)  // leading zeros: octal hazard
    #expect(IPv4Address("192.168.1.01") == nil)
    #expect(IPv4Address("0.0.0.0") != nil)  // a bare zero octet is fine
}

@Test func macRoundTripsThroughText() {
    let m = MACAddress("5a:94:ef:e4:0c:ee")
    #expect(m != nil)
    #expect(m?.bytes == [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
    #expect(m?.description == "5a:94:ef:e4:0c:ee")
    #expect(m?.isMulticast == false)
}

@Test func macRecognisesBroadcastAndMulticast() {
    #expect(MACAddress.broadcast.isBroadcast)
    #expect(MACAddress.broadcast.isMulticast)
    #expect(MACAddress("01:00:5e:00:00:01")?.isMulticast == true)
    #expect(MACAddress("01:00:5e:00:00:01")?.isBroadcast == false)
}

@Test func subnetContainmentAndMask() {
    let net = IPv4Subnet(cidr: "192.168.127.0/24")
    #expect(net != nil)
    #expect(net?.mask == IPv4Address("255.255.255.0"))
    #expect(net?.broadcast == IPv4Address("192.168.127.255"))
    #expect(net?.contains(IPv4Address("192.168.127.2")!) == true)
    #expect(net?.contains(IPv4Address("192.168.128.2")!) == false)
}

@Test func subnetNormalisesToNetworkAddress() {
    // A host address with a prefix must normalise to the network address.
    let net = IPv4Subnet(cidr: "192.168.127.55/24")
    #expect(net?.address == IPv4Address("192.168.127.0"))
}

@Test func slashZeroAndSlashThirtyTwoAreValid() {
    #expect(IPv4Subnet(cidr: "0.0.0.0/0")?.contains(IPv4Address("8.8.8.8")!) == true)
    let host = IPv4Subnet(cidr: "10.0.0.1/32")
    #expect(host?.contains(IPv4Address("10.0.0.1")!) == true)
    #expect(host?.contains(IPv4Address("10.0.0.2")!) == false)
    #expect(IPv4Subnet(cidr: "10.0.0.1/33") == nil)
}

// Upstream documents --gatewayIP as "first usable address of subnet" and
// --hostIP as "last usable address of subnet". Both were hardcoded here, so a
// gateway asked for a different subnet published a host address on the old one:
// `host.containers.internal` -- the whole point of the thing -- answered with an
// address the guest could not route to, while the control API stayed perfectly
// healthy and said nothing.
@Test func usableAddressesAreTheEndsOfTheSubnetRatherThanOfTheLastOctet() {
    // A /25 is the case a "subtract from 255" derivation gets wrong: the
    // broadcast address is .127, not .255.
    let half = IPv4Subnet(cidr: "10.9.0.0/25")!
    #expect(half.firstUsable == IPv4Address("10.9.0.1")!)
    #expect(half.lastUsable == IPv4Address("10.9.0.126")!)

    // And it has to read through the address given rather than assume it was
    // already masked: 10.7.0.9/24 names the same subnet as 10.7.0.0/24.
    let offset = IPv4Subnet(cidr: "10.7.0.9/24")!
    #expect(offset.firstUsable == IPv4Address("10.7.0.1")!)
    #expect(offset.lastUsable == IPv4Address("10.7.0.254")!)
}

@Test func aGatewayGivenOnlyASubnetPlacesItselfAndTheHostOnIt() {
    let configuration = Gateway.Configuration(subnet: IPv4Subnet(cidr: "10.9.0.0/25")!)
    #expect(configuration.gatewayAddress == IPv4Address("10.9.0.1")!)
    #expect(configuration.hostAddress == IPv4Address("10.9.0.126")!)

    // An address that *is* given still wins over the derivation.
    let told = Gateway.Configuration(
        gatewayAddress: IPv4Address("10.9.0.9")!, subnet: IPv4Subnet(cidr: "10.9.0.0/25")!)
    #expect(told.gatewayAddress == IPv4Address("10.9.0.9")!)
}

// A configuration that runs and serves nobody.
//
// A gateway whose own address is outside the subnet it leases starts, binds its
// wire and answers ARP for that address. The guest is then told its router is on
// a network it is not on, and cannot install the route. Everything is running
// and nothing works — the same shape as the initialisation bug that made a
// gateway believe it was 0.0.0.0, and the same shape as the hardcoded host
// address that pointed off-subnet.
//
// Reported rather than trapped: a library that preconditions on a bad argument
// turns an operator's typo into a crash. The program asks and refuses to start.
@Test func aConfigurationThatCannotServeAnyoneSaysSoRatherThanRunning() {
    let subnet = IPv4Subnet(cidr: "192.168.127.0/24")!

    let offSubnet = Gateway.Configuration(
        gatewayAddress: IPv4Address("10.0.0.1")!, subnet: subnet)
    #expect(offSubnet.inconsistencies.count == 1, "\(offSubnet.inconsistencies)")
    #expect(offSubnet.inconsistencies.first?.contains("cannot route to its own router") == true)

    let sameAddress = Gateway.Configuration(
        gatewayAddress: IPv4Address("192.168.127.5")!, subnet: subnet,
        hostAddress: IPv4Address("192.168.127.5")!)
    #expect(sameAddress.inconsistencies.contains { $0.contains("both 192.168.127.5") })

    let strayLease = Gateway.Configuration(
        subnet: subnet,
        dhcpStaticLeases: [MACAddress("aa:bb:cc:dd:ee:ff")!: IPv4Address("10.0.0.9")!])
    #expect(strayLease.inconsistencies.contains { $0.contains("not inside the subnet") })

    // A static lease names an address directly, so it walks straight past the
    // pool's exclusions. Naming the host's address hands a guest the address
    // host.containers.internal resolves to.
    let collidingLease = Gateway.Configuration(
        subnet: subnet,
        dhcpStaticLeases: [MACAddress("aa:bb:cc:dd:ee:ff")!: IPv4Address("192.168.127.254")!])
    #expect(
        collidingLease.inconsistencies.contains { $0.contains("answers for itself") },
        "\(collidingLease.inconsistencies)")

    // And an ordinary static lease is silent.
    let goodLease = Gateway.Configuration(
        subnet: subnet,
        dhcpStaticLeases: [MACAddress("aa:bb:cc:dd:ee:ff")!: IPv4Address("192.168.127.9")!])
    #expect(goodLease.inconsistencies.isEmpty, "\(goodLease.inconsistencies)")

    // The ordinary case, and the derived one, are silent.
    #expect(Gateway.Configuration(subnet: subnet).inconsistencies.isEmpty)
    #expect(Gateway.Configuration(subnet: IPv4Subnet(cidr: "10.9.0.0/25")!).inconsistencies.isEmpty)
}
