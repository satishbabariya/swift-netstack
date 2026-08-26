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
