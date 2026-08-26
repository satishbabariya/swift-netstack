import Testing

@testable import Netstack

@Test func etherTypesHaveIANAValues() {
    #expect(EtherType.ipv4.rawValue == 0x0800)
    #expect(EtherType.arp.rawValue == 0x0806)
    #expect(EtherType.ipv6.rawValue == 0x86dd)
}

@Test func ipProtocolsHaveIANAValues() {
    #expect(IPProtocol.icmp.rawValue == 1)
    #expect(IPProtocol.tcp.rawValue == 6)
    #expect(IPProtocol.udp.rawValue == 17)
}

@Test func icmpTypesHaveIANAValues() {
    #expect(ICMPv4Type.echoReply.rawValue == 0)
    #expect(ICMPv4Type.destinationUnreachable.rawValue == 3)
    #expect(ICMPv4Type.echoRequest.rawValue == 8)
    #expect(ICMPv4Type.timeExceeded.rawValue == 11)
}

@Test func unknownProtocolNumbersRoundTrip() {
    // Open enums: an unrecognised value must survive rather than trap, so an
    // unexpected ethertype is droppable instead of fatal.
    #expect(EtherType(rawValue: 0x1234).rawValue == 0x1234)
}
