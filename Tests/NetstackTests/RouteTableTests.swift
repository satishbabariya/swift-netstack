import NIOEmbedded
import Testing

@testable import Netstack

private func makeNIC(spoofing: Bool) -> NIC {
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    nic.allowsAnySource = spoofing
    return nic
}

@Test func resolvesAnOnLinkDestination() {
    let nic = makeNIC(spoofing: false)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    let route = table.lookup(destination: IPv4Address("192.168.127.2")!, preferredSource: nil)
    #expect(route?.nic.id == 1)
    #expect(route?.source == IPv4Address("192.168.127.1"))
    #expect(route?.nextHop == IPv4Address("192.168.127.2"))
    #expect(route?.isLocal == true)
}

@Test func prefersTheLongestMatchingPrefix() {
    let nic = makeNIC(spoofing: false)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "0.0.0.0/0")!, gateway: IPv4Address("192.168.127.254"), nicID: 1))
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    let onLink = table.lookup(destination: IPv4Address("192.168.127.9")!, preferredSource: nil)
    #expect(onLink?.nextHop == IPv4Address("192.168.127.9"))
    #expect(onLink?.isLocal == true)

    let offLink = table.lookup(destination: IPv4Address("8.8.8.8")!, preferredSource: nil)
    #expect(offLink?.nextHop == IPv4Address("192.168.127.254"))
    #expect(offLink?.isLocal == false)
}

@Test func returnsNilWhenNothingMatches() {
    let nic = makeNIC(spoofing: false)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))
    #expect(table.lookup(destination: IPv4Address("8.8.8.8")!, preferredSource: nil) == nil)
}

@Test func spoofingHonoursAnUnownedSource() {
    let nic = makeNIC(spoofing: true)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    // Answering the guest as though we were a host on the internet.
    let route = table.lookup(destination: IPv4Address("192.168.127.2")!, preferredSource: IPv4Address("93.184.216.34"))
    #expect(route?.source == IPv4Address("93.184.216.34"))
}

@Test func withoutSpoofingAnUnownedSourceIsIgnored() {
    let nic = makeNIC(spoofing: false)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    let route = table.lookup(destination: IPv4Address("192.168.127.2")!, preferredSource: IPv4Address("93.184.216.34"))
    #expect(route?.source == IPv4Address("192.168.127.1"))
}

@Test func anOwnedPreferredSourceIsAlwaysHonoured() {
    let nic = makeNIC(spoofing: false)
    nic.addAddress(IPv4Address("192.168.127.5")!, prefixLength: 24)
    let table = RouteTable()
    table.register(nic)
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    let route = table.lookup(destination: IPv4Address("192.168.127.2")!, preferredSource: IPv4Address("192.168.127.5"))
    #expect(route?.source == IPv4Address("192.168.127.5"))
}

@Test func aRouteToAnUnregisteredNICResolvesToNothing() {
    let table = RouteTable()
    table.add(Route(destination: IPv4Subnet(cidr: "0.0.0.0/0")!, gateway: nil, nicID: 99))
    #expect(table.lookup(destination: IPv4Address("8.8.8.8")!, preferredSource: nil) == nil)
}

@Test func fallsThroughToTheNextRouteWhenTheBestMatchsNICIsUnregistered() {
    let nic = makeNIC(spoofing: false)
    let table = RouteTable()
    table.register(nic)
    // Best (longest-prefix) match points at a NIC that was never registered.
    table.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 99))
    // Less-specific default route to the NIC that IS registered.
    table.add(Route(destination: IPv4Subnet(cidr: "0.0.0.0/0")!, gateway: IPv4Address("192.168.127.254"), nicID: 1))

    let route = table.lookup(destination: IPv4Address("192.168.127.2")!, preferredSource: nil)
    #expect(route?.nic.id == 1)
    #expect(route?.nextHop == IPv4Address("192.168.127.254"))
    #expect(route?.isLocal == false)
}
