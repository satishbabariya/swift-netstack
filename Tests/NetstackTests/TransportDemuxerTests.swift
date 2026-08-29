import NIOCore
import Testing

@testable import Netstack

private final class Recorder: TransportEndpointDelegate {
    var count = 0
    var lastPayload: [UInt8] = []
    var lastRemotePort: UInt16?
    func deliver(header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16) {
        count += 1
        lastPayload = Array(payload.readableBytesView)
        lastRemotePort = remotePort
    }
}

private func header(from source: String, to destination: String) -> IPv4Header {
    IPv4Header(source: IPv4Address(source)!, destination: IPv4Address(destination)!, protocolNumber: .udp, payloadLength: 1)
}

private func id(_ localAddress: String, _ localPort: UInt16, _ remoteAddress: String, _ remotePort: UInt16) -> TransportEndpointID {
    TransportEndpointID(
        localAddress: IPv4Address(localAddress)!, localPort: localPort,
        remoteAddress: IPv4Address(remoteAddress)!, remotePort: remotePort)
}

@Test func deliversToAnExactFourTupleMatch() throws {
    let demuxer = TransportDemuxer()
    let recorder = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "192.168.127.2", 4000), protocolNumber: .udp, delegate: recorder)

    let delivered = demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0xaa]), localPort: 53, remotePort: 4000)

    #expect(delivered)
    #expect(recorder.count == 1)
    #expect(recorder.lastPayload == [0xaa])
}

@Test func fallsBackToAWildcardListener() throws {
    let demuxer = TransportDemuxer()
    let listener = Recorder()
    // A listener bound to a local address and port, any peer.
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: listener)

    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.9", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 7000))
    #expect(listener.count == 1)
}

@Test func prefersTheExactMatchOverTheWildcard() throws {
    let demuxer = TransportDemuxer()
    let exact = Recorder()
    let listener = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "192.168.127.2", 4000), protocolNumber: .udp, delegate: exact)
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: listener)

    _ = demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000)

    #expect(exact.count == 1)
    #expect(listener.count == 0)
}

@Test func matchesAListenerBoundToAnyLocalAddress() throws {
    let demuxer = TransportDemuxer()
    let listener = Recorder()
    try demuxer.register(id("0.0.0.0", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: listener)

    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "10.0.0.1", to: "93.184.216.34"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 9000))
    #expect(listener.count == 1)
}

@Test func reportsNoMatch() {
    let demuxer = TransportDemuxer()
    #expect(!demuxer.deliver(
        protocolNumber: .udp, header: header(from: "1.2.3.4", to: "5.6.7.8"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 99, remotePort: 100))
}

@Test func keepsProtocolsApart() throws {
    let demuxer = TransportDemuxer()
    let udp = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: udp)
    // Same tuple, different protocol: must not match.
    #expect(!demuxer.deliver(
        protocolNumber: .tcp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000))
    #expect(udp.count == 0)
}

@Test func registeringTheSameTupleTwiceThrows() throws {
    let demuxer = TransportDemuxer()
    // Delegates are held weakly, so the first registration needs a strong
    // reference kept alive for the duration of the test: an anonymous
    // `Recorder()` temporary would be deallocated the instant `register`
    // returns, the weak slot would go nil, and the second `register` would
    // see a freed slot instead of the live one this test means to exercise.
    let recorder = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: recorder)
    #expect(throws: StackError.portInUse) {
        try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: Recorder())
    }
}

@Test func unregisterFreesTheTuple() throws {
    let demuxer = TransportDemuxer()
    let target = id("192.168.127.1", 53, "0.0.0.0", 0)
    // Both delegates must stay alive for the whole test, or the weak slot
    // goes nil on its own and register()'s dead-slot check — not
    // unregister() — is what lets the third call through. See
    // registeringTheSameTupleTwiceThrows for the same reasoning.
    let first = Recorder()
    let second = Recorder()
    try demuxer.register(target, protocolNumber: .udp, delegate: first)
    demuxer.unregister(target, protocolNumber: .udp)
    try demuxer.register(target, protocolNumber: .udp, delegate: second)
}

@Test func aProtocolHandlerOverridesEndpointMatching() throws {
    let demuxer = TransportDemuxer()
    let endpoint = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: endpoint)

    var intercepted = 0
    demuxer.setProtocolHandler(.udp) { _, _, _, _ in
        intercepted += 1
        return true
    }

    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000))
    #expect(intercepted == 1)
    #expect(endpoint.count == 0)
}

@Test func aHandlerReturningFalseFallsThroughToEndpoints() throws {
    let demuxer = TransportDemuxer()
    let endpoint = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: endpoint)
    demuxer.setProtocolHandler(.udp) { _, _, _, _ in false }

    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000))
    #expect(endpoint.count == 1)
}

@Test func removingAProtocolHandlerResumesEndpointMatching() throws {
    let demuxer = TransportDemuxer()
    let endpoint = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: endpoint)

    // While installed, the handler consumes everything and the endpoint
    // sees nothing.
    demuxer.setProtocolHandler(.udp) { _, _, _, _ in true }
    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000))
    #expect(endpoint.count == 0)

    // Passing nil must remove it, so endpoint matching resumes.
    demuxer.setProtocolHandler(.udp, nil)
    #expect(demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x02]), localPort: 53, remotePort: 4000))
    #expect(endpoint.count == 1)
    #expect(endpoint.lastPayload == [0x02])
}

@Test func deliverReportsFalseWhenTheDelegateHasDeallocated() throws {
    let demuxer = TransportDemuxer()
    let target = id("192.168.127.1", 53, "0.0.0.0", 0)
    do {
        let scoped = Recorder()
        try demuxer.register(target, protocolNumber: .udp, delegate: scoped)
    }
    // `scoped` is gone now: the weak slot is nil even though the
    // registration is still in the table. `deliver` must report false, not
    // silently swallow the packet, so the caller can send ICMP
    // port-unreachable.
    #expect(!demuxer.deliver(
        protocolNumber: .udp, header: header(from: "192.168.127.2", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 4000))
}

@Test func aSpecificAddressListenerBeatsAWildcardListener() throws {
    let demuxer = TransportDemuxer()
    let specific = Recorder()
    let wildcard = Recorder()
    try demuxer.register(id("192.168.127.1", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: specific)
    try demuxer.register(id("0.0.0.0", 53, "0.0.0.0", 0), protocolNumber: .udp, delegate: wildcard)

    _ = demuxer.deliver(
        protocolNumber: .udp, header: header(from: "10.0.0.1", to: "192.168.127.1"),
        payload: ByteBuffer(bytes: [0x01]), localPort: 53, remotePort: 9000)

    #expect(specific.count == 1)
    #expect(wildcard.count == 0)
}

@Test func ephemeralPortAllocationIsScopedToTheLocalAddress() throws {
    let demuxer = TransportDemuxer()
    let addressA = IPv4Address("192.168.127.1")!
    let addressB = IPv4Address("192.168.127.2")!

    // Occupy the very first candidate port on a DIFFERENT local address.
    // register() legitimately allows this: the same port is reusable on a
    // different local address, since the full four-tuple (including
    // localAddress) is the registration key.
    let busy = Recorder()
    try demuxer.register(
        TransportEndpointID(localAddress: addressB, localPort: 49152, remoteAddress: .any, remotePort: 0),
        protocolNumber: .udp, delegate: busy)

    // The allocator must still hand out 49152 on addressA: a predicate that
    // ignores localAddress (checking only protocolNumber and localPort)
    // would see it as globally in-use and skip straight to 49153.
    let port = try demuxer.allocateEphemeralPort(protocolNumber: .udp, localAddress: addressA)
    #expect(port == 49152)
}

@Test func allocatesDistinctEphemeralPorts() throws {
    let demuxer = TransportDemuxer()
    var seen: Set<UInt16> = []
    // Recorders must stay alive for the whole test, or every registration's
    // weak slot goes nil immediately and allocateEphemeralPort's in-use
    // predicate never sees a live registration to avoid.
    var recorders: [Recorder] = []
    for _ in 0..<50 {
        let port = try demuxer.allocateEphemeralPort(protocolNumber: .udp, localAddress: IPv4Address("192.168.127.1")!)
        #expect(port >= 49152)
        #expect(!seen.contains(port))
        seen.insert(port)
        let recorder = Recorder()
        recorders.append(recorder)
        try demuxer.register(
            TransportEndpointID(localAddress: IPv4Address("192.168.127.1")!, localPort: port, remoteAddress: .any, remotePort: 0),
            protocolNumber: .udp, delegate: recorder)
    }
}
