import NIOCore
import Testing

@testable import Netstack


private func codec() -> VectorFrames {
    VectorFrames(
        gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
        guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)
}

@Test func encodesATCPSynAgainstLiteralWireBytes() throws {
    let line = TCPLine(flags: "S", seqStart: 0, seqEnd: 0, payloadLength: 0,
                       ack: nil, window: 65535, options: [])
    let frame = try codec().encode(.tcp(line), direction: .inbound)
    let bytes = Array(frame.readableBytesView)

    // Ethernet: destination is the gateway, source the guest, ethertype IPv4.
    #expect(Array(bytes[0..<6]) == MACAddress("5a:94:ef:e4:0c:ee")!.bytes)
    #expect(Array(bytes[6..<12]) == MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    #expect(bytes[12] == 0x08 && bytes[13] == 0x00)
    // IPv4: version/IHL, protocol 6 (TCP), source is the guest.
    #expect(bytes[14] == 0x45)
    #expect(bytes[23] == 6)
    #expect(Array(bytes[26..<30]) == IPv4Address("192.168.127.2")!.bytes)
    #expect(Array(bytes[30..<34]) == IPv4Address("192.168.127.1")!.bytes)
    // TCP: data offset 5 (no options), SYN flag set, window 65535.
    #expect(bytes[46] >> 4 == 5)
    #expect(bytes[47] == 0x02)
    #expect(UInt16(bytes[48]) << 8 | UInt16(bytes[49]) == 65535)
    // The IPv4 header carries a valid checksum of its own.
    #expect(Array(bytes[14..<34]).withUnsafeBytes { Checksum.compute($0) } == 0)
}

@Test func encodesTCPOptionsInTheDeclaredOrder() throws {
    let line = TCPLine(flags: "S", seqStart: 0, seqEnd: 0, payloadLength: 0,
                       ack: nil, window: 65535, options: ["mss 1460", "wscale 7", "sackOK"])
    let frame = try codec().encode(.tcp(line), direction: .inbound)
    let bytes = Array(frame.readableBytesView)

    // Data offset must have grown past 5 to cover the options.
    #expect(bytes[46] >> 4 > 5)
    let optionStart = 34 + 20
    // MSS: kind 2, length 4, value 1460.
    #expect(bytes[optionStart] == 2 && bytes[optionStart + 1] == 4)
    #expect(UInt16(bytes[optionStart + 2]) << 8 | UInt16(bytes[optionStart + 3]) == 1460)
    // Window scale: kind 3, length 3, shift 7.
    #expect(bytes[optionStart + 4] == 3 && bytes[optionStart + 5] == 3 && bytes[optionStart + 6] == 7)
    // SACK-permitted: kind 4, length 2.
    #expect(bytes[optionStart + 7] == 4 && bytes[optionStart + 8] == 2)
    // Padded to a 4-byte boundary.
    #expect((Int(bytes[46] >> 4) * 4) % 4 == 0)
}

@Test func decodesWhatItEncodesForEveryForm() throws {
    let forms: [VectorPacket] = [
        .tcp(TCPLine(flags: "S.", seqStart: 100, seqEnd: 100, payloadLength: 0, ack: 1, window: 512, options: [])),
        .tcp(TCPLine(flags: "P.", seqStart: 1, seqEnd: 5, payloadLength: 4, ack: 9, window: 512, options: [])),
        .icmpEcho(request: true, identifier: 0x1234, sequence: 42),
        .udp(source: 4000, destination: 53, length: 12),
        .arpRequest(target: IPv4Address("192.168.127.1")!, sender: IPv4Address("192.168.127.2")!),
    ]
    for form in forms {
        let frame = try codec().encode(form, direction: .inbound)
        #expect(codec().decode(frame) == form, "round trip failed for \(form)")
    }
}

@Test func decodeReturnsNilForAFrameItDoesNotUnderstand() {
    // A frame the codec cannot classify must not be silently treated as a
    // match — the runner asserts on decoded values, so an unrecognised frame
    // has to surface rather than compare equal to nothing.
    #expect(codec().decode(ByteBuffer(bytes: [0x01, 0x02, 0x03])) == nil)
}

@Test func outboundFramesReverseTheAddresses() throws {
    let line = TCPLine(flags: "S.", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: 1, window: 65535, options: [])
    let frame = try codec().encode(.tcp(line), direction: .expectedOutbound)
    let bytes = Array(frame.readableBytesView)
    // Gateway -> guest this time.
    #expect(Array(bytes[0..<6]) == MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    #expect(Array(bytes[26..<30]) == IPv4Address("192.168.127.1")!.bytes)
    #expect(Array(bytes[30..<34]) == IPv4Address("192.168.127.2")!.bytes)
}
