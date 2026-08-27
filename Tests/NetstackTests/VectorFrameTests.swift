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

@Test func everyTCPFlagCharacterEncodesToItsRFC793WireBit() throws {
    // `decodesWhatItEncodesForEveryForm` below cannot check this: `encode`
    // and `decodeTCPFlags` read the SAME `tcpFlagBits` table, so a wrong bit
    // is applied symmetrically and the round trip agrees with itself.
    // Verified — with the table rewritten to
    // `("F", 0x04), ("S", 0x02), ("R", 0x01), ("P", 0x80), (".", 0x10), ("U", 0x40)`
    // — four of the six flags on the wrong wire bit — all 329 tests in the
    // suite passed. That matters beyond this codec: `VectorRunner` decodes
    // the REAL stack's output through this table to compare it against a
    // script, so a wrong bit here silently mis-reads live wire bytes.
    //
    // Literal values from RFC 9293 §3.1 (the control-bit field, low bit
    // first): FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20.
    // `TCPHeaderTests.crossChecksAgainstTheVectorCodec` pins "S" against
    // `TCPHeader.parse`, an independent implementation, but only "S".
    let expected: [(Character, UInt8)] = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), (".", 0x10), ("U", 0x20)]
    for (character, bit) in expected {
        let line = TCPLine(flags: String(character), seqStart: 0, seqEnd: 0, payloadLength: 0, ack: nil, window: 65535, options: [])
        let bytes = Array(try codec().encode(.tcp(line), direction: .inbound).readableBytesView)
        // Ethernet 14 + IPv4 20 = 34; the TCP flags byte is at offset 13.
        #expect(bytes[34 + 13] == bit, "flag '\(character)' must encode to 0x\(String(bit, radix: 16))")
    }

    // All six at once, so a table that happens to be a permutation of the
    // right bits (each flag alone landing on some other flag's bit) cannot
    // pass the per-character loop by accident.
    let all = TCPLine(flags: "FSRP.U", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: 1, window: 65535, options: [])
    let allBytes = Array(try codec().encode(.tcp(all), direction: .inbound).readableBytesView)
    #expect(allBytes[34 + 13] == 0x3f)  // 0x01|0x02|0x04|0x08|0x10|0x20
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

@Test func encodingATCPLineWithAnUnrecognizedFlagCharacterThrows() {
    // Only "S.FRPU" are recognised wire flag bits (see `tcpFlagBits`); a
    // `TCPLine` built directly (bypassing `VectorScript`'s own, separate
    // flag-character check) must still be rejected by the codec itself.
    let line = TCPLine(flags: "X", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: nil, window: nil, options: [])
    #expect(throws: VectorFrameError.unrecognizedTCPFlag("X")) {
        try codec().encode(.tcp(line), direction: .inbound)
    }
}

@Test func encodingAMalformedTCPOptionThrows() {
    // Neither a recognised keyword ("mss"/"wscale"/"sackOK"/"timestamp") nor
    // parseable as one of them with the wrong number of parts.
    let line = TCPLine(flags: "S", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: nil, window: nil, options: ["banana"])
    #expect(throws: VectorFrameError.malformedTCPOption("banana")) {
        try codec().encode(.tcp(line), direction: .inbound)
    }
}

@Test func encodingAnOversizedUDPPayloadThrows() {
    // One byte past `UDPHeader.maximumPayloadLength` (65507): the same
    // boundary `UDPTests.serializeRejectsOneByteOverTheLargestUDPPayload`
    // checks at `UDPHeader.serialize` itself, exercised here through the
    // vector codec's own call site.
    #expect(throws: VectorFrameError.udpPayloadTooLarge) {
        try codec().encode(.udp(source: 4000, destination: 53, length: UDPHeader.maximumPayloadLength + 1), direction: .inbound)
    }
}

@Test func encodingAnUnknownICMPUnreachableCodeThrows() {
    // Only the five names in `unreachableCodeNames` ("network", "host",
    // "protocol", "port", "frag-needed") are recognised.
    #expect(throws: VectorFrameError.unknownICMPUnreachableCode("bogus")) {
        try codec().encode(.icmpUnreachable(code: "bogus"), direction: .inbound)
    }
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
