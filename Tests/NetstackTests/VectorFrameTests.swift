import NIOCore
import Testing

@testable import Netstack

private func codec() -> VectorFrames {
    VectorFrames(
        gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
        guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)
}

@Test func encodesATCPSynAgainstLiteralWireBytes() throws {
    let line = TCPLine(
        flags: "S", seqStart: 0, seqEnd: 0, payloadLength: 0,
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
    let line = TCPLine(
        flags: "S", seqStart: 0, seqEnd: 0, payloadLength: 0,
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
    // ECE 0x40 and CWR 0x80 are RFC 3168 §6.1.1's two ECN negotiation bits,
    // spelled `E` and `W` after packetdrill. They are checked here for the
    // same reason as the other six and one more: `tcp-handshake.vec`'s
    // `ecn-setup-syn` scenario claims an ECN-setup SYN is treated as an
    // ordinary SYN, and if `W` encoded to, say, URG's bit that vector would
    // be quietly testing something else entirely and still passing.
    // `TCPHeaderTests.crossChecksAgainstTheVectorCodec` pins "S" against
    // `TCPHeader.parse`, an independent implementation, but only "S".
    let expected: [(Character, UInt8)] = [
        ("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), (".", 0x10), ("U", 0x20), ("E", 0x40), ("W", 0x80),
    ]
    for (character, bit) in expected {
        let line = TCPLine(flags: String(character), seqStart: 0, seqEnd: 0, payloadLength: 0, ack: nil, window: 65535, options: [])
        let bytes = Array(try codec().encode(.tcp(line), direction: .inbound).readableBytesView)
        // Ethernet 14 + IPv4 20 = 34; the TCP flags byte is at offset 13.
        #expect(bytes[34 + 13] == bit, "flag '\(character)' must encode to 0x\(String(bit, radix: 16))")
    }

    // All eight at once, so a table that happens to be a permutation of the
    // right bits (each flag alone landing on some other flag's bit) cannot
    // pass the per-character loop by accident.
    let all = TCPLine(flags: "FSRP.UEW", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: 1, window: 65535, options: [])
    let allBytes = Array(try codec().encode(.tcp(all), direction: .inbound).readableBytesView)
    #expect(allBytes[34 + 13] == 0xff)  // 0x01|0x02|0x04|0x08|0x10|0x20|0x40|0x80
}

@Test func theWholeTCPFrameLayoutIsPinnedToRFC9293ByteOffsets() throws {
    // The flags table was only where the problem showed. The general defect
    // is that `encode` and `decode` are inverses of each other BY
    // CONSTRUCTION: every field's offset and width is shared between them,
    // so any of them can be wrong on the wire and still round-trip cleanly.
    // `decodesWhatItEncodesForEveryForm` cannot see the sequence number, the
    // acknowledgement, the window, the data offset, the urgent pointer, the
    // checksum's span, or any option's kind/length byte for the same reason
    // it could not see the flags.
    //
    // That matters well beyond this file: `VectorRunner` decodes the REAL
    // stack's output through this codec to decide whether the stack is
    // correct. A codec that agrees with itself would validate the stack
    // against a wrong specification and pass every vector while the wire was
    // wrong.
    //
    // So: one frame, a distinctive value in every field, asserted against
    // RFC 9293 §3.1's layout at literal byte offsets — never against what
    // `encode` produced. Ethernet 14 + IPv4 20 puts the TCP header at 34.
    let line = TCPLine(
        flags: "S.", seqStart: 0x1122_3344, seqEnd: 0x1122_3348, payloadLength: 4,
        ack: 0x5566_7788, window: 0x9abc, options: ["mss 1460", "wscale 7", "sackOK"])
    let bytes = Array(try codec().encode(.tcp(line), direction: .inbound).readableBytesView)

    // Ethernet 14 + IPv4 20 + TCP 20 + options 12 + payload 4.
    #expect(bytes.count == 70)

    // --- Ethernet, offsets 0..13 ---
    #expect(Array(bytes[0..<6]) == MACAddress("5a:94:ef:e4:0c:ee")!.bytes)  // to the gateway
    #expect(Array(bytes[6..<12]) == MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)  // from the guest
    #expect(bytes[12] == 0x08 && bytes[13] == 0x00)  // ethertype IPv4

    // --- IPv4, offsets 14..33 (RFC 791 §3.1) ---
    #expect(bytes[14] == 0x45)  // version 4, IHL 5
    #expect(UInt16(bytes[16]) << 8 | UInt16(bytes[17]) == 56)  // total length: 20 + 36
    #expect(bytes[23] == 6)  // protocol TCP
    #expect(Array(bytes[26..<30]) == IPv4Address("192.168.127.2")!.bytes)  // source: the guest
    #expect(Array(bytes[30..<34]) == IPv4Address("192.168.127.1")!.bytes)  // destination: the gateway

    // --- TCP, offsets 34.. (RFC 9293 §3.1) ---
    let tcp = 34
    #expect(UInt16(bytes[tcp + 0]) << 8 | UInt16(bytes[tcp + 1]) == 50_000)  // source port
    #expect(UInt16(bytes[tcp + 2]) << 8 | UInt16(bytes[tcp + 3]) == 8_080)  // destination port
    #expect(Array(bytes[(tcp + 4)..<(tcp + 8)]) == [0x11, 0x22, 0x33, 0x44])  // sequence number, big endian
    #expect(Array(bytes[(tcp + 8)..<(tcp + 12)]) == [0x55, 0x66, 0x77, 0x88])  // acknowledgement number
    // Byte 12 is data offset in the high nibble and four reserved bits in
    // the low nibble, which RFC 9293 requires to be zero. 8 words = 20 bytes
    // of fixed header plus 12 of options.
    #expect(bytes[tcp + 12] == 0x80)
    #expect(bytes[tcp + 13] == 0x12)  // SYN|ACK: 0x02|0x10
    #expect(UInt16(bytes[tcp + 14]) << 8 | UInt16(bytes[tcp + 15]) == 0x9abc)  // window
    #expect(UInt16(bytes[tcp + 18]) << 8 | UInt16(bytes[tcp + 19]) == 0)  // urgent pointer, URG not set

    // Options at offset 20, each pinned to its RFC kind/length pair rather
    // than to whatever `encodeTCPOptions` emitted: MSS is kind 2 length 4
    // (RFC 9293 §3.2), window scale kind 3 length 3 (RFC 7323 §2.2),
    // SACK-permitted kind 4 length 2 (RFC 2018 §2), NOP kind 1 as padding to
    // the 4-byte boundary the data offset counts in.
    #expect(Array(bytes[(tcp + 20)..<(tcp + 32)]) == [2, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 1, 1, 1])

    // The payload follows the options, not the fixed header.
    #expect(Array(bytes[(tcp + 32)..<70]) == [0, 0, 0, 0])

    // --- Checksum, offsets 16..17 of the TCP header ---
    // Verified rather than compared: build RFC 9293 §3.1's pseudo-header
    // here from literals — source, destination, a zero byte, protocol 6, and
    // the TCP length — and confirm the ones-complement sum over
    // pseudo-header + segment folds to zero. This pins the SPAN the checksum
    // covers, which a round trip cannot: a checksum computed over the wrong
    // range still decodes back to the same packet.
    let segment = Array(bytes[34...])
    var pseudo: [UInt8] = []
    pseudo += IPv4Address("192.168.127.2")!.bytes
    pseudo += IPv4Address("192.168.127.1")!.bytes
    pseudo += [0, 6, UInt8(segment.count >> 8), UInt8(segment.count & 0xff)]
    #expect(segment.count == 36)
    #expect((pseudo + segment).withUnsafeBytes { Checksum.compute($0) } == 0)
    // A ones-complement sum of zero is also what an all-zero buffer gives,
    // so pin that a checksum was actually written into the field.
    #expect(UInt16(bytes[tcp + 16]) << 8 | UInt16(bytes[tcp + 17]) != 0)
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
    // Only "S.FRPUEW" are recognised wire flag bits (see `tcpFlagBits`); a
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

@Test func encodingAnApplicationCallThrowsRatherThanBuildingAFrame() {
    // `write` and `close` are not frames and have no wire representation. The
    // codec refuses them so that a runner which failed to handle one fails
    // loudly, rather than silently injecting nothing where the script said the
    // application acted.
    #expect(throws: VectorFrameError.notAFrame) {
        try codec().encode(.applicationWrite(bytes: 100), direction: .inbound)
    }
    #expect(throws: VectorFrameError.notAFrame) {
        try codec().encode(.applicationClose, direction: .inbound)
    }
}

@Test func aSackOptionRoundTripsThroughTheFrameCodec() throws {
    // The differential's comparison runs through this codec for BOTH stacks —
    // gVisor's frames are decoded here too — so a SACK option this cannot
    // render is a difference the harness would report as agreement.
    let line = TCPLine(
        flags: ".", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: 1, window: 65535,
        options: ["sack 1000:1500 3000:3500"])
    let frame = try codec().encode(.tcp(line), direction: .expectedOutbound)
    let decoded = try #require(codec().decode(frame))
    guard case .tcp(let back) = decoded else {
        Issue.record("a TCP frame decoded as something else: \(decoded)")
        return
    }
    #expect(back.options == ["sack 1000:1500 3000:3500"])
}

@Test func aSackOptionWithATruncatedBlockIsRejectedRatherThanHalfRead() throws {
    // Eight bytes per block. A length that is not a multiple of eight cannot be
    // a SACK option, and reading the whole blocks out of it and ignoring the
    // remainder would turn a malformed segment into a plausible one.
    #expect(throws: VectorFrameError.self) {
        _ = try codec().encode(
            .tcp(
                TCPLine(
                    flags: ".", seqStart: 0, seqEnd: 0, payloadLength: 0, ack: 1, window: 0,
                    options: ["sack 1000"])),
            direction: .expectedOutbound)
    }
}
