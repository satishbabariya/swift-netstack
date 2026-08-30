import NIOCore
import Testing

@testable import Netstack

@Test func parsesAPacketdrillStyleHandshake() throws {
    let script = try VectorScript.parse(
        """
        0.000 < S  0:0(0)   win 65535 <mss 1460,wscale 7,sackOK>
        0.000 > S. 0:0(0) ack 1 win 65535 <mss 1460,wscale 7,sackOK>
        0.100 < .  1:1(0) ack 1 win 512
        """)

    #expect(script.events.count == 3)

    let syn = script.events[0]
    #expect(syn.time == .milliseconds(0))
    #expect(syn.direction == .inbound)
    guard case .tcp(let line) = syn.packet else {
        Issue.record("expected tcp")
        return
    }
    #expect(line.flags == "S")
    #expect(line.seqStart == 0)
    #expect(line.payloadLength == 0)
    #expect(line.ack == nil)
    #expect(line.window == 65535)
    #expect(line.options == ["mss 1460", "wscale 7", "sackOK"])

    let synack = script.events[1]
    #expect(synack.direction == .expectedOutbound)
    guard case .tcp(let reply) = synack.packet else {
        Issue.record("expected tcp")
        return
    }
    #expect(reply.flags == "S.")
    #expect(reply.ack == 1)

    #expect(script.events[2].time == .milliseconds(100))
}

@Test func parsesAPayloadBearingSegment() throws {
    let script = try VectorScript.parse("0.250 < P. 1:1461(1460) ack 1 win 512")
    guard case .tcp(let line) = script.events[0].packet else {
        Issue.record("expected tcp")
        return
    }
    #expect(line.flags == "P.")
    #expect(line.seqStart == 1)
    #expect(line.seqEnd == 1461)
    #expect(line.payloadLength == 1460)
    #expect(script.events[0].time == .milliseconds(250))
}

@Test func parsesTheNonTCPProtocolForms() throws {
    let script = try VectorScript.parse(
        """
        0.000 < arp who-has 192.168.127.1 tell 192.168.127.2
        0.000 > arp reply 192.168.127.1 is-at 5a:94:ef:e4:0c:ee
        0.010 < icmp echo_request id 4660 seq 42
        0.010 > icmp echo_reply id 4660 seq 42
        0.020 < udp 4000 > 53 (12)
        0.020 > icmp unreachable port
        """)
    #expect(script.events.count == 6)

    guard case .arpRequest(let target, let sender) = script.events[0].packet else {
        Issue.record("arp")
        return
    }
    #expect(target == IPv4Address("192.168.127.1"))
    #expect(sender == IPv4Address("192.168.127.2"))

    guard case .icmpEcho(let request, let identifier, let sequence) = script.events[2].packet else {
        Issue.record("icmp")
        return
    }
    #expect(request)
    #expect(identifier == 4660)
    #expect(sequence == 42)

    guard case .udp(let source, let destination, let length) = script.events[4].packet else {
        Issue.record("udp")
        return
    }
    #expect(source == 4000)
    #expect(destination == 53)
    #expect(length == 12)
}

@Test func ignoresBlankLinesAndComments() throws {
    let script = try VectorScript.parse(
        """
        # the guest opens a connection
        0.000 < S 0:0(0) win 65535

        0.000 > S. 0:0(0) ack 1 win 65535
        """)
    #expect(script.events.count == 2)
}

@Test func rejectsMalformedLines() {
    // A line with no direction marker is not a packet and must not be
    // silently skipped — a typo that drops an assertion is exactly the
    // failure mode this harness exists to prevent.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 S 0:0(0) win 65535") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("notatime < S 0:0(0) win 65535") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 0:0 win 65535") }
}

@Test func rejectsATimeFieldThatCannotBeRepresentedAsNanoseconds() {
    // `Double("1e19")` parses cleanly, and the naive `Int64(Double)` conversion traps once the
    // scaled value no longer fits in an Int64 — a typo in a vector file must fail one test, not
    // kill the whole test process. `inf`/`nan` are equally fatal to that naive conversion.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("1e19 < S 0:0(0)") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("inf < S 0:0(0)") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("nan < S 0:0(0)") }
}

@Test func rejectsAnUnterminatedTCPOptionList() {
    // The option-rejoining loop in parseTCP walks fields looking for a
    // closing ">". If the input never supplies one, the loop must not spin
    // forever or index out of bounds — and it must not silently accept a
    // truncated/garbled option list either. Malformed input like this must
    // be rejected loudly, not parsed into a wrong-but-plausible result.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 0:0(0) win 65535 <mss 1460") }
}

@Test func rejectsANegativeTimeField() {
    // A negative time makes no sense against a logical clock that only ever
    // advances forward, and `Double("-1.000")` parses cleanly enough to slip
    // past a naive check.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("-1.000 < S 0:0(0)") }
}

@Test func rejectsUnparseableAckAndWindowValues() {
    // `UInt32("banana")`, `UInt32("4294967296")`, and `UInt16("70000")` are
    // all nil — which, unless the parser checks explicitly, is
    // indistinguishable from "the field was never present". A
    // present-but-unparseable value must throw, not silently become "no
    // ack/window expected".
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S. 0:0(0) ack banana") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S. 0:0(0) ack 4294967296") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S. 0:0(0) win 70000") }
}

@Test func rejectsADuplicateAckOrWindowKey() {
    // A repeated key must not silently overwrite the earlier value — that
    // hides a real authoring mistake (or a merge conflict) behind a
    // plausible-looking vector.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S. 0:0(0) ack 1 ack 2") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S. 0:0(0) win 100 win 200") }
}

@Test func rejectsASequenceRangeThatDisagreesWithTheDeclaredLength() {
    // `5:3(0)` puts the end before the start, and `1:100(0)` implies 99
    // bytes of payload while declaring 0 — both must be rejected rather than
    // silently parsed. Sequence numbers wrap at 2^32, so this must be
    // checked with wrapping arithmetic rather than trusting the fields
    // independently.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 5:3(0)") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 1:100(0)") }
}

@Test func rejectsANegativePayloadLength() {
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 0:0(-5)") }
}

@Test func rejectsInvalidTCPFlagCharacters() {
    // An unrecognised first token (e.g. a typo'd protocol keyword) must not
    // silently fall through to being parsed as a "valid" TCP packet with a
    // garbage flags string.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < banana 1:2(1)") }
}

@Test func rejectsANegativeUDPPayloadLength() {
    // `Int("-12")` parses cleanly, so without an explicit range check
    // "udp 4000 > 53 (-12)" would parse to `.udp(length: -12)` — a payload
    // length that can never exist on the wire. Mirrors the TCP path's
    // `UInt32(exactly:)` guard on its declared length.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.020 < udp 4000 > 53 (-12)") }
}

@Test func rejectsEmptyTCPOptionListElements() {
    // `split` defaults to dropping empty subsequences, so
    // "<mss 1460,,sackOK>" would otherwise silently lose the empty element
    // between the two commas instead of failing.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 0:0(0) <mss 1460,,sackOK>") }
}

@Test func parsesTheApplicationCallForms() throws {
    // A packet-only DSL cannot state a send-side vector at all — "the
    // application wrote 300 bytes here" is not something any sequence of
    // packets says. See `VectorPacket`.
    let script = try VectorScript.parse(
        """
        0.010 < write 300
        0.020 < close
        """)
    #expect(script.events.count == 2)
    #expect(script.events[0].time == .milliseconds(10))
    #expect(script.events[0].packet == .applicationWrite(bytes: 300))
    #expect(script.events[1].time == .milliseconds(20))
    #expect(script.events[1].packet == .applicationClose)
    // Both are `<`: something entering the stack, from above rather than off
    // the wire.
    #expect(script.events.allSatisfy { $0.direction == .inbound })
}

@Test func rejectsMalformedApplicationCallLines() {
    // An application call in the `>` direction would be a claim that the stack
    // emits a system call, which is not a thing a script can mean.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 > write 300") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 > close") }
    // A zero-byte write reads as "the application wrote" and asserts nothing:
    // `Sender.write` treats an empty buffer as a no-op that succeeds, so the
    // line would sit in a file looking like a specification and be none.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 < write 0") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 < write -5") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 < write banana") }
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.010 < close now") }
}
