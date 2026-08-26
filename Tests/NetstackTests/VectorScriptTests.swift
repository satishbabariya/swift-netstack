import NIOCore
import Testing

@testable import Netstack

@Test func parsesAPacketdrillStyleHandshake() throws {
    let script = try VectorScript.parse("""
        0.000 < S  0:0(0)   win 65535 <mss 1460,wscale 7,sackOK>
        0.000 > S. 0:0(0) ack 1 win 65535 <mss 1460,wscale 7,sackOK>
        0.100 < .  1:1(0) ack 1 win 512
        """)

    #expect(script.events.count == 3)

    let syn = script.events[0]
    #expect(syn.time == .milliseconds(0))
    #expect(syn.direction == .inbound)
    guard case .tcp(let line) = syn.packet else { Issue.record("expected tcp"); return }
    #expect(line.flags == "S")
    #expect(line.seqStart == 0)
    #expect(line.payloadLength == 0)
    #expect(line.ack == nil)
    #expect(line.window == 65535)
    #expect(line.options == ["mss 1460", "wscale 7", "sackOK"])

    let synack = script.events[1]
    #expect(synack.direction == .expectedOutbound)
    guard case .tcp(let reply) = synack.packet else { Issue.record("expected tcp"); return }
    #expect(reply.flags == "S.")
    #expect(reply.ack == 1)

    #expect(script.events[2].time == .milliseconds(100))
}

@Test func parsesAPayloadBearingSegment() throws {
    let script = try VectorScript.parse("0.250 < P. 1:1461(1460) ack 1 win 512")
    guard case .tcp(let line) = script.events[0].packet else { Issue.record("expected tcp"); return }
    #expect(line.flags == "P.")
    #expect(line.seqStart == 1)
    #expect(line.seqEnd == 1461)
    #expect(line.payloadLength == 1460)
    #expect(script.events[0].time == .milliseconds(250))
}

@Test func parsesTheNonTCPProtocolForms() throws {
    let script = try VectorScript.parse("""
        0.000 < arp who-has 192.168.127.1 tell 192.168.127.2
        0.000 > arp reply 192.168.127.1 is-at 5a:94:ef:e4:0c:ee
        0.010 < icmp echo_request id 4660 seq 42
        0.010 > icmp echo_reply id 4660 seq 42
        0.020 < udp 4000 > 53 (12)
        0.020 > icmp unreachable port
        """)
    #expect(script.events.count == 6)

    guard case .arpRequest(let target, let sender) = script.events[0].packet else { Issue.record("arp"); return }
    #expect(target == IPv4Address("192.168.127.1"))
    #expect(sender == IPv4Address("192.168.127.2"))

    guard case .icmpEcho(let request, let identifier, let sequence) = script.events[2].packet else { Issue.record("icmp"); return }
    #expect(request)
    #expect(identifier == 4660)
    #expect(sequence == 42)

    guard case .udp(let source, let destination, let length) = script.events[4].packet else { Issue.record("udp"); return }
    #expect(source == 4000)
    #expect(destination == 53)
    #expect(length == 12)
}

@Test func ignoresBlankLinesAndComments() throws {
    let script = try VectorScript.parse("""
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

@Test func rejectsAnUnterminatedTCPOptionList() {
    // The option-rejoining loop in parseTCP walks fields looking for a
    // closing ">". If the input never supplies one, the loop must not spin
    // forever or index out of bounds — and it must not silently accept a
    // truncated/garbled option list either. Malformed input like this must
    // be rejected loudly, not parsed into a wrong-but-plausible result.
    #expect(throws: VectorScriptError.self) { try VectorScript.parse("0.000 < S 0:0(0) win 65535 <mss 1460") }
}
