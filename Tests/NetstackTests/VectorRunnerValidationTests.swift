import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func harness() -> (Stack, RecordingEndpoint, ManualClock, EmbeddedEventLoop) {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: clock)
    stack.start()
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    return (stack, link, clock, loop)
}

@Test func theRunnerReproducesKnownGoodARPICMPAndUDPBehaviour() throws {
    let url = Bundle.module.url(forResource: "Vectors/arp-icmp-udp", withExtension: "vec")!
    let script = try VectorScript.parse(String(contentsOf: url, encoding: .utf8))
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: Never.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAWrongExpectation() throws {
    // The instrument must fail when the script is wrong, or it proves nothing.
    let script = try VectorScript.parse(
        """
        0.000 < arp who-has 192.168.127.1 tell 192.168.127.2
        0.000 > arp reply 192.168.127.99 is-at 5a:94:ef:e4:0c:ee
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAMissingReply() throws {
    // Expecting a frame the stack never sends must fail, not pass vacuously.
    let script = try VectorScript.parse(
        """
        0.000 < icmp echo_request id 1 seq 1
        0.000 > icmp echo_reply id 1 seq 1
        0.000 > icmp echo_reply id 1 seq 2
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAFrameEmittedAtTheWrongTime() throws {
    // Content-only comparison is invisible to a stack that emits the right
    // bytes at the wrong logical time — exactly the failure mode a
    // retransmission vector exists to catch (fired too early, or a stale
    // duplicate sitting in the buffer). None of Plan 1's existing protocols
    // (ARP/ICMP/UDP) reply on a delay, so there is no way to make correct
    // production code emit early; this constructs the mismatch directly
    // instead, by giving the `.expectedOutbound` line a DIFFERENT time than
    // the `.inbound` line whose synchronous reply actually produces the
    // frame. The reply is really emitted at 0.100s (it happens synchronously
    // inside `link.inject`), but the script claims 0.200s — the runner must
    // catch that disagreement even though the CONTENT matches exactly.
    let script = try VectorScript.parse(
        """
        0.100 < icmp echo_request id 1 seq 1
        0.200 > icmp echo_reply id 1 seq 1
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerRejectsAScriptWhoseTimesGoBackwards() throws {
    // A script whose second event claims an earlier time than its first is
    // malformed — the runner must reject it outright rather than silently
    // let its own `elapsed` bookkeeping drift backwards, which would
    // desynchronise every delta computed after this point.
    let script = try VectorScript.parse(
        """
        0.200 < icmp echo_request id 1 seq 1
        0.100 < icmp echo_request id 2 seq 2
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorScriptOutOfOrder.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDistinguishesTwoFramesEmittedAtGenuinelyDifferentTimes() throws {
    // `Stack`'s only timer (maintenance) never writes to the link, so
    // production code cannot produce two timer-driven emissions to test
    // this against. This constructs the shape directly, as a deliberately
    // scheduled write on the `EmbeddedEventLoop` — a test double standing
    // in for what a retransmission timer would do: two frames, written
    // straight onto the link (bypassing the stack entirely), five and
    // fifteen milliseconds after time zero. The script checkpoints each at
    // its true time with its own `.expectedOutbound` line; both must match.
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let codec = VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)
        let first = try! codec.encode(.icmpEcho(request: false, identifier: 1, sequence: 1), direction: .expectedOutbound)
        let second = try! codec.encode(.icmpEcho(request: false, identifier: 2, sequence: 2), direction: .expectedOutbound)
        _ = loop.scheduleTask(in: .milliseconds(5)) { link.write([PacketBuffer(received: first)]) }
        _ = loop.scheduleTask(in: .milliseconds(15)) { link.write([PacketBuffer(received: second)]) }

        let script = try! VectorScript.parse(
            """
            0.005 > icmp echo_reply id 1 seq 1
            0.015 > icmp echo_reply id 2 seq 2
            """)
        let runner = VectorRunner(script: script, codec: codec)
        #expect(throws: Never.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerRejectsAFrameEmittedEarlyInsideASingleAdvance() throws {
    // The shape fix round 2 exists to close: ONE frame, genuinely emitted
    // at 5ms (a deliberately scheduled write, same test-double technique as
    // above — `Stack` has nothing that would do this on its own), but the
    // script's only checkpoint for it claims 15ms, with NO intermediate
    // `.expectedOutbound` line at 5ms to catch it there instead. Advancing
    // straight to 15ms in one jump (the pre-fix behaviour) would stamp this
    // frame with the jump's destination (15ms) rather than when it actually
    // fired, matching the script by accident and passing silently. Advancing
    // in sub-steps stamps it with the sub-step boundary nearest 5ms instead,
    // which disagrees with the declared 15ms and must be rejected.
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let codec = VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)
        let early = try! codec.encode(.icmpEcho(request: false, identifier: 1, sequence: 1), direction: .expectedOutbound)
        _ = loop.scheduleTask(in: .milliseconds(5)) { link.write([PacketBuffer(received: early)]) }

        let script = try! VectorScript.parse("0.015 > icmp echo_reply id 1 seq 1")
        let runner = VectorRunner(script: script, codec: codec)
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAnUnexpectedExtraFrame() throws {
    // A stack that emits MORE than the script says is also wrong.
    let script = try VectorScript.parse("0.000 < icmp echo_request id 1 seq 1")
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(
            script: script,
            codec: VectorFrames(
                gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
                guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}
