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
        let runner = VectorRunner(script: script, codec: VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: Never.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAWrongExpectation() throws {
    // The instrument must fail when the script is wrong, or it proves nothing.
    let script = try VectorScript.parse("""
        0.000 < arp who-has 192.168.127.1 tell 192.168.127.2
        0.000 > arp reply 192.168.127.99 is-at 5a:94:ef:e4:0c:ee
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(script: script, codec: VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAMissingReply() throws {
    // Expecting a frame the stack never sends must fail, not pass vacuously.
    let script = try VectorScript.parse("""
        0.000 < icmp echo_request id 1 seq 1
        0.000 > icmp echo_reply id 1 seq 1
        0.000 > icmp echo_reply id 1 seq 2
        """)
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(script: script, codec: VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}

@Test func theRunnerDetectsAnUnexpectedExtraFrame() throws {
    // A stack that emits MORE than the script says is also wrong.
    let script = try VectorScript.parse("0.000 < icmp echo_request id 1 seq 1")
    let (stack, link, clock, loop) = harness()
    withExtendedLifetime(stack) {
        let runner = VectorRunner(script: script, codec: VectorFrames(
            gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
            guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!))
        #expect(throws: VectorMismatch.self) { try runner.run(against: stack, link: link, clock: clock, loop: loop) }
    }
}
