import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

/// Validates the differential DRIVER itself (`DifferentialRun`), not TCP —
/// there is no Swift TCP code yet. Like `VectorRunnerValidationTests`
/// before it, this is checked against protocols both stacks already
/// implement correctly (ARP and ICMP) BEFORE it is ever pointed at TCP: if
/// the two stacks disagree here, the harness is misconfigured, and finding
/// that out during TCP work would waste days blaming the wrong code.
///
/// UDP is deliberately not included, unlike the vector runner's validation
/// vector. `differential/harness/main.go`'s `stack.Options.TransportProtocols`
/// registers only `tcp.NewProtocol` (see its `stack.New` call) — no
/// `udp.NewProtocol` — so the Go side of this harness cannot answer a UDP
/// datagram at all. A UDP vector here would not validate the driver; it
/// would just prove gVisor drops what it was never told to handle.

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
    return (stack, link, clock, loop)
}

@Test func bothStacksAgreeOnARPAndICMP() throws {
    // Neither stack is under development here — Plan 1 verified the Swift side
    // independently, and gVisor is upstream. If they disagree, the harness is
    // wrong, and that must surface before any TCP depends on it.
    guard let harness = differentialHarnessPathIfBuilt() else {
        // Skip rather than fail when the Go binary is absent: contributors
        // without a Go toolchain must still be able to run `swift test`.
        return
    }
    let codec = VectorFrames(
        gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
        guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)

    let frames = [
        try codec.encode(
            .arpRequest(target: IPv4Address("192.168.127.1")!, sender: IPv4Address("192.168.127.2")!), direction: .inbound),
        try codec.encode(.icmpEcho(request: true, identifier: 4660, sequence: 42), direction: .inbound),
    ]

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

    try withExtendedLifetime(stack) {
        let run = DifferentialRun(harnessPath: harness, codec: codec)
        let divergences = try run.compare(
            frames: frames, advanceMs: [0, 10], against: stack, link: link, clock: clock, loop: loop)
        #expect(divergences.isEmpty, "stacks diverged on protocols both already implement: \(divergences)")
    }
}

@Test func theDifferentialDetectsADeliberateDivergence() throws {
    guard let harnessPath = differentialHarnessPathIfBuilt() else { return }
    let codec = VectorFrames(
        gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
        guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)
    let (stack, link, clock, loop) = harness()

    try withExtendedLifetime(stack) {
        // Feed the Swift stack a frame the Go stack never sees: a write
        // scheduled directly onto the link (bypassing the stack, the same
        // technique `VectorRunnerValidationTests` uses to construct a
        // controlled timing scenario), timed to land inside the one step
        // `compare` below drives both stacks through. The Go harness's
        // `frames` list never contains anything that would produce this —
        // it is purely a Swift-side extra.
        let extra = try codec.encode(
            .icmpEcho(request: false, identifier: 9999, sequence: 1), direction: .expectedOutbound)
        _ = loop.scheduleTask(in: .milliseconds(10)) {
            link.write([PacketBuffer(received: extra)])
        }

        let frames = [
            try codec.encode(
                .arpRequest(target: IPv4Address("192.168.127.1")!, sender: IPv4Address("192.168.127.2")!), direction: .inbound)
        ]

        let run = DifferentialRun(harnessPath: harnessPath, codec: codec)
        let divergences = try run.compare(
            frames: frames, advanceMs: [10], against: stack, link: link, clock: clock, loop: loop)

        // Both stacks answer the ARP request identically, so the two
        // emitted lists share a matching PREFIX (index 0). The Swift-only
        // extra frame is a pure TAIL: Swift emits 2 frames total, Go emits
        // 1. `zip(swiftFrames, goFrames)` would compare only that matching
        // prefix, find it equal, and report nothing — this must fail
        // against exactly that bug, not just against a driver that never
        // compares anything at all.
        #expect(!divergences.isEmpty, "the driver must report the Swift-only extra frame, not silently drop it via a shorter zip")
        #expect(
            divergences.contains { $0.frameIndex == 1 && $0.goBytes == nil },
            "expected a divergence naming index 1 with no Go counterpart, got: \(divergences)")
    }
}
