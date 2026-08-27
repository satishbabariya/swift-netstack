import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

@testable import Netstack

private final class CollectingDispatcher: LinkDispatcher {
    var received: [ByteBuffer] = []
    func deliverInbound(_ frame: PacketBuffer) {
        received.append(frame.frame)
    }
}

@Test func recordingEndpointCapturesWrites() {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    link.write([PacketBuffer(received: ByteBuffer(bytes: [0x01, 0x02]))])
    link.write([PacketBuffer(received: ByteBuffer(bytes: [0x03]))])

    let frames = link.drainTransmitted()
    #expect(frames.count == 2)
    #expect(Array(frames[0].readableBytesView) == [0x01, 0x02])
    #expect(Array(frames[1].readableBytesView) == [0x03])
    #expect(link.drainTransmitted().isEmpty)
}

@Test func recordingEndpointInjectsInbound() {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let dispatcher = CollectingDispatcher()
    link.attach(dispatcher)

    link.inject(ByteBuffer(bytes: [0xaa, 0xbb]))
    #expect(dispatcher.received.count == 1)
    #expect(Array(dispatcher.received[0].readableBytesView) == [0xaa, 0xbb])
}

@Test func injectingWithNoDispatcherIsDropped() {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)

    // No dispatcher attached: the frame must be dropped outright, as a real
    // wire drops what nothing is listening for. It must not trap, and it
    // must not be queued for a dispatcher that attaches later.
    link.inject(ByteBuffer(bytes: [0xaa]))

    let dispatcher = CollectingDispatcher()
    link.attach(dispatcher)
    #expect(dispatcher.received.isEmpty)

    // The endpoint is still usable afterwards.
    link.inject(ByteBuffer(bytes: [0xbb]))
    #expect(dispatcher.received.count == 1)
    #expect(Array(dispatcher.received[0].readableBytesView) == [0xbb])
}

@Test func loopbackDeliversWritesBackInbound() {
    let loop = EmbeddedEventLoop()
    let link = LoopbackEndpoint(eventLoop: loop)
    let dispatcher = CollectingDispatcher()
    link.attach(dispatcher)

    link.write([PacketBuffer(received: ByteBuffer(bytes: [0x42]))])
    #expect(dispatcher.received.count == 1)
    #expect(Array(dispatcher.received[0].readableBytesView) == [0x42])
}

@Test func injectingWithNothingEverAttachedIsLegal() {
    // The never-attached case is a real state a wire can be in and must
    // stay silent. Only "attached, then deallocated" is a bug, and that is
    // what the assert distinguishes.
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    link.inject(ByteBuffer(bytes: [0xaa]))
    link.write([PacketBuffer(received: ByteBuffer(bytes: [0xbb]))])
    #expect(link.drainTransmitted().count == 1)
}

@Test func defaultMTUIsEthernetSized() {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    #expect(link.mtu == 1500)
}

@Test func injectingAfterTheDispatcherWasDeallocatedTraps() async {
    // `injectingWithNoDispatcherIsDropped` and
    // `injectingWithNothingEverAttachedIsLegal` only cover the side that must
    // stay SILENT. Neither exercises the side the `hasAttached` flag was
    // added for: "attached, then deallocated", which is a bug that would
    // otherwise present as packets vanishing into a link that still looks
    // wired up. Deleting the assert entirely left both of them green.
    //
    // The assert is compiled in under `swift test`'s debug build, so tripping
    // it in-process would take down the whole run. An exit test isolates the
    // trap to a child process, which is what actually proves the two cases
    // are told apart rather than merely documented as being.
    await #expect(processExitsWith: .failure) {
        let loop = EmbeddedEventLoop()
        let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
        do {
            let dispatcher = CollectingDispatcher()
            link.attach(dispatcher)
            withExtendedLifetime(dispatcher) {}
        }
        // The dispatcher is gone but the link still believes it is attached.
        link.inject(ByteBuffer(bytes: [0xaa]))
    }
}

@Test func writingAfterTheDispatcherWasDeallocatedTraps() async {
    // The same distinction on the transmit path, and on `LoopbackEndpoint`
    // rather than `RecordingEndpoint`, since both carry their own copy of the
    // `hasAttached` flag and the assert that reads it.
    await #expect(processExitsWith: .failure) {
        let loop = EmbeddedEventLoop()
        let link = LoopbackEndpoint(eventLoop: loop)
        do {
            let dispatcher = CollectingDispatcher()
            link.attach(dispatcher)
            withExtendedLifetime(dispatcher) {}
        }
        link.write([PacketBuffer(received: ByteBuffer(bytes: [0x42]))])
    }
}

@Test func injectingFromOffTheLinksEventLoopTraps() async {
    // `LinkEndpoint`'s doc comment says every callback arrives on
    // `eventLoop` and every `write` must be made from it, and the
    // implementations enforce that with `preconditionInEventLoop()`. Nothing
    // was checking that they still do: removing every one of those
    // preconditions left the whole suite green, because every existing test
    // uses an `EmbeddedEventLoop`, whose `inEventLoop` is hardcoded to
    // `true` and therefore can never fail the check.
    //
    // Loop confinement is the ONLY thing protecting this package's state —
    // there are no locks anywhere in `Sources/Netstack` — so a real, threaded
    // loop and a genuinely off-loop call is the only way to state that it is
    // still enforced rather than merely asserted in prose.
    await #expect(processExitsWith: .failure) {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let link = RecordingEndpoint(eventLoop: group.next(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
        // Called from this thread, which is not the loop's own.
        link.inject(ByteBuffer(bytes: [0xaa]))
    }
}
