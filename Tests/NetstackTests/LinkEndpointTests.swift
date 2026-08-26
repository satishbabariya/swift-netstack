import NIOCore
import NIOEmbedded
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

@Test func defaultMTUIsEthernetSized() {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    #expect(link.mtu == 1500)
}
