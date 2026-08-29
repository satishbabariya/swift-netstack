import NIOCore
import NIOPosix

/// A `LinkEndpoint` over a NIO `Channel` carrying whole ethernet frames.
///
/// ## The one premise everything above this rests on
///
/// One message on this channel is one ethernet frame. A datagram socket gives
/// that for free -- the kernel keeps the boundaries -- and a stream socket gets
/// it from `FrameDecoder`. Which of the two is in use is decided by how the
/// channel was built; by the time frames reach here the difference is gone,
/// which is the whole reason this type is not two types.
///
/// ## What this refuses, and why the refusals are here rather than upstream
///
/// - **An inbound frame larger than the MTU is dropped.** The link is what
///   declares the MTU, so the link is where a frame that contradicts it stops.
///   Passing it up would mean every layer above had to be written against
///   frames the link said could not exist.
/// - **An outbound frame larger than the MTU is dropped, not truncated.** A
///   truncated ethernet frame is not a smaller frame, it is a corrupt one, and
///   on the stream transport it also destroys the framing of everything after
///   it.
///
/// Both are silent. A link drops; it does not report. Anything that needs to
/// know a frame did not arrive is a protocol above this one, and TCP already
/// does.
public final class WireLinkEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    /// No offloads. Every checksum on this wire is computed and verified in
    /// software, because the wire is a unix socket and there is no hardware to
    /// have done it -- and because the peer is a guest, so an inbound checksum
    /// this stack did not verify is a checksum nobody verified.
    public let capabilities: LinkCapabilities = []
    public let eventLoop: EventLoop

    private let channel: Channel

    /// Whether every frame must be flushed on its own.
    ///
    /// ## This is the datagram transport's whole correctness, in one flag
    ///
    /// NIO writes several pending buffers with `writev`. On a byte stream that
    /// is exactly the optimisation it looks like. On a **datagram** socket an
    /// `iovec` of two buffers produces ONE datagram containing both -- so two
    /// ethernet frames written together arrive as a single datagram, and the
    /// premise the entire gateway rests on ("one datagram is one frame") is
    /// broken by an efficiency.
    ///
    /// Measured, not assumed: two 30- and 40-byte writes flushed together came
    /// out of a `socketpair(AF_UNIX, SOCK_DGRAM)` as one 70-byte datagram.
    /// `aBatchOfFramesArrivesAsSeparateDatagrams` is that measurement kept.
    ///
    /// The stream transport does not need this and must not have it: there the
    /// length prefix carries the boundaries, and flushing per frame would spend
    /// a syscall on each for nothing.
    private let flushPerFrame: Bool

    private weak var dispatcher: (any LinkDispatcher)?
    private var hasAttached = false

    /// Frames dropped for exceeding the MTU, inbound and outbound. Not a
    /// statistic for its own sake: a wire that silently drops is a wire whose
    /// misconfiguration looks exactly like a quiet guest, and this is the
    /// difference.
    public private(set) var inboundDropped = 0
    public private(set) var outboundDropped = 0

    /// Where rejected frames are reported, if anywhere.
    ///
    /// A `var` set after construction rather than an `init` parameter, because
    /// the wire is built by `WireBootstrap` before the clock and logger that
    /// `Gateway` configures exist. Nothing reads it off the loop.
    public var log: RateLimitedLogger?

    /// Adopt a channel that already delivers whole frames as `ByteBuffer`s.
    ///
    /// The channel is the parameter rather than a socket path so that a test can
    /// pass an `EmbeddedChannel` and drive the wire without one, and so the two
    /// transports can share every line below the framing.
    public init(channel: Channel, linkAddress: MACAddress, mtu: UInt32 = 1500, flushPerFrame: Bool = false) {
        self.channel = channel
        self.flushPerFrame = flushPerFrame
        self.eventLoop = channel.eventLoop
        self.linkAddress = linkAddress
        // The MTU here is the payload an ethernet frame may carry; the frames on
        // the wire are that plus a header. Stored as given, and `maximumFrame`
        // is what the bounds below are actually measured against.
        self.mtu = mtu
    }

    /// The largest whole frame this link will carry: the MTU plus an ethernet
    /// header. Nothing on this wire is VLAN-tagged, so there is no allowance for
    /// a tag -- add one here, not at each use, if that ever changes.
    public var maximumFrame: Int { Int(mtu) + EthernetHeader.length }

    public func attach(_ dispatcher: LinkDispatcher) {
        eventLoop.preconditionInEventLoop()
        self.dispatcher = dispatcher
        hasAttached = true
    }

    public func write(_ packets: [PacketBuffer]) {
        eventLoop.preconditionInEventLoop()
        var wrote = false
        for packet in packets {
            let frame = packet.frame
            guard frame.readableBytes > 0, frame.readableBytes <= maximumFrame else {
                outboundDropped += 1
                // The only event here this stack causes itself, so it is the
                // only one logged as an error: a frame longer than the MTU
                // reached the wire, which means something above chose a segment
                // size the link cannot carry.
                log?.record(.outboundFrameRejected, ["bytes": .stringConvertible(frame.readableBytes), "limit": .stringConvertible(maximumFrame)])
                continue
            }
            channel.write(frame, promise: nil)
            wrote = true
            // See `flushPerFrame`. The batch is the point of taking an array,
            // and on a datagram wire the batch is exactly what must not happen.
            if flushPerFrame { channel.flush() }
        }
        if wrote, !flushPerFrame { channel.flush() }
    }

    /// Called by `WireInboundHandler` on the channel's own loop.
    fileprivate func deliver(_ frame: ByteBuffer) {
        eventLoop.preconditionInEventLoop()
        guard frame.readableBytes > 0, frame.readableBytes <= maximumFrame else {
            inboundDropped += 1
            log?.record(.inboundFrameRejected, ["bytes": .stringConvertible(frame.readableBytes), "limit": .stringConvertible(maximumFrame)])
            return
        }
        assert(dispatcher != nil || !hasAttached, "dispatcher was deallocated while still attached to this link")
        dispatcher?.deliverInbound(PacketBuffer(received: frame))
    }

    /// Close the wire. Idempotent, because the peer closing it is one of the
    /// ways this gets called.
    public func close() -> EventLoopFuture<Void> {
        channel.close().recover { _ in () }
    }
}

/// Hands each inbound frame to its link.
///
/// Holds the link **weakly**. The link owns the channel, the channel's pipeline
/// owns this handler, and a strong reference here would close the cycle -- a
/// wire that is never released and, with it, the whole stack behind it.
final class WireInboundHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private weak var link: WireLinkEndpoint?

    init(link: WireLinkEndpoint) {
        self.link = link
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        link?.deliver(unwrapInboundIn(data))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // A framing error is fatal to the connection and only to the
        // connection: the peer and this decoder no longer agree about where
        // frames begin, so every byte after it is noise. Closing is the only
        // honest response, and it is what a real wire does when it fails.
        context.close(promise: nil)
    }
}

/// The datagram half of the envelope dance.
///
/// A connected datagram channel still delivers `AddressedEnvelope`s and still
/// wants them on the way out, so this unwraps inbound and wraps outbound. The
/// remote address is the one the channel is connected to -- a datagram from
/// anywhere else cannot reach a connected socket, so there is nothing to check
/// here that the kernel has not.
final class DatagramEnvelopeHandler: ChannelDuplexHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let remote: SocketAddress

    init(remote: SocketAddress) {
        self.remote = remote
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(wrapInboundOut(unwrapInboundIn(data).data))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(wrapOutboundOut(AddressedEnvelope(remoteAddress: remote, data: unwrapOutboundIn(data))), promise: promise)
    }
}

/// The envelope dance for a **bound** datagram socket, whose peer is not known
/// until something sends to it.
///
/// A connected socket is told its peer; a bound one is not, and there is nothing
/// to tell it with. So the peer is learned from the first datagram that arrives
/// and replies go to whoever last sent — the same rule upstream's `unixgram`
/// transport uses, and correct for the one thing this wire carries: a single
/// guest on a single ethernet segment.
///
/// **A write before anything has arrived is dropped**, and dropping is the only
/// honest option: there is no address to send to. In practice a gateway never
/// speaks first — it answers a guest's DHCP, its ARP, its SYN — so the case is
/// one a working setup does not reach, and a link that queued for a peer it might
/// never learn would be holding frames against a guest that never booted.
final class LearnedPeerHandler: ChannelDuplexHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private var peer: SocketAddress?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        peer = envelope.remoteAddress
        context.fireChannelRead(wrapInboundOut(envelope.data))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard let peer else {
            promise?.fail(StackError.notConnected)
            return
        }
        context.write(
            wrapOutboundOut(AddressedEnvelope(remoteAddress: peer, data: unwrapOutboundIn(data))),
            promise: promise)
    }
}
