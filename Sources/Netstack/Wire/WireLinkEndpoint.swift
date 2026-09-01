import Foundation
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
public final class WireLinkEndpoint: GatewayLink, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    /// No offloads. Every checksum on this wire is computed and verified in
    /// software, because the wire is a unix socket and there is no hardware to
    /// have done it -- and because the peer is a guest, so an inbound checksum
    /// this stack did not verify is a checksum nobody verified.
    public let capabilities: LinkCapabilities = []
    public let eventLoop: EventLoop

    private var channel: Channel?

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

    /// Bytes carried, counted for frames that were actually accepted -- a
    /// rejected frame is not traffic that crossed.
    /// Whether the underlying channel is still open. For diagnosing a wire that
    /// has stopped rather than guessing at it.
    public var isActiveForTesting: Bool { channel?.isActive ?? false }

    public private(set) var bytesReceived = 0
    public private(set) var bytesSent = 0

    /// The descriptor to write through directly, when this wire was adopted
    /// from one.
    ///
    /// ## Why not just `channel.write`
    ///
    /// A full unix datagram queue is reported as **ENOBUFS** on BSD where Linux
    /// reports EAGAIN. NIO retries the second and treats the first as an
    /// unrecoverable write error: it closes the channel. So a guest that stops
    /// reading for a moment -- a paused VM, a stalled vCPU, a slow reader --
    /// leaves this gateway with a **closed wire and no network, permanently**,
    /// and nothing above notices.
    ///
    /// Measured, not deduced: two hundred DHCP exchanges with the guest not
    /// reading, and the wire is closed with `outboundDropped` still at zero.
    ///
    /// Upstream has the same failure and the same fix -- see
    /// `pkg/tap/switch.go`, which retries on ENOBUFS and cites
    /// gvisor-tap-vsock#367. This does that: writes go to the descriptor with a
    /// bounded retry, and a frame that still cannot go is dropped and counted,
    /// which is what a link does when its queue is full.
    ///
    /// Only for wires adopted from a descriptor the caller handed over, which is
    /// the Virtualization.framework path and the one that matters most. The
    /// bootstraps that let NIO create the socket keep NIO's write path and keep
    /// its behaviour; `WireBootstrap` says which is which.
    private let rawDescriptor: NIOBSDSocket.Handle?

    /// Where a direct write should go, on a wire whose peer is learned rather
    /// than connected.
    ///
    /// The bound datagram wire -- `--listen-vfkit`, the default -- has a socket
    /// with no peer until a guest sends to it, so `send` has nowhere to go and
    /// the write has to be a `sendto`. Set by `LearnedPeerHandler` on the loop,
    /// from the same envelope it learns the peer from.
    fileprivate var learnedPeer: SocketAddress?

    /// Frames dropped because the wire would not take them after retrying.
    public private(set) var outboundBackedUp = 0

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
    public init(
        channel: Channel, linkAddress: MACAddress, mtu: UInt32 = 1500, flushPerFrame: Bool = false,
        rawDescriptor: NIOBSDSocket.Handle? = nil
    ) {
        self.rawDescriptor = rawDescriptor
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
            if let descriptor = rawDescriptor {
                if writeDirectly(frame, to: descriptor) {
                    bytesSent += frame.readableBytes
                }
                continue
            }
            guard let channel else {
                // No guest on the wire. Dropped and counted, which is what a
                // real link does while the cable is out -- and the alternative,
                // holding frames for a guest that may never return, is a queue
                // with no bound and no reader.
                outboundDropped += 1
                log?.record(.outboundFrameDropped, ["reason": .string("no guest is on the wire")])
                continue
            }
            // A link drops when its queue is full, and this is that queue.
            //
            // Without this the stream wires had no bound at all: NIO holds
            // whatever cannot be written yet, so a guest that asks questions and
            // never reads the answers grows that queue as fast as it can ask.
            // Measured at four hundred thousand ARP requests, read nothing:
            //
            //     rss before:   8432 KiB
            //     rss after:  153568 KiB
            //
            // The datagram wire was hardened against exactly this and the stream
            // wires -- every multi-guest one -- were not. `isWritable` is false
            // once NIO holds more than the high watermark, so the bound is that
            // watermark plus the frame in hand.
            guard channel.isWritable else {
                outboundDropped += 1
                outboundBackedUp += 1
                log?.record(.outboundFrameDropped, ["reason": .string("the peer is not reading")])
                continue
            }
            channel.write(frame, promise: nil)
            bytesSent += frame.readableBytes
            wrote = true
            // See `flushPerFrame`. The batch is the point of taking an array,
            // and on a datagram wire the batch is exactly what must not happen.
            if flushPerFrame { channel.flush() }
        }
        if wrote, !flushPerFrame { channel?.flush() }
    }

    /// Called by `WireInboundHandler` on the channel's own loop.
    fileprivate func deliver(_ frame: ByteBuffer) {
        eventLoop.preconditionInEventLoop()
        guard frame.readableBytes > 0, frame.readableBytes <= maximumFrame else {
            inboundDropped += 1
            log?.record(.inboundFrameRejected, ["bytes": .stringConvertible(frame.readableBytes), "limit": .stringConvertible(maximumFrame)])
            return
        }
        bytesReceived += frame.readableBytes
        assert(dispatcher != nil || !hasAttached, "dispatcher was deallocated while still attached to this link")
        dispatcher?.deliverInbound(PacketBuffer(received: frame))
    }

    /// Put one frame on the wire, retrying while the peer's queue is full.
    ///
    /// See `rawDescriptor` for why this exists rather than `channel.write`. The
    /// retry is bounded: a peer that has stopped reading altogether must not
    /// block this event loop, which carries every other connection on the
    /// gateway. Past the bound the frame is dropped and counted, which is what a
    /// link does when its queue is full -- and unlike a closed channel, a
    /// dropped frame is something TCP recovers from and UDP is allowed to lose.
    private func writeDirectly(_ frame: ByteBuffer, to descriptor: NIOBSDSocket.Handle) -> Bool {
        let bytes = frame.readableBytesView
        for _ in 0..<16 {
            let written = bytes.withUnsafeBytes { raw -> Int in
                // `sendto` when the peer was learned rather than connected, and
                // `send` when the socket has one. Both are the same syscall with
                // a destination or without.
                if let peer = learnedPeer {
                    return peer.withSockAddr { address, size in
                        sendto(
                            descriptor, raw.baseAddress, raw.count, 0, address, socklen_t(size))
                    }
                }
                return send(descriptor, raw.baseAddress, raw.count, 0)
            }
            if written == bytes.count { return true }
            let failure = errno
            // No peer yet, on a wire that learns one. Not a link failure and not
            // counted as one: the guest has simply not spoken, and a gateway
            // never speaks first -- it answers DHCP, ARP and SYN.
            // `aWriteBeforeAnyFrameHasArrivedIsRefusedRatherThanQueued` pins
            // that this stays silent, and it was written before this path
            // existed.
            if failure == EDESTADDRREQ || failure == ENOTCONN { return false }
            // ECONNREFUSED is deliberately NOT in this list, and it took an
            // experiment to be sure. On an unconnected unix datagram socket --
            // which is what the listening wire has, since it learns its peer and
            // sends with `sendto` -- macOS reports:
            //
            //     full queue  -> ENOBUFS
            //     peer gone   -> ECONNREFUSED
            //
            // I read a flood's ECONNREFUSED as "queue full" and added it here,
            // which would have retried sixteen times for a guest that has
            // definitively left and then reported it as merely slow. The errno
            // was the guest's process exiting. A departed peer is a rejection
            // and should be counted as one.
            guard
                failure == ENOBUFS || failure == EWOULDBLOCK || failure == EAGAIN
                    || failure == EINTR
            else {
                outboundDropped += 1
                log?.record(.outboundFrameRejected, ["errno": .stringConvertible(failure)])
                return false
            }
        }
        outboundBackedUp += 1
        log?.record(.outboundFrameDropped, ["reason": .string("the peer is not reading")])
        return false
    }

    /// Close the wire. Idempotent, because the peer closing it is one of the
    /// ways this gets called.
    /// Take over a new channel, for a guest that went away and came back.
    ///
    /// A VM reboots. On the datagram wire that needs nothing -- the peer is
    /// whoever last sent -- but a stream wire's connection dies with the guest,
    /// and the link is what the stack above is attached to, so a reconnection
    /// has to reach the same link rather than build another one. Without this
    /// the second connection was accepted and closed and the gateway had to be
    /// restarted along with the VM.
    ///
    /// The caller must have configured the new channel's pipeline to deliver
    /// here, and it must be on this link's own loop.
    public func adopt(_ channel: Channel) {
        eventLoop.preconditionInEventLoop()
        precondition(channel.eventLoop === eventLoop, "a wire's channels all live on its own loop")
        self.channel?.close(promise: nil)
        self.channel = channel
        guestsAdopted += 1
    }

    /// Called when the current guest's connection ends, so `write` stops
    /// pretending there is somewhere to send.
    fileprivate func guestLeft(_ channel: Channel) {
        eventLoop.preconditionInEventLoop()
        // Compared, because a closing channel that has already been replaced is
        // the ordinary reconnection order and must not clear its successor.
        guard self.channel === channel else { return }
        self.channel = nil
    }

    /// How many guests have taken this wire over. One for the first.
    public private(set) var guestsAdopted = 1

    /// A socket file this link bound for itself, to be removed when it closes.
    ///
    /// Only the dialling wires have one: they need an address of their own so
    /// the far end has somewhere to reply, and a socket file left behind after
    /// the link is gone is litter in whatever directory it was put in.
    ///
    /// Also the path a LISTENING wire bound, for the same reason and with the
    /// same remedy: closing a unix socket does not unlink it, so both listening
    /// wires left a file behind that looks like a wire and answers nothing.
    /// Measured across a clean shutdown of the executable, `--listen-vfkit` and
    /// `--listen-qemu` left theirs while `--listen-vpnkit` and `--listen-switch`
    /// did not, which is the sort of difference nobody chooses.
    public var localSocketPath: String?

    /// Closes whatever lets the next guest in, for a link that came from a
    /// listening wire.
    ///
    /// `NetworkSwitch` has carried one of these since closing a switch was found
    /// to leave its listener accepting. The single-guest listening wires were
    /// not given one at the same time, and `--listen-qemu` had the same defect:
    /// nothing held its `ServerBootstrap` channel, so a guest connecting after
    /// `close()` was still accepted, onto a link whose gateway had gone.
    var stopListening: (@Sendable () -> EventLoopFuture<Void>)?

    public func close() -> EventLoopFuture<Void> {
        // Stop accepting before anything else: a guest let in while the rest of
        // this runs arrives on a link that is being taken apart.
        let listener = stopListening?() ?? eventLoop.makeSucceededVoidFuture()
        stopListening = nil
        if let localSocketPath {
            try? FileManager.default.removeItem(atPath: localSocketPath)
            self.localSocketPath = nil
        }
        guard let channel else { return listener }
        return listener.flatMap { channel.close().recover { _ in () } }
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

    func channelInactive(context: ChannelHandlerContext) {
        // The guest is gone. Told to the link so it stops writing into a dead
        // channel, and told with the channel so a connection that has already
        // been replaced -- the ordinary reconnection order -- does not clear its
        // own successor on the way out.
        link?.guestLeft(context.channel)
        context.fireChannelInactive()
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

    /// The link, so a direct write knows where to send.
    ///
    /// Weak on the same terms as `WireInboundHandler`: the link owns the
    /// channel, the channel's pipeline owns this, and a strong reference back
    /// would close the cycle.
    weak var link: WireLinkEndpoint?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        peer = envelope.remoteAddress
        link?.learnedPeer = envelope.remoteAddress
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
