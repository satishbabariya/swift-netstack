import NIOCore
import NIOPosix

/// How a `WireLinkEndpoint` gets a wire.
///
/// ## The two shapes of wire, and which host uses which
///
/// - **Datagram.** One datagram is one ethernet frame, with the kernel keeping
///   the boundaries. This is what Virtualization.framework's
///   `VZFileHandleNetworkDeviceAttachment` speaks, what `vfkit` speaks, and what
///   upstream calls `unixgram`. On Apple platforms it is the interesting one:
///   the host makes a `socketpair(AF_UNIX, SOCK_DGRAM)`, hands one end to the
///   VM and keeps the other, so there is no path to connect to and no listener
///   to accept -- only a file descriptor that is already connected.
/// - **Stream.** A byte stream with `FrameDecoder`'s length prefix in front of
///   each frame. This is qemu's `-netdev socket`, and bess and stdio use the
///   same framing.
///
/// `adoptingDatagramSocket` is therefore the entry point that matters most, and
/// it is the one that takes a descriptor rather than an address.
public enum WireBootstrap {
    /// Take over an already-connected datagram socket.
    ///
    /// **Ownership passes to NIO.** The descriptor is closed when the returned
    /// link's channel closes, and it must not be closed by the caller -- a
    /// double close is not a leak, it is a descriptor number that something
    /// else has since been given.
    ///
    /// The receive buffer is sized to a whole frame. A read truncates rather
    /// than fails, so a buffer smaller than the frame would deliver the front of
    /// one as if it were all of it -- a corruption that looks like a peer
    /// sending malformed packets and is not.
    ///
    /// ## Why this is a `ClientBootstrap` and not a `DatagramBootstrap`
    ///
    /// It looks like the wrong one. `DatagramBootstrap.withBoundSocket` adopts
    /// the descriptor and produces a channel that reads datagrams -- and then
    /// **traps on the first write**. Its pending-writes manager learns the
    /// connected peer from `connect0`, which an adopted socket never goes
    /// through, so an unaddressed write hits
    /// `preconditionFailure("Pending write without address on unconnected
    /// socket")`. Supplying an address instead does not help: a socketpair's
    /// peer is unnamed, so there is no address to supply.
    ///
    /// A stream channel over the same descriptor uses plain `read` and `write`,
    /// which on a datagram socket are one datagram each -- boundaries preserved
    /// by the kernel, measured on a real socketpair and not assumed. The one
    /// thing that must not be inherited from the stream side is vectored
    /// writing, which is what `flushPerFrame` exists to prevent.
    public static func adoptingDatagramSocket(
        _ descriptor: NIOBSDSocket.Handle, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500
    ) -> EventLoopFuture<WireLinkEndpoint> {
        let frameSize = Int(mtu) + EthernetHeader.length
        return ClientBootstrap(group: group)
            .channelOption(.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: frameSize))
            .withConnectedSocket(descriptor)
            .flatMap { channel in
                configure(
                    channel: channel, linkAddress: linkAddress, mtu: mtu, framed: false, flushPerFrame: true)
            }
    }

    /// Connect a unix datagram socket to `path` -- upstream's `unixgram`, and
    /// vfkit's wire.
    public static func connectingDatagramSocket(
        toPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500
    ) -> EventLoopFuture<WireLinkEndpoint> {
        let frameSize = Int(mtu) + EthernetHeader.length
        do {
            let remote = try SocketAddress(unixDomainSocketPath: path)
            return DatagramBootstrap(group: group)
                .channelOption(.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: frameSize))
                .connect(to: remote)
                .flatMap { channel in
                    // A `DatagramBootstrap.connect` DOES go through `connect0`,
                    // so this channel knows its peer and writes on it are safe.
                    // It is the adopted-descriptor path above that cannot.
                    configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: false, remote: remote)
                }
        } catch {
            return group.any().makeFailedFuture(error)
        }
    }

    /// Take over an already-connected stream socket carrying length-prefixed
    /// frames -- qemu's `-netdev socket,fd=`.
    ///
    /// Ownership passes to NIO, as above.
    public static func adoptingStreamSocket(
        _ descriptor: NIOBSDSocket.Handle, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500
    ) -> EventLoopFuture<WireLinkEndpoint> {
        ClientBootstrap(group: group).withConnectedSocket(descriptor).flatMap { channel in
            configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true)
        }
    }

    /// Connect a unix stream socket to `path`, carrying length-prefixed frames.
    public static func connectingStreamSocket(
        toPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500
    ) -> EventLoopFuture<WireLinkEndpoint> {
        do {
            let remote = try SocketAddress(unixDomainSocketPath: path)
            return ClientBootstrap(group: group).connect(to: remote).flatMap { channel in
                configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true)
            }
        } catch {
            return group.any().makeFailedFuture(error)
        }
    }

    /// Build the link and install the pipeline, on the channel's own loop.
    ///
    /// The link is constructed **before** the handlers that reference it, and
    /// referenced weakly by them: the link owns the channel and the channel's
    /// pipeline owns the handlers, so a strong reference back would close a
    /// cycle around a wire that is never released.
    private static func configure(
        channel: Channel, linkAddress: MACAddress, mtu: UInt32, framed: Bool, remote: SocketAddress? = nil,
        flushPerFrame: Bool = false
    ) -> EventLoopFuture<WireLinkEndpoint> {
        let link = WireLinkEndpoint(
            channel: channel, linkAddress: linkAddress, mtu: mtu, flushPerFrame: flushPerFrame)
        return channel.eventLoop.submit {
            let sync = channel.pipeline.syncOperations
            if let remote {
                try sync.addHandler(DatagramEnvelopeHandler(remote: remote))
            }
            if framed {
                let maximumFrame = Int(mtu) + EthernetHeader.length
                try sync.addHandler(ByteToMessageHandler(FrameDecoder(maximumFrame: maximumFrame)))
                try sync.addHandler(MessageToByteHandler(FrameEncoder(maximumFrame: maximumFrame)))
            }
            try sync.addHandler(WireInboundHandler(link: link))
            return link
        }
    }
}
