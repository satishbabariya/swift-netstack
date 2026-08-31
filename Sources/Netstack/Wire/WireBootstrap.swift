import Foundation
import NIOConcurrencyHelpers
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
                // The descriptor is handed on so the link can write through it
                // directly. See `WireLinkEndpoint.rawDescriptor`: NIO closes the
                // channel when a write returns ENOBUFS, which a full unix
                // datagram queue does on BSD, and a guest that pauses would
                // otherwise take the gateway's network down with it for good.
                configure(
                    channel: channel, linkAddress: linkAddress, mtu: mtu, framed: false,
                    flushPerFrame: true, rawDescriptor: descriptor)
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
        _ descriptor: NIOBSDSocket.Handle, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        framing: StreamFraming = .qemu
    ) -> EventLoopFuture<WireLinkEndpoint> {
        ClientBootstrap(group: group).withConnectedSocket(descriptor).flatMap { channel in
            configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing)
        }
    }

    /// Take over a pair of pipes -- ordinarily this process's own stdin and
    /// stdout -- as the wire.
    ///
    /// This is upstream's `--listen-stdio`, whose framing it documents as
    /// "HyperKitProtocol without the handshake": two little-endian length bytes
    /// and then the frame, which is `.hyperkit` here. The caller passes the two
    /// descriptors rather than this reaching for 0 and 1 itself, because a
    /// library that took over the process's standard streams on its own would be
    /// making a decision that belongs to the program.
    ///
    /// **Ownership passes to NIO**, which closes both when the channel closes.
    /// Whatever the process was going to say on stdout has to go somewhere else
    /// before this is called: a frame and a log line on the same descriptor
    /// makes the log line part of a frame.
    public static func adoptingPipes(
        input: CInt, output: CInt, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        framing: StreamFraming = .hyperkit
    ) -> EventLoopFuture<WireLinkEndpoint> {
        NIOPipeBootstrap(group: group)
            .takingOwnershipOfDescriptors(input: input, output: output)
            .flatMap { channel in
                configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing)
            }
    }

    /// Connect a unix stream socket to `path`, carrying length-prefixed frames.
    public static func connectingStreamSocket(
        toPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        framing: StreamFraming = .qemu
    ) -> EventLoopFuture<WireLinkEndpoint> {
        do {
            let remote = try SocketAddress(unixDomainSocketPath: path)
            return ClientBootstrap(group: group).connect(to: remote).flatMap { channel in
                configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing)
            }
        } catch {
            return group.any().makeFailedFuture(error)
        }
    }

    /// Bind a unix datagram socket at `path` and serve whoever sends to it.
    ///
    /// This is the shape vfkit and qemu expect: they are given a path and dial
    /// it, so the gateway is the one that listens. Every `connecting…` entry
    /// point above is the other way round, for a host that already knows where
    /// the guest is.
    ///
    /// The peer is **learned from the first datagram** rather than configured,
    /// because a bound datagram socket has no peer until something sends to it
    /// and there is nothing to configure it with. Replies go to whoever last
    /// sent, which is the same rule upstream's `unixgram` transport uses and is
    /// correct for the one thing this wire carries: a single guest.
    public static func listeningDatagramSocket(
        atPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500
    ) -> EventLoopFuture<WireLinkEndpoint> {
        let frameSize = Int(mtu) + EthernetHeader.length
        do {
            try FileManager.default.removeItem(atPath: path)
        } catch {
            // Absent is the ordinary case and not an error. Anything else -- a
            // path that exists and cannot be removed -- surfaces from the bind
            // below, where the message names the path.
        }
        do {
            let local = try SocketAddress(unixDomainSocketPath: path)
            return DatagramBootstrap(group: group)
                .channelOption(.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: frameSize))
                .bind(to: local)
                .flatMap { channel in
                    configure(channel: channel, linkAddress: linkAddress, mtu: mtu, framed: false, learnsPeer: true)
                }
        } catch {
            return group.any().makeFailedFuture(error)
        }
    }

    /// Bind a unix stream socket at `path` and serve the first guest to connect.
    ///
    /// The returned future completes when that connection arrives, not when the
    /// socket is bound -- there is no link until there is a guest, and a link
    /// with no wire behind it would be a thing callers could write to and lose.
    ///
    /// One guest **at a time**. A second connection while one is live is closed
    /// rather than served: this wire carries one ethernet segment, and two
    /// guests on it would need a switch that learns which addresses are behind
    /// which socket -- which is what `switchedStreamSocket` is for.
    ///
    /// But a guest that goes away releases the wire, and the next connection
    /// takes it over. VMs reboot, and a stream connection dies with the guest;
    /// this used to hold the slot forever, so the gateway had to be restarted
    /// along with the VM. The datagram wire never had the problem -- its peer is
    /// whoever last sent -- which is why it went unnoticed.
    public static func listeningStreamSocket(
        atPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        framing: StreamFraming = .qemu
    ) -> EventLoopFuture<WireLinkEndpoint> {
        try? FileManager.default.removeItem(atPath: path)
        // Children pinned to one loop, the way `switchedStreamSocket` pins
        // them, and for a reason beyond consistency: `ServerBootstrap` spreads
        // children across the group it is given, so the "have we already taken
        // one?" flag was shared between threads and needed a lock to be read at
        // all.
        //
        // That lock was the second in `Sources/Netstack`, in a package whose
        // whole concurrency design is that there are none -- everything is
        // confined to an event loop instead. On one loop the flag is ordinary
        // loop-confined state and the lock is not needed. `scripts/conventions.sh`
        // now fails the build if another appears.
        let loop = group.next()
        let arrived = loop.makePromise(of: WireLinkEndpoint.self)
        let accepted = FirstGuest()
        ServerBootstrap(group: group, childGroup: loop)
            .serverChannelOption(.backlog, value: 1)
            .childChannelInitializer { channel in
                // On `loop`, because the child was pinned to it.
                guard !accepted.taken else { return channel.close() }
                accepted.taken = true
                // Released when this guest's connection ends, so the next one is
                // served rather than closed.
                channel.closeFuture.whenComplete { _ in accepted.taken = false }

                // The first guest builds the link; every later one takes over
                // the same link, because that is what the stack above is
                // attached to. Building a second would leave the gateway talking
                // to a wire nobody is on.
                if let existing = accepted.link {
                    return configure(
                        channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true,
                        framing: framing, adopting: existing
                    ).map { _ in }
                }
                return configure(
                    channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing
                ).map { link in
                    accepted.link = link
                    arrived.succeed(link)
                }
            }
            .bind(unixDomainSocketPath: path)
            .whenFailure { arrived.fail($0) }
        return arrived.futureResult
    }

    /// Bind a unix stream socket and give **every** guest that connects a port
    /// on a switch, so one gateway serves a whole network rather than one VM.
    ///
    /// The returned future completes when the socket is **bound**, not when a
    /// guest arrives -- unlike `listeningStreamSocket`, and deliberately. A link
    /// with no wire behind it is not a link, so that one has to wait; a switch
    /// with no ports is an ordinary and valid state, and a caller that had to
    /// wait for the first guest could not publish ports or answer its control
    /// socket until one turned up.
    ///
    /// ## Why `childGroup` is a single loop
    ///
    /// Everything in this package is loop-confined instead of locked, and the
    /// switch reads and writes its CAM on every frame. `ServerBootstrap` spreads
    /// child channels across the group it is given, so accepting guests on a
    /// multi-threaded group would deliver frames to the switch from several
    /// threads at once -- a data race, not a slow path. Pinning the children to
    /// the switch's own loop is what makes the no-locks rule hold here.
    public static func switchedStreamSocket(
        atPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        maximumGuests: Int = 32, maximumAddressesPerPort: Int = 16, framing: StreamFraming = .qemu
    ) -> EventLoopFuture<NetworkSwitch> {
        try? FileManager.default.removeItem(atPath: path)
        let loop = group.next()
        let netSwitch = NetworkSwitch(
            linkAddress: linkAddress, mtu: mtu, eventLoop: loop,
            maximumAddressesPerPort: maximumAddressesPerPort)
        let limit = max(1, maximumGuests)
        let admitting = AdmittedGuests()

        return ServerBootstrap(group: group, childGroup: loop)
            .childChannelInitializer { channel in
                // Counted on the switch's loop, where `portCount` is safe to
                // read -- and the child is already on that loop, so this is a
                // check rather than a hop.
                //
                // `admitting` is the part that took a falsification to find.
                // `configure` finishes on a LATER tick of this loop, so the port
                // does not exist yet when the next connection is checked: every
                // guest in a burst read `portCount == 0` and every one was
                // admitted. The limit was checkable and not enforced, under
                // exactly the condition it exists for -- many guests at once --
                // in a package whose threat model is that the guest is hostile.
                //
                // Counting the admission rather than the port closes the window,
                // because that happens here, synchronously, before this returns.
                guard netSwitch.portCount + admitting.pending < limit else {
                    return channel.close()
                }
                admitting.pending += 1
                return configure(
                    channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing
                ).map { link in
                    admitting.pending -= 1
                    let id = netSwitch.addPort(link)
                    // A guest that goes away takes its port with it, and with it
                    // everything the switch learned on that port. Without this a
                    // disconnected guest's addresses keep naming a dead port and
                    // frames for them are dropped in silence.
                    channel.closeFuture.whenComplete { _ in
                        _ = netSwitch.removePort(id)
                    }
                }.flatMapErrorThrowing { error in
                    // Released on the way out too. A reservation that is only
                    // ever taken is a limit that shrinks to nothing over a long
                    // enough run.
                    admitting.pending -= 1
                    throw error
                }
            }
            .bind(unixDomainSocketPath: path)
            .map { _ in netSwitch }
    }

    /// Build the link and install the pipeline, on the channel's own loop.
    ///
    /// The link is constructed **before** the handlers that reference it, and
    /// referenced weakly by them: the link owns the channel and the channel's
    /// pipeline owns the handlers, so a strong reference back would close a
    /// cycle around a wire that is never released.
    /// Internal rather than private because `ControlPlane` builds a link on a
    /// connection it hijacked from HTTP, which is the same job as every
    /// bootstrap above with the socket already in hand.
    static func configure(
        channel: Channel, linkAddress: MACAddress, mtu: UInt32, framed: Bool, remote: SocketAddress? = nil,
        flushPerFrame: Bool = false, learnsPeer: Bool = false, framing: StreamFraming = .qemu,
        rawDescriptor: NIOBSDSocket.Handle? = nil, adopting existing: WireLinkEndpoint? = nil
    ) -> EventLoopFuture<WireLinkEndpoint> {
        let link =
            existing
            ?? WireLinkEndpoint(
                channel: channel, linkAddress: linkAddress, mtu: mtu, flushPerFrame: flushPerFrame,
                rawDescriptor: rawDescriptor)
        return channel.eventLoop.submit {
            let sync = channel.pipeline.syncOperations
            if learnsPeer {
                try sync.addHandler(LearnedPeerHandler())
            } else if let remote {
                try sync.addHandler(DatagramEnvelopeHandler(remote: remote))
            }
            if framed {
                let maximumFrame = Int(mtu) + EthernetHeader.length
                try sync.addHandler(
                    ByteToMessageHandler(FrameDecoder(maximumFrame: maximumFrame, framing: framing)))
                try sync.addHandler(
                    MessageToByteHandler(FrameEncoder(maximumFrame: maximumFrame, framing: framing)))
            }
            try sync.addHandler(WireInboundHandler(link: link))
            // Last, so the link only starts writing here once the pipeline can
            // carry what it writes.
            if existing != nil { link.adopt(channel) }
            return link
        }
    }
}

/// Whether a guest is on this wire, and which link it is on.
///
/// A class rather than a captured `var` because the compiler cannot see that the
/// closure reading it is pinned to a single loop, and `@unchecked Sendable` on
/// exactly the terms the rest of this package uses: the safety is real and comes
/// from loop confinement, not from anything the compiler checked. A lock here
/// would be the second in `Sources/Netstack`, which is the thing
/// `scripts/conventions.sh` exists to prevent.
/// Guests admitted but not yet holding a port.
///
/// See `switchedStreamSocket`: the port appears a tick after the admission, and
/// the gap is wide enough to fit every connection in a burst. Loop-confined on
/// exactly the terms `FirstGuest` is.
private final class AdmittedGuests: @unchecked Sendable {
    var pending = 0
}

private final class FirstGuest: @unchecked Sendable {
    var taken = false
    /// Kept so a guest that reconnects takes over the link the stack is already
    /// attached to, rather than getting a second one nothing is listening to.
    var link: WireLinkEndpoint?
}
