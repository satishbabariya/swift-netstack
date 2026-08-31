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
        do {
            let remote = try SocketAddress(unixDomainSocketPath: path)

            // Bound to an address of its own before it dials, and that is the
            // whole of what was wrong here.
            //
            // A unix datagram socket that only connects has no address, so the
            // far end has nowhere to send its answers: this carried frames out
            // and received nothing, ever. Measured -- the outward frame arrived
            // and the reply never did. macOS does not autobind the way Linux
            // does, so nothing filled the gap.
            //
            // In the temporary directory rather than beside the target, because
            // `sun_path` is about a hundred bytes and a name derived from a path
            // that is already long does not fit.
            let localPath = FileManager.default.temporaryDirectory
                .appendingPathComponent("netstack-\(getpid())-\(UInt32.random(in: 0..<UInt32.max)).sock")
                .path
            let local = try SocketAddress(unixDomainSocketPath: localPath)

            #if canImport(Darwin)
                let descriptor = socket(AF_UNIX, SOCK_DGRAM, 0)
            #else
                let descriptor = socket(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0)
            #endif
            guard descriptor >= 0 else {
                return group.any().makeFailedFuture(IOError(errnoCode: errno, reason: "socket"))
            }
            let bound = local.withSockAddr { address, size in
                bind(descriptor, address, socklen_t(size))
            }
            guard bound == 0 else {
                let failure = errno
                close(descriptor)
                return group.any().makeFailedFuture(
                    IOError(errnoCode: failure, reason: "bind \(localPath)"))
            }
            let connected = remote.withSockAddr { address, size in
                connect(descriptor, address, socklen_t(size))
            }
            guard connected == 0 else {
                let failure = errno
                close(descriptor)
                try? FileManager.default.removeItem(atPath: localPath)
                return group.any().makeFailedFuture(IOError(errnoCode: failure, reason: "connect \(path)"))
            }

            // Adopted, so this shares the direct-write path rather than growing
            // a second copy of it -- which is how the listening wire came to be
            // missing the ENOBUFS handling the adopted one had.
            return adoptingDatagramSocket(
                descriptor, group: group, linkAddress: linkAddress, mtu: mtu
            ).map { link in
                link.localSocketPath = localPath
                return link
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
        // Absent is the ordinary case and not an error, and a path holding
        // something that is not a socket is left alone -- see
        // `removeStaleSocket`. Either way the bind below is what reports it, and
        // its message names the path.
        removeStaleSocket(at: path)
        // Bound by hand, so the descriptor can be kept.
        //
        // Not fussiness: NIO closes a datagram channel when a write returns
        // ENOBUFS, and a full unix datagram queue returns exactly that on BSD.
        // `adoptingDatagramSocket` was given a direct-write path for this and
        // the LISTENING wire -- which is `--listen-vfkit`, the default, and the
        // one vfkit uses -- was not. A guest that paused took the gateway's
        // network down for good, silently, and it stayed down: a later guest
        // could not even connect, because the socket was gone.
        do {
            let local = try SocketAddress(unixDomainSocketPath: path)
            #if canImport(Darwin)
                let descriptor = socket(AF_UNIX, SOCK_DGRAM, 0)
            #else
                let descriptor = socket(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0)
            #endif
            guard descriptor >= 0 else {
                return group.any().makeFailedFuture(
                    IOError(errnoCode: errno, reason: "socket for \(path)"))
            }
            let bound = local.withSockAddr { address, size in
                bind(descriptor, address, socklen_t(size))
            }
            guard bound == 0 else {
                let failure = errno
                close(descriptor)
                return group.any().makeFailedFuture(IOError(errnoCode: failure, reason: "bind \(path)"))
            }
            return DatagramBootstrap(group: group)
                .channelOption(.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: frameSize))
                .withBoundSocket(descriptor)
                .flatMap { channel in
                    configure(
                        channel: channel, linkAddress: linkAddress, mtu: mtu, framed: false,
                        flushPerFrame: true, learnsPeer: true, rawDescriptor: descriptor)
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
        removeStaleSocket(at: path)
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

    /// Take a place on `netSwitch` for a guest that has just connected, or say
    /// there is none.
    ///
    /// Returns the closure that gives the place back, to be called when the
    /// guest has a port -- or nil when the limit is reached, in which case the
    /// caller closes the connection.
    ///
    /// The counting is the point, and it is why this is one function rather than
    /// the same four lines in two listeners. `configure` finishes on a LATER
    /// tick, so the port does not exist yet when the next connection is checked:
    /// against the port count alone, every guest in a burst reads zero and every
    /// one is admitted. The limit was checkable and not enforced, under exactly
    /// the condition it exists for, in a package whose threat model is that the
    /// guest is hostile. Counting the admission closes the window, because that
    /// happens here, synchronously.
    ///
    /// The place is returned exactly once, whichever happens first: the guest
    /// getting its port, or the connection ending before it does. A reservation
    /// taken and never given back is a limit that shrinks to nothing over a long
    /// enough run.
    private static func admit(
        _ channel: Channel, to netSwitch: NetworkSwitch, limit: Int, admitting: AdmittedGuests
    ) -> (@Sendable () -> Void)? {
        guard netSwitch.portCount + admitting.pending < limit else { return nil }
        admitting.pending += 1
        let held = AdmittedGuests()
        held.pending = 1
        let release: @Sendable () -> Void = {
            guard held.pending == 1 else { return }
            held.pending = 0
            admitting.pending -= 1
        }
        channel.closeFuture.whenComplete { _ in release() }
        return release
    }

    /// Bind a `SOCK_SEQPACKET` unix socket carrying bare ethernet frames, one
    /// per message, and give every guest that connects a port on a switch.
    ///
    /// `--listen-bess`. There is no length prefix and none is needed: the socket
    /// type preserves message boundaries, so one `read` is one frame and one
    /// `write` is one frame -- which is why `flushPerFrame` is on, since a
    /// gathering write would put two frames in one message and the peer would
    /// see one frame twice the size.
    ///
    /// ## Why this is hand-rolled where the others are not
    ///
    /// NIO binds stream and datagram sockets; it has nothing for
    /// `SOCK_SEQPACKET`. But `NIOPipeBootstrap` will take ownership of an
    /// already-open descriptor and do plain `read`/`write` on it, and on a
    /// seqpacket socket that is exactly the right behaviour. So the listening
    /// and the accepting are POSIX, and everything after the accept is ordinary
    /// NIO.
    ///
    /// The accept loop is a thread, because a blocking `accept` is the only way
    /// to wait on a descriptor NIO cannot watch. It is not the datapath -- it
    /// runs once per guest -- and it touches nothing but the loop it hands each
    /// descriptor to.
    ///
    /// ## Not every platform has it
    ///
    /// Darwin does not support `SOCK_SEQPACKET` on `AF_UNIX` at all: the
    /// `socket` call fails with `EPROTOTYPE`. The returned future fails with
    /// that error rather than pretending, so the message names the reason.
    public static func seqPacketSocket(
        atPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        maximumGuests: Int = 32, maximumAddressesPerPort: Int = 16
    ) -> EventLoopFuture<NetworkSwitch> {
        let loop = group.next()
        #if canImport(Darwin)
            let listener = socket(AF_UNIX, SOCK_SEQPACKET, 0)
        #else
            let listener = socket(AF_UNIX, Int32(SOCK_SEQPACKET.rawValue), 0)
        #endif
        guard listener >= 0 else {
            return loop.makeFailedFuture(
                IOError(errnoCode: errno, reason: "SOCK_SEQPACKET on AF_UNIX"))
        }

        removeStaleSocket(at: path)
        var local = sockaddr_un()
        local.sun_family = sa_family_t(AF_UNIX)
        let room = MemoryLayout.size(ofValue: local.sun_path)
        guard path.utf8.count < room else {
            close(listener)
            return loop.makeFailedFuture(
                IOError(errnoCode: ENAMETOOLONG, reason: "socket path is longer than \(room - 1)"))
        }
        withUnsafeMutableBytes(of: &local.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, size) }
        }
        guard bound == 0, listen(listener, 32) == 0 else {
            let failure = errno
            close(listener)
            return loop.makeFailedFuture(IOError(errnoCode: failure, reason: "bind \(path)"))
        }

        let netSwitch = NetworkSwitch(
            linkAddress: linkAddress, mtu: mtu, eventLoop: loop,
            maximumAddressesPerPort: maximumAddressesPerPort)
        let limit = max(1, maximumGuests)
        let admitting = AdmittedGuests()

        let accepting = Thread {
            while true {
                let guest = accept(listener, nil, nil)
                if guest < 0 {
                    // The listener was closed, or the process is going away.
                    // Either way there is nothing left to accept.
                    if errno == EINTR { continue }
                    return
                }
                loop.execute {
                    // Adopted on the switch's loop, where the accounting lives.
                    NIOPipeBootstrap(group: loop)
                        .channelOption(
                            .recvAllocator,
                            value: FixedSizeRecvByteBufferAllocator(
                                capacity: Int(mtu) + EthernetHeader.length)
                        )
                        .takingOwnershipOfDescriptor(inputOutput: guest)
                        // On failure NIO hands the descriptor back and says so:
                        // "you still own the file descriptor and are responsible
                        // for closing them". Without this branch a failed adopt
                        // leaks one per accepted connection, silently, on a path
                        // nothing else watches.
                        .flatMapErrorThrowing { error in
                            close(guest)
                            throw error
                        }
                        .whenSuccess { channel in
                            guard
                                let release = admit(
                                    channel, to: netSwitch, limit: limit, admitting: admitting)
                            else {
                                channel.close(promise: nil)
                                return
                            }
                            // `framed: false`: the socket type is the framing.
                            // `flushPerFrame`: a gathering write would put two
                            // frames in one message.
                            // `rawDescriptor` for the same reason every other
                            // datagram wire has one: a write that cannot fit
                            // returns ENOBUFS, and NIO answers that by closing
                            // the channel. The socket is connected here -- it
                            // came from `accept` -- so the direct write is a
                            // plain `send`.
                            _ = configure(
                                channel: channel, linkAddress: linkAddress, mtu: mtu,
                                framed: false, flushPerFrame: true, rawDescriptor: guest
                            ).map { link in
                                release()
                                let id = netSwitch.addPort(link)
                                channel.closeFuture.whenComplete { _ in _ = netSwitch.removePort(id) }
                            }
                        }
                }
            }
        }
        accepting.name = "netstack-bess-accept"
        accepting.start()

        // Closing the descriptor is what stops the thread: it is blocked in
        // `accept`, which returns an error when the socket it is waiting on goes
        // away. Nothing else can reach it.
        netSwitch.stopListening = {
            close(listener)
            return loop.makeSucceededVoidFuture()
        }

        return loop.makeSucceededFuture(netSwitch)
    }

    /// Bind a unix stream socket that speaks hyperkit's vpnkit protocol, and
    /// give every guest that connects a port on a switch.
    ///
    /// `--listen-vpnkit`. The difference from `switchedStreamSocket` is the
    /// opening exchange -- see `VpnKitHandshakeHandler` -- after which the wire
    /// is ordinary hyperkit framing. The guest is *told* its hardware address
    /// here rather than choosing one, which is why `macForUUID` exists: upstream
    /// maps the UUID hyperkit sends to a configured address and invents one when
    /// it is not in the map.
    public static func vpnKitStreamSocket(
        atPath path: String, group: EventLoopGroup, linkAddress: MACAddress, mtu: UInt32 = 1500,
        maximumGuests: Int = 32, maximumAddressesPerPort: Int = 16,
        handshakeAllowance: TimeAmount = .seconds(10),
        macForUUID: @escaping @Sendable (String) -> MACAddress = { _ in MACAddress.randomLocallyAdministered() }
    ) -> EventLoopFuture<NetworkSwitch> {
        removeStaleSocket(at: path)
        let loop = group.next()
        let netSwitch = NetworkSwitch(
            linkAddress: linkAddress, mtu: mtu, eventLoop: loop,
            maximumAddressesPerPort: maximumAddressesPerPort)
        let limit = max(1, maximumGuests)
        let admitting = AdmittedGuests()

        return ServerBootstrap(group: group, childGroup: loop)
            .childChannelInitializer { channel in
                guard let release = admit(channel, to: netSwitch, limit: limit, admitting: admitting)
                else { return channel.close() }

                // The handshake first, alone in the pipeline. The frame codec is
                // installed by its completion, so the decoder never sees the
                // handshake bytes -- which are not frames and whose first two
                // bytes would be read as a length.
                let handshake = VpnKitHandshakeHandler(
                    allocator: channel.allocator, mtu: UInt16(truncatingIfNeeded: mtu),
                    allowance: handshakeAllowance, macForUUID: macForUUID
                ) { _ in
                    release()
                    _ = configure(
                        channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true,
                        framing: .hyperkit
                    ).map { link in
                        let id = netSwitch.addPort(link)
                        channel.closeFuture.whenComplete { _ in _ = netSwitch.removePort(id) }
                    }
                }
                // `syncOperations` directly, with no hop and no closure: the
                // child is pinned to this loop and `childChannelInitializer`
                // runs on it. `addHandler` would want the handler to be
                // `Sendable`, and one holding a buffer of half a handshake
                // cannot honestly be -- so the answer is not to send it
                // anywhere.
                do {
                    try channel.pipeline.syncOperations.addHandler(handshake)
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    release()
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .bind(unixDomainSocketPath: path)
            .map { listener in
                netSwitch.stopListening = { listener.close().recover { _ in () } }
                return netSwitch
            }
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
        removeStaleSocket(at: path)
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
                // check rather than a hop. See `admit` for why it counts
                // admissions and not only ports.
                guard let release = admit(channel, to: netSwitch, limit: limit, admitting: admitting)
                else { return channel.close() }
                return configure(
                    channel: channel, linkAddress: linkAddress, mtu: mtu, framed: true, framing: framing
                ).map { link in
                    release()
                    let id = netSwitch.addPort(link)
                    // A guest that goes away takes its port with it, and with it
                    // everything the switch learned on that port. Without this a
                    // disconnected guest's addresses keep naming a dead port and
                    // frames for them are dropped in silence.
                    channel.closeFuture.whenComplete { _ in
                        _ = netSwitch.removePort(id)
                    }
                }
            }
            .bind(unixDomainSocketPath: path)
            .map { listener in
                netSwitch.stopListening = { listener.close().recover { _ in () } }
                return netSwitch
            }
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
                let learner = LearnedPeerHandler()
                learner.link = link
                try sync.addHandler(learner)
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
