import NIOCore
import NIOPosix

/// A port on the host, carried into the guest.
///
/// The mirror image of `OutboundTCPForwarder`: there, a guest dialled out and
/// this process dialled a real socket for it; here, something on the host dials
/// a real socket and this process opens a connection *into* the guest for it.
/// Both are `GlueHandler` in the middle, and both must run on the stack's event
/// loop for the same reason.
///
/// ## What it is for
///
/// A container publishes a port. Without this, a service inside the guest is
/// reachable only from the guest, and "publish 8080" has no meaning -- the
/// guest's address is on a subnet that exists only inside this process.
///
/// ## What bounds an attacker
///
/// The peer here is whatever can reach the listening socket, which on a
/// developer's machine is anything on it and, if the host address says so,
/// anything on the network. So:
///
/// - **`maximumConnections` is the same bound as the outbound side's**, for the
///   same reason: each accepted connection is a guest-side endpoint and a host
///   socket, and something that opens them faster than they close would spend
///   this process's descriptors.
/// - **The listener binds where it is told and defaults to loopback.** A default
///   of `0.0.0.0` publishes a guest's port to the whole network the moment
///   somebody forwards one, which is not what "publish a port to my machine"
///   means and is not a mistake the user would see.
public final class PortForwarder: @unchecked Sendable {
    private let stack: Stack
    private let eventLoop: EventLoop
    private let guestAddress: IPv4Address
    private let guestPort: UInt16
    private let maximumConnections: Int
    private var listener: Channel?
    private var live = 0

    public var establishedCount: Int { live }
    public private(set) var refusedForLimit = 0

    /// Where the listening socket ended up, which is how a caller learns the
    /// port when it asked for zero.
    public var listeningAddress: SocketAddress? { listener?.localAddress }

    public init(
        stack: Stack, guestAddress: IPv4Address, guestPort: UInt16, maximumConnections: Int = 256
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.guestAddress = guestAddress
        self.guestPort = guestPort
        self.maximumConnections = max(1, maximumConnections)
    }

    /// Start listening. `host` defaults to loopback: see the type comment for
    /// why that default is not `0.0.0.0`.
    public func listen(host: String = "127.0.0.1", port: Int) -> EventLoopFuture<Void> {
        ServerBootstrap(group: eventLoop)
            .serverChannelOption(.backlog, value: 64)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.autoRead, value: false)
            .childChannelInitializer { [weak self] inbound in
                guard let self else { return inbound.close() }
                return self.accept(inbound)
            }
            .bind(host: host, port: port)
            .map { [weak self] channel in
                self?.listener = channel
            }
    }

    private func accept(_ inbound: Channel) -> EventLoopFuture<Void> {
        guard live < maximumConnections else {
            refusedForLimit += 1
            // Closed rather than queued. A host connection this gateway will not
            // serve should fail now: the dialler learns immediately, and nothing
            // is held here waiting for room that may never come.
            return inbound.close()
        }

        let endpoint = TCPEndpoint(stack: stack)
        let guestChannel = NetstackStreamChannel(
            eventLoop: eventLoop, endpoint: endpoint, owns: true, parent: nil)
        guestChannel.installCallbacks()

        live += 1
        let slot = PortForwardSlot(forwarder: self)
        inbound.closeFuture.whenComplete { _ in slot.release() }
        guestChannel.closeFuture.whenComplete { _ in slot.release() }

        let (guestGlue, hostGlue) = GlueHandler.matchedPair()
        do {
            try guestChannel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
            try guestChannel.pipeline.syncOperations.addHandler(guestGlue)
            try inbound.pipeline.syncOperations.addHandler(hostGlue)
        } catch {
            inbound.close(promise: nil)
            guestChannel.close(promise: nil)
            return inbound.eventLoop.makeSucceededVoidFuture()
        }

        // Registered first, connected second, and the order matters: `connect`
        // makes the guest-side channel active as soon as the handshake
        // completes, and a channel that becomes active before its pipeline is
        // registered delivers `channelActive` to nobody.
        guestChannel.register0(promise: nil)
        let address = try? SocketAddress(ipAddress: guestAddress.description, port: Int(guestPort))
        guard let address else {
            inbound.close(promise: nil)
            guestChannel.close(promise: nil)
            return inbound.eventLoop.makeSucceededVoidFuture()
        }
        let connected = eventLoop.makePromise(of: Void.self)
        guestChannel.connect0(to: address, promise: connected)
        connected.futureResult.whenFailure { _ in
            // The guest is not listening, or is gone. The host dialler is told
            // by the only means a TCP server has: the connection it made goes
            // away.
            inbound.close(promise: nil)
        }
        return inbound.eventLoop.makeSucceededVoidFuture()
    }

    public func close() {
        listener?.close(promise: nil)
        listener = nil
    }
}

/// One forwarded connection's place in `maximumConnections`, returned exactly
/// once however many of its channels close. See `ConnectionSlot` in
/// `OutboundTCPForwarder` for the argument.
private final class PortForwardSlot: @unchecked Sendable {
    private weak var forwarder: PortForwarder?
    private var released = false

    init(forwarder: PortForwarder) {
        self.forwarder = forwarder
    }

    func release() {
        guard !released else { return }
        released = true
        forwarder?.releaseConnection()
    }
}

extension PortForwarder {
    fileprivate func releaseConnection() {
        live -= 1
    }
}
