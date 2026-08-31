import Foundation
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
    private let keepAlive: TCPEndpoint.KeepAliveConfiguration?
    private var listener: Channel?
    private var live = 0

    public var establishedCount: Int { live }
    public private(set) var refusedForLimit = 0

    /// Where refusals are reported, if anywhere. `Gateway.forward` sets this.
    public var log: RateLimitedLogger?

    /// Where the listening socket ended up, which is how a caller learns the
    /// port when it asked for zero.
    public var listeningAddress: SocketAddress? { listener?.localAddress }

    /// `keepAlive` defaults on for the same reason it does on the outbound
    /// forwarder: see `OutboundTCPForwarder.init`.
    public init(
        stack: Stack, guestAddress: IPv4Address, guestPort: UInt16, maximumConnections: Int = 256,
        keepAlive: TCPEndpoint.KeepAliveConfiguration? = TCPEndpoint.KeepAliveConfiguration()
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.guestAddress = guestAddress
        self.guestPort = guestPort
        self.maximumConnections = max(1, maximumConnections)
        self.keepAlive = keepAlive
    }

    /// Listen on a unix socket instead of a TCP port, and carry each connection
    /// to the same guest address and port.
    ///
    /// Upstream's `unix` forwarding protocol, and the useful thing about it is
    /// exactly what makes it different from a TCP listener: the socket is a file,
    /// so who may reach the guest's port is decided by filesystem permissions
    /// rather than by whoever can open a connection to a port on this machine.
    ///
    /// An existing socket at that path is removed first, which is conventional
    /// and worth naming as a hazard: the path is deleted before it is bound, so
    /// pointing this at a file that is not a stale socket deletes that file.
    public func listen(unixSocketPath path: String) -> EventLoopFuture<Void> {
        removeStaleSocket(at: path)
        return bootstrap()
            .bind(unixDomainSocketPath: path)
            .map { [weak self] channel in
                self?.listener = channel
            }
    }

    private func bootstrap() -> ServerBootstrap {
        ServerBootstrap(group: eventLoop)
            .serverChannelOption(.backlog, value: 64)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.autoRead, value: false)
            .childChannelInitializer { [weak self] inbound in
                guard let self else { return inbound.close() }
                return self.accept(inbound)
            }
    }

    /// Start listening. `host` defaults to loopback: see the type comment for
    /// why that default is not `0.0.0.0`.
    public func listen(host: String = "127.0.0.1", port: Int) -> EventLoopFuture<Void> {
        bootstrap()
            .bind(host: host, port: port)
            .map { [weak self] channel in
                self?.listener = channel
            }
    }

    private func accept(_ inbound: Channel) -> EventLoopFuture<Void> {
        guard live < maximumConnections else {
            refusedForLimit += 1
            // Shares the guest side's event and its window deliberately. The
            // connections refused here come from the host rather than from the
            // guest, but they are refused by the same limit for the same
            // reason, and an operator chasing "connections are being dropped"
            // wants both under one name with the direction said in the line.
            log?.record(.tcpRefusedByLimit, ["direction": .string("host-to-guest"), "limit": .stringConvertible(maximumConnections)])
            // Closed rather than queued. A host connection this gateway will not
            // serve should fail now: the dialler learns immediately, and nothing
            // is held here waiting for room that may never come.
            return inbound.close()
        }

        // Slot taken before the dial, and released by whichever side ends
        // first -- see `PortForwardSlot`.
        live += 1
        let slot = PortForwardSlot(forwarder: self)
        inbound.closeFuture.whenComplete { _ in slot.release() }

        guard
            let guestChannel = GuestSplice.connect(
                stack: stack, host: inbound, to: guestAddress, port: guestPort, keepAlive: keepAlive)
        else {
            slot.release()
            inbound.close(promise: nil)
            return inbound.eventLoop.makeSucceededVoidFuture()
        }
        guestChannel.closeFuture.whenComplete { _ in slot.release() }
        return inbound.eventLoop.makeSucceededVoidFuture()
    }

    /// Stop accepting, and complete when the listening socket is closed.
    ///
    /// Connections already spliced through it are deliberately left alone --
    /// withdrawing a forward means "accept no more", not "cut off work in
    /// progress" -- so this future covers the listener and nothing else.
    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        guard let listener else { return stack.eventLoop.makeSucceededVoidFuture() }
        self.listener = nil
        return listener.close().recover { _ in () }
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
