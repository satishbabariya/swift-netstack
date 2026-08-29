import NIOCore
import NIOPosix

/// Every TCP connection the guest opens, carried out to a real socket on the
/// host.
///
/// This is what the whole stack was for. `TCPForwarder` sees the guest's SYN
/// before anything is committed, this dials the destination for real, and only
/// a connection that actually succeeded is answered -- so a guest dialling a
/// port nothing is listening on gets a reset immediately rather than a
/// handshake followed by a silence.
///
/// ## The order is the design
///
/// Answering the SYN first and dialling afterwards is simpler and wrong. It
/// makes every failed connection look to the guest like a successful one that
/// died, so `connect()` returns success and the first read fails -- which is a
/// different error, arriving later, on a code path most applications handle
/// worse. It also commits an endpoint per SYN before knowing whether the
/// connection can exist, which is the resource a SYN flood is trying to spend.
///
/// ## What bounds a hostile guest here
///
/// - `TCPForwarder.maximumInFlight` bounds unanswered SYNs, and holding a
///   request while dialling is exactly the case that bound was written for: an
///   outbound `connect` can take as long as the network takes.
/// - `maximumConnections` bounds *established* ones. The forwarder's bound
///   stops counting once a request is settled, so without this a guest opens
///   connections that all succeed and holds a file descriptor per connection
///   until the host runs out -- a limit that is reached process-wide, and takes
///   everything else in the process with it.
public final class OutboundTCPForwarder: @unchecked Sendable {
    private let stack: Stack
    private let eventLoop: EventLoop
    private let maximumConnections: Int
    private let keepAlive: TCPEndpoint.KeepAliveConfiguration?
    private var forwarder: TCPForwarder?
    private var live = 0

    /// Connections currently spliced to a host socket.
    public var establishedCount: Int { live }

    /// Connections refused because the limit was already reached.
    public private(set) var refusedForLimit = 0

    /// Connections refused because the destination did not accept.
    public private(set) var refusedForDial = 0

    /// `keepAlive` is on by default here, which is the opposite of
    /// `TCPEndpoint`'s default and deliberately so.
    ///
    /// RFC 1122 wants keep-alive off because a probe costs traffic and can tear
    /// down a connection that is merely quiet. Neither applies to the guest side
    /// of a gateway: the probe travels over a unix socket, so it costs nothing,
    /// and the connection it might tear down is one whose peer is a VM this
    /// process can see the state of. What it buys is the case nothing else
    /// covers -- a guest that goes away without closing leaves an endpoint and
    /// the host socket spliced to it held forever, because with no data
    /// outstanding the retransmit timer never runs.
    public init(
        stack: Stack, maximumInFlight: Int = 512, maximumConnections: Int = 1024,
        keepAlive: TCPEndpoint.KeepAliveConfiguration? = TCPEndpoint.KeepAliveConfiguration()
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.maximumConnections = max(1, maximumConnections)
        self.keepAlive = keepAlive
        forwarder = TCPForwarder(stack: stack, maximumInFlight: maximumInFlight) { [weak self] request in
            self?.handle(request)
        }
    }

    /// Called by `ConnectionSlot` when a spliced connection ends.
    fileprivate func releaseConnection() {
        live -= 1
    }

    private func handle(_ request: ForwarderRequest) {
        guard live < maximumConnections else {
            refusedForLimit += 1
            request.refuse()
            return
        }
        guard
            let destination = try? SocketAddress(
                ipAddress: request.destination.description, port: Int(request.destinationPort))
        else {
            request.refuse()
            return
        }

        // Bootstrapped on the STACK's loop, not on a group of its own. Both
        // channels of a splice have to share a loop -- see `GlueHandler` -- and
        // this is the one place that can decide it.
        //
        // `autoRead` off on both sides, because the glue's backpressure is
        // exactly the reads it declines to issue. With it on the reads arrive
        // anyway and the queue moves one layer down, where nothing bounds it.
        ClientBootstrap(group: eventLoop)
            .channelOption(.autoRead, value: false)
            .connect(to: destination)
            .whenComplete { [weak self] outcome in
                guard let self else { return }
                switch outcome {
                case .failure:
                    // The guest hears "nothing is there" now, rather than after
                    // a handshake and a wait.
                    self.refusedForDial += 1
                    request.refuse()
                case .success(let outbound):
                    self.splice(request, to: outbound)
                }
            }
    }

    private func splice(_ request: ForwarderRequest, to outbound: Channel) {
        // `complete()` is what answers the SYN, and it is deliberately the last
        // thing that can fail: everything above this line is reversible with a
        // `refuse`, and nothing below it is.
        guard let endpoint = (try? request.complete()) ?? nil else {
            outbound.close(promise: nil)
            return
        }
        endpoint.keepAlive = keepAlive
        let guestChannel = NetstackStreamChannel(
            eventLoop: eventLoop, endpoint: endpoint, owns: true, parent: nil)
        guestChannel.installCallbacks()
        guestChannel.acceptedAddresses(
            local: try? SocketAddress(
                ipAddress: request.destination.description, port: Int(request.destinationPort)),
            remote: try? SocketAddress(ipAddress: request.source.description, port: Int(request.sourcePort)))

        live += 1
        let (guestGlue, hostGlue) = GlueHandler.matchedPair()
        do {
            // Not `setOption(...).wait()`: this runs ON the event loop, and
            // waiting there deadlocks by construction -- NIO traps rather than
            // letting it happen. The synchronous view is the right tool here for
            // the same reason it is right for the handlers below.
            try guestChannel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
            try guestChannel.pipeline.syncOperations.addHandler(guestGlue)
            try outbound.pipeline.syncOperations.addHandler(hostGlue)
        } catch {
            live -= 1
            outbound.close(promise: nil)
            guestChannel.close(promise: nil)
            return
        }

        // Counted down once, whichever side ends first. Both futures fire on a
        // splice that closes cleanly -- each channel closes the other -- so
        // decrementing on both would return the slot twice and let the limit
        // drift upward until it stopped limiting anything.
        let release = ConnectionSlot(forwarder: self)
        guestChannel.closeFuture.whenComplete { _ in release.release() }
        outbound.closeFuture.whenComplete { _ in release.release() }

        guestChannel.registerAlreadyConfigured0(promise: nil)
    }
}


/// One established connection's place in `maximumConnections`, returned exactly
/// once however many of its channels close.
///
/// A class rather than a captured flag because both `closeFuture` callbacks are
/// `@Sendable`, and a shared `var` between them would not be. Everything here
/// still runs on the stack's single event loop -- the `@unchecked` is about what
/// the compiler can prove, not about what is true.
private final class ConnectionSlot: @unchecked Sendable {
    private weak var forwarder: OutboundTCPForwarder?
    private var released = false

    init(forwarder: OutboundTCPForwarder) {
        self.forwarder = forwarder
    }

    func release() {
        guard !released else { return }
        released = true
        forwarder?.releaseConnection()
    }
}
