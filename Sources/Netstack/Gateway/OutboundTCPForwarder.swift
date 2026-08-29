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
    private let dialTimeout: TimeAmount
    private var forwarder: TCPForwarder?
    private var live = 0

    /// The channels of every spliced connection, so `close` can actually close
    /// them. Keyed by the identity of the `ConnectionSlot` that owns the pair,
    /// because that is the object both `closeFuture` callbacks already share and
    /// the one that guarantees a single removal however many of them fire.
    private var spliced: [ObjectIdentifier: (guest: Channel, host: Channel)] = [:]

    /// Connections currently spliced to a host socket.
    public var establishedCount: Int { live }

    /// Connections refused because the limit was already reached.
    public private(set) var refusedForLimit = 0

    /// Connections refused because the destination did not accept.
    public private(set) var refusedForDial = 0

    /// Where refusals are reported, if anywhere. `Gateway` sets this; a
    /// hand-assembled arrangement opts in by setting it too.
    public var log: RateLimitedLogger?


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
        keepAlive: TCPEndpoint.KeepAliveConfiguration? = TCPEndpoint.KeepAliveConfiguration(),
        dialTimeout: TimeAmount = .seconds(5)
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.maximumConnections = max(1, maximumConnections)
        self.keepAlive = keepAlive
        self.dialTimeout = dialTimeout
        forwarder = TCPForwarder(stack: stack, maximumInFlight: maximumInFlight) { [weak self] request in
            self?.handle(request)
        }
    }

    /// Called by `ConnectionSlot` when a spliced connection ends.
    fileprivate func releaseConnection(_ slot: ObjectIdentifier) {
        live -= 1
        spliced.removeValue(forKey: slot)
    }

    /// Stop accepting, and close every connection already carried.
    ///
    /// Unlike `PortForwarder.close`, this does tear down live connections, and
    /// the difference is not an inconsistency: withdrawing one published port
    /// leaves the gateway running, so work in progress through it should
    /// continue. This runs when the gateway itself is going away, and the guest
    /// on the other end of every one of these connections is going with it. A
    /// host socket left open then belongs to nothing and is closed by nothing.
    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        forwarder = nil
        let closing = spliced.values.flatMap {
            [$0.guest.close().recover { _ in () }, $0.host.close().recover { _ in () }]
        }
        spliced.removeAll()
        return EventLoopFuture.andAllSucceed(closing, on: eventLoop)
    }

    private func handle(_ request: ForwarderRequest) {
        guard live < maximumConnections else {
            refusedForLimit += 1
            log?.record(.tcpRefusedByLimit, ["limit": .stringConvertible(self.maximumConnections), "destination": .string("\(request.destination):\(request.destinationPort)")])
            request.refuse()
            return
        }
        // The slot is taken HERE, where the decision is made, not when the
        // splice succeeds.
        //
        // Taking it at the splice leaves the dial uncounted, and a dial is
        // asynchronous: every request that passes the guard while earlier dials
        // are still connecting sees the same low `live` and passes too. The
        // bound is then exceeded by however many dials are in flight -- a soak
        // found 33 against a limit of 32, and that figure is a property of how
        // fast the test's dials completed rather than of anything in the code.
        live += 1
        let slot = ConnectionSlot(forwarder: self)
        guard
            let destination = try? SocketAddress(
                ipAddress: request.destination.description, port: Int(request.destinationPort))
        else {
            slot.release()
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
        //
        // ## The connect timeout is a bound, not a nicety
        //
        // A dial to an address nothing answers at hangs for as long as the
        // operating system is willing to wait -- over a minute on macOS -- and
        // holds a half-open slot for all of it. A guest that dials unroutable
        // addresses in a loop therefore keeps `maximumInFlight` slots occupied
        // permanently, and every legitimate connection it or anything else makes
        // is dropped. That is not the flood the bound was written for; it is the
        // bound being used as the weapon.
        //
        // A soak test found it: a flood of SYNs to random addresses starved the
        // forwarder so completely that SYNs to a port that really was listening
        // never got through at all. Shortening the wait does not remove the
        // attack -- nothing can, for a gateway that dials on a guest's behalf --
        // but it turns a permanent occupation into one the guest has to keep
        // paying for, at a rate the half-open bound already limits.
        ClientBootstrap(group: eventLoop)
            .channelOption(.autoRead, value: false)
            .connectTimeout(dialTimeout)
            .connect(to: destination)
            .whenComplete { [weak self] outcome in
                guard let self else { return }
                switch outcome {
                case .failure:
                    // The guest hears "nothing is there" now, rather than after
                    // a handshake and a wait.
                    self.refusedForDial += 1
                    self.log?.record(.tcpDialFailed, ["destination": .string("\(request.destination):\(request.destinationPort)")])
                    slot.release()
                    request.refuse()
                case .success(let outbound):
                    self.splice(request, to: outbound, slot: slot)
                }
            }
    }

    private func splice(_ request: ForwarderRequest, to outbound: Channel, slot: ConnectionSlot) {
        // `complete()` is what answers the SYN, and it is deliberately the last
        // thing that can fail: everything above this line is reversible with a
        // `refuse`, and nothing below it is.
        guard let endpoint = (try? request.complete()) ?? nil else {
            slot.release()
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
            slot.release()
            outbound.close(promise: nil)
            guestChannel.close(promise: nil)
            return
        }

        // Counted down once, whichever side ends first. Both futures fire on a
        // splice that closes cleanly -- each channel closes the other -- so
        // decrementing on both would return the slot twice and let the limit
        // drift upward until it stopped limiting anything. The same object is
        // what every earlier failure path releases, so a slot is returned once
        // however far the connection got.
        spliced[ObjectIdentifier(slot)] = (guest: guestChannel, host: outbound)
        guestChannel.closeFuture.whenComplete { _ in slot.release() }
        outbound.closeFuture.whenComplete { _ in slot.release() }

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
        forwarder?.releaseConnection(ObjectIdentifier(self))
    }
}
