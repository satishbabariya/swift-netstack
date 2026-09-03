import NIOCore

/// One virtual network stack, owning one event loop and one link.
///
/// Every method and every callback runs on `eventLoop`. That is the whole
/// concurrency design: no locks, because there is nothing to contend for.
///
/// `shutdown()` is not merely tidy — it is mandatory. The maintenance timer
/// started by `start()` is a `RepeatedTask`, and NIO's `RepeatedTask`
/// self-perpetuates: each firing reschedules the next one as a closure the
/// event loop retains internally, independent of any external reference.
/// Dropping every reference to this `Stack` — including this `Stack` itself
/// — does not stop it; only `cancel()`, which `shutdown()` calls, does. Skip
/// `shutdown()` and the timer keeps firing forever, holding the
/// `Reassembler` and the `ARPCache` alive with it — both of which it sweeps
/// on every firing — even after the rest of the stack (`nic`, `arpResponder`,
/// `ipv4`, `routes`) has been deallocated.
// Deliberately NOT `Sendable`, checked or otherwise. Every stored property
// here is loop-confined, mutated only on `eventLoop`, and this type publicly
// exposes the entire graph (`nic`/`ipv4`/`routes`/`arpCache`/`reassembler`/
// `transportDemuxer`) that confinement is the only thing protecting -- no
// locks exist anywhere in this package. Making `Stack` itself `Sendable`
// would let that whole graph cross an isolation boundary through `Stack`
// alone, after which the compiler stops objecting to touching any part of it
// off-loop from anywhere a `Stack` reference reaches, not just from
// `shutdown()`. `shutdown()` still needs to capture stack-owned state inside
// a `@Sendable` closure for `EventLoop.flatSubmit`; see `ShutdownBox` just
// below, which earns exactly that one narrow crossing without extending
// `Sendable` to the public type itself.
public final class Stack {
    public struct Configuration: Sendable {
        /// The address the stack answers for — the guest's default gateway.
        public var gatewayAddress: IPv4Address
        public var subnet: IPv4Subnet
        /// Accept frames addressed to other hosts. On by default: the gateway
        /// terminates connections to arbitrary destinations, so it must.
        public var acceptsAnyDestination: Bool
        /// Transmit from addresses we do not own. On by default, same reason.
        public var allowsAnySource: Bool
        public var reassemblyTimeout: TimeAmount
        public var maintenanceInterval: TimeAmount

        public init(
            gatewayAddress: IPv4Address,
            subnet: IPv4Subnet,
            acceptsAnyDestination: Bool = true,
            allowsAnySource: Bool = true,
            reassemblyTimeout: TimeAmount = .seconds(30),
            maintenanceInterval: TimeAmount = .seconds(10)
        ) {
            self.gatewayAddress = gatewayAddress
            self.subnet = subnet
            self.acceptsAnyDestination = acceptsAnyDestination
            self.allowsAnySource = allowsAnySource
            self.reassemblyTimeout = reassemblyTimeout
            self.maintenanceInterval = maintenanceInterval
        }
    }

    public let eventLoop: EventLoop
    public let configuration: Configuration
    public let nic: NIC
    public let routes: RouteTable
    public let arpCache: ARPCache
    public let arpResponder: ARPResponder
    public let reassembler: Reassembler
    public let ipv4: IPv4Protocol
    public let transportDemuxer = TransportDemuxer()

    /// The stack's only source of time, held so the transports built on top of
    /// it (`TCPEndpoint`'s `Sender` and `TCPTimers`) read the same clock the
    /// `ARPCache` and the `Reassembler` do. Nothing in this package may call
    /// `NIODeadline.now()`, so an endpoint that could not reach this would have
    /// no lawful way to tell the time.
    public let clock: NetstackClock

    /// The per-stack RFC 6528 initial-send-sequence generator.
    ///
    /// Its secret is made **once, here**, and never leaves the process — that is
    /// the whole of what makes an ISS unguessable from another connection's.
    /// `TCPEndpoint.init(stack:)` takes this one; the internal
    /// `init(stack:initialSequenceNumbers:)` is the seam a test (or a
    /// differential vector written in absolute sequence numbers) overrides.
    /// Internal rather than public: a caller outside the module has no business
    /// replacing it, and making it public would put "use a constant ISS" in the
    /// package's supported surface.
    let initialSequenceNumbers: any InitialSequenceNumbers

    /// RFC 5961 §7's challenge-ACK budget, shared by **every** TCP connection on
    /// this stack.
    ///
    /// Here rather than in each `TCB` because a guest opens connections as freely
    /// as it sends segments: a per-connection bucket would still let it choose
    /// the multiplier, at the price of one SYN per hundred challenge ACKs. See
    /// `ChallengeACKBudget` for what the sharing costs.
    ///
    /// `var`, and mutated in place through `TCPStateMachine.receive` — loop-
    /// confined like everything else here, and holding no lock.
    var tcpChallengeACKs: ChallengeACKBudget

    private let allocator: ByteBufferAllocator
    private var maintenanceTask: RepeatedTask?

    /// Whether the maintenance timer is still running.
    ///
    /// Exists because the timer is otherwise unobservable from outside: it
    /// reschedules itself through the loop's queue and holds no reference
    /// anything can see, which is exactly the property that makes forgetting
    /// `shutdown()` a leak nobody notices. A test can watch this; nothing else
    /// should.
    public var isRunningForTesting: Bool { maintenanceTask != nil }

    public init(
        link: LinkEndpoint,
        configuration: Configuration,
        clock: NetstackClock = RealClock(),
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) {
        self.eventLoop = link.eventLoop
        self.configuration = configuration
        self.allocator = allocator
        self.clock = clock
        self.initialSequenceNumbers = RFC6528SequenceNumbers(clock: clock)
        self.tcpChallengeACKs = ChallengeACKBudget(clock: clock)

        let nic = NIC(id: 1, link: link)
        nic.addAddress(configuration.gatewayAddress, prefixLength: configuration.subnet.prefixLength)
        nic.acceptsAnyDestination = configuration.acceptsAnyDestination
        nic.allowsAnySource = configuration.allowsAnySource
        self.nic = nic

        let routes = RouteTable()
        routes.register(nic)
        routes.add(Route(destination: configuration.subnet, gateway: nil, nicID: nic.id))
        // With spoofing on, everything else is reachable through this NIC too:
        // the stack answers as any host the guest tries to reach. This route
        // has a shorter prefix (0) than the subnet route above, so longest-
        // prefix selection in RouteTable still prefers the subnet route for
        // on-link destinations; this one only ever matches what the subnet
        // route did not.
        if configuration.allowsAnySource {
            routes.add(Route(destination: IPv4Subnet(cidr: "0.0.0.0/0")!, gateway: nil, nicID: nic.id))
        }
        self.routes = routes

        let arpCache = ARPCache(clock: clock)
        let arpResponder = ARPResponder(nic: nic, cache: arpCache, allocator: allocator)
        let reassembler = Reassembler(clock: clock, timeout: configuration.reassemblyTimeout)
        self.arpCache = arpCache
        self.arpResponder = arpResponder
        self.reassembler = reassembler

        let ipv4 = IPv4Protocol(
            nic: nic, routes: routes, arpCache: arpCache, arpResponder: arpResponder,
            reassembler: reassembler, allocator: allocator)
        self.ipv4 = ipv4

        // `[weak ipv4]` for the reason every other closure in this file is:
        // `ARPCache` is held by `IPv4Protocol`, so a strong capture here would
        // be a cycle from the cache back to the thing that owns it. The cache
        // outlives nothing this does not.
        arpCache.onRecorded = { [weak ipv4] address, _ in
            ipv4?.resolved(address)
        }
    }

    /// Wire the protocol handlers to the NIC and start the maintenance timer.
    public func start() {
        // `[weak arpResponder]`, not `[arpResponder]`: `ARPResponder` now
        // holds `nic` strongly (see its own doc comment), so a strong
        // capture here would close NIC -> handlers -> closure ->
        // ARPResponder -> NIC, a self-contained retain cycle independent of
        // anything else in this graph. `arpResponder` is kept alive for as
        // long as this `Stack` is by the `public let arpResponder` field
        // regardless, so `weak` costs nothing here and matches the `[weak
        // ipv4]` pattern just below for the same reason.
        nic.setHandler(for: .arp) { [weak arpResponder] packet, ethernet in
            arpResponder?.handle(packet, ethernet)
        }
        // `[weak ipv4]`, not `[ipv4]`: `nic.handlers` would otherwise hold a
        // strong closure back to `ipv4`, which holds `routes` strongly,
        // whose `RouteTable.nics` holds this same `nic` strongly — NIC ->
        // closure -> IPv4Protocol -> RouteTable -> NIC, a cycle Stack itself
        // sits outside of, so the whole graph leaks for the life of the
        // process once `start()` is called. `nic`'s own `unowned` field on
        // `IPv4Protocol` does not touch this edge; it runs through
        // `RouteTable`, not through `IPv4Protocol.nic`. `weak` (rather than
        // `unowned`) means a handler that somehow fires after `ipv4` is gone
        // is a silent no-op instead of a trap.
        nic.setHandler(for: .ipv4) { [weak ipv4] packet, ethernet in
            ipv4?.handleInbound(packet, ethernet)
        }

        // `[weak ipv4]` here too: this closure is stored in `ipv4.handlers`
        // itself, so capturing `ipv4` strongly makes `IPv4Protocol` retain
        // itself directly — a second, independent cycle from the one above.
        ipv4.setHandler(for: .udp) { [weak ipv4, transportDemuxer, allocator] header, payload in
            guard let ipv4 else { return }
            var packet = PacketBuffer(received: payload)
            guard let udp = UDPHeader.parse(&packet, header: header) else { return }
            let delivered = transportDemuxer.deliver(
                protocolNumber: .udp, header: header, payload: packet.payload,
                localPort: udp.destinationPort, remotePort: udp.sourcePort)
            guard !delivered else { return }

            // Nothing is listening. Tell the sender, so it fails fast instead
            // of retrying into a void.
            var quoted = ByteBuffer()
            quoted.writeInteger(udp.sourcePort, endianness: .big)
            quoted.writeInteger(udp.destinationPort, endianness: .big)
            // `udp.length` is already the full wire field (header plus
            // payload) — see UDPHeader.parse — so it is quoted as-is.
            quoted.writeInteger(udp.length, endianness: .big)
            quoted.writeInteger(udp.checksum, endianness: .big)
            let message = ICMPv4.destinationUnreachable(
                code: .port, quoting: header, quotedPayload: quoted, allocator: allocator)
            try? ipv4.send(payload: message, to: header.source, from: header.destination, protocolNumber: .icmp)
        }

        // `[weak ipv4]` for the same reason as the UDP handler just above: this
        // closure is stored in `ipv4.handlers`, so a strong capture makes
        // `IPv4Protocol` retain itself. This is the THIRD handler closure
        // `start()` installs and the third chance to close one of the retain
        // cycles the two above already produced once each; see
        // `aStartedStackWithTcpIsReleasedWhenDroppedWithoutShutdown`, which is
        // the test that can actually see this capture on its own.
        //
        // `transportDemuxer` and `allocator` are captured by value into an
        // ordinary (non-`@Sendable`) closure, exactly as the UDP handler
        // captures them, so this adds no new "capture of non-Sendable type in a
        // @Sendable closure" warning to the population `Stack.swift` already
        // carries on its `scheduleRepeatedTask` closure.
        ipv4.setHandler(for: .tcp) { [weak ipv4, transportDemuxer, allocator] header, payload in
            guard let ipv4 else { return }
            var packet = PacketBuffer(received: payload)
            // Parsed here for two things: the checksum, so a corrupt segment
            // never reaches an endpoint or provokes a reset, and the ports the
            // demuxer keys on. The segment is then handed on WHOLE rather than
            // as its payload — unlike UDP, where the endpoint needs nothing from
            // the header — because a TCP endpoint needs the flags, the sequence
            // and acknowledgement numbers, the window and the options, and
            // `TransportEndpointDelegate.deliver` has nowhere to put a parsed
            // header. The endpoint parses it a second time; that cost is the
            // price of leaving the delegate protocol alone, and it is paid on a
            // buffer already known to be well formed.
            guard let tcp = TCPHeader.parse(&packet, header: header) else { return }
            let delivered = transportDemuxer.deliver(
                protocolNumber: .tcp, header: header, payload: payload,
                localPort: tcp.destinationPort, remotePort: tcp.sourcePort)
            guard !delivered else { return }

            // Nothing is listening. RFC 9293 §3.10.7.1: answer with a reset, so
            // a guest's connect() fails fast instead of retrying into a void —
            // the TCP counterpart of the ICMP port-unreachable the UDP handler
            // above sends. `closedSegmentArrives` is the one place that chooses
            // between the RFC's two reset forms, and it is called rather than
            // reimplemented here.
            let segment = TCPSegment(header: tcp, payload: packet.payload)
            for action in TCPStateMachine.closedSegmentArrives(segment: segment) {
                guard case .sendRst(let sequence, let ack) = action else { continue }
                TCPWire.sendReset(
                    sequence: sequence, ack: ack,
                    sourcePort: tcp.destinationPort, destinationPort: tcp.sourcePort,
                    from: header.destination, to: header.source, via: ipv4, allocator: allocator)
            }
        }

        // A second start() would overwrite the reference to a task that keeps
        // rescheduling itself, leaving it unreachable and unstoppable. Cancel
        // first so it can never be orphaned.
        assert(maintenanceTask == nil, "Stack.start() called more than once")
        maintenanceTask?.cancel()

        // `scheduleRepeatedTask` wants a `@Sendable` body, and neither
        // `Reassembler` nor `ARPCache` is `Sendable` — deliberately, since both
        // are loop-confined and marking them `Sendable` would claim a guarantee
        // they do not offer to any other caller. Capturing them directly
        // therefore warns, and under Swift 6 language mode it is an error.
        //
        // `MaintenanceBox` carries them behind an `@unchecked Sendable`
        // conformance scoped to one `private` type, on the same reasoning as
        // `ShutdownBox` above: NIO runs a repeated task's body on the event loop
        // it was scheduled on and nowhere else, so the capture never crosses a
        // thread boundary and the confinement every other access in this package
        // relies on still holds. The box captures the two collaborators rather
        // than `self` for the same reason the old capture list did — capturing
        // `self` here would close `nic.handlers -> closure -> Stack` and leak the
        // whole graph once per sandbox.
        let box = MaintenanceBox(reassembler: reassembler, arpCache: arpCache)
        maintenanceTask = eventLoop.scheduleRepeatedTask(
            initialDelay: configuration.maintenanceInterval,
            delay: configuration.maintenanceInterval
        ) { _ in
            box.reassembler.reapExpired()
            box.arpCache.reapExpired()
        }
    }

    /// Tear down the stack: detach every handler and cancel the maintenance
    /// timer.
    ///
    /// Unlike everything else in this package, which relies entirely on
    /// loop confinement instead of locks and therefore must only ever be
    /// called from `eventLoop`, this — like `StackBootstrap.bind` — is
    /// documented as safe to call from any thread. It earns that by
    /// marshaling onto `eventLoop` before touching anything loop-confined,
    /// the same way `bind` does; see that method's own comment for why the
    /// `inEventLoop` check below is load-bearing rather than an
    /// optimisation. Skipping it — an unconditional `flatSubmit` — would
    /// hang any test that calls `shutdown()` and then drives an
    /// `EmbeddedEventLoop` itself without anything else pumping it, which
    /// this project's own test suite already does (see `StackTests`), and
    /// which has bitten this exact method once already: it used to clear
    /// the handler tables unconditionally, off-loop, before this fix.
    public func shutdown() -> EventLoopFuture<Void> {
        if eventLoop.inEventLoop {
            return shutdownOnLoop()
        } else {
            // `EventLoop.flatSubmit` requires an `@Sendable` closure — that
            // closure crosses to `eventLoop`'s thread, so the compiler must
            // see everything it captures as safe for that crossing. Capturing
            // `self` directly would need `Stack` itself to be `Sendable`,
            // which is deliberately not true (see the type's own doc
            // comment) — that conformance would extend past this one
            // marshal to every public, loop-confined property `Stack`
            // exposes. `ShutdownBox` captures `self` instead, behind an
            // `@unchecked Sendable` conformance scoped to this one `private`
            // type: it is safe for exactly the same reason `shutdownOnLoop`
            // itself is — the closure's body runs only once, only after
            // `flatSubmit` has actually handed control to `eventLoop`'s own
            // thread, matching the confinement guarantee every other
            // loop-confined access in this package already relies on.
            let box = ShutdownBox(stack: self)
            return eventLoop.flatSubmit { box.stack.shutdownOnLoop() }
        }
    }

    private func shutdownOnLoop() -> EventLoopFuture<Void> {
        // Enforce, rather than merely document, what `shutdown()`'s comment
        // above claims. Every line below touches loop-confined state that
        // the ingress path reads concurrently, and this package has no locks
        // — so if `shutdown()` ever stops marshaling, that must be a loud,
        // immediate failure on the first off-loop call rather than a data
        // race that shows up as corruption somewhere else much later. It is
        // also what lets a test detect the marshal's removal at all:
        // clearing the handler tables off-loop produces exactly the same
        // observable result as clearing them on-loop, so nothing about
        // `shutdown()`'s return value can tell the two apart. The same
        // `preconditionInEventLoop()` guards `LinkEndpoint`'s own
        // loop-confined entry points for the same reason.
        eventLoop.preconditionInEventLoop()

        // Defense in depth alongside the `[weak ipv4]` captures in `start()`:
        // those already keep `start()` from leaving a retain cycle, but
        // clearing the tables here also releases what the handler closures
        // captured — `arpResponder`, `transportDemuxer`, `allocator` — as
        // soon as the stack is deliberately shut down, rather than only when
        // every external reference to `nic` and `ipv4` themselves also goes
        // away, and it means a handler cannot fire at all once shutdown has
        // begun. The ingress path reads these same tables, so clearing them
        // off-loop — which is what happened here before this method
        // marshaled onto `eventLoop` — would be a data race, not just a
        // logic bug.
        nic.removeAllHandlers()
        ipv4.removeAllHandlers()

        guard let task = maintenanceTask else {
            return eventLoop.makeSucceededVoidFuture()
        }
        maintenanceTask = nil
        let promise = eventLoop.makePromise(of: Void.self)
        task.cancel(promise: promise)
        return promise.futureResult
    }

    deinit {
        // The maintenance timer reschedules itself through the event loop's own
        // queue, so it outlives every external reference to this Stack. Only
        // `cancel()` breaks that chain. A bare cancel is safe here: it does not
        // require being on the event loop, captures no `self`, and takes no
        // promise — so it cannot deadlock the way awaiting `shutdown()` would.
        maintenanceTask?.cancel()
    }
}

/// A one-shot, `Sendable` carrier for a `Stack` reference, used only to get
/// `shutdown()`'s marshaled closure past `EventLoop.flatSubmit`'s `@Sendable`
/// requirement without making the public `Stack` type itself `Sendable`.
///
/// `@unchecked`, not derived — `Stack` is not `Sendable` and never will be
/// (see its own doc comment) — but safe here specifically because this type
/// is `private` (so nothing outside `shutdown()` can construct one or treat
/// a `Stack` as `Sendable` through it), holds the reference only long enough
/// to hand it across a single `flatSubmit` call, and the closure that reads
/// `stack` back out only ever runs after `flatSubmit` has scheduled it onto
/// `eventLoop`'s own thread — the same confinement guarantee every other
/// loop-confined access in this package already relies on instead of a lock.
private struct ShutdownBox: @unchecked Sendable {
    let stack: Stack
}

/// The maintenance timer's two collaborators, carried across
/// `scheduleRepeatedTask`'s `@Sendable` requirement. Safe for exactly the reason
/// `ShutdownBox` is: NIO runs the body on the scheduling event loop and nowhere
/// else, so nothing here is ever touched off-loop. Scoped to this one `private`
/// type so the claim cannot leak to any other use of either collaborator.
private struct MaintenanceBox: @unchecked Sendable {
    let reassembler: Reassembler
    let arpCache: ARPCache
}
