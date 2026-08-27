import NIOCore

/// A TCP endpoint: the public face of everything under `Transport/TCP/`.
///
/// Loop-confined like the rest of this package -- every method must be called
/// on `stack.eventLoop`, and every callback fires there. No locks.
///
/// ## What this type is, and what the interface it was given implies
///
/// One endpoint owns a **table of connections**, keyed by the peer's address
/// and port, and each connection owns its own TCB, reassembly queue, retransmit
/// queue and pair of timers. That is gVisor's forwarder model, which this
/// stack already follows elsewhere (see `TCPStateMachine`'s note on why a RST
/// in SYN-RECEIVED deletes rather than returns to LISTEN): there is no
/// long-lived LISTEN block a connection falls back into, only one block per
/// accepted connection, created on demand when a SYN arrives.
///
/// The specified interface has no `accept()`, so a connection is *accepted* the
/// moment it is created and there is no queue of unaccepted ones for a backlog
/// to bound. `listen(backlog:)`'s bound is therefore applied to the connection
/// table as a whole, which is the only reading under which it bounds anything.
/// Two consequences follow from the same absence and are worth stating rather
/// than discovering:
///
/// - `send(_:)` has no way to name a connection, so it refuses to guess: it
///   throws unless exactly one connection exists.
/// - `close()` frees the four-tuple immediately, as its contract requires, so
///   it cannot linger to complete a four-way handshake. It sends a FIN on every
///   connection and then tears the endpoint down; a graceful half-close needs a
///   lingering state this interface has nowhere to express. The consequence is
///   that **TIME-WAIT is unreachable from here**, and it is spelled out at
///   `armTimeWaitTimer` rather than left to be discovered.
///
/// ## Egress goes through exactly one point
///
/// `emit(_:sequence:on:...)` is the **only** function in this type that puts a
/// frame on the wire, and `onEmit` is the observation hook on it. That is a
/// design requirement carried from the differential harness rather than a
/// tidiness preference: when the Go side of that harness was first built it
/// reported `emitted: []` on 100% of runs, because gVisor's forwarder
/// dispatches its handler on an untracked goroutine and the collector only saw
/// frames produced inline. ARP-only validation could never have caught it --
/// ARP is synchronous and TCP is not.
///
/// This type emits from two places: inline, while handling a delivered segment,
/// and later, from a retransmission or TIME-WAIT timer body. If those reached
/// the link by different routes, anything watching one would silently miss the
/// other, and every retransmission test would be comparing against nothing.
/// `everyFrameLeavesThroughOnePointIncludingOnesEmittedFromATimerBody` is what
/// holds it.
///
/// ## Bounds
///
/// Everything a guest can drive is bounded, and each bound refuses rather than
/// evicts -- the newcomer loses, exactly as `TCPReassembler` and `Sender` rule
/// for their own caps, because evicting hands a flooder a way to destroy a
/// legitimate flow's state for the price of one segment.
///
/// - The reassembly queue and the retransmit queue carry `TCPReassembler`'s and
///   `Sender`'s own caps.
/// - The connection table is bounded by the backlog. A SYN arriving when it is
///   full is **dropped** (not reset): a legitimate peer retransmits its SYN,
///   whereas a reset would turn a transient overload into a hard failure.
public final class TCPEndpoint: TransportEndpointDelegate {
    /// The largest backlog any caller may ask for. The application chooses the
    /// backlog, not the guest, so this is a guard rail rather than a defence --
    /// but a connection is not free, and a mistyped backlog should not be able
    /// to authorise an unbounded table.
    static let maximumBacklog = 1024

    /// Per-connection send-buffer bound, in `Sender`'s overhead-charged units.
    /// Matches `TCPReassembler.defaultMaximumBytes` so the two directions of a
    /// connection cost the same order of memory.
    static let sendBufferBytes = 256 * 1024

    /// The window this endpoint advertises, and the widest one it will ever
    /// advertise (`TCB.rcvWndMax`). 65535 is the largest a 16-bit window field
    /// can carry, and nothing here negotiates a window scale -- see the SYN-ACK
    /// option list in `emitSynAck` for why not.
    static let receiveWindowBytes = 65535

    /// RFC 9293 §3.7.1's default when a peer sends no MSS option. Deliberately
    /// the conservative 536 rather than an Ethernet-shaped guess: a peer that
    /// says nothing has told us nothing about the path.
    static let defaultPeerSegmentSize = 536

    private struct Peer: Hashable {
        let address: IPv4Address
        let port: UInt16
    }

    /// One connection's entire state. A class, so the timer bodies and the
    /// delivery path address the same object rather than copies -- `Receiver`
    /// wraps a reference and `Sender` holds a queue, and both are documented as
    /// "hold exactly one per connection".
    private final class Connection {
        let peer: Peer
        /// The address this connection answers from. Resolved once, because the
        /// TCP checksum's pseudo-header must be computed against the same
        /// source the IP header ends up carrying.
        let localAddress: IPv4Address
        let localPort: UInt16
        let timers: TCPTimers
        var tcb: TCB
        var receiver: Receiver
        var sender: Sender
        /// The segment size to cut: `min(what the peer advertised, what our own
        /// link can carry)`.
        var mss: Int
        /// `onClosed` fires once per connection. The peer's FIN and a reset are
        /// both "this stream is over", and a connection can meet both.
        var closedReported = false

        init(
            peer: Peer, localAddress: IPv4Address, localPort: UInt16, timers: TCPTimers, tcb: TCB,
            receiver: Receiver, sender: Sender, mss: Int
        ) {
            self.peer = peer
            self.localAddress = localAddress
            self.localPort = localPort
            self.timers = timers
            self.tcb = tcb
            self.receiver = receiver
            self.sender = sender
            self.mss = mss
        }
    }

    private let stack: Stack
    private let initialSequenceNumbers: any InitialSequenceNumbers
    private let allocator = ByteBufferAllocator()

    private var boundID: TransportEndpointID?
    private var isListening = false
    private var backlog = 0
    private var connections: [Peer: Connection] = [:]

    /// In-order bytes from the peer, oldest first.
    public var onData: ((ByteBuffer) -> Void)?
    /// A connection reached ESTABLISHED.
    public var onEstablished: (() -> Void)?
    /// A connection's stream is over: the peer's FIN was reached, or the block
    /// was deleted by a reset or by the end of the closing handshake. Fires at
    /// most once per connection.
    public var onClosed: (() -> Void)?

    /// Every frame this endpoint emits, header and payload, at the single
    /// egress point -- see the type's doc comment. Internal because `TCPHeader`
    /// is: the differential collector lives inside this module.
    var onEmit: ((TCPHeader, ByteBuffer) -> Void)?

    public convenience init(stack: Stack) {
        self.init(stack: stack, initialSequenceNumbers: stack.initialSequenceNumbers)
    }

    /// The ISS seam. Tests and differential vectors pass
    /// `FixedInitialSequenceNumbers`; production takes the stack's RFC 6528
    /// generator through the public initialiser above. Internal, so "use a
    /// constant ISS" never becomes part of this package's supported surface --
    /// see `InitialSequenceNumbers` for what a predictable one costs.
    init(stack: Stack, initialSequenceNumbers: any InitialSequenceNumbers) {
        self.stack = stack
        self.initialSequenceNumbers = initialSequenceNumbers
    }

    deinit {
        // `TransportDemuxer` holds delegates weakly, so a dropped endpoint stops
        // receiving on its own; this reclaims the table SLOT, without which the
        // port stays unbindable until something else happens to evict the
        // stale entry. The connections' `TCPTimers` cancel themselves in their
        // own `deinit`, which is why the timer bodies below must capture this
        // endpoint weakly: a strong capture would keep it -- and the whole
        // connection graph -- alive on the loop's queue until the deadline.
        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .tcp)
        }
    }

    // MARK: - Application interface

    /// Bind to a local address and port. Port 0 allocates an ephemeral one.
    public func bind(address: IPv4Address, port: UInt16) throws {
        guard boundID == nil else { throw StackError.invalidEndpointState }
        let localPort =
            port == 0
            ? try stack.transportDemuxer.allocateEphemeralPort(protocolNumber: .tcp, localAddress: address)
            : port
        let id = TransportEndpointID(localAddress: address, localPort: localPort, remoteAddress: .any, remotePort: 0)
        try stack.transportDemuxer.register(id, protocolNumber: .tcp, delegate: self)
        boundID = id
    }

    /// Accept connections, up to `backlog` of them at a time.
    ///
    /// See the type's doc comment for why the bound is on the table rather than
    /// on a queue of unaccepted connections, and for the refuse-never-evict
    /// policy when it binds.
    public func listen(backlog: Int) throws {
        guard boundID != nil, connections.isEmpty else { throw StackError.invalidEndpointState }
        self.backlog = max(1, min(backlog, Self.maximumBacklog))
        isListening = true
    }

    /// Active open. The endpoint must already be bound.
    public func connect(to address: IPv4Address, port: UInt16) throws {
        guard let boundID, !isListening, connections.isEmpty else { throw StackError.invalidEndpointState }

        // A wildcard bind has no address of its own to answer from, and the
        // checksum's pseudo-header must match the IP header's source exactly
        // (see `UDPEndpoint.send`, which documents the same hazard at length).
        // Resolve it here, before anything is serialized, rather than leaving
        // routing to pick one afterwards.
        let localAddress: IPv4Address
        if boundID.localAddress == .any {
            guard let route = stack.routes.lookup(destination: address, preferredSource: nil) else {
                throw StackError.noRoute
            }
            localAddress = route.source
        } else {
            localAddress = boundID.localAddress
        }

        let peer = Peer(address: address, port: port)
        let connection = makeConnection(
            peer: peer, localAddress: localAddress, localPort: boundID.localPort, peerSegmentSize: nil)
        // SYN-SENT: our SYN occupies one sequence number, so SND.NXT is ISS+1
        // and the only acknowledgement SYN-SENT will accept is ISS+1.
        connection.tcb.state = .synSent
        connection.tcb.sndNxt = connection.tcb.iss + 1
        connections[peer] = connection

        emit(
            [.syn], sequence: connection.tcb.iss, on: connection,
            options: [.maximumSegmentSize(UInt16(advertisedSegmentSize))],
            acknowledgement: SequenceNumber(0))
    }

    /// Queue bytes for transmission.
    ///
    /// Throws `.wouldBlock` when the send buffer is full, in which case
    /// **nothing was queued**: `Sender.write` refuses rather than truncating, so
    /// the caller can apply backpressure instead of silently losing a prefix of
    /// the stream.
    public func send(_ bytes: ByteBuffer) throws {
        // The interface carries no connection identifier, so an endpoint with
        // more than one connection refuses rather than picking one.
        guard connections.count <= 1 else { throw StackError.invalidEndpointState }
        guard let connection = connections.values.first else { throw StackError.notConnected }
        switch connection.tcb.state {
        case .established, .closeWait:
            break
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            throw StackError.notConnected
        }
        guard connection.sender.write(bytes) else { throw StackError.wouldBlock }
        transmit(on: connection)
        armRetransmitTimer(on: connection)
    }

    /// Close every connection and free the four-tuple.
    ///
    /// The port is rebindable the instant this returns. See the type's doc
    /// comment for why that forecloses a graceful half-close.
    public func close() {
        for connection in connections.values {
            for action in TCPStateMachine.close(on: &connection.tcb) where action == .sendFin {
                emitFin(on: connection)
            }
            connection.timers.cancelAll()
        }
        connections.removeAll()

        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .tcp)
        }
        boundID = nil
        isListening = false
        onData = nil
        onEstablished = nil
        onClosed = nil
    }

    /// How many connections this endpoint currently holds. Not `private`,
    /// because `@testable import` elevates `internal` and not `private`, and
    /// "the backlog refused it" is otherwise indistinguishable from "the
    /// segment was silently mis-parsed".
    var connectionCountForTesting: Int { connections.count }

    // MARK: - Ingress

    /// `payload` is the WHOLE TCP segment -- header, options and body -- not
    /// the body alone. `Stack`'s TCP handler has already parsed it once to
    /// validate the checksum and read the ports it demultiplexes on, but
    /// `TransportEndpointDelegate.deliver` has nowhere to carry a parsed
    /// header, so it is parsed again here. That is the price of leaving the
    /// delegate protocol as UDP shaped it, and it is paid on a buffer already
    /// known to be well formed.
    public func deliver(header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16) {
        var packet = PacketBuffer(received: payload)
        guard let tcp = TCPHeader.parse(&packet, header: header) else { return }
        let segment = TCPSegment(header: tcp, payload: packet.payload)
        let peer = Peer(address: header.source, port: remotePort)

        if let connection = connections[peer] {
            // The peer's MSS arrives on its SYN, which for an active open is the
            // SYN-ACK -- after the connection was built. Adopting it is only
            // safe while nothing is queued or in flight, which SYN-SENT
            // guarantees.
            if connection.tcb.state == .synSent, tcp.flags.contains(.syn) {
                adoptPeerSegmentSize(from: tcp, on: connection)
            }
            process(segment: segment, on: connection)
            return
        }

        // A bare SYN opens a connection; anything else has nothing to attach to.
        // Pre-filtering here rather than letting the LISTEN handler answer keeps
        // a half-built block from being left in the table for a segment that was
        // never going to open anything -- the LISTEN handler's answer to a
        // SYN|ACK and this path's answer to one are the same reset either way.
        let opensAConnection =
            isListening && tcp.flags.contains(.syn) && !tcp.flags.contains(.ack) && !tcp.flags.contains(.rst)
        guard opensAConnection else {
            respondAsClosed(to: segment, localAddress: header.destination, localPort: localPort, peer: peer)
            return
        }

        // The backlog binds: refuse, and disturb nothing already admitted. A
        // legitimate peer retransmits its SYN; a flooder gets no purchase on
        // anyone else's connection.
        guard connections.count < backlog else { return }

        let connection = makeConnection(
            peer: peer, localAddress: header.destination, localPort: localPort,
            peerSegmentSize: peerSegmentSize(in: tcp))
        connections[peer] = connection
        process(segment: segment, on: connection)
    }

    /// Drive one segment through the state machine and act on what it returns.
    private func process(segment: TCPSegment, on connection: Connection) {
        let stateBefore = connection.tcb.state
        let actions = TCPStateMachine.receive(
            segment: segment, on: &connection.tcb, receiver: &connection.receiver, sender: &connection.sender)

        var wantsAck = false
        var deleted = false
        for action in actions {
            switch action {
            case .sendSynAck:
                emitSynAck(on: connection)
            case .sendAck:
                wantsAck = true
            case .sendRst(let sequence, let ack):
                emit(
                    ack == nil ? [.rst] : [.rst, .ack], sequence: sequence, on: connection,
                    acknowledgement: ack ?? SequenceNumber(0), window: 0)
            case .sendFin:
                emitFin(on: connection)
            case .deliver(let buffer):
                onData?(buffer)
            case .startTimeWait:
                armTimeWaitTimer(on: connection)
            case .deleteTCB:
                deleted = true
            case .none:
                break
            }
        }

        // `onData` is application code and may have closed this endpoint out
        // from under us. Everything below touches connection state that
        // `close()` has already torn down in that case.
        guard connections[connection.peer] === connection else { return }

        if stateBefore != .established, connection.tcb.state == .established {
            onEstablished?()
        }

        if deleted {
            remove(connection)
            reportClosed(connection)
            return
        }

        // Data the acknowledgement just unblocked, and any pending fast
        // retransmission. Every segment this returns already carries the ACK
        // bit and the current RCV.NXT, so a bare acknowledgement alongside them
        // would be a second frame saying the same thing.
        let transmitted = transmit(on: connection)
        if wantsAck, transmitted == 0 {
            emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
        }
        armRetransmitTimer(on: connection)

        switch connection.tcb.state {
        case .closeWait, .closing, .lastAck, .timeWait, .closed:
            // The peer's FIN is past: no more data will arrive on this stream.
            reportClosed(connection)
        case .listen, .synSent, .synReceived, .established, .finWait1, .finWait2:
            break
        }
    }

    /// RFC 9293 §3.10.7.1, for a segment that matched no connection here.
    ///
    /// The state machine owns the choice between the RFC's two reset forms --
    /// the ACK-bit-clear one that reuses SEG.ACK, and the ACK-bearing one for a
    /// segment that carried no acknowledgement to reuse -- and getting it wrong
    /// is not cosmetic: a peer discards a reset it cannot validate, which a
    /// guest waiting on `connect()` experiences as a hang rather than a
    /// refusal.
    private func respondAsClosed(
        to segment: TCPSegment, localAddress: IPv4Address, localPort: UInt16, peer: Peer
    ) {
        for action in TCPStateMachine.closedSegmentArrives(segment: segment) {
            guard case .sendRst(let sequence, let ack) = action else { continue }
            let header = TCPHeader(
                sourcePort: localPort,
                destinationPort: peer.port,
                sequence: sequence,
                acknowledgement: ack ?? SequenceNumber(0),
                dataOffset: 5,
                flags: ack == nil ? [.rst] : [.rst, .ack],
                window: 0,
                checksum: 0,
                urgentPointer: 0,
                options: [])
            emit(header, payload: ByteBuffer(), from: localAddress, to: peer.address)
        }
    }

    // MARK: - Egress: one point, and the shapes that go through it

    /// **The single egress point.** Nothing else in this type reaches the wire.
    ///
    /// Both overloads funnel here, so a frame produced inline while handling a
    /// segment and a frame produced later inside a timer body are observed by
    /// the same `onEmit`. See the type's doc comment for the failure this
    /// prevents.
    private func emit(_ header: TCPHeader, payload: ByteBuffer, from source: IPv4Address, to destination: IPv4Address) {
        onEmit?(header, payload)
        // A send can legitimately fail -- the next hop's link address may not be
        // resolved yet, in which case `IPv4Protocol.send` has just emitted an
        // ARP request and the retransmission timer will bring this segment back.
        // Failing loudly here would turn an ordinary first-packet ARP round trip
        // into a connection error.
        try? TCPWire.send(header, payload: payload, from: source, to: destination, via: stack.ipv4, allocator: allocator)
    }

    private func emit(
        _ flags: TCPFlags, sequence: SequenceNumber, on connection: Connection,
        payload: ByteBuffer = ByteBuffer(), options: [TCPOption] = [],
        acknowledgement: SequenceNumber? = nil, window: UInt16? = nil
    ) {
        let header = TCPHeader(
            sourcePort: connection.localPort,
            destinationPort: connection.peer.port,
            sequence: sequence,
            acknowledgement: acknowledgement ?? connection.tcb.rcvNxt,
            dataOffset: 5,
            flags: flags,
            window: window ?? advertisedWindow(of: connection),
            checksum: 0,
            urgentPointer: 0,
            options: options)
        emit(header, payload: payload, from: connection.localAddress, to: connection.peer.address)
    }

    /// The SYN-ACK, and the one place this stack decides which options it
    /// advertises.
    ///
    /// **MSS only.** The codec can emit `windowScale` and `sackPermitted`, and
    /// neither belongs here:
    ///
    /// - A window scale would make us lie about our window. Nothing in this
    ///   stack applies a scale, so advertising `wscale 7` alongside a 65535
    ///   window promises 8 MB against a reassembler that caps at 256 KiB. The
    ///   peer fills the pipe it was promised, most of it is dropped, and it
    ///   presents as packet loss with no error anywhere. RFC 7323 §2.2 makes
    ///   omission the clean fix: scaling is used only if BOTH sides send the
    ///   option, so leaving it out disables it in both directions.
    /// - `sackPermitted` would invite the peer to spend header space on SACK
    ///   blocks this stack discards, and RFC 2018 expects a receiver that sent
    ///   it to actually send SACK blocks back.
    ///
    /// MSS stays, because it is the one option this stack acts on.
    private func emitSynAck(on connection: Connection) {
        emit(
            [.syn, .ack], sequence: connection.tcb.iss, on: connection,
            options: [.maximumSegmentSize(UInt16(advertisedSegmentSize))])
    }

    /// Our FIN. `TCPStateMachine.close(on:)` has already bumped SND.NXT to
    /// reserve the sequence number it consumes, so the FIN occupies SND.NXT - 1.
    private func emitFin(on connection: Connection) {
        emit([.fin, .ack], sequence: connection.tcb.sndNxt + (-1), on: connection)
    }

    /// Put whatever the sender has ready on the wire: a pending fast
    /// retransmission first, then as much new data as `min(cwnd, SND.WND)`
    /// allows. Returns how many segments went out.
    ///
    /// `segmentsToTransmit` advances SND.NXT over what it returns, so
    /// everything it returns must be sent.
    @discardableResult
    private func transmit(on connection: Connection) -> Int {
        let segments = connection.sender.segmentsToTransmit(tcb: &connection.tcb, mss: connection.mss)
        for segment in segments {
            emit(segment.flags.union(.ack), sequence: segment.sequence, on: connection, payload: segment.payload)
        }
        return segments.count
    }

    // MARK: - Timers

    /// Bring the retransmission timer into line with what the sender says.
    ///
    /// The sender owns *when*; this owns the timer. Both closures below capture
    /// `[weak self]` and re-find the connection by key rather than capturing it:
    /// `TCPTimers`' bodies run unconditionally even when their owner is gone
    /// (Task 13 chose that deliberately, so a broken `deinit` is observable
    /// rather than silent), so a strong capture here would keep the whole
    /// connection graph alive on the loop's queue until the deadline and then
    /// drive a connection that no longer exists.
    private func armRetransmitTimer(on connection: Connection) {
        guard let deadline = connection.sender.retransmitDeadline else {
            connection.timers.cancelRetransmit()
            return
        }
        let now = stack.clock.now()
        let delay = deadline > now ? deadline - now : .nanoseconds(0)
        let peer = connection.peer
        connection.timers.scheduleRetransmit(after: delay) { [weak self] in
            self?.retransmitTimerFired(peer: peer)
        }
    }

    private func retransmitTimerFired(peer: Peer) {
        guard let connection = connections[peer] else { return }
        if let segment = connection.sender.retransmitTimerFired(tcb: &connection.tcb) {
            emit(segment.flags.union(.ack), sequence: segment.sequence, on: connection, payload: segment.payload)
        }
        armRetransmitTimer(on: connection)
    }

    /// **Unreachable today, and it is worth saying so rather than letting this
    /// read as live code.**
    ///
    /// TIME-WAIT is only entered by the side that closes FIRST: FIN-WAIT-1 or
    /// FIN-WAIT-2 plus the peer's FIN, or CLOSING plus its acknowledgement. All
    /// three require this endpoint to still be receiving after `close()`, and
    /// `close()` frees the four-tuple as its contract requires -- after which
    /// nothing is delivered here and no connection can leave FIN-WAIT-1. So
    /// `.startTimeWait` never arrives, and the `[weak self]` below is
    /// **unfalsifiable**: making it strong leaves the whole suite green, which
    /// was measured rather than assumed.
    ///
    /// It is written correctly anyway, because the reachability is the
    /// interface's, not the state machine's -- `TCPStateMachine` returns the
    /// action in three places, and the day this endpoint can linger past
    /// `close()` it will arrive. Reaching it needs, in order: registering each
    /// closing connection under its own exact four-tuple as the bind key is
    /// released (`TransportDemuxer.deliver` already prefers the specific key,
    /// so the port stays rebindable), and retransmitting our FIN, without which
    /// a connection whose FIN is lost pins the endpoint forever. Neither is
    /// small, and neither belongs in a wiring task.
    private func armTimeWaitTimer(on connection: Connection) {
        let peer = connection.peer
        connection.timers.startTimeWait { [weak self] in
            guard let self, let connection = self.connections[peer] else { return }
            self.remove(connection)
        }
    }

    // MARK: - Connection bookkeeping

    private func makeConnection(
        peer: Peer, localAddress: IPv4Address, localPort: UInt16, peerSegmentSize: Int?
    ) -> Connection {
        let iss = initialSequenceNumbers.initialSendSequence(
            localAddress: localAddress, localPort: localPort,
            remoteAddress: peer.address, remotePort: peer.port)
        let mss = negotiatedSegmentSize(peerSegmentSize)
        return Connection(
            peer: peer,
            localAddress: localAddress,
            localPort: localPort,
            timers: TCPTimers(eventLoop: stack.eventLoop, clock: stack.clock),
            // LISTEN, with RCV.NXT and IRS still unset: the state machine
            // initialises both from the peer's ISS when the SYN is processed,
            // and it is the only writer of them during the handshake.
            tcb: TCB(
                state: .listen,
                sndUna: iss,
                sndNxt: iss,
                sndWnd: 0,
                sndWl1: SequenceNumber(0),
                sndWl2: SequenceNumber(0),
                iss: iss,
                rcvNxt: SequenceNumber(0),
                rcvWnd: Self.receiveWindowBytes,
                irs: SequenceNumber(0)),
            receiver: Receiver(reassembler: TCPReassembler()),
            sender: Sender(
                congestionControl: Reno(maximumSegmentSize: mss), clock: stack.clock,
                maximumBufferedBytes: Self.sendBufferBytes),
            mss: mss)
    }

    private func remove(_ connection: Connection) {
        connection.timers.cancelAll()
        connections.removeValue(forKey: connection.peer)
    }

    private func reportClosed(_ connection: Connection) {
        guard !connection.closedReported else { return }
        connection.closedReported = true
        onClosed?()
    }

    /// The MSS we advertise: what one link frame can carry after the IPv4 and
    /// TCP headers. Floored at RFC 9293's 536 so a pathologically small link
    /// MTU cannot produce a segment size no peer will accept.
    private var advertisedSegmentSize: Int {
        max(Self.defaultPeerSegmentSize, Int(stack.nic.link.mtu) - IPv4Header.minimumLength - TCPHeader.minimumLength)
    }

    private func peerSegmentSize(in header: TCPHeader) -> Int? {
        for option in header.options {
            if case .maximumSegmentSize(let value) = option { return Int(value) }
        }
        return nil
    }

    /// What we will actually cut: never more than the peer will accept, never
    /// more than our own link can carry, and never zero -- a zero segment size
    /// comes straight off a peer-supplied option and would otherwise wedge the
    /// connection permanently.
    private func negotiatedSegmentSize(_ peerSegmentSize: Int?) -> Int {
        max(1, min(peerSegmentSize ?? Self.defaultPeerSegmentSize, advertisedSegmentSize))
    }

    /// Only safe in SYN-SENT, where nothing is queued and nothing is in flight:
    /// `Reno` takes its SMSS at initialisation, so adopting a negotiated MSS
    /// means rebuilding the sender, and rebuilding one that held a retransmit
    /// queue would drop it.
    private func adoptPeerSegmentSize(from header: TCPHeader, on connection: Connection) {
        guard let advertised = peerSegmentSize(in: header) else { return }
        connection.mss = negotiatedSegmentSize(advertised)
        connection.sender = Sender(
            congestionControl: Reno(maximumSegmentSize: connection.mss), clock: stack.clock,
            maximumBufferedBytes: Self.sendBufferBytes)
    }

    /// RCV.WND for the wire. `Receiver` owns the figure and has already written
    /// it into the TCB; this only clamps it to the field, which cannot be
    /// exceeded with no window scale negotiated.
    private func advertisedWindow(of connection: Connection) -> UInt16 {
        UInt16(min(max(0, connection.tcb.rcvWnd), Int(UInt16.max)))
    }
}

/// Serializes one TCP segment and hands it to the IPv4 layer.
///
/// Shared by `TCPEndpoint`'s single egress point and by `Stack`'s TCP handler,
/// which answers a segment for a port nobody is listening on. Two copies of
/// "build a TCP header and send it" would be two places for the pseudo-header
/// source address to drift from the one that ends up in the IP header, which is
/// the defect `UDPEndpoint.send` already documents at length.
enum TCPWire {
    /// The checksum's pseudo-header must be computed against the SAME source
    /// address the IP header ends up carrying, so `source` is passed to both
    /// `serialize` and `ipv4.send` — never resolved twice.
    static func send(
        _ header: TCPHeader, payload: ByteBuffer, from source: IPv4Address, to destination: IPv4Address,
        via ipv4: IPv4Protocol, allocator: ByteBufferAllocator
    ) throws {
        let segment = header.serialize(payload: payload, source: source, destination: destination, allocator: allocator)
        try ipv4.send(payload: segment, to: destination, from: source, protocolNumber: .tcp)
    }

    /// RFC 9293 §3.10.7.1's refusal, for a segment that reached a port with no
    /// endpoint behind it. `sequence`/`ack` come from
    /// `TCPStateMachine.closedSegmentArrives`, which is where the choice between
    /// the two RST forms is made and documented.
    static func sendReset(
        sequence: SequenceNumber, ack: SequenceNumber?, sourcePort: UInt16, destinationPort: UInt16,
        from source: IPv4Address, to destination: IPv4Address, via ipv4: IPv4Protocol, allocator: ByteBufferAllocator
    ) {
        let header = TCPHeader(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            sequence: sequence,
            acknowledgement: ack ?? SequenceNumber(0),
            dataOffset: 5,
            flags: ack == nil ? [.rst] : [.rst, .ack],
            window: 0,
            checksum: 0,
            urgentPointer: 0,
            options: [])
        try? send(header, payload: ByteBuffer(), from: source, to: destination, via: ipv4, allocator: allocator)
    }
}
