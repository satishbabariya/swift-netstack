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
/// - `close()` releases the **listening** key immediately, as its contract
///   requires, but a **connected** four-tuple is held until that connection is
///   finished — through FIN retransmission, and through TIME-WAIT. Releasing it
///   at `close()` is what made TIME-WAIT unreachable in this type's first
///   version: the state without the protection. See `close()`.
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
/// - TIME-WAIT blocks are bounded by `maximumTimeWaitConnections`, and this one
///   evicts oldest-first rather than refusing, because a connection that has
///   already closed cannot be refused. See that constant.
/// - Our own FIN is retransmitted at most `maximumFinTransmissions` times before
///   the connection is given up, so a peer that never acknowledges it cannot pin
///   a block, a registration and a timer for the life of the process.
/// - **The zero-window probe is the one thing here with no count bound at all**,
///   and that is required rather than overlooked: RFC 1122 §4.2.2.17 makes
///   "Sender timeout OK conn with zero wind" a MUST NOT. What bounds it is the
///   interval (sixty seconds in the steady state) and the two resources a
///   persisting connection holds, both of which are capped above — the block, by
///   the backlog, and the send queue, by `sendBufferBytes`.
///   `Sender.persistTimerFired` states the whole argument, including what RFC
///   6429 §3 says the real cost of a persisting connection is.
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
    /// The window advertised in the handshake, and the widest one expressible
    /// there. RFC 7323 §2.2 forbids scaling the window in a SYN or SYN-ACK, so
    /// whatever scale is negotiated *on* the handshake cannot be used *by* it —
    /// 65535 is the ceiling for those two segments no matter what.
    static let receiveWindowBytes = 65535

    /// The widest window this connection may grow to once scaling is in effect.
    ///
    /// Bounded by what the reassembler can actually hold, not by what the field
    /// can express. Advertising more than the queue can take is the same defect
    /// the four-step ordering below exists to prevent, arriving by another route:
    /// the peer fills the pipe it was promised and most of it is dropped.
    static let maximumReceiveWindowBytes = TCPReassembler.defaultMaximumBytes

    /// The smallest shift that lets `maximumReceiveWindowBytes` fit the header's
    /// 16-bit field. **Derived, not written down**: a literal would drift the
    /// moment someone changed the cap, and the two silently disagreeing is how
    /// a stack ends up advertising a window it cannot honour.
    ///
    /// At the current 256 KiB cap this is 3. Note how close the boundary is —
    /// `65535 << 2` is 262,140, four bytes short of 262,144 — which is the other
    /// reason not to hardcode it.
    static let derivedWindowScale: UInt8 = {
        var shift: UInt8 = 0
        while maximumReceiveWindowBytes >> Int(shift) > Int(UInt16.max) { shift += 1 }
        return shift
    }()

    /// The Window Scale shift this stack puts in its own SYN and SYN-ACK, or
    /// `nil` for "send no Window Scale option". **`nil`, deliberately, and this
    /// is the single input that turns window scaling on.**
    ///
    /// It reaches every connection through `TCB.windowScaleToOffer`, and
    /// `TCB.negotiateWindowScale(fromSynOptions:)` is the rule it feeds: RFC
    /// 7323 §2.2 uses scaling only if *both* sides send the option, so a `nil`
    /// here holds `sndWindScale` and `rcvWindScale` at zero on every connection
    /// no matter what the peer offers.
    ///
    /// **Do not make this non-`nil` before the shifts are actually applied.**
    /// The four steps are ordered: record the negotiated shifts, apply
    /// `sndWindScale` to SND.WND (the two non-SYN sites in `TCPStateMachine`),
    /// apply `rcvWindScale` to the window we advertise
    /// (`Receiver.advertisedWindow` and `advertisedWindow(of:)` below), and only
    /// then send the option. Reversing that order means advertising `win 65535`
    /// *meaning up to 1 GB* against a reassembler that caps at 256 KiB: the peer
    /// fills the pipe it was promised, most of it is dropped, and it presents as
    /// packet loss with no error raised anywhere. See `emitSynAck`.
    ///
    /// Flipping it is not the whole of that last step either — the option has to
    /// be added to the SYN in `connect` and to the SYN-ACK in `emitSynAck`, and
    /// the SYN-ACK's copy must be gated on `tcb.peerOfferedWindowScale`. RFC
    /// 7323 §2.2: "If a Window Scale option was received in the initial `<SYN>`
    /// segment, then this option MAY be sent in the `<SYN,ACK>` segment." See
    /// `TCB.peerOfferedWindowScale` for how exactly to read that clause.
    static let windowScaleToOffer: UInt8? = derivedWindowScale

    /// Whether this stack offers RFC 7323 Timestamps.
    ///
    /// Turned on only once the echo exists: a peer that sees the option in our
    /// SYN will stamp every segment it sends and expect its own values back, and
    /// a stack that offered without echoing would break the peer's RTTM while
    /// looking, on the wire, like it had agreed to support it. Same ordering as
    /// the window scale, for the same reason.
    static let offersTimestamps = true

    /// Whether this stack puts SACK-Permitted in its SYN and SYN-ACK.
    ///
    /// Reporting and using are separate, and this is the reporting half: with
    /// it on, a peer learns exactly which ranges arrived out of order, which is
    /// what lets its sender retransmit the hole rather than everything after it.
    static let offersSelectiveAcknowledgement = true

    /// RFC 1122 §4.2.3.6's keep-alive, and it is **off unless a caller turns it
    /// on**, which the RFC states as a MUST.
    ///
    /// The reason is not politeness. A keep-alive probe on an idle connection
    /// can tear down a connection that is merely quiet -- a path outage shorter
    /// than the probe budget kills a session that would have recovered -- and it
    /// costs traffic on links that charge for it. The RFC's own words: "TCP
    /// keep-alives are an optional TCP mechanism, and it is not required".
    ///
    /// A gateway is one of the places it earns its cost. A guest that goes away
    /// without closing leaves an endpoint and a host socket held for as long as
    /// the connection is nominally established, and nothing else ever notices:
    /// there is no data to retransmit, so the retransmit timer never runs.
    public var keepAlive: KeepAliveConfiguration?

    /// Whether new connections use RFC 8985 RACK alongside RFC 6675's
    /// scoreboard.
    ///
    /// Off by default for the same reason CUBIC is: the differential harness
    /// compares this stack against gVisor with gVisor's own RACK disabled, so
    /// turning it on here would compare one stack's time-based loss detection
    /// against another stack's absence of it. What stands behind RACK is
    /// `RackTests`, against RFC 8985's own rules.
    public var rack = false

    /// Which congestion-control algorithm new connections on this endpoint use.
    ///
    /// Reno by default: it is the one the differential harness validates against
    /// gVisor. Changing it after a connection exists does not affect that
    /// connection -- the algorithm is chosen when the sender is built, and
    /// rebuilding one that held a retransmit queue would drop it.
    public var congestionControl: CongestionControlAlgorithm = .reno

    /// How a keep-alive behaves once enabled.
    public struct KeepAliveConfiguration: Sendable {
        /// How long a connection must be idle before the first probe. RFC 1122
        /// §4.2.3.6 requires this to default to no less than two hours.
        public var idle: TimeAmount
        /// The gap between probes once they start.
        public var interval: TimeAmount
        /// How many unanswered probes end the connection.
        public var count: Int

        public init(idle: TimeAmount = .hours(2), interval: TimeAmount = .seconds(75), count: Int = 9) {
            self.idle = idle
            self.interval = interval
            self.count = max(1, count)
        }
    }

    /// What the Timestamps option costs a data segment, in bytes.
    ///
    /// Ten bytes of option plus two of padding to a four-byte boundary. It comes
    /// out of the payload, not out of thin air: a segment built to the
    /// unadjusted MSS and then given twelve more bytes of options exceeds the
    /// path MTU the MSS was derived from, and the result is either fragmentation
    /// or a drop. Charged in `negotiatedSegmentSize`.
    static let timestampOptionBytes = 12

    /// RFC 9293 §3.8.6.3's ceiling on a delayed acknowledgement: "an ACK should
    /// not be excessively delayed; in particular, the delay MUST be less than
    /// 0.5 seconds". Taken at the limit rather than under it, because the only
    /// thing a shorter delay buys is more frames — and the timer is the fallback
    /// for a flow the every-second-segment rule never fires on.
    static let delayedAckTimeout = TimeAmount.milliseconds(500)

    // Not implemented here, and recorded because it was measured rather than
    // guessed: gVisor answers the FIRST full-sized segment after a handshake at
    // once, where "every second full-sized segment" alone would hold it. Linux
    // calls that quick-ACK mode; RFC 9293 neither requires nor forbids it, and
    // the argument for it is real — a delayed acknowledgement at the start of a
    // connection delays the sender's congestion window opening, and slow start
    // is when the window most needs to move.
    //
    // It belongs in its own change. Adding it here was tried and reverted: it
    // invalidated five expectations that had just been re-derived for the delay,
    // which is how one justified change turns into churn that obscures both. See
    // `differential/README.md`.

    /// RFC 9293 §3.7.1's default when a peer sends no MSS option. Deliberately
    /// the conservative 536 rather than an Ethernet-shaped guess: a peer that
    /// says nothing has told us nothing about the path.
    static let defaultPeerSegmentSize = 536

    /// How many connections may sit in TIME-WAIT at once.
    ///
    /// A TIME-WAIT block is guest-reachable state that outlives the connection
    /// by 2·MSL — sixty seconds here — and a guest that opens and closes in a
    /// loop accumulates one per connection. Everything a guest can drive in this
    /// stack is capped, so this is too.
    ///
    /// **The policy is oldest-first eviction, and it is the opposite of the
    /// refuse-the-newcomer rule `TCPReassembler` and `Sender` follow.** Those
    /// can refuse, because a refused segment is retransmitted and nothing is
    /// lost. A connection that has reached TIME-WAIT cannot be refused — it has
    /// already closed — so the only question is which block to give up, and the
    /// oldest is the one whose late segments have had the longest to drain and
    /// is therefore worth the least. That is also what Linux does.
    static let defaultMaximumTimeWaitConnections = 256

    /// How many times our FIN is retransmitted before the connection is given
    /// up. RFC 1122 §4.2.3.5's R2, in retransmissions rather than in seconds:
    /// with the RTO doubling from one second and capped at
    /// `RTTEstimator.maximumTimeout`, eight attempts is about three minutes.
    ///
    /// A bound is required, not tidiness: a peer that never acknowledges our FIN
    /// would otherwise pin the connection, its four-tuple registration and its
    /// timer for the life of the process.
    static let maximumFinTransmissions = 8

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
        /// `onPeerFinished` likewise. The peer can FIN once, but the state that
        /// says so is reached again by every segment that arrives afterwards.
        var peerFinishReported = false
        /// A FIN this side has asked for and cannot send yet, because the
        /// sender still holds payload the window has not let out. The FIN's
        /// sequence number is `snd.nxt`, so sending it now would place it on
        /// top of bytes that have not gone.
        var finPending = false

        /// When our half of the handshake went out and how many times, so that
        /// the round trip can be sampled once it completes -- and refused when
        /// Karn says it is ambiguous. Defaulted rather than passed to `init`,
        /// because every connection starts with nothing recorded. See
        /// `HandshakeRTT`.
        var handshake = HandshakeRTT()

        /// The four-tuple this connection holds in the demuxer in its own right,
        /// once `close()` has released the endpoint's listening key. Nil while
        /// the listening key still covers it. See `close()`.
        var registeredID: TransportEndpointID?

        /// The sequence number our FIN occupies, once one has been sent.
        /// `Sender` deliberately models no control flags, so the FIN's
        /// retransmission is this endpoint's to drive; see
        /// `finNeedsRetransmission`.
        var finSequence: SequenceNumber?

        /// Whether an acknowledgement is being held under RFC 9293 §3.8.6.3.
        ///
        /// Checked inside the timer body as well as here, because a segment that
        /// arrives before the timer fires can send the acknowledgement early —
        /// and then the timer must not send a second one saying the same thing.
        var delayedAckPending = false
        /// Unanswered keep-alive probes since the last sign of life.
        var keepAliveProbes = 0
        /// When our FIN last went out, and whether it has been probed. See
        /// `finProbeDeadline`.
        var finSentAt: NIODeadline?
        var finProbeSent = false

        /// New in-order bytes received since the last acknowledgement went out.
        ///
        /// RFC 9293 §3.8.6.3 asks for an acknowledgement "for at least every
        /// second full-sized segment **or 2*RMSS bytes** of new data", and the
        /// byte form is the one to implement: counting *segments* would answer
        /// two one-byte segments as eagerly as two full ones, which is exactly
        /// the interactive traffic delayed acknowledgements exist to coalesce.
        /// Bytes make the trigger proportional to what the peer actually sent.
        ///
        /// Reset by every acknowledgement however it was triggered, so the count
        /// is always "since the peer last heard from us" rather than "since the
        /// last timer".
        var unacknowledgedBytesSinceAck = 0

        /// Bytes delivered in order and not yet taken by the application.
        ///
        /// **This is what makes the advertised window mean something.** Before
        /// it existed, `onData` was called synchronously and the reassembler's
        /// space was freed in the same pass, so the window described a buffer
        /// that never held anything — honest in the narrow sense that the stack
        /// really did have all that room, and useless in the sense that an
        /// application which ignored `onData` had its data acknowledged and
        /// dropped. The peer was told the bytes arrived; nobody had them.
        ///
        /// Held as a single `ByteBuffer` rather than a queue of them: the
        /// application reads a byte count, not a segment list, and the segment
        /// boundaries carry no meaning above the stack.
        var receiveBuffer = ByteBuffer()

        /// True while `process` is running for this connection.
        ///
        /// A read that happens inside `onData` is a read the arriving segment
        /// caused, and that segment is usually about to be acknowledged anyway.
        /// Emitting a window update there produces two frames carrying the same
        /// acknowledgement number and the same window — the second saying
        /// nothing the first did not. The update waits and rides the
        /// acknowledgement instead, which is what `read`'s own comment says it
        /// should do.
        var inProcessPass = false

        /// A window update that `read` deferred because it happened inside a
        /// processing pass. Cleared by whatever acknowledgement carries it.
        var windowUpdatePending = false

        /// When the FIN should next be retransmitted. An **absolute** deadline
        /// rather than a delay, so that re-arming the timer on every arriving
        /// segment cannot push it further out -- a peer that sends anything at
        /// all would otherwise defer our FIN indefinitely.
        var finDeadline: NIODeadline?
        var finTimeout: TimeAmount = RTTEstimator.minimumTimeout
        var finTransmissions = 0

        /// The order in which this connection entered TIME-WAIT, or nil if it
        /// has not. An ordinary counter, so that eviction can pick the oldest
        /// with an `Int` comparison and never a `SequenceNumber` one.
        var timeWaitOrder: UInt64?

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

    private let maximumTimeWaitConnections: Int
    private let delayedAckTimeout: TimeAmount
    private let nagleDisabled: Bool

    private var boundID: TransportEndpointID?
    private var isListening = false
    private var sendSideClosed = false
    private var backlog = 0
    private var connections: [Peer: Connection] = [:]
    /// Hands out `Connection.timeWaitOrder`. Monotonic, so "oldest" is a fact
    /// rather than a guess about dictionary order.
    private var timeWaitSequence: UInt64 = 0

    /// In-order bytes from the peer, oldest first.
    /// Called when in-order bytes have arrived and `read` will return some.
    ///
    /// **A readiness signal, not a delivery**, and the change is deliberate. It
    /// used to carry the bytes, which meant an application that ignored it had
    /// them acknowledged to the peer and then dropped — the stack promising
    /// delivery it had not made. Now the bytes wait in the connection's receive
    /// buffer, the advertised window shrinks by what is held, and an application
    /// that never reads stops the peer rather than losing its data.
    ///
    /// Fired once per batch of arriving segments, not once per segment: an
    /// application reads whatever is there, and a second signal for the same
    /// readiness only costs it a wasted call.
    public var onData: (() -> Void)?

    /// Fired when a write that was previously refused could now be retried.
    ///
    /// ## Why this exists, and why it is not "the buffer has room"
    ///
    /// `send` refuses rather than truncating, which leaves the caller holding
    /// the bytes. Something has to tell it to try again. Before this signal
    /// the only thing that did was the *source's* next `onData` — fine while
    /// the source keeps sending, and a permanent stall the moment it stops.
    /// `aSpliceDeliversItsHeldChunkOnceTheFarSideDrains` is that stall: the far
    /// side drained, had room, and nothing asked it again.
    ///
    /// It fires only after a refusal, not whenever space is freed. An
    /// acknowledgement frees send-buffer space on almost every segment, so the
    /// unconditional form would signal constantly to tell nobody anything. The
    /// refusal is what creates a caller waiting to hear.
    public var onWritable: (() -> Void)?

    /// Take up to `maximum` bytes of in-order data, and reopen the window by
    /// what was taken.
    ///
    /// Returns an empty buffer when nothing has arrived. The window update this
    /// causes is not sent here — it rides the next acknowledgement, or the
    /// window-update path if the window was closed, which is the same rule a
    /// peer's own reads follow.
    @discardableResult
    public func read(maximum: Int = Int.max) -> ByteBuffer {
        guard let connection = connections.values.first else { return ByteBuffer() }
        let count = min(maximum, connection.receiveBuffer.readableBytes)
        guard count > 0 else { return ByteBuffer() }
        let taken = connection.receiveBuffer.readSlice(length: count) ?? ByteBuffer()
        connection.receiveBuffer.discardReadBytes()
        connection.tcb.setHeldBytes(connection.receiveBuffer.readableBytes)
        // Taking bytes reopens the window, and the peer has to be told — but not
        // on every read.
        //
        // RFC 1122 §4.2.3.3's silly-window-syndrome avoidance, from the receiver
        // side: a window update is worth a segment only when it opens the window
        // by something worth sending into. Announcing every byte as it is read
        // produces one frame per read and invites the peer to answer each with a
        // one-byte segment, which is the syndrome itself — the connection ends up
        // carrying more header than data.
        //
        // The threshold is the conventional one: two segments, or half the
        // buffer, whichever is smaller. Below it the update rides the next
        // ordinary acknowledgement, which costs nothing extra.
        //
        // The exception is a window that was CLOSED. There is no next ordinary
        // acknowledgement in that case — the peer has stopped sending and is
        // waiting on a probe — so an update that waits for one waits for the
        // persist timer instead, and the connection resumes a probe interval
        // late for no reason.
        // Measured as what this read FREED, not as the difference between the
        // buffer's capacity and the last advertised window. Those two are not
        // comparable: the advertisement is capped by the 16-bit field whenever
        // no window scale is negotiated, so subtracting one from the other says
        // the window opened by 196 KiB on a connection where nothing was ever
        // held. That comparison fired on every read and produced an update
        // frame each time — the syndrome this rule exists to prevent, caused by
        // the rule meant to prevent it.
        let threshold = min(2 * connection.mss, connection.tcb.rcvWndMax / 2)
        let wasClosed = connection.tcb.rcvWnd == 0
        let worthAnnouncing = wasClosed ? count > 0 : count >= threshold
        let canAnnounce =
            connection.tcb.state == .established || connection.tcb.state == .finWait1
            || connection.tcb.state == .finWait2
        if worthAnnouncing, canAnnounce {
            if connection.inProcessPass {
                connection.windowUpdatePending = true
            } else {
                emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
            }
        }
        return taken
    }
    /// A connection reached ESTABLISHED.
    /// Set by a refused `send`, cleared by the signal it arms. Without it this
    /// endpoint cannot tell "space was freed" — true constantly — from "space
    /// was freed and someone is waiting for it".
    private var sendRefused = false

    public var onEstablished: (() -> Void)?
    /// A connection's stream is over: the peer's FIN was reached, or the block
    /// was deleted by a reset or by the end of the closing handshake. Fires at
    /// most once per connection.
    public var onClosed: (() -> Void)?

    /// Called when the peer's FIN arrives on a connection whose *send* side is
    /// still open -- the half-closed state, CLOSE-WAIT.
    ///
    /// Set it and the peer's FIN reports here instead of through `onClosed`; a
    /// caller that leaves it nil sees the older behaviour, where a FIN in
    /// either direction ends the stream. `onClosed` still fires for this
    /// connection when it really finishes, so nothing that waits on it waits
    /// forever.
    public var onPeerFinished: (() -> Void)?

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
    ///
    /// `maximumTimeWaitConnections` is injected for the same reason
    /// `TCPReassembler`'s caps are: a cap that can only be exercised by building
    /// its production value's worth of state is a cap nothing tests.
    init(
        stack: Stack, initialSequenceNumbers: any InitialSequenceNumbers,
        maximumTimeWaitConnections: Int = TCPEndpoint.defaultMaximumTimeWaitConnections,
        delayedAckTimeout: TimeAmount = TCPEndpoint.delayedAckTimeout,
        nagleDisabled: Bool = false
    ) {
        self.stack = stack
        self.initialSequenceNumbers = initialSequenceNumbers
        self.maximumTimeWaitConnections = max(1, maximumTimeWaitConnections)
        // Injectable so the differential can turn the delay off. gVisor's own
        // acknowledgement timing does not match this stack's -- see
        // `differential/README.md` -- and a comparison that cannot align frames
        // measures nothing at all. Zero here means "acknowledge at once", which
        // is what the run needs and what every RFC 9293 §3.8.6.3 permission is
        // an exception to.
        self.delayedAckTimeout = delayedAckTimeout
        self.nagleDisabled = nagleDisabled
    }

    deinit {
        // `TransportDemuxer` holds delegates weakly, so a dropped endpoint stops
        // receiving on its own; this reclaims the table SLOTS, without which a
        // port stays occupied until something else happens to evict the stale
        // entry. The connections' `TCPTimers` cancel themselves in their own
        // `deinit`, which is why the timer bodies below must capture this
        // endpoint weakly: a strong capture would keep it -- and the whole
        // connection graph -- alive on the loop's queue until the deadline.
        //
        // Both kinds of key have to go: the listening key, and the per-connection
        // four-tuples a closed-but-lingering connection holds (see `close()`).
        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .tcp)
        }
        for connection in connections.values {
            guard let id = connection.registeredID else { continue }
            stack.transportDemuxer.unregister(id, protocolNumber: .tcp)
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

    /// Prepare to receive one connection a forwarder has already decided to
    /// accept, **without taking the listening port**.
    ///
    /// ## Why binding would be wrong here, not merely unnecessary
    ///
    /// `bind` registers the wildcard key `(local, port, any, 0)`, and that key
    /// is exclusive. A forwarder that bound one per accepted connection could
    /// therefore accept exactly **one connection per destination port** — the
    /// second would fail with `portInUse`. That is not an edge case: a browser
    /// opens six connections to the same host and port, and a gateway that
    /// serves only the first is not a gateway.
    ///
    /// It cost nothing to give up because the forwarder holds the demuxer's
    /// protocol slot and routes segments to this endpoint by four-tuple itself.
    /// The listening key would never have been matched against. Each connection
    /// still registers in its own right once it exists, which is what a
    /// lingering TIME-WAIT needs and what keeps two peers dialling the same port
    /// apart.
    ///
    /// Found by an accept-backpressure test that accepted its second connection
    /// and got nothing: `complete()` threw, the request was consumed, and the
    /// only visible symptom was a connection that vanished.
    func listenForForwardedConnection() {
        isListening = true
        backlog = 1
    }

    /// Active open. Binds first if nothing has, which is what a socket does.
    ///
    /// The implicit bind is not a convenience: an endpoint dialling out has no
    /// reason to care which local port it uses, and requiring the caller to
    /// choose one makes every caller repeat the same two lines and gives each of
    /// them a chance to pick a port already in use. The local ADDRESS is not
    /// arbitrary in the same way -- it is this stack's own, and it is what the
    /// peer will answer to -- so it comes from the NIC rather than from a
    /// wildcard.
    public func connect(to address: IPv4Address, port: UInt16) throws {
        guard !isListening, connections.isEmpty else { throw StackError.invalidEndpointState }
        if boundID == nil {
            guard let local = stack.nic.primaryAddress else { throw StackError.noRoute }
            try bind(address: local, port: 0)
        }
        guard let boundID else { throw StackError.invalidEndpointState }

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

        // The active open's half of the handshake: our SYN goes out here and
        // the SYN-ACK answering it closes the round trip. Recorded immediately
        // before the emit rather than after it because `emit` is synchronous and
        // the clock cannot move inside it, so the two instants are the same one.
        connection.handshake.recordTransmission(at: stack.clock.now())
        emit(
            [.syn], sequence: connection.tcb.iss, on: connection,
            options: [.maximumSegmentSize(UInt16(advertisedSegmentSize))]
                + windowScaleOption(for: connection, answeringPeerSyn: false)
                + handshakeTimestampOption(for: connection, answeringPeerSyn: false)
                + handshakeSackPermittedOption(for: connection, answeringPeerSyn: false),
            acknowledgement: SequenceNumber(0),
            window: unscaledAdvertisedWindow(of: connection))
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
        // Past the FIN, whether it has gone out or is still waiting behind the
        // queue. Accepting a write here would either follow a FIN that has
        // already been sent -- data past the end of the stream -- or be counted
        // by the deferred close below as a reason to keep waiting, which turns
        // "shut the send side" into "shut it eventually, maybe".
        guard !sendSideClosed else { throw StackError.notConnected }
        guard let connection = connections.values.first else { throw StackError.notConnected }
        switch connection.tcb.state {
        case .established, .closeWait:
            break
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            throw StackError.notConnected
        }
        guard connection.sender.write(bytes) else {
            sendRefused = true
            throw StackError.wouldBlock
        }
        transmit(on: connection)
        armRetransmitTimer(on: connection)
        // A write into a connection whose peer has closed its window puts
        // nothing on the wire, so this is the ONE place an episode of persist
        // can begin without a segment having arrived. Without it the connection
        // waits for the peer to send something before it starts probing, which
        // is precisely the wedge the probe exists to break.
        armPersistTimer(on: connection)
        // A write is a sign of life and puts data in flight, so the keep-alive
        // stands down and the retransmit timer takes over the question.
        connection.keepAliveProbes = 0
        armKeepAliveTimer(on: connection)
        // And it creates a new tail. Armed here as well as on arrival, because a
        // connection that sends its last segment and hears nothing more never
        // reaches the arrival path -- which is exactly the case the probe is
        // for.
        armTailProbeTimer(on: connection)
    }

    /// Close every connection, release the **listening** port, and keep every
    /// connection's own four-tuple until that connection is actually finished.
    ///
    /// ## The two things "close" means here are genuinely different
    ///
    /// - The **listening key** — `(localAddress, localPort, any, 0)` — is
    ///   released immediately. Nothing is in flight for it, and the port is
    ///   rebindable the instant this returns.
    /// - A **connected** four-tuple is not. It stays registered, in this
    ///   endpoint's own name, until the connection reaches CLOSED or its
    ///   TIME-WAIT timer fires.
    ///
    /// The second half is the whole point of TIME-WAIT and it took a measurement
    /// to see. This method used to drop every connection and release everything,
    /// which left `.startTimeWait` unreachable: making its timer body's `[weak
    /// self]` a strong capture failed nothing, because no connection could ever
    /// get there. That is not a missing test — it is the protection missing.
    /// RFC 9293 §3.10.7.4 holds the four-tuple for 2·MSL precisely so that a
    /// late or duplicate segment from the old connection is absorbed by the
    /// dying block rather than delivered into a **new** connection that has
    /// reused the same tuple. Releasing it at `close()` pays for the timer and
    /// buys none of that.
    ///
    /// `TransportDemuxer.deliver` tries the exact four-tuple before either
    /// wildcard, so a successor that binds the same local port gets everything
    /// except the segments belonging to a connection still dying here — which is
    /// exactly the discrimination TIME-WAIT is for.
    ///
    /// ## What this cannot do
    ///
    /// The demuxer holds delegates weakly, so these registrations live only as
    /// long as the `TCPEndpoint` object does. Dropping a closed endpoint ends
    /// its TIME-WAIT protection early (`deinit` unregisters, deliberately, so
    /// nothing is left dangling). Surviving that would mean moving TIME-WAIT
    /// blocks into the `Stack`, which is a larger design than this interface
    /// implies; a caller that wants the protection must hold the endpoint.
    ///
    /// `onData` and `onEstablished` are cleared — the application asked to stop
    /// — but `onClosed` is **not**, because `close()` is now asynchronous and
    /// that callback is the only way to learn it finished.
    public func close() {
        shutdownWrite()
        onData = nil
        onEstablished = nil
        onWritable = nil
    }

    /// Claims the peer's FIN, if it arrived before anyone was listening for it.
    ///
    /// A FIN is an event and it is over: `onPeerFinished` fires when the
    /// segment is processed, and a caller that adopts an established endpoint
    /// afterwards -- which is what the forwarder does, since it only builds the
    /// guest channel once the host side has been dialled -- would never hear
    /// about one that had already passed. The next segment in CLOSE-WAIT would
    /// raise it again, but on a connection whose peer has finished speaking
    /// there may not be a next segment.
    ///
    /// Returns true once per connection, and marks the FIN reported, so the
    /// answer and the callback cannot both fire for the same one.
    public func adoptPeerFinished() -> Bool {
        for connection in connections.values where connection.tcb.state == .closeWait {
            guard !connection.peerFinishReported else { continue }
            connection.peerFinishReported = true
            return true
        }
        return false
    }

    /// Sends a FIN and stops accepting writes, leaving the receive half open.
    ///
    /// This is the half of `close()` that TCP has always had and this endpoint
    /// did not expose. A peer that has finished sending has not necessarily
    /// finished listening: `nc host port` with no stdin sends its FIN in the
    /// same millisecond as the third leg of its handshake and then waits for
    /// the answer. Answering that FIN by tearing down both directions discards
    /// the reply -- which is what a real Linux guest saw against this gateway
    /// before this existed.
    ///
    /// `onData`, `onWritable` and `onEstablished` all survive, because the
    /// point is to keep receiving. `onClosed` reports the connection's real
    /// end, as it does after `close()`.
    ///
    /// Calling this twice, or calling `close()` after it, sends one FIN. TCP
    /// agrees -- a second CLOSE in FIN-WAIT or LAST-ACK is defined to do
    /// nothing -- but the registration below is not idempotent on its own, and
    /// running it twice would hand the demuxer a tuple it already holds and
    /// drop the connection as the failure path.
    public func shutdownWrite() {
        guard !sendSideClosed else { return }
        sendSideClosed = true
        for connection in connections.values {
            // A FIN consumes the sequence number at `snd.nxt`, and `snd.nxt` is
            // the first byte the sender has not TRANSMITTED -- not the first it
            // has not been given. A connection whose window or congestion
            // window is full is holding payload behind that point, and closing
            // here would put the FIN on top of it: the peer would see the
            // stream end early and this side would then retransmit data past
            // its own FIN. So the close waits, and `transmit` finishes it once
            // the queue is empty.
            guard connection.sender.unsentBytes == 0 else {
                connection.finPending = true
                continue
            }
            for action in TCPStateMachine.close(on: &connection.tcb) {
                switch action {
                case .sendFin:
                    emitFin(on: connection)
                case .deleteTCB:
                    // LISTEN or SYN-SENT: nothing was ever established, so there
                    // is no four-tuple worth holding and nothing to wait out.
                    remove(connection)
                default:
                    break
                }
            }
        }

        // Register what survives under its own key BEFORE releasing the
        // listening one, so no segment can fall through the gap between them.
        for connection in connections.values {
            registerInOwnRight(connection)
            armRetransmitTimer(on: connection)
            // Cancels it, in every state `close()` can leave a connection in.
            // RFC 6429 §4 is the requirement being met here: a connection in the
            // persist condition "needs to allow ... to be closed or aborted by
            // their applications", which is the counterweight to persist itself
            // having no give-up rule.
            armPersistTimer(on: connection)
            // Past ESTABLISHED, so `armKeepAliveTimer` cancels rather than
            // arms. Called anyway rather than cancelling directly, so there is
            // one place that decides when a keep-alive should run.
            armKeepAliveTimer(on: connection)
        }
        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .tcp)
        }
        boundID = nil
        isListening = false
    }

    /// How many connections this endpoint currently holds, live and lingering
    /// alike. Not `private`, because `@testable import` elevates `internal` and
    /// not `private`, and "the backlog refused it" is otherwise
    /// indistinguishable from "the segment was silently mis-parsed".
    var connectionCountForTesting: Int { connections.count }

    /// The congestion window of the single connection this endpoint holds, or
    /// nil if it holds none or more than one.
    ///
    /// Here so that "nothing was declared lost" can be asserted directly. A
    /// vector that pins the ABSENCE of a retransmission is equally true of a
    /// stack that halved its congestion window and then had nothing to
    /// retransmit, and the difference between those two is invisible on the
    /// wire until the next write.
    var congestionWindowForTesting: Int? {
        guard connections.count == 1, let connection = connections.values.first else { return nil }
        return connection.sender.congestionControl.congestionWindow
    }

    /// Whether the single connection this endpoint holds is running CUBIC.
    ///
    /// A type test rather than a behavioural one, and deliberately: what needs
    /// checking here is that the SELECTION reached the sender. The behaviour of
    /// each algorithm is covered where the algorithm is, and a test that
    /// inferred which one was in use from a window figure would be re-testing
    /// that behaviour to answer a question about wiring.
    var rackStateForTesting: (send: NIODeadline?, rtt: TimeAmount, window: TimeAmount, minRTT: TimeAmount?)? {
        connections.values.first?.sender.rackStateForTesting
    }

    var sackedForTesting: Int? {
        guard let connection = connections.values.first else { return nil }
        return connection.sender.selectivelyAcknowledgedBytes
    }

    var tailProbeDeadlineForTesting: NIODeadline? {
        connections.values.first?.sender.tailProbeDeadline
    }

    var rackDeadlineForTesting: NIODeadline? {
        connections.values.first?.sender.rackReorderDeadline
    }

    var presumedLostForTesting: Int? {
        guard let connection = connections.values.first else { return nil }
        return connection.sender.presumedLostBytes
    }

    var flightForTesting: Int? {
        guard let connection = connections.values.first else { return nil }
        return connection.sender.flightSize
    }

    var usesRackForTesting: Bool {
        guard let connection = connections.values.first else { return false }
        return connection.sender.rackEnabledForTesting
    }

    var usesCubicForTesting: Bool {
        guard let connection = connections.values.first else { return false }
        return connection.sender.congestionControl is Cubic
    }

    /// Whether the single connection this endpoint holds has a zero-window probe
    /// scheduled, or nil if it holds none or more than one.
    ///
    /// The NIO-level fact, not the sender's opinion: `Sender.persistDeadline`
    /// says when a probe is due and this says that a timer was actually armed
    /// for it. A test asserting only the former passes on an endpoint that never
    /// calls `armPersistTimer`.
    var hasPersistScheduledForTesting: Bool? {
        guard connections.count == 1, let connection = connections.values.first else { return nil }
        return connection.timers.hasPersistScheduled
    }

    /// How many of them are in TIME-WAIT. The cap is on this number, and a cap
    /// asserted without it would be satisfied by an endpoint that holds nothing
    /// at all.
    var timeWaitCountForTesting: Int {
        connections.values.reduce(0) { $0 + ($1.tcb.state == .timeWait ? 1 : 0) }
    }

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
        connection.inProcessPass = true
        defer { connection.inProcessPass = false }
        let stateBefore = connection.tcb.state
        // The challenge-ACK budget comes from the STACK, not from the connection:
        // every connection this endpoint holds, and every connection every other
        // endpoint on the same stack holds, spends from one bucket. See
        // `ChallengeACKBudget`.
        let actions = TCPStateMachine.receive(
            segment: segment, on: &connection.tcb, receiver: &connection.receiver, sender: &connection.sender,
            challengeACKs: &stack.tcpChallengeACKs,
            timestampClockNow: timestampClock())

        var wantsAck = false
        var wantsDelayableAck = false
        var delivered = false
        var deleted = false
        for action in actions {
            switch action {
            case .sendSynAck:
                emitSynAck(on: connection)
            case .sendAck:
                wantsAck = true
            case .sendAckMayDelay:
                wantsDelayableAck = true
            case .sendRst(let sequence, let ack):
                emit(
                    ack == nil ? [.rst] : [.rst, .ack], sequence: sequence, on: connection,
                    acknowledgement: ack ?? SequenceNumber(0), window: 0)
            case .sendFin:
                emitFin(on: connection)
            case .deliver(var buffer):
                // Into the buffer, then signal. `onData` is a readiness
                // notification now, not a delivery: the bytes stay here until
                // `read` takes them, and the window shrinks by exactly what is
                // held. An application that ignores the signal stops the peer
                // instead of losing data.
                connection.receiveBuffer.writeBuffer(&buffer)
                connection.tcb.setHeldBytes(connection.receiveBuffer.readableBytes)
                delivered = true
            case .startTimeWait:
                armTimeWaitTimer(on: connection)
            case .deleteTCB:
                deleted = true
            case .none:
                break
            }
        }

        // Signal AFTER the action loop, once, however many segments were
        // delivered. Calling it per segment would make an application that reads
        // on every signal do so more often than there is reason to, and the
        // signal carries no payload for it to miss.
        if delivered { onData?() }

        // `onData` is application code and may have closed this endpoint out
        // from under us. Everything below touches connection state that
        // `close()` has already torn down in that case.
        guard connections[connection.peer] === connection else { return }

        if stateBefore != .established, connection.tcb.state == .established {
            adoptCongestionControlSegmentSize(on: connection)
            seedRoundTripEstimateFromHandshake(on: connection)
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
        // A deferred window update is satisfied by anything that carries the
        // current window, which every segment this endpoint sends does.
        if transmitted > 0 || wantsAck { connection.windowUpdatePending = false }
        if connection.windowUpdatePending {
            connection.windowUpdatePending = false
            emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
        }
        if wantsAck, transmitted == 0 {
            emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
            connection.delayedAckPending = false
            connection.unacknowledgedBytesSinceAck = 0
        } else if wantsDelayableAck, transmitted == 0 {
            // RFC 9293 §3.8.6.3: acknowledge every SECOND full-sized segment,
            // and never hold one longer than 500 ms.
            //
            // Both halves are required and they answer different failures. The
            // every-second-segment rule is what keeps a bulk transfer's
            // acknowledgement clock running — a receiver that only ever waited
            // out the timer would ACK twice a second, and the sender's window
            // would open in 500 ms steps. The timer is what bounds the wait when
            // the second segment never comes, which is the whole of an
            // interactive flow.
            connection.unacknowledgedBytesSinceAck += segment.payload.readableBytes
            if connection.unacknowledgedBytesSinceAck >= 2 * connection.mss {
                emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
                connection.delayedAckPending = false
                connection.unacknowledgedBytesSinceAck = 0
            } else if delayedAckTimeout == .zero {
                // No delay configured: answer at once. Keeps the branch above the
                // single place that decides eligibility, rather than making
                // every caller test the timeout.
                emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
                connection.unacknowledgedBytesSinceAck = 0
            } else if !connection.delayedAckPending {
                connection.delayedAckPending = true
                connection.timers.scheduleDelayedAck(after: delayedAckTimeout) { [weak self, weak connection] in
                    guard let self, let connection, connection.delayedAckPending else { return }
                    connection.delayedAckPending = false
                    connection.unacknowledgedBytesSinceAck = 0
                    self.emit([.ack], sequence: connection.tcb.sndNxt, on: connection)
                }
            }
        }
        armRetransmitTimer(on: connection)
        armPersistTimer(on: connection)
        armRackTimer(on: connection)
        armTailProbeTimer(on: connection)
        // Re-armed on every arriving segment, which is what makes "idle" mean
        // idle: any sign of life from the peer pushes the first probe out by a
        // full interval, and clears the probes already spent.
        connection.keepAliveProbes = 0
        armKeepAliveTimer(on: connection)

        switch connection.tcb.state {
        case .closeWait, .closing, .lastAck, .timeWait, .closed:
            // The peer's FIN is past: no more data will arrive on this stream.
            reportPeerFinished(connection)
        case .listen, .synSent, .synReceived, .established, .finWait1, .finWait2:
            break
        }

        // Last, after every send this segment provoked. Signalling earlier would
        // invite the waiter to write into a buffer this call is still about to
        // fill from its own queue, and the retry would be refused for a reason
        // that had nothing to do with the peer.
        signalWritableIfWaiting(on: connection)
    }

    /// Wake a caller whose `send` was refused, if there is now anywhere for it
    /// to go.
    ///
    /// `sendRefused` is what makes this quiet. An acknowledgement frees send
    /// buffer space on almost every segment, so signalling on space alone would
    /// fire constantly and tell nobody anything -- which is asserted by
    /// `aWritableSignalIsNotSentToAnEndpointThatWasNeverRefused` rather than
    /// left as a claim.
    ///
    /// The state test is honestly weaker than it looks, and saying so is the
    /// point. `close()` clears `onWritable` along with the other callbacks, so
    /// this endpoint cannot in practice reach FIN-WAIT-1 with a waiter still
    /// attached; removing the switch entirely fails no test, and that was run
    /// rather than assumed. What it buys is that the flag does not survive into
    /// a state where nothing could ever satisfy it -- cheap, and one less piece
    /// of state whose staleness a future reader has to reason about.
    ///
    /// One connection is all this can ever concern: `send` refuses outright on
    /// an endpoint holding more than one, so a per-endpoint flag cannot be
    /// armed by one connection and answered by another.
    private func signalWritableIfWaiting(on connection: Connection) {
        guard sendRefused else { return }
        switch connection.tcb.state {
        case .established, .closeWait:
            guard connection.sender.hasBufferSpace else { return }
            sendRefused = false
            onWritable?()
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            sendRefused = false
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
        let ack = acknowledgement ?? connection.tcb.rcvNxt
        let header = TCPHeader(
            sourcePort: connection.localPort,
            destinationPort: connection.peer.port,
            sequence: sequence,
            acknowledgement: ack,
            dataOffset: 5,
            flags: flags,
            window: window ?? advertisedWindow(of: connection),
            checksum: 0,
            urgentPointer: 0,
            options: optionsToSend(for: connection, flags: flags, requested: options))
        // RFC 7323 §4.3's Last.ACK.sent, recorded at the single point every
        // segment leaves by so it cannot drift from what the peer actually saw.
        // Only segments that carry the ACK bit count: a bare SYN acknowledges
        // nothing, and letting it move Last.ACK.sent would widen the window
        // TS.Recent may be adopted from.
        if flags.contains(.ack) {
            connection.tcb.recordAckSent(ack)
        }
        emit(header, payload: payload, from: connection.localAddress, to: connection.peer.address)
    }

    /// Everything this segment carries in its options area.
    ///
    /// The order is not cosmetic. Timestamps are added first because SACK takes
    /// whatever space is left -- `maximumSackBlocks(alongside:)` is given the
    /// options already committed to, so a connection using both reports three
    /// blocks and one using only SACK reports four. Deciding the count before
    /// the timestamp was added would have overflowed the 40-byte area, and the
    /// only symptom would have been a header the peer could not parse.
    private func optionsToSend(
        for connection: Connection, flags: TCPFlags, requested: [TCPOption]
    ) -> [TCPOption] {
        let withTimestamps = requested + timestampOption(for: connection, alreadyCarrying: requested)
        return withTimestamps + sackOption(for: connection, flags: flags, alreadyCarrying: withTimestamps)
    }

    /// The SACK option for an outgoing segment, or none.
    ///
    /// RFC 2018 §3: sent only on ACKs, only when SACK was negotiated, and only
    /// when there is something out of order to report. The SYN exclusion is
    /// separate from all of that -- a SYN carries SACK-*Permitted*, and a
    /// SYN-ACK that also carried blocks would be describing a queue that cannot
    /// exist yet.
    private func sackOption(
        for connection: Connection, flags: TCPFlags, alreadyCarrying: [TCPOption]
    ) -> [TCPOption] {
        guard connection.tcb.sackPermitted, flags.contains(.ack), !flags.contains(.syn) else { return [] }
        let blocks = connection.receiver.sackBlocks(
            rcvNxt: connection.tcb.rcvNxt,
            limit: TCPOptionCodec.maximumSackBlocks(alongside: alreadyCarrying))
        guard !blocks.isEmpty else { return [] }
        return [.selectiveAcknowledgement(blocks)]
    }

    /// The Timestamps option for an outgoing segment, or none.
    ///
    /// RFC 7323 §3: once negotiated the option goes on **every** segment, not
    /// only on data. A peer computing RTTM from the echo needs the echo on the
    /// acknowledgements too, and PAWS on the far side reads TSval from whatever
    /// arrives — a stack that stopped stamping bare ACKs would have them
    /// discarded by a conforming peer.
    ///
    /// `alreadyCarrying` exists because the handshake builds its own option list
    /// and must not end up with two: a SYN or SYN-ACK offers the option itself,
    /// and this would otherwise append a second copy.
    private func timestampOption(for connection: Connection, alreadyCarrying options: [TCPOption]) -> [TCPOption] {
        guard connection.tcb.timestampsEnabled else { return [] }
        for option in options {
            if case .timestamps = option { return [] }
        }
        return [.timestamps(value: timestampClock(), echo: connection.tcb.tsRecent)]
    }

    /// The Timestamps option for a SYN or SYN-ACK.
    ///
    /// Separate from `timestampOption` because the handshake's copy cannot be
    /// gated on `timestampsEnabled` — that flag is the *result* of the exchange
    /// this segment is half of. A SYN offers unconditionally; a SYN-ACK answers
    /// only an offer, per RFC 7323 §3's "if the option was received in the
    /// initial `<SYN>`", which `TCB.timestampsEnabled` records by then.
    private func handshakeTimestampOption(for connection: Connection, answeringPeerSyn: Bool) -> [TCPOption] {
        guard Self.offersTimestamps else { return [] }
        if answeringPeerSyn && !connection.tcb.timestampsEnabled { return [] }
        return [.timestamps(value: timestampClock(), echo: answeringPeerSyn ? connection.tcb.tsRecent : 0)]
    }

    /// The largest payload a segment on this connection can carry: the
    /// negotiated MSS less the options that ride on every one of them.
    ///
    /// **This is SMSS**, and naming it once is the point. RFC 5681 defines SMSS
    /// as the largest segment the sender can transmit "excluding TCP/IP headers
    /// and options", so it is this number and not the negotiated MSS that the
    /// congestion window is measured in. Using the MSS there instead makes the
    /// initial window of ten segments a few hundred bytes wider than ten
    /// segments, which is invisible until a write lands just past the boundary
    /// -- one extra short segment on the first burst, and thereafter two stacks
    /// with different ideas about what is outstanding.
    ///
    /// Found by the differential: gVisor stopped its opening burst one segment
    /// earlier, having sized its own initial window off `maxPayloadSize`.
    private func payloadSegmentSize(for connection: Connection) -> Int {
        max(1, connection.mss - maximumOptionBytes(for: connection))
    }

    /// Rebuild the sender's congestion control around the payload size, at the
    /// one moment the options that decide it are settled and nothing is in
    /// flight.
    ///
    /// A rebuild rather than a setter because `Reno` takes SMSS at
    /// initialisation and derives its initial window from it; the same reason
    /// `adoptPeerSegmentSize` rebuilds in SYN-SENT. Safe here for the same
    /// reason it is safe there, and the precondition says so rather than
    /// trusting it: nothing can have been written until the connection is
    /// established, which is the transition this runs on.
    private func adoptCongestionControlSegmentSize(on connection: Connection) {
        let size = payloadSegmentSize(for: connection)
        guard size != connection.sender.congestionControl.segmentSize else { return }
        precondition(
            connection.sender.bufferedBytes == 0,
            "the sender is being rebuilt with data already queued, which would drop it")
        let nagleDisabled = connection.sender.nagleDisabled
        connection.sender = Sender(
            congestionControl: congestionControl.make(maximumSegmentSize: size), clock: stack.clock,
            maximumBufferedBytes: Self.sendBufferBytes)
        connection.sender.nagleDisabled = nagleDisabled
        connection.sender.rackEnabled = rack
    }

    /// The largest options area this connection can put on a data segment.
    ///
    /// Built by asking for the maximum number of SACK blocks rather than the
    /// current one; see `transmit` for why the current one is the wrong
    /// question. The block contents are irrelevant -- only the encoded length is
    /// read -- so they are zeroes.
    private func maximumOptionBytes(for connection: Connection) -> Int {
        var options = timestampOption(for: connection, alreadyCarrying: [])
        if connection.tcb.sackPermitted {
            let count = TCPOptionCodec.maximumSackBlocks(alongside: options)
            if count > 0 {
                options.append(
                    .selectiveAcknowledgement(
                        Array(repeating: SACKBlock(left: SequenceNumber(0), right: SequenceNumber(0)), count: count)))
            }
        }
        return TCPOptionCodec.encode(options).count
    }

    /// SACK-Permitted for a SYN or SYN-ACK, gated exactly as the timestamp is:
    /// a SYN offers unconditionally, a SYN-ACK only answers an offer. By the
    /// time the SYN-ACK is built, `negotiateSelectiveAcknowledgement` has
    /// already recorded whether the peer sent one.
    private func handshakeSackPermittedOption(for connection: Connection, answeringPeerSyn: Bool) -> [TCPOption] {
        guard Self.offersSelectiveAcknowledgement else { return [] }
        if answeringPeerSyn && !connection.tcb.sackPermitted { return [] }
        return [.sackPermitted]
    }

    /// TSval, in milliseconds off the injected clock.
    ///
    /// RFC 7323 §4.4 wants a tick between 1 ms and 1 s; milliseconds sit at the
    /// fast end, which is what makes the value useful for RTTM on a host-local
    /// path where a round trip is microseconds. It is a `UInt32` and it wraps,
    /// which is why every comparison against it is serial arithmetic — see
    /// `TCB.updateTSRecent`.
    private func timestampClock() -> UInt32 {
        UInt32(truncatingIfNeeded: stack.clock.now().uptimeNanoseconds / 1_000_000)
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
    ///
    /// ## The window scale is now *negotiated*, and still not *advertised*
    ///
    /// `TCB.negotiateWindowScale(fromSynOptions:)` records both shifts as of the
    /// task that added it, so "nothing in this stack records a scale" is no
    /// longer the reason the option is absent here. The reason is the ordering:
    /// `windowScaleToOffer` is `nil`, so both shifts are zero on every
    /// connection and the window below is a true, unscaled 65535. Nothing about
    /// this list may change until the shifts are actually applied in both
    /// directions -- see `windowScaleToOffer` for the four steps and for what
    /// adding the option here will additionally require
    /// (`tcb.peerOfferedWindowScale`, per RFC 7323 §2.2).
    private func emitSynAck(on connection: Connection) {
        // Every SYN-ACK this stack sends passes through here, including the
        // repeat that answers a retransmitted SYN in SYN-RECEIVED -- which is
        // exactly the transmission Karn has to count. A second emission point
        // would not be a missing count so much as a silently wrong RTO.
        connection.handshake.recordTransmission(at: stack.clock.now())
        emit(
            [.syn, .ack], sequence: connection.tcb.iss, on: connection,
            options: [.maximumSegmentSize(UInt16(advertisedSegmentSize))]
                + windowScaleOption(for: connection, answeringPeerSyn: true)
                + handshakeTimestampOption(for: connection, answeringPeerSyn: true)
                + handshakeSackPermittedOption(for: connection, answeringPeerSyn: true),
            window: unscaledAdvertisedWindow(of: connection))
    }

    /// Our FIN. `TCPStateMachine.close(on:)` has already bumped SND.NXT to
    /// reserve the sequence number it consumes, so the FIN occupies SND.NXT - 1.
    ///
    /// Also arms its own retransmission deadline. `Sender` models a byte stream
    /// and no control flags -- deliberately, and the alternative was measured:
    /// giving it an in-flight record for the FIN makes `retransmitOldest`'s
    /// `offset + length <= queuedBytes` guard fail, so it returns nil and stops
    /// retransmitting **data** as well, on a timer that keeps re-arming. So the
    /// FIN's retransmission is this endpoint's, and this is where its clock
    /// starts.
    private func emitFin(on connection: Connection) {
        let sequence = connection.tcb.sndNxt + (-1)
        if connection.finSequence == nil {
            connection.finSequence = sequence
            connection.finTimeout = connection.sender.retransmissionTimeout
            connection.finTransmissions = 0
        }
        connection.finTransmissions += 1
        connection.finSentAt = stack.clock.now()
        connection.finDeadline = stack.clock.now() + connection.finTimeout
        emit([.fin, .ack], sequence: sequence, on: connection)
        // A FIN is a tail like any other, and the peer's acknowledgement of it
        // is what closes the connection. Armed here because nothing else will:
        // `close` does not go through the write path, and a connection whose
        // last act was a FIN never reaches the arrival path again if that FIN is
        // lost.
        armTailProbeTimer(on: connection)
    }

    /// Put whatever the sender has ready on the wire: a pending fast
    /// retransmission first, then as much new data as `min(cwnd, SND.WND)`
    /// allows. Returns how many segments went out.
    ///
    /// `segmentsToTransmit` advances SND.NXT over what it returns, so
    /// everything it returns must be sent.
    @discardableResult
    private func transmit(on connection: Connection) -> Int {
        // Options come out of the PAYLOAD, not out of the advertised MSS.
        //
        // RFC 6691 is explicit about this and it is the opposite of the obvious
        // reading: the MSS option "should not be decreased to account for any
        // possible IP or TCP options", because it describes what fits the path
        // for the peer's own segments. It is the *sender* that must shrink its
        // data by the size of the options it adds. Charging the option against
        // the advertised MSS instead would cut every segment on every
        // connection short by twelve bytes, including connections that never
        // negotiated timestamps.
        //
        // Conditional on the options actually being in use, which they can be
        // here — unlike during the handshake, where the MSS is fixed before the
        // negotiation settles.
        //
        // The budget is the WORST CASE this connection can emit, not what it
        // would emit right now, and the difference is a bug that took two
        // attempts to see.
        //
        // The first version charged the timestamp alone. When SACK started
        // riding on data segments the budget did not know, a full-sized segment
        // overflowed the 40-byte options area, the data offset wrapped, and the
        // frame was one no peer could parse -- reported by the differential, in
        // as many words, as "Swift emitted an undecodable frame".
        //
        // Charging the options present at this instant fixed that case and not
        // the general one. A segment is cut once and may be **retransmitted much
        // later**, when the connection is reporting more SACK blocks than it was
        // when the payload was sized: the retransmission carries a bigger header
        // over the same payload and overflows exactly as before. Nothing in the
        // sender remembers what the header cost the first time, and nothing
        // should -- the fix is to make the payload fit whatever the header may
        // grow to.
        //
        // gVisor arrives at the same answer (`endpoint.maxOptionSize` builds its
        // options with a full set of SACK blocks), which is why both stacks cut
        // 1420-byte segments on a connection with timestamps and SACK.
        let segments = connection.sender.segmentsToTransmit(
            tcb: &connection.tcb, mss: payloadSegmentSize(for: connection))
        for segment in segments {
            emit(segment.flags.union(.ack), sequence: segment.sequence, on: connection, payload: segment.payload)
        }
        // The queue has drained, so the FIN that was waiting behind it can go.
        // Here rather than in the write path: what releases the payload is the
        // peer's acknowledgement opening the window, and this is the one place
        // every route to a transmission passes through.
        if connection.finPending, connection.sender.unsentBytes == 0 {
            connection.finPending = false
            for action in TCPStateMachine.close(on: &connection.tcb) {
                switch action {
                case .sendFin:
                    emitFin(on: connection)
                case .deleteTCB:
                    remove(connection)
                default:
                    break
                }
            }
        }
        return segments.count
    }

    /// Fold the handshake's round trip into the connection's RTT estimator, at
    /// the one moment both ends of it are known.
    ///
    /// ## Both directions, one call site
    ///
    /// A passive open times SYN-ACK -> ACK and an active open times SYN ->
    /// SYN-ACK, and both finish at the same event: the transition INTO
    /// ESTABLISHED. Hooking the transition rather than the two segment paths
    /// separately is what makes the active and passive cases impossible to
    /// implement inconsistently, and it is why there is no second copy of this
    /// below.
    ///
    /// ## Ordering, which is the whole difficulty
    ///
    /// Two orderings have to hold, and neither raises anything when it does not:
    ///
    /// - **Before the first data send.** This runs inside `process`, ahead of
    ///   the `transmit` below it, so the first data segment's retransmission
    ///   timer is armed from the seeded RTO. Move it after `transmit` and the
    ///   estimator still ends up holding exactly the right numbers while the
    ///   timer that matters was armed from the wrong ones --
    ///   `the-handshake-seeds-the-retransmission-timeout` in `tcp-data.vec` is
    ///   the vector that catches that, as a frame 200 ms early.
    /// - **After `adoptPeerSegmentSize`.** On an active open, a SYN-ACK
    ///   carrying an MSS option makes `deliver` REBUILD `connection.sender`
    ///   from scratch, which throws away the estimator with everything else in
    ///   it. That happens before `process` runs, so seeding here is after the
    ///   rebuild and survives it. Seeding anywhere in `deliver` ahead of that
    ///   call would be discarded silently -- no error, no failing test, and an
    ///   active open that quietly keeps the unseeded behaviour.
    ///
    /// `HandshakeRTT` decides whether there is a sample at all; Karn's refusal
    /// and a zero-length round trip both arrive here as `nil`, and a connection
    /// that gets no sample simply keeps RFC 6298 §2.1's initial one-second RTO.
    private func seedRoundTripEstimateFromHandshake(on connection: Connection) {
        guard let sample = connection.handshake.sample(at: stack.clock.now()) else { return }
        connection.sender.measureHandshakeRoundTrip(sample)
    }

    /// Bytes delivered in order and not yet read, for tests.
    var heldBytesForTesting: Int { connections.values.first?.receiveBuffer.readableBytes ?? 0 }

    /// The same number, named for the assertion it serves: everything the peer
    /// sent and this stack accepted is still here to be read.
    var deliveredSoFarForTesting: Int { heldBytesForTesting }

    /// The first connection's smoothed round-trip estimate, for tests.
    ///
    /// Exposed because RFC 7323 §4.1's claim is about the *estimate*, and the
    /// RTO is a poor proxy for it — floored at one second, it reads the same
    /// whether a sample was taken or not. This project has already had to be
    /// shown that by arithmetic rather than by a failing test once.
    var smoothedRoundTripForTesting: TimeAmount {
        connections.values.first?.sender.smoothedRoundTrip ?? .zero
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
    /// One timer, two deadlines: the sender's, for unacknowledged data, and this
    /// endpoint's own, for an unacknowledged FIN. Arm at whichever comes first
    /// and let the body work out what is actually due.
    private func armRetransmitTimer(on connection: Connection) {
        guard let deadline = nextRetransmitDeadline(of: connection) else {
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

    private func nextRetransmitDeadline(of connection: Connection) -> NIODeadline? {
        let data = connection.sender.retransmitDeadline
        let fin = finNeedsRetransmission(connection) ? connection.finDeadline : nil
        switch (data, fin) {
        case (nil, nil): return nil
        case (let data?, nil): return data
        case (nil, let fin?): return fin
        case (let data?, let fin?): return min(data, fin)
        }
    }

    private func retransmitTimerFired(peer: Peer) {
        guard let connection = connections[peer] else { return }
        let now = stack.clock.now()

        if let deadline = connection.sender.retransmitDeadline, deadline <= now,
            let segment = connection.sender.retransmitTimerFired(tcb: &connection.tcb)
        {
            emit(segment.flags.union(.ack), sequence: segment.sequence, on: connection, payload: segment.payload)
        }

        if finNeedsRetransmission(connection), let deadline = connection.finDeadline, deadline <= now {
            guard connection.finTransmissions < Self.maximumFinTransmissions else {
                // RFC 1122 §4.2.3.5's R2: give the connection up rather than
                // hold its four-tuple, its timer and its block for a peer that
                // is never going to answer.
                remove(connection)
                reportClosed(connection)
                return
            }
            // RFC 6298 §5.5's backoff, run here because the sender's estimator
            // only backs off for segments the sender itself holds.
            connection.finTimeout = min(connection.finTimeout * 2, RTTEstimator.maximumTimeout)
            emitFin(on: connection)
        }

        armRetransmitTimer(on: connection)
    }

    /// Bring the persist timer into line with what the sender says, exactly as
    /// `armRetransmitTimer` does for the retransmission timer, and with the same
    /// `[weak self]` + re-find-by-key discipline for the same reason.
    ///
    /// The state gate is `send()`'s: those are the two states in which the
    /// application can put data into the send queue, so they are the only two in
    /// which a closed receive window can be holding data back. Everything past
    /// them either has a FIN in the sequence space -- which `Sender
    /// .persistApplies` refuses on its own, so this is belt as well as braces --
    /// or is a connection with nothing left to send.
    private func armPersistTimer(on connection: Connection) {
        switch connection.tcb.state {
        case .established, .closeWait:
            break
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            connection.timers.cancelPersist()
            return
        }
        guard let deadline = connection.sender.persistDeadline else {
            connection.timers.cancelPersist()
            return
        }
        let now = stack.clock.now()
        let delay = deadline > now ? deadline - now : .nanoseconds(0)
        let peer = connection.peer
        connection.timers.schedulePersist(after: delay) { [weak self] in
            self?.persistTimerFired(peer: peer)
        }
    }

    /// Arm, re-arm or cancel RFC 8985 §6.3's reordering timer.
    ///
    /// Armed wherever the persist timer is, and from the same places, so that
    /// "the connection did something" has one meaning across every timer here.
    private func armRackTimer(on connection: Connection) {
        guard let deadline = connection.sender.rackReorderDeadline else {
            connection.timers.cancelRackReorder()
            return
        }
        let now = stack.clock.now()
        let delay = deadline > now ? deadline - now : .nanoseconds(0)
        // A weak reference to the CONNECTION rather than a lookup by peer, which
        // the other timers use. Both work; this one needs the connection's TCB
        // inout, and re-finding it by four-tuple would be a second way of asking
        // the same question.
        connection.timers.scheduleRackReorder(after: delay) { [weak self, weak connection] in
            guard let self, let connection else { return }
            // Re-checked against the clock before acting, as the persist and
            // retransmit bodies are: this is re-armed on every arriving segment,
            // so it can be reached with the deadline already moved.
            guard connection.sender.rackReorderTimerFired(tcb: &connection.tcb) else {
                self.armRackTimer(on: connection)
                return
            }
            // Something was newly declared lost, so there is a retransmission to
            // send -- through the same path everything else leaves by.
            _ = self.transmit(on: connection)
            self.armRetransmitTimer(on: connection)
            self.armRackTimer(on: connection)
        }
    }

    /// Arm, re-arm or cancel RFC 8985 §7's tail loss probe.
    private func armTailProbeTimer(on connection: Connection) {
        let now = stack.clock.now()
        // The sender gives an INTERVAL from now, per RFC 8985 §7.5.1: the timer
        // is armed on a transmission or an acknowledgement, and the PTO runs
        // from that moment rather than from when the last segment went out. The
        // FIN half still yields a deadline, because a FIN has one send time and
        // nothing re-arms it.
        let delay: TimeAmount
        if let interval = connection.sender.tailProbeInterval {
            delay = interval
        } else if let deadline = finProbeDeadline(for: connection) {
            delay = deadline > now ? deadline - now : .nanoseconds(0)
        } else {
            connection.timers.cancelTailProbe()
            return
        }
        connection.timers.scheduleTailProbe(after: delay) { [weak self, weak connection] in
            guard let self, let connection else { return }
            if connection.sender.tailProbeInterval == nil, self.finProbeDeadline(for: connection) != nil {
                // The tail is a FIN, which the sender does not model: it tracks
                // the byte stream, and a FIN is sequence space the endpoint owns.
                // So the probe is the FIN again, sent through the one place FINs
                // leave by.
                connection.finProbeSent = true
                self.emitFin(on: connection)
                self.armRetransmitTimer(on: connection)
                return
            }
            guard
                let probe = connection.sender.tailProbeTimerFired(
                    tcb: &connection.tcb, mss: self.payloadSegmentSize(for: connection))
            else { return }
            self.emit(
                probe.flags.union(.ack), sequence: probe.sequence, on: connection, payload: probe.payload)
            // The retransmission timer keeps running underneath: the probe is a
            // shortcut to an acknowledgement, not a replacement for the deadline
            // that fires when none comes at all.
            self.armRetransmitTimer(on: connection)
        }
    }

    /// When to probe an unacknowledged FIN, or nil when there is not one.
    ///
    /// The sender models the byte stream and a FIN is not part of it -- it is
    /// sequence space this endpoint owns -- so a tail that is only a FIN is
    /// invisible to `Sender.tailProbeDeadline`. gVisor probes it, and the
    /// difference showed up as a FIN retransmission this stack did not make.
    ///
    /// Same interval as the sender's, and the same one-per-tail rule: a peer
    /// that ignored the first will not answer a second sooner than the
    /// retransmission timer finds out.
    private func finProbeDeadline(for connection: Connection) -> NIODeadline? {
        guard rack, !connection.finProbeSent, let sentAt = connection.finSentAt else { return nil }
        switch connection.tcb.state {
        case .finWait1, .closing, .lastAck:
            break
        case .closed, .listen, .synSent, .synReceived, .established, .closeWait, .finWait2, .timeWait:
            return nil
        }
        // Nothing else outstanding: with data still in flight the sender's own
        // probe covers this tail, and two probes for one tail is one too many.
        guard connection.sender.flightSize == 0 else { return nil }
        let smoothed = connection.sender.smoothedRoundTrip
        guard smoothed > .zero else { return nil }
        var interval = TimeAmount.nanoseconds(smoothed.nanoseconds * 2) + .milliseconds(200)
        let timeout = connection.sender.retransmissionTimeout
        if interval > timeout { interval = timeout }
        return sentAt + interval
    }

    /// Arm, re-arm or cancel the keep-alive timer for a connection.
    ///
    /// Called wherever the persist timer is armed, and from the same places, so
    /// that "the connection did something" has exactly one meaning here.
    ///
    /// ## What counts as idle, and why it is not "nothing arrived"
    ///
    /// The timer is armed only when there is **nothing outstanding**. With data
    /// in flight the retransmit timer is already asking the same question and
    /// asking it far more often; running both means the keep-alive fires during
    /// a transfer that is merely slow, and its probe -- a segment below SND.NXT
    /// -- draws a duplicate acknowledgement that the sender counts toward fast
    /// retransmit. A keep-alive that can cause a spurious retransmission is
    /// worse than none.
    private func armKeepAliveTimer(on connection: Connection) {
        guard let configuration = keepAlive else {
            connection.timers.cancelKeepAlive()
            return
        }
        switch connection.tcb.state {
        case .established, .closeWait:
            break
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            connection.timers.cancelKeepAlive()
            return
        }
        guard connection.sender.flightSize == 0 else {
            connection.timers.cancelKeepAlive()
            return
        }
        let delay = connection.keepAliveProbes == 0 ? configuration.idle : configuration.interval
        let peer = connection.peer
        connection.timers.scheduleKeepAlive(after: delay) { [weak self] in
            self?.keepAliveTimerFired(peer: peer)
        }
    }

    /// RFC 1122 §4.2.3.6's probe: a segment carrying no data at `SND.NXT - 1`.
    ///
    /// The sequence number is the whole trick and it is worth stating. A segment
    /// at SND.NXT would be new data the peer has not seen, and one below
    /// SND.UNA would be out of window; `SND.NXT - 1` is a byte the peer has
    /// **already acknowledged**, so it is unambiguously a duplicate and every
    /// TCP answers it with an acknowledgement. The RFC's alternative -- one
    /// garbage byte -- exists for implementations that ignore an empty segment,
    /// and is not sent here: it puts a byte into the peer's stream that the
    /// application would have to be trusted to discard.
    ///
    /// The `keepAlive` check here is not the same one `armKeepAliveTimer` makes,
    /// though falsification found that removing either alone changes nothing --
    /// each masks the other. What separates them is a caller turning keep-alive
    /// **off on a live connection**: every established connection already has a
    /// timer armed, and nothing re-arms it until a segment arrives, so without
    /// this check the scheduled probe still goes out on a connection whose owner
    /// has said it should not be probed.
    private func keepAliveTimerFired(peer: Peer) {
        guard let connection = connections[peer], let configuration = keepAlive else { return }
        switch connection.tcb.state {
        case .established, .closeWait:
            break
        case .closed, .listen, .synSent, .synReceived, .finWait1, .finWait2, .closing, .lastAck, .timeWait:
            return
        }

        if connection.keepAliveProbes >= configuration.count {
            // Out of probes. The peer is gone, and holding the connection open
            // holds an endpoint -- and on a gateway, the host socket spliced to
            // it -- for a peer that will never answer. A reset is what tells
            // anything downstream, since there is nobody left to send a FIN to.
            emit([.rst, .ack], sequence: connection.tcb.sndNxt, on: connection)
            connection.timers.cancelAll()
            remove(connection)
            reportClosed(connection)
            return
        }
        connection.keepAliveProbes += 1
        emit([.ack], sequence: connection.tcb.sndNxt + (-1), on: connection)
        armKeepAliveTimer(on: connection)
    }

    /// RFC 9293 §3.8.6.1's zero-window probe, out through the single egress
    /// point like everything else this endpoint emits.
    ///
    /// The deadline is re-checked against the clock before the probe is taken,
    /// for the same reason `retransmitTimerFired` re-checks the sender's: this
    /// body is re-armed on every arriving segment, so it can be reached with the
    /// deadline still in the future if the schedule and the sender's own idea of
    /// when disagree. Re-arming and returning is then the whole of the work.
    private func persistTimerFired(peer: Peer) {
        guard let connection = connections[peer] else { return }
        if let deadline = connection.sender.persistDeadline, deadline <= stack.clock.now(),
            let segment = connection.sender.persistTimerFired(tcb: &connection.tcb)
        {
            emit(segment.flags.union(.ack), sequence: segment.sequence, on: connection, payload: segment.payload)
        }
        armPersistTimer(on: connection)
    }

    /// True while a FIN we sent is still unacknowledged.
    ///
    /// The test is `SND.UNA != SND.NXT` in the three states that can hold an
    /// unacknowledged FIN — the same criterion `TCPStateMachine` itself uses to
    /// decide FIN-WAIT-1 -> FIN-WAIT-2 and LAST-ACK -> CLOSED, reused rather
    /// than re-derived. An equality, so there is no ordering question and
    /// nothing to get wrong at the half-space point. FIN-WAIT-2 and TIME-WAIT
    /// are excluded because reaching either required SND.UNA == SND.NXT.
    private func finNeedsRetransmission(_ connection: Connection) -> Bool {
        guard connection.finSequence != nil else { return false }
        switch connection.tcb.state {
        case .finWait1, .closing, .lastAck:
            return connection.tcb.sndUna != connection.tcb.sndNxt
        case .closed, .listen, .synSent, .synReceived, .established, .finWait2, .closeWait, .timeWait:
            return false
        }
    }

    /// Enter TIME-WAIT: hold the four-tuple for 2·MSL so late or duplicate
    /// segments from this connection are absorbed here rather than delivered
    /// into a new connection that reuses the tuple, then release it.
    ///
    /// This was unreachable in round 1, because `close()` released the
    /// four-tuple immediately — the state without the protection. It is
    /// reachable now, and the `[weak self]` below is falsifiable: making it
    /// strong fails `aConnectionInTimeWaitIsReleasedWhenTheEndpointIsDropped`.
    private func armTimeWaitTimer(on connection: Connection) {
        if connection.timeWaitOrder == nil {
            timeWaitSequence &+= 1
            connection.timeWaitOrder = timeWaitSequence
        }
        let peer = connection.peer
        connection.timers.startTimeWait { [weak self] in
            guard let self, let connection = self.connections[peer] else { return }
            self.remove(connection)
            self.reportClosed(connection)
        }
        enforceTimeWaitCap()
    }

    /// Oldest-first eviction, once more blocks are in TIME-WAIT than the cap
    /// allows. See `defaultMaximumTimeWaitConnections` for why this is the one
    /// table in this package that evicts rather than refusing.
    ///
    /// "Oldest" is `timeWaitOrder`, a plain monotonic counter — never a
    /// `SequenceNumber`, whose ordering is not a strict weak ordering over the
    /// whole space and would garble a `min`.
    private func enforceTimeWaitCap() {
        while timeWaitCountForTesting > maximumTimeWaitConnections {
            var oldest: Connection?
            for connection in connections.values {
                guard let order = connection.timeWaitOrder, connection.tcb.state == .timeWait else { continue }
                if let current = oldest?.timeWaitOrder, current <= order { continue }
                oldest = connection
            }
            guard let oldest else { return }
            remove(oldest)
            reportClosed(oldest)
        }
    }

    /// Give a connection a demuxer registration of its own, under its exact
    /// four-tuple, so it keeps receiving after the endpoint's listening key is
    /// released. Called from `close()`.
    ///
    /// A failure here can only mean the exact tuple is already registered, which
    /// nothing else in this endpoint can have done. Failing closed — dropping
    /// the connection — is the right direction: a lingering block that receives
    /// nothing is the useless half of TIME-WAIT.
    private func registerInOwnRight(_ connection: Connection) {
        let id = TransportEndpointID(
            localAddress: connection.localAddress, localPort: connection.localPort,
            remoteAddress: connection.peer.address, remotePort: connection.peer.port)
        do {
            try stack.transportDemuxer.register(id, protocolNumber: .tcp, delegate: self)
            connection.registeredID = id
        } catch {
            remove(connection)
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
                irs: SequenceNumber(0),
                windowScaleToOffer: Self.windowScaleToOffer,
                rcvWndMax: Self.maximumReceiveWindowBytes,
                offersTimestamps: Self.offersTimestamps,
                offersSelectiveAcknowledgement: Self.offersSelectiveAcknowledgement),
            receiver: Receiver(reassembler: TCPReassembler()),
            sender: {
                var sender = Sender(
                    congestionControl: congestionControl.make(maximumSegmentSize: mss), clock: stack.clock,
                    maximumBufferedBytes: Self.sendBufferBytes)
                sender.nagleDisabled = nagleDisabled
                sender.rackEnabled = rack
                return sender
            }(),
            mss: mss)
    }

    private func remove(_ connection: Connection) {
        connection.timers.cancelAll()
        // A connection that outlived `close()` holds a four-tuple of its own.
        // Releasing it here, at the single point every connection leaves by, is
        // what makes "TIME-WAIT ends and the tuple becomes reusable" true of
        // every exit — the timer firing, a reset, LAST-ACK completing, the cap
        // evicting, and the FIN retry budget running out.
        if let id = connection.registeredID {
            stack.transportDemuxer.unregister(id, protocolNumber: .tcp)
            connection.registeredID = nil
        }
        connections.removeValue(forKey: connection.peer)
    }

    /// The peer's FIN has been processed. Whether that ends the connection
    /// depends on who is asking.
    ///
    /// CLOSE-WAIT is the one state where it does not: the peer has finished
    /// sending and this side has not, so there is still a send half to use. A
    /// caller that asked for half-closure hears about it there and keeps its
    /// write side; one that did not gets the older meaning, where either FIN
    /// ends the stream. Every other state here has both halves finished, so
    /// both callers get the same answer.
    private func reportPeerFinished(_ connection: Connection) {
        guard let onPeerFinished, connection.tcb.state == .closeWait else {
            reportClosed(connection)
            return
        }
        guard !connection.peerFinishReported else { return }
        connection.peerFinishReported = true
        onPeerFinished()
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
            congestionControl: congestionControl.make(maximumSegmentSize: connection.mss), clock: stack.clock,
            maximumBufferedBytes: Self.sendBufferBytes)
        connection.sender.rackEnabled = rack
    }

    /// RCV.WND for the wire. `Receiver` owns the figure and has already written
    /// it into the TCB; this only clamps it to the field, which cannot be
    /// exceeded while `connection.tcb.rcvWindScale` is zero -- which it is on
    /// every connection, since `windowScaleToOffer` is `nil` and RFC 7323 §2.2
    /// scales nothing unless both sides sent the option. The step that applies
    /// our own shift turns this clamp into `RCV.WND >> rcvWindScale` against a
    /// ceiling of `65535 << rcvWindScale`, and must round the shift *downwards*
    /// (see `Receiver.advertisedWindow`, which owns that arithmetic).
    private func advertisedWindow(of connection: Connection) -> UInt16 {
        let scaled = max(0, connection.tcb.rcvWnd) >> Int(connection.tcb.rcvWindScale)
        return UInt16(min(scaled, Int(UInt16.max)))
    }

    /// The window for a segment that carries SYN, which RFC 7323 §2.2 says
    /// **must not be scaled**: "The window field in a segment where the SYN bit
    /// is set (i.e., a `<SYN>` or `<SYN,ACK>`) MUST NOT be scaled."
    ///
    /// A second window-building site rather than a condition inside the first,
    /// deliberately, and for the same reason `TCPStateMachine` labels its four
    /// peer-window decodes individually: the asymmetry is the thing a reader
    /// needs to see, and a branch hides it. `emit` defaults to the scaled one,
    /// so the two SYN-bearing callers pass this explicitly — which also means a
    /// new SYN-bearing emission that forgets to is visibly wrong at the call
    /// site rather than silently scaled.
    private func unscaledAdvertisedWindow(of connection: Connection) -> UInt16 {
        UInt16(min(max(0, connection.tcb.rcvWnd), Int(UInt16.max)))
    }

    /// The Window Scale option to put in an outgoing SYN, or `nil`.
    ///
    /// On a SYN-ACK this is gated on the peer having offered one first: RFC 7323
    /// §2.2 permits the option in a `<SYN,ACK>` only "if a Window Scale option
    /// was received in the initial `<SYN>` segment". `TCB.peerOfferedWindowScale`
    /// is the flag rather than a non-zero shift, because a `shift.cnt` of 0 is a
    /// legal offer and a recorded 0 cannot tell the two apart.
    private func windowScaleOption(for connection: Connection, answeringPeerSyn: Bool) -> [TCPOption] {
        guard let shift = Self.windowScaleToOffer else { return [] }
        if answeringPeerSyn && !connection.tcb.peerOfferedWindowScale { return [] }
        return [.windowScale(shift)]
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
