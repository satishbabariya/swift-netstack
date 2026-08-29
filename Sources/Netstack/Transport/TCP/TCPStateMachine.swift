import NIOCore

/// A received TCP segment: header plus payload bytes, exactly what a
/// caller has after `TCPHeader.parse` and slicing off the header/options.
/// `TCPHeader` alone carries no length information -- TCP has no length
/// field of its own, so a header by itself cannot answer "how many bytes
/// does this segment occupy in the sequence space", which the state
/// machine needs both for the acceptability test (RFC 9293 §3.10.7.4) and
/// to build `.deliver` actions. This is the one addition beyond what the
/// brief's interface list named; it is unavoidable plumbing, not a design
/// choice, since `receive(segment:on:receiver:)` takes a single `segment` argument.
struct TCPSegment: Sendable {
    var header: TCPHeader
    var payload: ByteBuffer

    init(header: TCPHeader, payload: ByteBuffer = ByteBuffer()) {
        self.header = header
        self.payload = payload
    }

    /// SEG.LEN (RFC 9293 §3.10.7.4): payload bytes, plus one each for SYN
    /// and FIN, since both consume a sequence number of their own.
    ///
    /// Deliberately *not* computed here. This used to be a second, independent
    /// implementation of the same formula alongside `Segment.length`, and two
    /// copies of SEG.LEN in one module can drift: the acceptability test below
    /// and the reassembler's gap arithmetic would then disagree about how much
    /// sequence space a segment occupies, which is precisely the kind of
    /// disagreement that lets a segment be accepted by one and mis-placed by
    /// the other. There is now one definition, in `Segment`, and this is a
    /// projection onto it.
    var length: Int { reassemblySegment.length }
}

/// RFC 9293's TCP state machine. `receive(segment:on:receiver:)` is the "SEGMENT
/// ARRIVES" event (§3.10.7): given a segment and the connection's control
/// block, it mutates the block in place and returns what the caller should
/// do about it. `close(on:)` is the other half of the state diagram, the
/// application-initiated "CLOSE Call" (§3.10.4), which is not triggered by
/// a segment at all.
///
/// Every flag check below dispatches with `flags.contains(_:)`, never `==`
/// against a whole `TCPFlags` value. `TCPHeader.parse` carries all eight
/// raw bits of the wire's flags byte through into `TCPFlags.rawValue`,
/// including the CWR and ECE bits that `TCPFlags` deliberately does not
/// name (see its doc comment) -- an ECN-setup SYN (SYN with ECE and CWR
/// also set, which Linux sends by default in several configurations) would
/// fail a `flags == [.syn]` comparison even though it is an ordinary SYN.
/// `.contains(.syn)` ignores those unnamed bits entirely, which is exactly
/// what's needed here: this state machine has no ECN behavior to give them.
///
/// ## What this machine does *not* own
///
/// Everything about *bytes*: which received bytes are in order, when RCV.NXT
/// advances over them, what is handed to the application, and what receive
/// window is advertised back. All of that belongs to `Receiver`, which is
/// passed in and called at step 5 below.
///
/// That split is deliberate and load-bearing rather than tidiness. This file
/// once advanced RCV.NXT and emitted `.deliver` itself, for in-order data
/// only, while `TCPReassembler` did the same job with out-of-order handling on
/// top. Two components each individually correct, both believing they own
/// RCV.NXT, is the shape behind every serious defect this stack has produced:
/// the connection's idea of what it has received would depend on which path a
/// segment happened to take, and no test of either component alone can see it.
///
/// The split is by *phase*, and it is worth stating exactly, because the
/// stronger claim that used to stand here — "exactly one writer of `tcb.rcvNxt`
/// and `tcb.rcvWnd`, and it is not this file" — is contradicted two screens
/// down, at the `.listen` and `.synSent` handlers. This file **initialises**
/// RCV.NXT from the peer's ISS during the handshake, at those two sites and
/// nowhere else. `Receiver` **advances** it over received bytes, and owns
/// `tcb.rcvWnd` outright. The two writers cannot both run for one segment:
/// `generalSegmentArrives`, which is the only path that drives the receiver, is
/// never entered in LISTEN or SYN-SENT. There is exactly one *advancer*, and it
/// is not this file.
///
/// Do not reintroduce a sequence comparison here that `Receiver` already makes —
/// if the same comparison appears in both files, the defect is back. (The
/// in-order-FIN gate in step 5 is not one of those: `Receiver` compares RCV.NXT
/// against a *recorded* FIN position, this file compares an *arriving segment's*
/// start against RCV.NXT, and they answer different questions.)
///
/// ## SND.UNA is split the same way, and the split is by *phase* here too
///
/// State it exactly, because the stronger claim is the one that lets a defect
/// through:
///
/// - This file writes SND.UNA at **two** kinds of site. `.listen` sets it to
///   ISS (initialisation). `.synSent` and the SYN-RECEIVED arm of step 4 move
///   it over our own **SYN**, which is the one sequence number `Sender` does
///   not model — that type moves a byte stream and holds no record of a SYN, so
///   handing it the acknowledgement of one would have it grow the congestion
///   window by a byte the path never carried. Both of those sites can *only*
///   retire the SYN: in SYN-SENT and SYN-RECEIVED the only acceptable
///   acknowledgement is ISS+1, since nothing else has been sent.
/// - `Sender.acknowledged` moves it over **data**, and it is the only advancer
///   of data. The ESTABLISHED arm of step 4 calls it instead of assigning
///   SND.UNA itself.
///
/// The two cannot run for one segment: they are different arms of one `switch`
/// on `tcb.state`, and by the time the ESTABLISHED arm is reachable SND.UNA is
/// already past the SYN. That is the whole invariant; it is weaker than "this
/// file never writes SND.UNA", and the weaker true statement is the one worth
/// having.
///
/// `Sender` is driven from **inside** this function for the same reason
/// `Receiver` is: a caller that ran the state machine and then acknowledged
/// separately would have both write SND.UNA for the same segment, and the
/// second writer would see nothing left to acknowledge — the sender would
/// silently retire nothing, keep every transmitted segment outstanding forever,
/// and refuse every later write (`segmentsToTransmit` fails closed when
/// SND.NXT and its own accounting disagree).
struct TCPStateMachine {
    /// `receiver` owns RCV.NXT, delivery and the advertised window, and is
    /// `inout` because it carries per-connection state.
    ///
    /// It is driven here rather than by the caller, and only after the segment
    /// has passed the RST, acceptability, SYN and ACK checks and been trimmed to
    /// the offered window, so that nothing unacceptable and nothing outside the
    /// window ever reaches the reassembly queue. That ordering is a security
    /// property, not an optimisation, and it takes both halves. The
    /// acceptability test admits a segment whose first *or* last byte is in the
    /// window and bounds neither its extent nor its end, so it alone does not
    /// confine anything: 5000 bytes starting at RCV.NXT pass it against a 4-byte
    /// window. `receiverInput(for:tcb:)` is the half that confines (RFC 9293
    /// §3.9's trim), and it runs here, between the test and the receiver. A
    /// receiver driven ahead of either would queue — and eventually deliver —
    /// bytes the connection said it would not accept, with `TCPReassembler`'s
    /// quarter-of-the-sequence-space domain bound as the only remaining limit.
    /// Reversing the two, so that a caller
    /// reassembled first and then asked the state machine what to do, would
    /// also need a way to re-enter this function for a FIN whose gap has since
    /// filled; no such re-drive exists, and the comment that used to assume one
    /// is what left an out-of-order FIN unhandled forever.
    /// Internal, like everything else in `Transport/TCP/`: these types are
    /// mechanisms, and no caller outside this module can drive them past the
    /// gates below. The module's public surface is `Stack` and the Channel
    /// types.
    /// `sender` owns SND.UNA's advancement over data and the retransmit queue,
    /// and is `inout` for the same reason `receiver` is. It is driven here, at
    /// the one site that has just decided the acknowledgement is acceptable, so
    /// that no caller is in a position to acknowledge separately — see the
    /// type's doc comment on the SND.UNA split.
    ///
    /// `challengeACKs` is RFC 5961 §7's throttle, and it is `inout` because it is
    /// **not** this connection's: it belongs to the whole stack (`Stack.tcpChallengeACKs`)
    /// and every connection on it spends from the same bucket. See
    /// `ChallengeACKBudget` for why it is shared and what that costs.
    ///
    /// It is drawn on here, inside the machine, for the same reason `receiver`
    /// and `sender` are driven here: this is the only place that knows *why* an
    /// ACK is being sent. `TCPAction.sendAck` covers both an acknowledgement of
    /// received data and a challenge, and on the wire they are the same frame, so
    /// a caller that tried to throttle the returned actions could only throttle
    /// both — which would stop a guest's data transfer dead for as long as it
    /// kept the bucket empty, an attack on the connection delivered by the
    /// defence.
    static func receive(
        segment: TCPSegment, on tcb: inout TCB, receiver: inout Receiver, sender: inout Sender,
        challengeACKs: inout ChallengeACKBudget, timestampClockNow: UInt32? = nil
    ) -> [TCPAction] {
        switch tcb.state {
        case .closed:
            return closedStateSegmentArrives(segment: segment)
        case .listen:
            return listenStateSegmentArrives(segment: segment, tcb: &tcb)
        case .synSent:
            return synSentStateSegmentArrives(segment: segment, tcb: &tcb)
        case .synReceived, .established, .finWait1, .finWait2, .closeWait, .closing, .lastAck, .timeWait:
            return generalSegmentArrives(
                segment: segment, tcb: &tcb, receiver: &receiver, sender: &sender, challengeACKs: &challengeACKs,
                timestampClockNow: timestampClockNow)
        }
    }

    // MARK: - CLOSED (RFC 9293 §3.10.7.1)

    /// Not reachable through any test in this task -- a caller has no TCB
    /// to invoke `receive` on for a connection that was never opened -- but
    /// kept faithful to the RFC for the sake of completeness, and because a
    /// TCB legitimately reaches `.closed` mid-flight (e.g. LAST-ACK + ACK)
    /// and could in principle see one more stray segment after that.
    /// Internal rather than private: `Stack`'s TCP handler answers a segment
    /// for a port with no endpoint behind it, and that is exactly this
    /// function's case — a CLOSED connection with no TCB. Calling it there
    /// rather than reimplementing the reset is what keeps the choice between
    /// RFC 9293 §3.10.7.1's two reset forms (see `TCPAction.sendRst`) in one
    /// place. It was dead code until that call site existed.
    static func closedSegmentArrives(segment: TCPSegment) -> [TCPAction] {
        closedStateSegmentArrives(segment: segment)
    }

    private static func closedStateSegmentArrives(segment: TCPSegment) -> [TCPAction] {
        let header = segment.header
        if header.flags.contains(.rst) {
            return [.none]
        }
        if header.flags.contains(.ack) {
            // <SEQ=SEG.ACK><CTL=RST>, ACK bit clear.
            return [.sendRst(sequence: header.acknowledgement, ack: nil)]
        }
        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>. SEG.LEN counts the SYN
        // and FIN flags as well as the payload (see `TCPSegment.length`), so
        // a bare SYN at sequence N is acknowledged with N+1 -- acknowledging
        // N instead would be a refusal the peer discards, which the guest
        // cannot tell apart from the port simply not answering.
        return [.sendRst(sequence: SequenceNumber(0), ack: header.sequence + segment.length)]
    }

    // MARK: - LISTEN (RFC 9293 §3.10.7.2)

    private static func listenStateSegmentArrives(segment: TCPSegment, tcb: inout TCB) -> [TCPAction] {
        let header = segment.header

        // First check for a RST: ignore it (there is nothing to reset).
        if header.flags.contains(.rst) {
            return [.none]
        }

        // Second check for an ACK: nothing has been sent, so any ACK here
        // is bogus. Reset it.
        if header.flags.contains(.ack) {
            return [.sendRst(sequence: header.acknowledgement, ack: nil)]
        }

        // Third check for a SYN: this is a passive open. Security/
        // compartment and precedence checks from the RFC are out of scope
        // for this stack (IPv4 only, no precedence field).
        if header.flags.contains(.syn) {
            tcb.irs = header.sequence
            tcb.rcvNxt = header.sequence + 1
            tcb.sndUna = tcb.iss
            tcb.sndNxt = tcb.iss + 1
            // RFC 7323's Window Scale negotiation, passive-open half: the
            // peer's shift is in this SYN, ours is whatever the SYN-ACK about
            // to be sent will carry. One of exactly two call sites; see
            // `TCB.negotiateWindowScale(fromSynOptions:)` for why there are no
            // others and why the result is still zero on every connection.
            tcb.negotiateWindowScale(fromSynOptions: header.options)
            tcb.negotiateTimestamps(fromSynOptions: header.options)
            tcb.state = .synReceived
            return [.sendSynAck]
        }

        // Anything else (a bare data or FIN segment with no SYN) has
        // nothing to attach to yet. Drop it.
        return [.none]
    }

    // MARK: - SYN-SENT (RFC 9293 §3.10.7.3)

    private static func synSentStateSegmentArrives(segment: TCPSegment, tcb: inout TCB) -> [TCPAction] {
        let header = segment.header
        var ackAcceptable = false

        // First check the ACK bit: acceptable iff ISS < SEG.ACK =< SND.NXT
        // (nothing beyond the not-yet-acked SYN could possibly be ACKed
        // from here).
        //
        // A forward-distance range test, never a negated `lessThan` -- see
        // the acceptance-test section of `SequenceNumber`. This site used to
        // spell the negation structurally rather than with a `!` operator:
        // it computed `ackTooOld`/`ackTooNew` from positive `lessThan`s and
        // accepted when neither held, which is the same `!lessThan` accept
        // guard wearing a disguise, with the same hole and invisible to a
        // grep for `!`. Worth remembering when auditing for the next one.
        if header.flags.contains(.ack) {
            let ack = header.acknowledgement
            guard ack.isInRange(after: tcb.iss, throughAndIncluding: tcb.sndNxt) else {
                if header.flags.contains(.rst) {
                    return [.none]
                }
                return [.sendRst(sequence: ack, ack: nil)]
            }
            ackAcceptable = true
        }

        // Second check the RST bit: only honour it if the ACK (if any) was
        // acceptable above -- an unacknowledged RST here could be a stray
        // duplicate from an earlier attempt.
        if header.flags.contains(.rst) {
            if ackAcceptable {
                tcb.state = .closed
                return [.deleteTCB]
            }
            return [.none]
        }

        // Fourth (third, security/precedence, is out of scope) check the
        // SYN bit: this is either the SYN|ACK of an active open, or a bare
        // SYN from a simultaneous open.
        if header.flags.contains(.syn) {
            tcb.irs = header.sequence
            tcb.rcvNxt = header.sequence + 1
            // The other of the two Window Scale call sites, covering both ways
            // out of SYN-SENT: the SYN-ACK of an active open and the peer's
            // bare SYN in a simultaneous open. It runs before the branch below
            // because RFC 7323 treats them identically -- the option is carried
            // by any segment with the SYN bit set, and in a simultaneous open
            // both sides have already sent theirs.
            tcb.negotiateWindowScale(fromSynOptions: header.options)
            tcb.negotiateTimestamps(fromSynOptions: header.options)
            if header.flags.contains(.ack), ackAcceptable {
                // Handshake retirement of our own SYN, which is the one
                // sequence number `Sender` does not model. The acceptable range
                // checked above is `ISS < SEG.ACK =< SND.NXT` with SND.NXT ==
                // ISS+1, so this can only ever be ISS+1: it puts SND.UNA on the
                // first data byte and never moves over data. See the type's doc
                // comment on the SND.UNA split.
                tcb.sndUna = header.acknowledgement
            }

            if tcb.iss.lessThan(tcb.sndUna) {
                // Our SYN has been acknowledged: the handshake is complete.
                tcb.state = .established
                // Snd.Wind.Scale (RFC 7323 §2.3): one of FOUR sites in this file
                // that decode the PEER's window, and one of the two that must
                // NEVER be shifted.
                //
                // `header` here is the peer's SYN-ACK. RFC 7323 §2.3: "The window
                // field (SEG.WND) in the header of every incoming segment, with
                // the exception of <SYN> segments, MUST be left-shifted by
                // Snd.Wind.Shift bits before updating SND.WND". §2.2 says the
                // same thing from the sender's side: "The window field in a
                // segment where the SYN bit is set (i.e., a <SYN> or <SYN,ACK>)
                // MUST NOT be scaled." It cannot be -- the peer chose that
                // window before it knew whether scaling had been agreed at all.
                // Shifting it would multiply the peer's opening window by up to
                // 2^14 and have this stack transmit a megabyte into a 64 KiB
                // buffer on the first write, which is the same defect as
                // advertising a scale we do not apply, pointed the other way.
                //
                // The four sites are: this one and the simultaneous-open one
                // below (both SYN-bearing, both stay unscaled forever), and the
                // SYN-RECEIVED and ESTABLISHED window updates in
                // `generalSegmentArrives` (both reached only by a non-SYN
                // segment, and both now take `<< tcb.sndWindScale`). A previous
                // revision of these comments said "each of the three needs
                // `<< Snd.Wind.Scale`", which is wrong twice over: there are four,
                // and two of them must not be shifted.
                //
                // The absence of a shift on this line is therefore a decision,
                // not an omission left for a later task — the shift is recorded
                // (`TCB.negotiateWindowScale(fromSynOptions:)`), is available on
                // this line, and is applied at both of the other two sites in
                // `generalSegmentArrives`. Both SYN-bearing sites
                // have a test of their own saying so; see
                // `theWindowInASynAckIsNotScaledEvenThoughThatSynAckNegotiatedAScale`.
                tcb.sndWnd = Int(header.window)
                tcb.sndWl1 = header.sequence
                tcb.sndWl2 = header.acknowledgement
                return [.sendAck]
            }

            // Simultaneous open: the peer's SYN arrived before it had
            // acknowledged ours. Answer with our own SYN|ACK and wait in
            // SYN-RECEIVED for it to be acknowledged in turn.
            tcb.state = .synReceived
            // Snd.Wind.Scale: the second of the two SYN-bearing peer-window
            // decodes -- this is the peer's own SYN -- so it stays unscaled for
            // the same reason as the one above. See there, and
            // `theWindowInASimultaneousOpensSynIsNotScaledEitherRfc7323`.
            tcb.sndWnd = Int(header.window)
            tcb.sndWl1 = header.sequence
            tcb.sndWl2 = header.acknowledgement
            return [.sendSynAck]
        }

        return [.none]
    }

    // MARK: - SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2,
    // CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT (RFC 9293 §3.10.7.4)

    /// The steps below are numbered and ordered exactly as RFC 9293 orders
    /// them for these eight states -- do not reorder them; later steps
    /// depend on earlier ones having already run (in particular, the RST
    /// and SYN checks assume the segment has already passed the sequence
    /// acceptability test).
    ///
    /// ## Every challenge ACK below is gated on one budget
    ///
    /// There are six sites and they are deliberately not distinguished from each
    /// other:
    ///
    /// 1. RFC 5961 §3.2's answer to a blind reset that is in the window but not
    ///    at RCV.NXT (step 1).
    /// 2. RFC 9293 §3.10.7.4 step 1's acknowledge-and-drop for an unacceptable
    ///    segment (step 2).
    /// 3. The same, for the TIME-WAIT arm that also restarts the 2·MSL timer —
    ///    the ACK is gated, the timer is not; see there.
    /// 4. RFC 5961 §4's answer to a SYN on a synchronized connection (step 3).
    /// 5. RFC 5961 §5's answer to an acknowledgement of data never sent (step 4).
    /// 6. TIME-WAIT's answer to any other acceptable segment (step 4).
    ///
    /// An attacker does not care which branch it provokes, so a budget any one
    /// of them could bypass would not be a budget — it would read as protection
    /// while the guest picked another branch. `everyChallengeAckPathDrawsOnOneBudget`
    /// is what holds this: it empties the bucket through one path and requires
    /// the others to fall silent with it.
    ///
    /// What does *not* draw on it, and why:
    ///
    /// - **Step 5's acknowledgement of received data.** That is the connection's
    ///   flow control, not a challenge. Throttling it would wedge a guest's data
    ///   transfer for as long as a flood kept the bucket empty.
    /// - **Step 2's SYN-ACK retransmission in SYN-RECEIVED.** It is not an ACK
    ///   and it is not a challenge: it is a handshake frame this connection
    ///   already sent, reproduced for a peer whose copy was lost. Throttling it
    ///   would let a flood on one connection stop another from ever being
    ///   established, which is a denial of service inflicted by the defence. It
    ///   is 1:1 in frames and in bytes, and a guest that wants the same work from
    ///   us can get it for the same price by opening connections — see the report
    ///   for this task.
    /// - **Every RST.** RFC 9293 §3.10.7.1's refusal is a different mechanism with
    ///   a different purpose, and suppressing one leaves a peer hanging on
    ///   `connect()` rather than told it was refused.
    private static func generalSegmentArrives(
        segment: TCPSegment, tcb: inout TCB, receiver: inout Receiver, sender: inout Sender,
        challengeACKs: inout ChallengeACKBudget, timestampClockNow: UInt32? = nil
    ) -> [TCPAction] {
        let header = segment.header

        // RFC 7323 §5.3 R1: PAWS, and it runs FIRST — before RFC 5961's reset
        // handling, before the window test, before everything.
        //
        // §5.3 places R1 first and the ordering is the whole defence. A replayed
        // segment's point is to land inside the window, where nothing else
        // distinguishes it from a real one; checking the window first would admit
        // it to every step in between. The reset path is the one that matters
        // most: a replayed RST that PAWS would have caught tears the connection
        // down, and putting PAWS after the reset step means the one segment an
        // attacker most wants to replay is the one PAWS never sees. That is not
        // hypothetical — it is what this code did until a test asked for it.
        //
        // **A RST is exempt from the acknowledgement, not from the drop.** §5.3
        // says acknowledge and drop; RFC 9293 says never acknowledge a RST,
        // because two peers answering each other's resets never stop. The drop
        // survives, the acknowledgement does not — which is also the safer
        // reading, since the alternative has PAWS admit a reset it just judged
        // stale.
        //
        // The acknowledgement spends from RFC 5961 §7's budget like every other
        // one this file emits: a peer that can make us answer a replayed segment
        // is the same amplification as one that can make us answer an
        // out-of-window segment, and it chooses the rate either way.
        if tcb.pawsRejects(header) {
            if header.flags.contains(.rst) { return [.none] }
            return challengeACKs.consume() ? [.sendAck] : [.none]
        }

        var actions: [TCPAction] = []

        // Step 1 (RFC 5961 §3.2): the RST bit, checked and gated on its own
        // dedicated in-window test -- deliberately NOT the general
        // acceptability test used in step 2 below, so that a RST is
        // defended independently of it. A RST is a request to tear down
        // the connection; honouring one whose sequence number is nowhere
        // near RCV.NXT would let any off-path attacker who can merely
        // guess the four-tuple kill the connection blind. Only a RST whose
        // sequence number exactly matches RCV.NXT is treated as a genuine
        // reset; one that is merely somewhere in the window gets an RFC
        // 5961 challenge ACK instead, and one that is outside the window
        // entirely is silently discarded.
        //
        // An in-window RST deletes the TCB in every state handled here,
        // SYN-RECEIVED included. RFC 9293 §3.10.7.4 distinguishes a
        // SYN-RECEIVED reached by passive open (return to LISTEN) from one
        // reached by an active or simultaneous open (delete), and this
        // deliberately does not: the distinction presupposes a long-lived
        // LISTEN TCB that a connection can fall back into. This stack
        // follows gVisor's forwarder model -- one TCB per accepted
        // connection, created on demand when a SYN arrives -- so there is no
        // shared LISTEN TCB to return to, and "return to LISTEN" and "delete
        // the TCB" name the same outcome: this connection's block goes away
        // and the next SYN creates a fresh one. `TCB` therefore records no
        // open-provenance flag, and needs none. This is a settled ruling,
        // not an oversight.
        if header.flags.contains(.rst) {
            // TIME-WAIT is the one synchronized state where a reset changes
            // nothing at all. RFC 1337 §3, fix 1: a reset arriving in TIME-WAIT
            // is IGNORED.
            //
            // RFC 9293 §3.10.7.4 says the opposite in as many words ("TIME-WAIT
            // STATE: if the RST bit is set, then enter the CLOSED state, delete
            // the TCB, and return"), and this deliberately does not follow it.
            // The block exists precisely to stop a delayed duplicate from this
            // connection being delivered into the next one on the same
            // four-tuple, and a peer that resets it is a peer asking to have
            // that protection removed. RFC 1337 names the resulting failures --
            // old duplicate data accepted into a new connection, and a new
            // connection killed by a stale reset -- and its fix 1 is to refuse.
            //
            // gVisor refuses unconditionally (`rcv.go`'s
            // `handleTimeWaitSegment`: "we do not support TIME_WAIT
            // assassination"). Linux hides it behind `net.ipv4.tcp_rfc1337`,
            // off by default, on the reasoning that the peer is not usually an
            // adversary. Here it always is: this stack terminates traffic from
            // a sandbox whose purpose is to escape, so a default that trusts
            // the peer not to attack is the wrong default. The Task 17
            // differential found this by disagreeing with gVisor about it; see
            // `tcp-close.vec`'s `a-reset-does-not-assassinate-time-wait`.
            if tcb.state == .timeWait {
                return [.none]
            }

            guard isInReceiveWindow(header.sequence, tcb: tcb) else {
                return [.none]
            }
            if header.sequence == tcb.rcvNxt {
                tcb.state = .closed
                return [.deleteTCB]
            }
            return challengeACK(&challengeACKs)
        }

        // Step 2 (RFC 9293 §3.10.7.4): sequence number acceptability for
        // everything that is not a RST. An unacceptable segment is ACKed
        // (so the peer can resynchronize on RCV.NXT) and dropped -- it
        // must not be allowed to touch RCV.NXT or anything else in the
        // TCB, or a peer could inject data anywhere in the stream.
        guard isSegmentAcceptable(segment, tcb: tcb) else {
            // RFC 9293 §3.10.7.4, TIME-WAIT: "the only thing that can arrive is
            // a retransmission of the remote FIN. Acknowledge it, and restart
            // the 2 MSL timeout." That retransmission is *unacceptable* by the
            // test just above -- it sits at RCV.NXT - 1, one behind the window
            // -- so this is the only place it can be recognised, and before the
            // fix it was recognised nowhere: a real FIN retransmission got a
            // bare ACK and no timer, while any acceptable segment at all (an
            // empty ACK will do) restarted the timer from step 4. Exactly
            // backwards, and the wrong half was the one a peer could drive for
            // free.
            //
            // The bar for restarting the timer is now the same as the bar for
            // honouring a RST in step 1 or a FIN in step 5: name RCV.NXT
            // exactly. A blind sender cannot hold a TIME-WAIT block open
            // without it.
            //
            // The ACK draws on the budget like every other answer to an
            // unacceptable segment; the timer restart does not, and is
            // unconditional. Making the restart contingent on a token would hand
            // a guest a way to expire a TIME-WAIT block early — flood the budget
            // flat on one connection and the FIN retransmissions that keep
            // another's block alive stop refreshing it — and the block is exactly
            // the protection RFC 1337 §3 says must not be removable by the peer.
            if tcb.state == .timeWait, isRetransmissionOfProcessedFin(segment, tcb: tcb) {
                return challengeACKs.consume() ? [.sendAck, .startTimeWait] : [.startTimeWait]
            }

            // The second place an *unacceptable* segment must do more than draw
            // an ACK, and for the same reason as the TIME-WAIT case above: it
            // sits one behind the window by construction and so can be
            // recognised nowhere else. A peer whose SYN-ACK was lost
            // retransmits its SYN, which is at IRS -- one before RCV.NXT --
            // and answering that with a bare ACK tells it nothing it can use:
            // it has no connection yet, so it keeps retransmitting the SYN
            // until it gives up. Resending the SYN-ACK is what every stack this
            // one is compared against does, and it is what the differential
            // vectors expect (the same SYN twice, the same SYN-ACK twice).
            //
            // The SYN-ACK is reproduced from the TCB this connection already
            // holds, so the sequence number is identical. Regenerating it would
            // be worse than useless: a peer that has recorded the first one
            // would either fail to connect or reset.
            //
            // The bar is the same exact one as everywhere else in this file:
            // name IRS precisely. A blind sender that cannot guess the peer's
            // own ISS gets a bare ACK, and one that can has nothing to gain --
            // this resends a frame already sent, to the same peer, and creates
            // no state.
            if tcb.state == .synReceived, isRetransmissionOfTheSynWeAnswered(segment, tcb: tcb) {
                return [.sendSynAck]
            }
            return challengeACK(&challengeACKs)
        }

        // RFC 7323 §4.3's TS.Recent update, on an ACCEPTABLE segment and only
        // there. §4.3 is written against segments that pass the window test, and
        // running it earlier would let a segment the connection is about to
        // discard set the timestamp every later echo carries — and, once PAWS
        // reads TS.Recent, the value every later segment is judged against.
        tcb.updateTSRecent(from: header)

        // Step 3 (RFC 5961 §4): the SYN bit. A SYN this late in the
        // connection is either a very old duplicate or a blind injection
        // attempt; resetting the connection because of it would let any
        // off-path attacker who can guess the four-tuple kill it. Send a
        // challenge ACK instead and drop the segment.
        if header.flags.contains(.syn) {
            return challengeACK(&challengeACKs)
        }

        // Step 4: the ACK bit. RFC 9293 drops any segment with the ACK bit
        // off at this point -- a live connection past the handshake always
        // sets it, so its absence marks the segment as bogus.
        guard header.flags.contains(.ack) else {
            return [.none]
        }

        switch tcb.state {
        case .synReceived:
            // SND.UNA < SEG.ACK =< SND.NXT: our SYN|ACK is acknowledged.
            // A forward-distance range test, never a negated `lessThan` --
            // see the acceptance-test section of `SequenceNumber`.
            if header.acknowledgement.isInRange(after: tcb.sndUna, throughAndIncluding: tcb.sndNxt) {
                // Handshake retirement, not data advancement: in SYN-RECEIVED
                // the only thing sent is the SYN|ACK, so SND.NXT is ISS+1 and
                // this range admits exactly ISS+1. `Sender` does not model the
                // SYN and must not be told about it (see the type's doc
                // comment); it takes over on the ESTABLISHED arm below, from a
                // SND.UNA this line has already put on the first data byte.
                tcb.sndUna = header.acknowledgement
                tcb.state = .established
                // RFC 9293 §3.10.7.4, SYN-RECEIVED: "enter ESTABLISHED state
                // and continue processing with the variables below set to:
                // SND.WND <- SEG.WND, SND.WL1 <- SEG.SEQ, SND.WL2 <- SEG.ACK."
                //
                // This was missing, and it is the whole of the send window on
                // the passive-open path: nothing in LISTEN or SYN-RECEIVED sets
                // SND.WND otherwise, so a connection opened by a guest began
                // life with a send window of ZERO and could not transmit a byte
                // until some later segment happened to trip the window update
                // in the ESTABLISHED arm below. `Sender.segmentsToTransmit`
                // sends `min(cwnd, SND.WND)` bytes, so the first write after
                // every accepted handshake silently emitted nothing. Nothing
                // could see it until an endpoint drove the two together; see
                // `dataWrittenByTheApplicationIsSegmentedAndSent`.
                // Snd.Wind.Scale: one of the two peer-window decodes that DOES
                // take `<< tcb.sndWindScale`. Step 3 above has already returned
                // for anything carrying a SYN, so whatever reaches here is a
                // non-SYN segment and RFC 7323 §2.3's `<SYN>` exception does not
                // cover it: "The window field (SEG.WND) in the header of every
                // incoming segment, with the exception of <SYN> segments, MUST
                // be left-shifted by Snd.Wind.Shift bits before updating
                // SND.WND". See the synSent site above for the full list of four
                // and for why the other two must never take the shift.
                tcb.sndWnd = Int(header.window) << tcb.sndWindScale
                tcb.sndWl1 = header.sequence
                tcb.sndWl2 = header.acknowledgement
            } else if header.acknowledgement.lessThan(tcb.sndUna) {
                break  // old duplicate ACK of the SYN itself; ignore, continue to steps 5-6.
            } else {
                return [.sendRst(sequence: header.acknowledgement, ack: nil)]
            }

        case .established, .finWait1, .finWait2, .closeWait, .closing, .lastAck, .timeWait:
            // SND.UNA =< SEG.ACK =< SND.NXT is the acceptable-ACK window
            // (RFC 9293 §3.10.7.4). SEG.ACK == SND.UNA is inside it on
            // purpose: it advances nothing, but it still carries a window
            // update, which is how a sender escapes a zero window.
            //
            // A forward-distance range test, never a negated `lessThan`
            // (see the acceptance-test section of `SequenceNumber`). The
            // pair of negated bounds this replaces admitted SND.UNA + 2^31
            // whenever nothing was in flight -- the ordinary state of an
            // idle connection -- letting a guest drag SND.UNA half the
            // sequence space forward, past data never sent, which is exactly
            // what the bound below the guard exists to prevent.
            guard header.acknowledgement.isInRange(from: tcb.sndUna, throughAndIncluding: tcb.sndNxt) else {
                // Outside it in one of two directions. Behind SND.UNA it is
                // a duplicate ACK of data already acknowledged: ignore it
                // and carry on to steps 5-6, which may still have work to
                // do. Ahead of SND.NXT it acknowledges data that was never
                // sent: ACK (so the peer can resynchronize) and drop.
                if header.acknowledgement.lessThan(tcb.sndUna) {
                    break
                }
                // RFC 5961 §5's challenge: an acknowledgement of data this
                // connection never sent. Same budget as the other five.
                return challengeACK(&challengeACKs)
            }

            // The window update runs FIRST, before the acknowledgement is
            // handed on. `Sender.acknowledged` reads `tcb.sndWnd` to tell a
            // duplicate ACK from a window update that happens to repeat the
            // last acknowledgement number, and counting the latter as the
            // former fast-retransmits segments nothing was ever lost of. Its
            // doc comment states that ordering as the caller's obligation, and
            // this is the caller.
            if tcb.sndWl1.lessThan(header.sequence)
                || (tcb.sndWl1 == header.sequence && header.acknowledgement.isAtOrAfter(tcb.sndWl2))
            {
                // Snd.Wind.Scale: the other decode that DOES take
                // `<< tcb.sndWindScale`, and the one that carries every window
                // update for the life of the connection. Non-SYN by the same
                // step-3 argument as the SYN-RECEIVED site above.
                // `CongestionControl` commits the send decision to
                // `min(cwnd, sndWnd)` in bytes, so leaving this unscaled once a
                // scale is negotiated under-uses the path by up to 2^14.
                //
                // ## Both shifts here rely on `TCPOptionCodec`'s clamp
                //
                // Neither this site nor the SYN-RECEIVED one bounds
                // `tcb.sndWindScale`, because `TCPOptionCodec.parse` has already
                // clamped a peer's shift.cnt to RFC 7323 §2.3's maximum of 14
                // (see `TCPOptionCodec.maximumWindowScale`, and
                // `TCB.negotiateWindowScale(fromSynOptions:)`, which records it
                // and re-checks nothing either). The largest SND.WND these two
                // lines can produce is therefore 65535 << 14 = 1,073,725,440,
                // just under 2^30, and nothing here can overflow an `Int`.
                //
                // That ceiling is not a comfort margin: it is what keeps the
                // serial arithmetic meaningful. RFC 7323 §2.3: "two times the
                // maximum window size must be less than 2^31, or max window <
                // 2^30", because a sender and receiver can be out of phase by a
                // full window and `SequenceNumber`'s comparisons — and every
                // `isInRange` built on them — are only defined over less than
                // half the sequence space. A shift of 15 would still fit an
                // `Int`; what it would break is every window test in this file.
                // Anything that moves or relaxes the clamp is changing what
                // these two lines can be made to compute.
                tcb.sndWnd = Int(header.window) << tcb.sndWindScale
                tcb.sndWl1 = header.sequence
                tcb.sndWl2 = header.acknowledgement
            }

            // SND.UNA moves HERE and nowhere else on the data path: this file
            // decided the acknowledgement is acceptable (a state question,
            // where RFC 5961's hardening lives) and hands it to the single
            // advancer, which retires the queue, takes an RTT sample, feeds
            // congestion control and moves SND.UNA. Assigning `tcb.sndUna`
            // here as well would leave the sender nothing to retire: it would
            // read `advanced == 0`, classify a genuine acknowledgement as a
            // duplicate, keep every transmitted segment outstanding forever and
            // refuse every subsequent write.
            //
            // The return value is discarded because it cannot be false: it
            // guards on `isInRange(from: tcb.sndUna, throughAndIncluding:
            // tcb.sndNxt)`, the identical test the `guard` above has just
            // passed. That guard is `acknowledged`'s own, for callers that
            // reach it without coming through here, and is not a second opinion
            // this file relies on.
            // `header.window` and not `tcb.sndWnd`: RFC 5681 §3.2's
            // duplicate-ACK test is about the window this segment ADVERTISED,
            // and the update just above may deliberately have refused to take
            // it. See `Sender.acknowledged`.
            // The peer's echo of our own timestamp, when the option is in use.
            // RFC 7323 §4.1 makes the round trip it measures unambiguous, which
            // is what lets `Sender` take a sample Karn would otherwise refuse.
            var echoed: UInt32?
            if tcb.timestampsEnabled {
                for option in header.options {
                    if case .timestamps(_, let echo) = option { echoed = echo }
                }
            }
            _ = sender.acknowledged(
                upTo: header.acknowledgement, tcb: &tcb, segmentLength: segment.length,
                advertisedWindow: Int(header.window),
                echoedTimestamp: echoed, timestampClockNow: timestampClockNow)

            switch tcb.state {
            case .finWait1:
                if tcb.sndUna == tcb.sndNxt {
                    tcb.state = .finWait2
                }
            case .closing:
                if tcb.sndUna == tcb.sndNxt {
                    tcb.state = .timeWait
                    actions.append(.startTimeWait)
                }
            case .lastAck:
                if tcb.sndUna == tcb.sndNxt {
                    tcb.state = .closed
                    return [.deleteTCB]
                }
            case .timeWait:
                // Acknowledge it, and nothing more. A retransmission of the
                // peer's FIN does NOT reach here -- it fails the acceptability
                // test above and is handled there. What reaches here is any
                // acceptable segment with a plausible ACK: a bare ACK, a window
                // probe, a duplicate. Restarting the 2*MSL timer for those,
                // which is what this used to do while claiming only a FIN
                // retransmission could arrive, let a peer hold the block open
                // indefinitely by sending anything at all -- the very threat
                // `ReceiveOutcome.finReached` was made edge-triggered to close,
                // reachable by another route.
                //
                // It is also a challenge ACK by the definition this file uses --
                // an ACK for a segment that is being dropped -- so it draws on
                // the budget too. Nothing in TIME-WAIT needs it: a retransmitted
                // FIN never reaches here (it is unacceptable, and step 2 answers
                // it), so what this acknowledges is a bare ACK or a duplicate,
                // for which the peer has no use. Leaving it ungated would have
                // been a bypass with a state to reach it from.
                if challengeACKs.consume() {
                    actions.append(.sendAck)
                }
            case .established, .finWait2, .closeWait:
                break
            case .closed, .listen, .synSent, .synReceived:
                break  // unreachable: this switch only covers the cases matched above.
            }

        case .closed, .listen, .synSent:
            break  // unreachable: generalSegmentArrives is never entered in these states.
        }

        // Step 5: process the segment text. Only ESTABLISHED, FIN-WAIT-1,
        // and FIN-WAIT-2 accept new data -- in every other state reachable
        // here, the peer has already sent its FIN, so trailing data is
        // ignored rather than delivered.
        //
        // Which states accept data is a question about *state*, so it is
        // answered here. Everything after that -- whether these particular
        // bytes are in order, what that unblocks, how far RCV.NXT moves and
        // what window is left to advertise -- is a question about *bytes*,
        // so it is answered by the receiver and simply reported back. Note
        // that the switch reads `tcb.state` after step 4 may have moved
        // SYN-RECEIVED to ESTABLISHED, which is what lets a handshake-
        // completing segment carry data.
        var outcome: ReceiveOutcome?
        var finRefused = false
        switch tcb.state {
        case .established, .finWait1, .finWait2:
            let input = receiverInput(for: segment, tcb: tcb)
            finRefused = input.finRefused
            outcome = receiver.accept(input.segment, tcb: &tcb)
        case .synReceived:
            // Only reachable through the "old duplicate ACK of our SYN|ACK"
            // break above, since an acceptable ACK has already moved the
            // state to ESTABLISHED. There is no established connection to
            // deliver to yet, so the segment is dropped exactly as the
            // previous in-order-only implementation dropped it. The peer
            // retransmits.
            break
        case .closeWait, .closing, .lastAck, .timeWait:
            break  // the peer's FIN is already past; trailing data is ignored.
        case .closed, .listen, .synSent:
            break  // unreachable: generalSegmentArrives is never entered in these states.
        }

        if let outcome {
            for buffer in outcome.delivered {
                actions.append(.deliver(buffer))
            }
        }

        // `finReached` is currently implied by `shouldAck` -- a segment
        // that occupies no sequence space cannot advance RCV.NXT and so
        // cannot be the one that reaches the FIN. Kept as an explicit
        // disjunct anyway: RFC 9293 requires a FIN to be acknowledged,
        // and that requirement must not become contingent on how
        // `shouldAck` is defined tomorrow.
        //
        // `finRefused` is the third disjunct and the one that costs nothing to
        // legitimate traffic: a peer whose FIN was stripped for being out of
        // position must be told where we actually are, so that its FIN
        // retransmission -- which a peer that has sent a FIN repeats until it
        // is acknowledged -- arrives at RCV.NXT and is honoured. A bare refused
        // FIN occupies no sequence space once stripped, so without this it
        // would draw no ACK at all and the peer would wait out its RTO.
        if outcome?.shouldAck == true || outcome?.finReached == true || finRefused {
            // Delayable only when the receiver said so AND nothing else here
            // wanted an acknowledgement of its own. A refused FIN or a reached
            // FIN is an answer the peer is waiting on, not routine data flow.
            let delayable = outcome?.ackMayBeDelayed == true && outcome?.finReached != true && !finRefused
            actions.append(delayable ? .sendAckMayDelay : .sendAck)
        }

        // Step 6: the FIN bit. The *transition* is a state change and stays
        // here; deciding *when* the FIN's sequence has been reached is byte
        // arithmetic and belongs to the receiver, which reports it exactly
        // once.
        //
        // Since step 5 only lets an in-order FIN through, the segment that
        // carries the FIN and the segment that reaches it are now the same one.
        // The receiver's `finReached` is still not a restatement of that: it
        // fires only once RCV.NXT has actually advanced over every byte in
        // front of the FIN, which an in-order FIN-bearing segment does not
        // guarantee on its own (its own payload can be refused by a full
        // reassembly queue). A FIN that arrives ahead of a gap is not lost by
        // being refused here -- a peer that has sent a FIN retransmits it until
        // it is acknowledged, and the ACK step 5 sends tells it where to
        // restart. Waiting one retransmission is the entire cost of closing the
        // hole; nothing re-drives this function for a gap that has since
        // filled, and nothing needs to.
        if outcome?.finReached == true {
            switch tcb.state {
            case .synReceived, .established:
                // SYN-RECEIVED is unreachable here (see step 5's switch) but
                // is kept as RFC 9293 §3.10.7.4 writes it, so that widening
                // step 5 to that state does not silently lose the transition.
                tcb.state = .closeWait
            case .finWait1:
                if tcb.sndUna == tcb.sndNxt {
                    tcb.state = .timeWait
                    actions.append(.startTimeWait)
                } else {
                    tcb.state = .closing
                }
            case .finWait2:
                tcb.state = .timeWait
                actions.append(.startTimeWait)
            case .closeWait, .closing, .lastAck, .timeWait:
                // Already past this point; a retransmitted FIN changes nothing
                // further. TIME-WAIT is in this list rather than restarting the
                // 2*MSL timer here because it cannot reach here at all: step 5
                // does not drive the receiver in TIME-WAIT, so `outcome` is nil
                // and `finReached` is never true. That branch was dead, and it
                // was dead while carrying a security rationale, which is worse
                // than either alone -- it read as the place the timer was
                // governed while the live restart sat unguarded in step 4. The
                // restart now lives in step 2, on the retransmitted FIN, and
                // nowhere else.
                break
            case .closed, .listen, .synSent:
                break  // unreachable here.
            }
        }

        return actions.isEmpty ? [.none] : actions
    }

    // MARK: - RFC 5961 §7

    /// One challenge ACK, if the stack-wide budget has a token for it.
    ///
    /// `[.none]` and not `[]` when it does not: every early return in
    /// `generalSegmentArrives` hands back a non-empty list, and an empty one
    /// would be a second spelling of "nothing to do" for `TCPEndpoint.process`
    /// to get right.
    ///
    /// Dropped, never deferred. A challenge ACK queued behind the budget would
    /// arrive answering a segment the peer has long since moved past, and one
    /// held per suppressed segment is exactly the memory the flood was after.
    private static func challengeACK(_ budget: inout ChallengeACKBudget) -> [TCPAction] {
        budget.consume() ? [.sendAck] : [.none]
    }

    // MARK: - What the receiver is allowed to see

    /// The segment as `Receiver` should see it: trimmed to the offered window,
    /// and with a FIN that is not exactly in order stripped off.
    ///
    /// ## The FIN, hardened like the RST (RFC 5961 §3.2, applied by analogy)
    ///
    /// Step 1 above will not tear a connection down on a RST that is merely
    /// somewhere in the window; it insists on RCV.NXT exactly, and challenges
    /// anything else with an ACK. A FIN reaches the application as very nearly
    /// the same outcome — the stream is over — and it had no such check at all.
    /// A guest that could name any sequence number in a 64 KiB window, which is
    /// no guess worth the name, could send one bare FIN carrying no data and
    /// either **truncate** the stream (the FIN's position is recorded on
    /// admission and first-received-wins makes it authoritative forever, so the
    /// application gets a clean EOF mid-stream while the bytes behind the forged
    /// position are dropped) or **wedge teardown permanently** (name a position
    /// the stream never reaches and the peer's real FIN, retransmit as it may,
    /// is never acted on). Both were demonstrated. The truncation is the worse
    /// of the two: the application is told the stream ended normally.
    ///
    /// So the FIN is honoured only when the segment carrying it starts at
    /// exactly RCV.NXT and the FIN's own sequence number falls inside the
    /// window we offered. Otherwise the flag is stripped, the segment's data (if
    /// any) is processed as ordinary out-of-order or trimmed data, and the peer
    /// gets an ACK. The attacker's job is now identical for the two flags: name
    /// RCV.NXT exactly.
    ///
    /// The check reads the *arriving* segment's start, before trimming, and
    /// that ordering is load-bearing. Trimming first would move the start of any
    /// segment overlapping RCV.NXT up to RCV.NXT, and the gate would then admit
    /// a FIN from a segment that merely reached back over the left edge — which
    /// needs no knowledge of RCV.NXT at all, and would hand the whole hole back.
    ///
    /// ## The trim (RFC 9293 §3.9)
    ///
    /// `isSegmentAcceptable` admits a segment whose first *or* last byte is in
    /// the window. It bounds neither the extent nor the end, so 5000 bytes at
    /// RCV.NXT and 5000 bytes at RCV.NXT+3 both pass against a 4-byte window,
    /// and everything past the right edge would otherwise be delivered or queued
    /// on the strength of `TCPReassembler`'s quarter-of-the-sequence-space
    /// domain bound — the one limit two files' comments assert must never be the
    /// operative one. RFC 9293 §3.9 expects the segment to be trimmed instead:
    /// the portion beyond the right edge is dropped, and so is the portion below
    /// RCV.NXT, which has already been received.
    ///
    /// Trimming here rather than in `Receiver` is deliberate. The window is the
    /// state machine's to interpret — `Receiver`'s own contract is that it does
    /// not test acceptability — and doing it here keeps every comparison against
    /// RCV.WND in the file that also owns `isSegmentAcceptable` and
    /// `isInReceiveWindow`. A window comparison in `Receiver` would be the
    /// second-owner shape both files exist to avoid.
    ///
    /// ## The low side of the trim is redundant, and deliberately kept anyway
    ///
    /// Dropping the portion *below* RCV.NXT changes no observable behaviour
    /// today: `TCPReassembler.novelRanges` clips its cursor at RCV.NXT and
    /// `insert` refuses a segment that ends at or behind it, so the bytes this
    /// removes are bytes the reassembler would discard a moment later. Setting
    /// `below` to zero was falsified against the whole suite and nothing failed.
    /// It is kept because it is what makes the sentence above — nothing outside
    /// the window reaches the receiver — true of *this* function rather than
    /// true only in combination with a neighbour's silent behaviour, which is
    /// the dependency shape that has produced this stack's worst defects. It is
    /// also not the two-owner hazard that shape usually is: both sides clamp to
    /// the same boundary, so they cannot disagree about the result, only about
    /// who did it.
    ///
    /// Because no connection-level behaviour can see it,
    /// `aTrimHandsTheReceiverNothingOutsideTheWindowInEitherDirection` asserts
    /// this function's own return value, which is why it is `internal` rather
    /// than `private` (`@testable import` elevates `internal`, not `private`).
    /// The alternative was an unguarded line that reads as protection.
    ///
    /// - Returns: the segment to hand the receiver, and whether a FIN was
    ///   stripped (which owes the peer an ACK even when nothing else does).
    static func receiverInput(for segment: TCPSegment, tcb: TCB) -> (segment: Segment, finRefused: Bool) {
        let arriving = segment.reassemblySegment
        // Step 3 has already returned for anything carrying a SYN, so the
        // segment's first sequence number is its first payload byte.
        let start = arriving.sequence
        let payloadLength = arriving.payload.readableBytes

        var honourFin = false
        if let finPosition = arriving.finSequence {
            honourFin = start == tcb.rcvNxt && finPosition.inWindow(start: tcb.rcvNxt, size: tcb.rcvWnd)
        }

        let below = max(0, tcb.rcvNxt - start)
        let above = max(0, (start + payloadLength) - (tcb.rcvNxt + tcb.rcvWnd))
        let kept = max(0, payloadLength - below - above)
        var payload = ByteBuffer()
        if kept > 0 {
            payload = arriving.payload.getSlice(at: arriving.payload.readerIndex + below, length: kept) ?? ByteBuffer()
        }

        let trimmed = Segment(
            sequence: start + below,
            flags: honourFin ? arriving.flags : arriving.flags.subtracting(.fin),
            payload: payload)
        return (trimmed, arriving.flags.contains(.fin) && !honourFin)
    }

    /// Whether this segment is a retransmission of the peer's FIN — the one
    /// this connection has already processed, which by construction sits at
    /// `RCV.NXT - 1`, since reaching a FIN steps RCV.NXT one past it.
    ///
    /// Only TIME-WAIT asks. It is the one state where RFC 9293 §3.10.7.4 wants
    /// an *unacceptable* segment to do more than draw an ACK, and the position
    /// it must match is exact, so a peer cannot refresh a TIME-WAIT block
    /// without knowing where the connection actually is.
    /// Whether this segment is a retransmission of the very SYN this connection
    /// answered: a bare SYN, occupying exactly its own sequence number, sitting
    /// at IRS.
    ///
    /// Only SYN-RECEIVED asks. `segment.length == 1` is what makes "bare"
    /// exact — a SYN carrying data or a FIN is not a retransmission of
    /// anything this connection has seen, and must not be answered as one.
    private static func isRetransmissionOfTheSynWeAnswered(_ segment: TCPSegment, tcb: TCB) -> Bool {
        let header = segment.header
        return header.flags.contains(.syn) && !header.flags.contains(.ack)
            && header.sequence == tcb.irs && segment.length == 1
    }

    private static func isRetransmissionOfProcessedFin(_ segment: TCPSegment, tcb: TCB) -> Bool {
        guard let finPosition = segment.reassemblySegment.finSequence else { return false }
        return finPosition + 1 == tcb.rcvNxt
    }

    // MARK: - Acceptability tests

    /// RFC 9293 §3.10.7.4's segment acceptability test.
    private static func isSegmentAcceptable(_ segment: TCPSegment, tcb: TCB) -> Bool {
        let header = segment.header
        let segLen = segment.length

        if tcb.rcvWnd == 0 {
            return segLen == 0 && header.sequence == tcb.rcvNxt
        }
        if segLen == 0 {
            return header.sequence.inWindow(start: tcb.rcvNxt, size: tcb.rcvWnd)
        }
        return header.sequence.inWindow(start: tcb.rcvNxt, size: tcb.rcvWnd)
            || (header.sequence + (segLen - 1)).inWindow(start: tcb.rcvNxt, size: tcb.rcvWnd)
    }

    /// RFC 5961 §3.2's (looser, RST-specific) in-window test: a sequence
    /// number is close enough to be worth taking seriously as a reset,
    /// distinct from the general data-acceptability test above.
    private static func isInReceiveWindow(_ sequence: SequenceNumber, tcb: TCB) -> Bool {
        if tcb.rcvWnd == 0 {
            return sequence == tcb.rcvNxt
        }
        return sequence.inWindow(start: tcb.rcvNxt, size: tcb.rcvWnd)
    }
}

extension TCPStateMachine {
    /// RFC 9293 §3.10.4's "CLOSE Call": an application-initiated close, not
    /// a segment arrival. `receive(segment:on:receiver:)` above is the only entry
    /// point RFC 9293's "SEGMENT ARRIVES" event maps onto; this is the
    /// other half of the state diagram's edges, driven by the local
    /// application rather than the network, and is not one of the
    /// interfaces the brief named -- it exists because "local close
    /// (established -> finWait1)" is one of the transitions the brief
    /// explicitly asks to be covered, and nothing reachable through
    /// `receive` can produce it.
    ///
    /// The three transitions that queue a FIN return `.sendFin` explicitly.
    /// Bumping `sndNxt` to reserve the FIN's sequence number is not on its
    /// own a signal to send anything: leaving the sender to infer "there is
    /// an unsent FIN" from `state` and `sndNxt` would be an unwritten
    /// contract between two files, and a sender that got it subtly wrong
    /// would produce connections that open correctly and then never close.
    static func close(on tcb: inout TCB) -> [TCPAction] {
        switch tcb.state {
        case .listen, .synSent:
            tcb.state = .closed
            return [.deleteTCB]
        case .synReceived, .established:
            tcb.sndNxt = tcb.sndNxt + 1  // our FIN consumes a sequence number
            tcb.state = .finWait1
            return [.sendFin]
        case .closeWait:
            tcb.sndNxt = tcb.sndNxt + 1
            tcb.state = .lastAck
            return [.sendFin]
        case .finWait1, .finWait2, .closing, .lastAck, .timeWait, .closed:
            return []  // already closing or closed; a second CLOSE has no effect.
        }
    }
}
