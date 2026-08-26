import NIOCore

/// A received TCP segment: header plus payload bytes, exactly what a
/// caller has after `TCPHeader.parse` and slicing off the header/options.
/// `TCPHeader` alone carries no length information -- TCP has no length
/// field of its own, so a header by itself cannot answer "how many bytes
/// does this segment occupy in the sequence space", which the state
/// machine needs both for the acceptability test (RFC 9293 §3.10.7.4) and
/// to build `.deliver` actions. This is the one addition beyond what the
/// brief's interface list named; it is unavoidable plumbing, not a design
/// choice, since `receive(segment:on:)` takes a single `segment` argument.
public struct TCPSegment: Sendable {
    public var header: TCPHeader
    public var payload: ByteBuffer

    public init(header: TCPHeader, payload: ByteBuffer = ByteBuffer()) {
        self.header = header
        self.payload = payload
    }

    /// SEG.LEN (RFC 9293 §3.10.7.4): payload bytes, plus one each for SYN
    /// and FIN, since both consume a sequence number of their own.
    var length: Int {
        payload.readableBytes + (header.flags.contains(.syn) ? 1 : 0) + (header.flags.contains(.fin) ? 1 : 0)
    }
}

/// RFC 9293's TCP state machine. `receive(segment:on:)` is the "SEGMENT
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
public struct TCPStateMachine {
    public static func receive(segment: TCPSegment, on tcb: inout TCB) -> [TCPAction] {
        switch tcb.state {
        case .closed:
            return closedStateSegmentArrives(segment: segment)
        case .listen:
            return listenStateSegmentArrives(segment: segment, tcb: &tcb)
        case .synSent:
            return synSentStateSegmentArrives(segment: segment, tcb: &tcb)
        case .synReceived, .established, .finWait1, .finWait2, .closeWait, .closing, .lastAck, .timeWait:
            return generalSegmentArrives(segment: segment, tcb: &tcb)
        }
    }

    // MARK: - CLOSED (RFC 9293 §3.10.7.1)

    /// Not reachable through any test in this task -- a caller has no TCB
    /// to invoke `receive` on for a connection that was never opened -- but
    /// kept faithful to the RFC for the sake of completeness, and because a
    /// TCB legitimately reaches `.closed` mid-flight (e.g. LAST-ACK + ACK)
    /// and could in principle see one more stray segment after that.
    private static func closedStateSegmentArrives(segment: TCPSegment) -> [TCPAction] {
        let header = segment.header
        if header.flags.contains(.rst) {
            return [.none]
        }
        if header.flags.contains(.ack) {
            return [.sendRst(sequence: header.acknowledgement)]
        }
        return [.sendRst(sequence: SequenceNumber(0))]
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
            return [.sendRst(sequence: header.acknowledgement)]
        }

        // Third check for a SYN: this is a passive open. Security/
        // compartment and precedence checks from the RFC are out of scope
        // for this stack (IPv4 only, no precedence field).
        if header.flags.contains(.syn) {
            tcb.irs = header.sequence
            tcb.rcvNxt = header.sequence + 1
            tcb.sndUna = tcb.iss
            tcb.sndNxt = tcb.iss + 1
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
        if header.flags.contains(.ack) {
            let ack = header.acknowledgement
            let ackTooOld = ack.lessThan(tcb.iss) || ack == tcb.iss
            let ackTooNew = tcb.sndNxt.lessThan(ack)
            if ackTooOld || ackTooNew {
                if header.flags.contains(.rst) {
                    return [.none]
                }
                return [.sendRst(sequence: ack)]
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
            if header.flags.contains(.ack), ackAcceptable {
                tcb.sndUna = header.acknowledgement
            }

            if tcb.iss.lessThan(tcb.sndUna) {
                // Our SYN has been acknowledged: the handshake is complete.
                tcb.state = .established
                tcb.sndWnd = Int(header.window)
                tcb.sndWl1 = header.sequence
                tcb.sndWl2 = header.acknowledgement
                return [.sendAck]
            }

            // Simultaneous open: the peer's SYN arrived before it had
            // acknowledged ours. Answer with our own SYN|ACK and wait in
            // SYN-RECEIVED for it to be acknowledged in turn.
            tcb.state = .synReceived
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
    private static func generalSegmentArrives(segment: TCPSegment, tcb: inout TCB) -> [TCPAction] {
        let header = segment.header
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
        if header.flags.contains(.rst) {
            guard isInReceiveWindow(header.sequence, tcb: tcb) else {
                return [.none]
            }
            if header.sequence == tcb.rcvNxt {
                tcb.state = .closed
                return [.deleteTCB]
            }
            return [.sendAck]
        }

        // Step 2 (RFC 9293 §3.10.7.4): sequence number acceptability for
        // everything that is not a RST. An unacceptable segment is ACKed
        // (so the peer can resynchronize on RCV.NXT) and dropped -- it
        // must not be allowed to touch RCV.NXT or anything else in the
        // TCB, or a peer could inject data anywhere in the stream.
        guard isSegmentAcceptable(segment, tcb: tcb) else {
            return [.sendAck]
        }

        // Step 3 (RFC 5961 §4): the SYN bit. A SYN this late in the
        // connection is either a very old duplicate or a blind injection
        // attempt; resetting the connection because of it would let any
        // off-path attacker who can guess the four-tuple kill it. Send a
        // challenge ACK instead and drop the segment.
        if header.flags.contains(.syn) {
            return [.sendAck]
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
            if tcb.sndUna.lessThan(header.acknowledgement) && !tcb.sndNxt.lessThan(header.acknowledgement) {
                tcb.sndUna = header.acknowledgement
                tcb.state = .established
            } else if header.acknowledgement.lessThan(tcb.sndUna) {
                break  // old duplicate ACK of the SYN itself; ignore, continue to steps 5-6.
            } else {
                return [.sendRst(sequence: header.acknowledgement)]
            }

        case .established, .finWait1, .finWait2, .closeWait, .closing, .lastAck, .timeWait:
            // An ACK beyond SND.NXT acknowledges data that was never sent;
            // honouring it would advance SND.UNA past unsent data. Reject
            // it (ACK, drop) rather than accept it.
            if header.acknowledgement.lessThan(tcb.sndUna) {
                break  // duplicate ACK of already-acknowledged data; ignore.
            }
            guard !tcb.sndNxt.lessThan(header.acknowledgement) else {
                return [.sendAck]
            }

            tcb.sndUna = header.acknowledgement
            if tcb.sndWl1.lessThan(header.sequence)
                || (tcb.sndWl1 == header.sequence && !header.acknowledgement.lessThan(tcb.sndWl2)) {
                tcb.sndWnd = Int(header.window)
                tcb.sndWl1 = header.sequence
                tcb.sndWl2 = header.acknowledgement
            }

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
                // Only a retransmission of the remote's already-processed
                // FIN reaches here; re-ACK it and restart the 2*MSL timer.
                actions.append(.sendAck)
                actions.append(.startTimeWait)
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
        if segment.payload.readableBytes > 0 {
            switch tcb.state {
            case .established, .finWait1, .finWait2:
                if header.sequence == tcb.rcvNxt {
                    tcb.rcvNxt = tcb.rcvNxt + segment.payload.readableBytes
                    actions.append(.deliver(segment.payload))
                    actions.append(.sendAck)
                }
            // An out-of-order segment that is merely in-window (its start
            // is ahead of RCV.NXT) is accepted by step 2 above but not
            // delivered here -- reassembly of out-of-order data is out of
            // this task's scope (see `Reassembler`).
            default:
                break
            }
        }

        // Step 6: the FIN bit. Only recognised once it is the next
        // in-order byte -- an out-of-order FIN is left for a later segment
        // to complete the sequence up to it.
        if header.flags.contains(.fin), header.sequence + segment.payload.readableBytes == tcb.rcvNxt {
            tcb.rcvNxt = tcb.rcvNxt + 1
            actions.append(.sendAck)

            switch tcb.state {
            case .synReceived, .established:
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
            case .closeWait, .closing, .lastAck:
                break  // already past this point; a retransmitted FIN changes nothing further.
            case .timeWait:
                actions.append(.startTimeWait)  // restart the 2*MSL timer.
            case .closed, .listen, .synSent:
                break  // unreachable here.
            }
        }

        return actions.isEmpty ? [.none] : actions
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
    /// a segment arrival. `receive(segment:on:)` above is the only entry
    /// point RFC 9293's "SEGMENT ARRIVES" event maps onto; this is the
    /// other half of the state diagram's edges, driven by the local
    /// application rather than the network, and is not one of the
    /// interfaces the brief named -- it exists because "local close
    /// (established -> finWait1)" is one of the transitions the brief
    /// explicitly asks to be covered, and nothing reachable through
    /// `receive` can produce it.
    public static func close(on tcb: inout TCB) -> [TCPAction] {
        switch tcb.state {
        case .listen, .synSent:
            tcb.state = .closed
            return [.deleteTCB]
        case .synReceived, .established:
            tcb.sndNxt = tcb.sndNxt + 1  // our FIN consumes a sequence number
            tcb.state = .finWait1
            return []
        case .closeWait:
            tcb.sndNxt = tcb.sndNxt + 1
            tcb.state = .lastAck
            return []
        case .finWait1, .finWait2, .closing, .lastAck, .timeWait, .closed:
            return []  // already closing or closed; a second CLOSE has no effect.
        }
    }
}
