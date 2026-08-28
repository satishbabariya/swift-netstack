import NIOCore

/// The handshake's own round trip: when our half of it went out, how many times,
/// and whether what came back may be turned into an RTT sample.
///
/// ## Why the endpoint owns this and `Sender` does not
///
/// `Sender` models a byte stream and no control flags, deliberately: Task 14 of
/// Plan 2 measured what feeding it the SYN costs -- `cwnd` grows by a byte and a
/// stray one-byte segment can reach the wire -- so the SYN is not an `InFlight`
/// record and is not going to become one. The handshake is `TCPEndpoint`'s, so
/// its timing is too, and the only thing that crosses back into `Sender` is the
/// finished sample, through `Sender.measureHandshakeRoundTrip`.
///
/// ## What the sample is worth, which is not what it looks like
///
/// Almost nothing for its own value, and a great deal for its position. A real
/// handshake here takes microseconds and the RTO floor is a full second (RFC
/// 6298 §2.4), so no handshake sample this stack ever takes moves the first RTO
/// off the floor. What it moves is the sample AFTER it. Without one, the first
/// data sample takes RFC 6298 §2.2's first-measurement path, which is
/// deliberately the conservative one --
///
///     SRTT = R, RTTVAR = R / 2, so RTO = R + 4 * (R / 2) = 3R
///
/// -- and with one, the same measurement takes §2.3's Jacobson update instead.
/// The differential against gVisor measured the difference as a first FIN
/// retransmission at +2.148 s against gVisor's +1.000 s, from a 716 ms sample.
///
/// That is worth writing down, because from the outside this type looks
/// pointless: the next reader sees a microsecond sample folded in under a
/// one-second floor and deletes it as a no-op. The floor is exactly why it is
/// not a no-op.
///
/// ## Karn's algorithm applies to the handshake
///
/// RFC 6298 §3: no RTT sample may be computed from a segment that was
/// retransmitted, because the reply may be answering either transmission and a
/// sample measured against the wrong one corrupts the RTO for the whole
/// connection, not merely for the handshake. So this counts transmissions and
/// refuses a sample at two or more.
///
/// **A passive open can reach that count and an active open cannot -- and the
/// second half of that is true by ABSENCE rather than by construction.** Our
/// SYN-ACK goes out again when the peer's SYN arrives a second time in
/// SYN-RECEIVED (`TCPStateMachine`'s `isRetransmissionOfTheSynWeAnswered`),
/// which is peer-driven and needs no timer here. Our SYN goes out exactly once
/// only because this stack has no SYN retransmission timer at all:
/// `TCPEndpoint` drives one for data and one for the FIN and none for the
/// handshake. Anyone adding one must route it through `recordTransmission` too,
/// or the active open quietly begins taking ambiguous samples and not one test
/// in this package fails.
struct HandshakeRTT: Sendable, Equatable {
    private var sentAt: NIODeadline?
    private var transmissions = 0

    /// Our SYN (active open) or SYN-ACK (passive open) has just gone on the wire.
    ///
    /// The FIRST transmission's time is the one kept. Which one is kept cannot
    /// change any sample this type hands out -- at two transmissions there is no
    /// sample at all -- but keeping the first makes the recorded time mean "when
    /// this handshake started" rather than "when it was last repeated", which is
    /// what someone reading it in a debugger will assume it means.
    mutating func recordTransmission(at now: NIODeadline) {
        transmissions += 1
        if sentAt == nil { sentAt = now }
    }

    /// The sample to fold into the estimator, or `nil` when there is none to be
    /// had.
    ///
    /// Three ways to get nothing back, and the third is the one that disappears
    /// without a trace:
    ///
    /// 1. Nothing was ever recorded, so no handshake of ours is outstanding.
    /// 2. Karn: our half went out more than once and the reply is ambiguous.
    /// 3. **The round trip measured zero or negative.** `RTTEstimator.measure`
    ///    already discards such a sample, silently, so returning it would reach
    ///    the same outcome by a longer route -- but the case is worth naming
    ///    here because it is reachable and it fails invisibly. A host-local
    ///    handshake completes in microseconds; under a clock whose granularity
    ///    is coarser than that, the two deadlines are equal, the sample is zero,
    ///    and everything this type exists for vanishes with no error raised
    ///    anywhere. It is why the vectors drive handshakes of hundreds of
    ///    milliseconds: not realism, but the only way the measurement is
    ///    observable at all.
    func sample(at now: NIODeadline) -> TimeAmount? {
        guard transmissions == 1, let sentAt else { return nil }
        let elapsed = now - sentAt
        guard elapsed.nanoseconds > 0 else { return nil }
        return elapsed
    }
}
