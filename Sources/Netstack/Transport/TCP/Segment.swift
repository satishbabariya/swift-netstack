import NIOCore

/// A TCP segment reduced to the three things sequence-space arithmetic needs:
/// where it starts, whether it carries a SYN or a FIN, and its payload.
///
/// Deliberately smaller than `TCPSegment`, which carries a whole parsed
/// `TCPHeader`. Reassembly has no use for ports, windows, or options, and
/// carrying them would mean the reassembler's tests had to synthesise a
/// header (and a checksum) to express "ten bytes at sequence 1000". The two
/// are not rivals: `TCPSegment.reassemblySegment` projects one into the
/// other, so the seam between them is written down once.
///
/// `TCPSegment.length` computes SEG.LEN independently of `length` below.
/// That duplication is deliberate only in the sense that it was left alone:
/// `TCPStateMachine.swift` is owned by another change in flight this round,
/// so collapsing the two definitions into one is a follow-up, not part of
/// this task. Two copies of SEG.LEN in one module can drift.
public struct Segment: Sendable {
    public let sequence: SequenceNumber
    public let flags: TCPFlags
    public let payload: ByteBuffer

    public init(sequence: SequenceNumber, flags: TCPFlags, payload: ByteBuffer = ByteBuffer()) {
        self.sequence = sequence
        self.flags = flags
        self.payload = payload
    }

    /// SEG.LEN (RFC 9293 §3.10.7.4): payload bytes plus one for each of SYN
    /// and FIN — the segment's footprint in sequence space, which is what gap
    /// arithmetic must use. A bare FIN occupies one sequence number despite
    /// carrying no data, so a reassembler that measured segments by
    /// `payload.readableBytes` would compute a zero-width range for it and
    /// never notice it at all.
    public var length: Int {
        payload.readableBytes + (flags.contains(.syn) ? 1 : 0) + (flags.contains(.fin) ? 1 : 0)
    }

    /// Where this segment's payload starts in sequence space. A SYN occupies
    /// the segment's first sequence number, so on a SYN-bearing segment the
    /// data begins one past `sequence` — off by one from `sequence` itself,
    /// which is the whole reason this is spelled out rather than assumed.
    public var dataSequence: SequenceNumber {
        flags.contains(.syn) ? sequence + 1 : sequence
    }

    /// The sequence number the FIN occupies, if this segment carries one:
    /// SEG.SEQ + SEG.LEN - 1, i.e. immediately after the last payload byte.
    public var finSequence: SequenceNumber? {
        flags.contains(.fin) ? dataSequence + payload.readableBytes : nil
    }
}

extension TCPSegment {
    /// This segment as the reassembler sees it. The projection exists so the
    /// seam between the state machine's segment type and the reassembler's is
    /// written down in one place instead of being re-derived (and eventually
    /// mis-derived) at each call site.
    public var reassemblySegment: Segment {
        Segment(sequence: header.sequence, flags: header.flags, payload: payload)
    }
}
