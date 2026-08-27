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
/// `length` below is the module's only definition of SEG.LEN.
/// `TCPSegment.length` used to compute it independently; the two have since
/// been collapsed, and that property is now a projection onto this one. Two
/// copies could drift, and a drift between them would mean the acceptability
/// test and the reassembler's gap arithmetic disagreeing about how much
/// sequence space a segment occupies.
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
    ///
    /// Like `length`, this is the module's **only** definition of the quantity.
    /// It was briefly dead code while `TCPReassembler` computed the same thing
    /// from its own offset arithmetic (`rcvNxt + dataEnd`) — the same SEG.LEN
    /// duplication this file's header records as collapsed, reproduced one
    /// field over. It has been made live rather than deleted because three
    /// places now need "where does this segment's FIN sit": the reassembler,
    /// which records it; `TCPStateMachine`'s in-order-FIN gate, which decides
    /// whether it may be recorded at all; and that machine's TIME-WAIT test for
    /// a retransmission of a FIN already processed. Three independent
    /// derivations of one sequence number is exactly how the two halves of a
    /// FIN decision come to disagree.
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
