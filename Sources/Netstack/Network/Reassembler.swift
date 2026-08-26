import NIOCore

/// Reassembles IPv4 fragments into whole datagrams.
///
/// Bounded on two axes, because an incomplete datagram is otherwise an
/// unbounded allocation a peer controls: each pending datagram expires after
/// `timeout`, and the total held across all of them is capped at
/// `memoryLimit`, evicting oldest-first.
///
/// A correctly fragmenting sender never produces two fragments that claim
/// the same byte, so any incoming fragment whose byte range overlaps a
/// range already accepted for that datagram — an exact duplicate, a partial
/// overlap, or a second "final fragment" that disagrees with the first
/// about where the datagram ends — is dropped outright rather than merged.
/// Data that arrived first always wins; nothing already accepted is ever
/// silently rewritten by a later fragment. This is what closes the classic
/// overlapping-fragment ("teardrop") rewrite, and it also keeps a flood of
/// duplicate fragments from inflating this reassembler's own memory
/// accounting to evict unrelated, legitimate datagrams.
public final class Reassembler {
    /// RFC 791: total length is a 16-bit field.
    private static let maximumDatagram = 65535

    private struct Key: Hashable {
        let source: IPv4Address
        let destination: IPv4Address
        let identification: UInt16
        let protocolNumber: UInt8
    }

    private struct Pending {
        var header: IPv4Header
        var received: [(offset: Int, bytes: ByteBuffer)] = []
        var holdingBytes = 0
        /// Set when the fragment carrying the end of the datagram arrives.
        var totalLength: Int?
        let startedAt: NIODeadline
    }

    private let clock: NetstackClock
    private let timeout: TimeAmount
    private let memoryLimit: Int
    private var pending: [Key: Pending] = [:]
    private var heldBytes = 0

    public init(clock: NetstackClock, timeout: TimeAmount = .seconds(30), memoryLimit: Int = 4 * 1024 * 1024) {
        self.clock = clock
        self.timeout = timeout
        self.memoryLimit = memoryLimit
    }

    public var pendingCount: Int { pending.count }

    /// Feed one fragment in. Returns the whole datagram once it is complete,
    /// nil while it is still missing pieces or the fragment was rejected.
    public func process(header: IPv4Header, payload: ByteBuffer) -> (IPv4Header, ByteBuffer)? {
        let isFragment = header.flags.contains(.moreFragments) || header.fragmentOffset > 0
        guard isFragment else { return (header, payload) }

        let offset = header.fragmentOffset
        let length = payload.readableBytes
        let end = offset + length
        guard end <= Self.maximumDatagram else { return nil }

        let key = Key(
            source: header.source,
            destination: header.destination,
            identification: header.identification,
            protocolNumber: header.protocolNumber.rawValue
        )

        var entry = pending[key] ?? Pending(header: header, startedAt: clock.now())

        // Reject any fragment that overlaps a byte range already accepted
        // for this datagram (including an exact duplicate), and reject a
        // second "final fragment" that disagrees with the first about where
        // the datagram ends. First-received data always wins.
        let overlapsExisting = entry.received.contains { existing in
            offset < existing.offset + existing.bytes.readableBytes && existing.offset < end
        }
        guard !overlapsExisting else { return nil }
        if !header.flags.contains(.moreFragments), let existingTotal = entry.totalLength, existingTotal != end {
            return nil
        }

        entry.received.append((offset: offset, bytes: payload))
        entry.holdingBytes += length
        heldBytes += length
        if !header.flags.contains(.moreFragments) {
            entry.totalLength = end
        }
        pending[key] = entry

        if let complete = assemble(key: key) {
            return complete
        }
        enforceMemoryLimit()
        return nil
    }

    /// Drop every datagram that has been incomplete for longer than the
    /// timeout. Called from the stack's periodic maintenance timer.
    public func reapExpired() {
        let deadline = clock.now()
        for (key, entry) in pending where entry.startedAt + timeout <= deadline {
            heldBytes -= entry.holdingBytes
            pending.removeValue(forKey: key)
        }
    }

    private func assemble(key: Key) -> (IPv4Header, ByteBuffer)? {
        guard var entry = pending[key], let totalLength = entry.totalLength else { return nil }

        // Contiguous from zero to totalLength, or we are still missing a hole.
        entry.received.sort { $0.offset < $1.offset }
        var covered = 0
        for piece in entry.received {
            guard piece.offset <= covered else { return nil }
            covered = max(covered, piece.offset + piece.bytes.readableBytes)
        }
        guard covered >= totalLength else { return nil }

        var assembled = ByteBufferAllocator().buffer(capacity: totalLength)
        assembled.writeRepeatingByte(0, count: totalLength)
        for piece in entry.received {
            var bytes = piece.bytes
            let length = min(bytes.readableBytes, totalLength - piece.offset)
            guard length > 0, let slice = bytes.readSlice(length: length) else { continue }
            assembled.setBuffer(slice, at: piece.offset)
        }

        heldBytes -= entry.holdingBytes
        pending.removeValue(forKey: key)

        var header = entry.header
        header.flags.remove(.moreFragments)
        header.fragmentOffset = 0
        header.totalLength = UInt16(header.headerLength + totalLength)
        return (header, assembled)
    }

    private func enforceMemoryLimit() {
        while heldBytes > memoryLimit, !pending.isEmpty {
            guard let oldest = pending.min(by: { $0.value.startedAt < $1.value.startedAt }) else { return }
            heldBytes -= oldest.value.holdingBytes
            pending.removeValue(forKey: oldest.key)
        }
    }
}
