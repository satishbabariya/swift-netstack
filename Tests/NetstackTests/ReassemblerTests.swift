import Foundation
import NIOCore
import Testing

@testable import Netstack

/// Peak resident set size in bytes, as `getrusage` reports it on Darwin.
/// Used to measure REAL retained memory rather than trusting the
/// reassembler's own accounting, which is exactly the thing under test.
private func peakResidentBytes() -> Int {
    var info = rusage()
    getrusage(RUSAGE_SELF, &info)
    return info.ru_maxrss
}

private func fragment(id: UInt16, offset: Int, more: Bool, bytes: [UInt8]) -> (IPv4Header, ByteBuffer) {
    var header = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp,
        payloadLength: bytes.count
    )
    header.identification = id
    header.fragmentOffset = offset
    header.flags = more ? [.moreFragments] : []
    return (header, ByteBuffer(bytes: bytes))
}

/// A fragment whose header carries IPv4 options (IHL 6, a 24-byte header),
/// built from raw wire bytes and parsed through `IPv4Header.parse` — the
/// only way to get a `headerLength` other than the minimum 20, since its
/// setter is private. Options are NOP NOP NOP EOL (0x01 0x01 0x01 0x00).
private func fragmentWithOptions(id: UInt16, offset: Int, more: Bool, payloadLength: Int) -> (IPv4Header, ByteBuffer) {
    let headerLength = 24
    var bytes = [UInt8](repeating: 0, count: headerLength)
    bytes[0] = 0x46  // version 4, IHL 6 (24-byte header)
    bytes[1] = 0x00  // DSCP

    let totalLength = UInt16(headerLength + payloadLength)
    bytes[2] = UInt8(totalLength >> 8)
    bytes[3] = UInt8(totalLength & 0xff)

    bytes[4] = UInt8(id >> 8)
    bytes[5] = UInt8(id & 0xff)

    let offsetWords = UInt16(offset / 8)
    let flagsAndOffset = (more ? UInt16(0x2000) : 0) | offsetWords
    bytes[6] = UInt8(flagsAndOffset >> 8)
    bytes[7] = UInt8(flagsAndOffset & 0xff)

    bytes[8] = 64  // TTL
    bytes[9] = IPProtocol.udp.rawValue
    // bytes[10...11] checksum, filled in below.

    let source = IPv4Address("192.168.127.2")!
    let destination = IPv4Address("192.168.127.1")!
    bytes.replaceSubrange(12..<16, with: source.bytes)
    bytes.replaceSubrange(16..<20, with: destination.bytes)
    bytes[20] = 0x01  // NOP
    bytes[21] = 0x01  // NOP
    bytes[22] = 0x01  // NOP
    bytes[23] = 0x00  // EOL

    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)

    let payload = Array(repeating: UInt8(0xaa), count: payloadLength)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes + payload))
    let header = IPv4Header.parse(&packet)!
    return (header, packet.payload)
}

@Test func anUnfragmentedPacketPassesStraightThrough() {
    let reassembler = Reassembler(clock: ManualClock())
    let (header, payload) = fragment(id: 1, offset: 0, more: false, bytes: [0x01, 0x02])
    let result = reassembler.process(header: header, payload: payload)
    #expect(result != nil)
    #expect(Array(result!.1.readableBytesView) == [0x01, 0x02])
    #expect(reassembler.pendingCount == 0)
}

@Test func reassemblesFragmentsInOrder() {
    let reassembler = Reassembler(clock: ManualClock())
    let first = fragment(id: 7, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    let second = fragment(id: 7, offset: 8, more: false, bytes: [0xbb, 0xbb])

    #expect(reassembler.process(header: first.0, payload: first.1) == nil)
    #expect(reassembler.pendingCount == 1)

    let result = reassembler.process(header: second.0, payload: second.1)
    #expect(result != nil)
    #expect(result!.1.readableBytes == 10)
    #expect(Array(result!.1.readableBytesView.suffix(2)) == [0xbb, 0xbb])
    #expect(reassembler.pendingCount == 0)
}

@Test func reassemblesFragmentsOutOfOrder() {
    let reassembler = Reassembler(clock: ManualClock())
    let last = fragment(id: 9, offset: 16, more: false, bytes: [0xcc])
    let middle = fragment(id: 9, offset: 8, more: true, bytes: Array(repeating: UInt8(0xbb), count: 8))
    let first = fragment(id: 9, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))

    #expect(reassembler.process(header: last.0, payload: last.1) == nil)
    #expect(reassembler.process(header: middle.0, payload: middle.1) == nil)
    let result = reassembler.process(header: first.0, payload: first.1)

    #expect(result != nil)
    let bytes = Array(result!.1.readableBytesView)
    #expect(bytes.count == 17)
    #expect(bytes[0] == 0xaa)
    #expect(bytes[8] == 0xbb)
    #expect(bytes[16] == 0xcc)
}

@Test func keepsDatagramsWithDifferentIdentificationsApart() {
    let reassembler = Reassembler(clock: ManualClock())
    let a = fragment(id: 1, offset: 0, more: true, bytes: Array(repeating: UInt8(0x11), count: 8))
    let b = fragment(id: 2, offset: 0, more: true, bytes: Array(repeating: UInt8(0x22), count: 8))
    _ = reassembler.process(header: a.0, payload: a.1)
    _ = reassembler.process(header: b.0, payload: b.1)
    #expect(reassembler.pendingCount == 2)

    let aTail = fragment(id: 1, offset: 8, more: false, bytes: [0x11])
    let result = reassembler.process(header: aTail.0, payload: aTail.1)
    #expect(result?.1.readableBytes == 9)
    #expect(reassembler.pendingCount == 1)
}

@Test func expiresIncompleteDatagrams() {
    let clock = ManualClock()
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30))
    let first = fragment(id: 5, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    _ = reassembler.process(header: first.0, payload: first.1)
    #expect(reassembler.pendingCount == 1)

    clock.advance(by: .seconds(31))
    reassembler.reapExpired()
    #expect(reassembler.pendingCount == 0)

    // The late tail must not resurrect the discarded datagram.
    let second = fragment(id: 5, offset: 8, more: false, bytes: [0xbb])
    #expect(reassembler.process(header: second.0, payload: second.1) == nil)
}

@Test func evictsTheOldestWhenOverTheMemoryLimit() {
    let clock = ManualClock()
    // Each 8-byte fragment is charged `perFragmentOverhead` on top of its
    // payload length (see `Reassembler`'s doc comment on why); size the cap
    // for exactly 3 entries so 5 insertions still evict the oldest two.
    let entryCost = 8 + Reassembler.perFragmentOverhead
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30), memoryLimit: entryCost * 3)
    for id in UInt16(1)...UInt16(5) {
        let f = fragment(id: id, offset: 0, more: true, bytes: Array(repeating: UInt8(id), count: 8))
        _ = reassembler.process(header: f.0, payload: f.1)
        clock.advance(by: .milliseconds(1))
    }
    // 5 entries exceed the 3-entry cap; the oldest two are evicted.
    #expect(reassembler.pendingCount == 3)
}

@Test func rejectsAFragmentThatWouldOverrunTheMaximumDatagram() {
    // The 65535 limit covers header + payload. A payload that fits the
    // limit on its own but overruns it once the 20-byte header is added
    // must be rejected at admission — at assembly the conversion to
    // UInt16 is non-failable and would trap the process.
    let reassembler = Reassembler(clock: ManualClock())
    let head = fragment(id: 40, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 65512))
    // `process` returns nil for any incomplete, still-pending fragment
    // whether it was accepted or rejected, so that alone proves nothing.
    // pendingCount confirms this one really was accepted.
    #expect(reassembler.process(header: head.0, payload: head.1) == nil)
    #expect(reassembler.pendingCount == 1)

    // end = 65520; 65520 + 20 > 65535, so this must be refused.
    let tail = fragment(id: 40, offset: 65512, more: false, bytes: Array(repeating: UInt8(0xbb), count: 8))
    #expect(reassembler.process(header: tail.0, payload: tail.1) == nil)
    #expect(reassembler.pendingCount == 1)   // still incomplete, not assembled
}

@Test func rejectsASingleFragmentWhosePayloadAloneExceedsTheMaximum() {
    // A single fragment whose payload alone already exceeds 65535 must be
    // caught even before the header is added in. Pinned separately from the
    // header+payload case above so that if the admission bound is ever split
    // into two conditions, this input still has a test that catches it.
    let reassembler = Reassembler(clock: ManualClock())
    let bad = fragment(id: 3, offset: 65528, more: false, bytes: Array(repeating: UInt8(0), count: 16))
    #expect(reassembler.process(header: bad.0, payload: bad.1) == nil)
    #expect(reassembler.pendingCount == 0)
}

@Test func aFirstFragmentWithOptionsCannotOverrunTheDatagramLimit() {
    // The stored entry header is fixed by the fragment that creates the
    // entry and may carry options; totalLength comes from the terminator.
    // Bounding each fragment against its OWN header lets three
    // individually-admissible fragments overflow at assembly, which traps.
    //
    // The datagram totals 65515 payload bytes: 20 + 65515 == 65535 fits, but
    // 24 + 65515 == 65539 does not. A fragmenting sender never actually
    // splits a datagram this way (only the first fragment ever carries the
    // original header, options included, and IP fragmentation itself is
    // rare at all) — this is a hostile construction, not a valid multi-hop
    // fragmentation pattern.
    let reassembler = Reassembler(clock: ManualClock())

    // Creates the entry. Its 24-byte header (options) becomes entry.header.
    let head = fragmentWithOptions(id: 60, offset: 0, more: true, payloadLength: 15)
    #expect(reassembler.process(header: head.0, payload: head.1) == nil)
    #expect(reassembler.pendingCount == 1)

    // Ordinary 20-byte header. Its OWN header + end (20 + 65515) would fit,
    // but the entry's stored 24-byte header + end (24 + 65515 = 65539)
    // does not — this must be rejected, and no assembly may occur.
    let terminator = fragment(id: 60, offset: 15, more: false, bytes: Array(repeating: UInt8(0xbb), count: 65500))
    let result = reassembler.process(header: terminator.0, payload: terminator.1)
    #expect(result == nil)
    #expect(reassembler.pendingCount == 1)   // only the head fragment's entry remains
}

@Test func rejectsAnOverlappingFragment() {
    // Legitimate fragmentation never overlaps. An overlapping fragment is
    // an attempt to rewrite bytes already accepted (the teardrop family),
    // so it is dropped rather than merged — and the datagram still
    // completes from the fragments that were accepted.
    let reassembler = Reassembler(clock: ManualClock())
    let first = fragment(id: 20, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    #expect(reassembler.process(header: first.0, payload: first.1) == nil)

    // Overlaps bytes 4..<8, which are already accepted. Must be dropped.
    let overlapping = fragment(id: 20, offset: 4, more: true, bytes: Array(repeating: UInt8(0xff), count: 8))
    #expect(reassembler.process(header: overlapping.0, payload: overlapping.1) == nil)

    let last = fragment(id: 20, offset: 8, more: false, bytes: [0xbb, 0xbb])
    let result = reassembler.process(header: last.0, payload: last.1)

    #expect(result != nil)
    let bytes = Array(result!.1.readableBytesView)
    #expect(bytes.count == 10)
    #expect(bytes.prefix(8).allSatisfy { $0 == 0xaa })   // 0xff never landed
    #expect(Array(bytes.suffix(2)) == [0xbb, 0xbb])
}

@Test func duplicateFragmentsCannotEvictOtherDatagrams() {
    // The eviction policy is oldest-first when over the memory cap. If a
    // peer's duplicate fragments were counted repeatedly, it could inflate
    // its own accounted size and push an older, legitimate datagram out.
    let clock = ManualClock()
    // Size the cap for exactly 2 entries' worth (see
    // `evictsTheOldestWhenOverTheMemoryLimit` for why raw payload bytes are
    // no longer the right unit).
    let entryCost = 8 + Reassembler.perFragmentOverhead
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30), memoryLimit: entryCost * 2)

    let victim = fragment(id: 1, offset: 0, more: true, bytes: Array(repeating: UInt8(0x11), count: 8))
    _ = reassembler.process(header: victim.0, payload: victim.1)
    clock.advance(by: .milliseconds(1))

    // The same fragment of a second datagram, sent four times.
    for _ in 0..<4 {
        let flood = fragment(id: 2, offset: 0, more: true, bytes: Array(repeating: UInt8(0x22), count: 8))
        _ = reassembler.process(header: flood.0, payload: flood.1)
    }

    // Held bytes must reflect 2 admitted fragments, not 5 — so nothing was
    // evicted and the older datagram survives.
    #expect(reassembler.pendingCount == 2)

    let victimTail = fragment(id: 1, offset: 8, more: false, bytes: [0x11])
    #expect(reassembler.process(header: victimTail.0, payload: victimTail.1)?.1.readableBytes == 9)
}

@Test func rejectsASecondFinalFragmentThatDisagrees() {
    // The fragment with moreFragments clear defines where the datagram
    // ends. A second one claiming a different end must not overwrite it,
    // or a peer could truncate or extend someone else's datagram.
    let reassembler = Reassembler(clock: ManualClock())
    let terminator = fragment(id: 30, offset: 8, more: false, bytes: [0xbb, 0xbb])
    #expect(reassembler.process(header: terminator.0, payload: terminator.1) == nil)

    // Different end (18, not 10), and deliberately non-overlapping so the
    // overlap check cannot be what rejects it.
    let conflicting = fragment(id: 30, offset: 16, more: false, bytes: [0xcc, 0xcc])
    #expect(reassembler.process(header: conflicting.0, payload: conflicting.1) == nil)

    let head = fragment(id: 30, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    let result = reassembler.process(header: head.0, payload: head.1)

    // Completes at the length the FIRST terminator declared: 10 bytes.
    #expect(result?.1.readableBytes == 10)
}

@Test func admittedFragmentsDoNotPinTheirOriginalFrameStorage() {
    // A fragment's payload reaches `process` as a NIO `getSlice`/`readSlice`
    // off the frame it arrived in — copy-on-write, so an uncopied slice
    // keeps the ENTIRE original allocation alive until something writes into
    // it. Confirms the slice really is COW-backed by the whole frame, and then
    // asserts on what the reassembler actually RETAINED: the pending payload's
    // `storageCapacity`, which is exactly the quantity COW pinning moves.
    //
    // `storageCapacity` reports the size of the whole allocation a `ByteBuffer`
    // references, so the two cases separate by three orders of magnitude with
    // no measurement noise in between: a fresh, exactly-sized 1-byte copy
    // reports 1, an uncopied 1-byte slice of the 1500-byte frame reports the
    // frame's full allocation (2048, measured with the copy deleted — NIO
    // rounds capacity to a power of two). Nothing about a process-wide RSS
    // reading is involved, so nothing here can be masked by a concurrent test.
    //
    // This is NOT redundant with `perFragmentOverhead`'s guard, and the two
    // must not be conflated: real per-fragment retention cost (the array
    // element, the backing storage object, malloc's minimum bucket) is
    // genuinely invisible to `storageCapacity`, which is why the old
    // `heldStorageBytes` diagnostic could not catch the missing overhead
    // charge. COW pinning is the one failure `storageCapacity` sees perfectly.
    let reassembler = Reassembler(clock: ManualClock())
    var frame = ByteBufferAllocator().buffer(capacity: 1500)
    frame.writeRepeatingByte(0xaa, count: 1500)
    let onebyte = frame.getSlice(at: frame.readerIndex, length: 1)!
    #expect(onebyte.storageCapacity >= 1500)   // confirms the slice really is COW-backed by the whole frame

    var header = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: 1)
    header.identification = 99
    header.flags = [.moreFragments]
    _ = reassembler.process(header: header, payload: onebyte)

    #expect(reassembler.pendingCount == 1)
    // An upper bound alone is satisfied by having retained nothing at all, so
    // assert the fragment is actually being held before bounding what it holds.
    #expect(reassembler.pendingFragmentCount == 1)
    #expect(reassembler.pendingPayloadStorageBytes <= 32)
}

@Test func admittedFragmentsDoNotPinTheirFramesUnderAFloodOfMinimalFragments() {
    // The same guarantee as `admittedFragmentsDoNotPinTheirOriginalFrameStorage`
    // above, at the scale where it matters — the flood shape that
    // `reassemblyMemoryLimitBoundsRealRSSUnderAFloodOfMinimalFragments` uses,
    // where eviction is running and hundreds of fragments are held at once.
    //
    // Every datagram gets its OWN 1500-byte frame here, which is the whole
    // point of this test existing separately. Slicing a flood off ONE shared
    // frame — as the RSS test does — cannot see COW pinning at all: however
    // many slices point into a single frame, they pin that one allocation
    // between them, so uncopied slices and copies retain nearly the same
    // amount. Distinct frames are what make the difference observable, and
    // `storageCapacity` is what observes it: 1 byte per fragment when
    // copy-on-admission runs, the frame's whole allocation when it does not
    // (2048 for a 1500-byte frame, since NIO rounds capacity to a power of
    // two). Measured with the copy deleted: 2,310,144 bytes pinned against a
    // 36,096-byte bound, a 64x separation.
    let memoryLimit = 200_000
    let fragmentsPerDatagram = 4
    let datagrams = 5_000
    let reassembler = Reassembler(
        clock: ManualClock(), timeout: .seconds(3600), memoryLimit: memoryLimit,
        maximumPendingDatagrams: 1_000_000)

    for d in 0..<datagrams {
        var frame = ByteBufferAllocator().buffer(capacity: 1500)
        frame.writeRepeatingByte(0xaa, count: 1500)
        for i in 0..<fragmentsPerDatagram {
            let slice = frame.getSlice(at: i * 8, length: 1)!
            var header = IPv4Header(
                source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
                protocolNumber: .udp, payloadLength: 1)
            header.identification = UInt16(d % 65536)
            header.fragmentOffset = i * 8
            header.flags = [.moreFragments]
            _ = reassembler.process(header: header, payload: slice)
        }
    }

    // Eviction must actually have left fragments pending — an upper bound on
    // retained storage is trivially satisfied by an empty reassembler.
    #expect(reassembler.pendingFragmentCount >= fragmentsPerDatagram)
    // 32 bytes of allocation per 1-byte payload is generous headroom over the
    // 1 an exactly-sized copy really costs, and 64x below the 2048 an
    // uncopied slice of its frame would pin.
    #expect(reassembler.pendingPayloadStorageBytes <= reassembler.pendingFragmentCount * 32)
}

@Test func reassemblyMemoryLimitBoundsRealRSSUnderAFloodOfMinimalFragments() {
    // The reviewer's attack shape: 1-byte fragments at 8-byte offsets, with
    // `MoreFragments` always set so `totalLength` is never established and
    // `assemble()` never runs — nothing is ever released by completing, so
    // the memory cap's eviction is the only thing keeping this bounded.
    // Fragments are sliced off a shared 1500-byte MTU-sized frame, the way
    // `PacketBuffer` really delivers them.
    //
    // This test does NOT guard the copy-on-admission fix, and an earlier
    // version of this comment claiming it did was wrong — verified by
    // deleting the copy, at which point all 20 tests in this file still
    // passed. Sharing one frame across every fragment is precisely what
    // makes the shape blind to COW pinning: however many slices point into a
    // single allocation, they pin that one allocation between them, so
    // uncopied slices cost essentially the same as copies here. "Slices
    // behave the way real delivery does" is not "many distinct frames are
    // retained". Copy-on-admission is guarded by
    // `admittedFragmentsDoNotPinTheirFramesUnderAFloodOfMinimalFragments`
    // above, which uses a distinct frame per datagram and asserts on
    // `storageCapacity` rather than RSS. What this test guards is the
    // per-fragment overhead charge.
    //
    // Before `perFragmentOverhead` was charged, the reviewer measured 147.7
    // bytes of REAL retention per accounted byte on this exact shape — a
    // 4 MiB nominal cap permitted roughly 620 MB of actual memory, and the
    // `heldStorageBytes` diagnostic that existed to catch this could not see
    // it (a fresh 1-byte buffer's `storageCapacity` is 1). This test asserts
    // real RSS growth via `getrusage` instead, so a regression of either fix
    // shows up directly rather than only in an accounting number that can
    // itself be wrong.
    //
    // `getrusage`'s `ru_maxrss` is a process-wide, monotonically
    // non-decreasing high-water mark, and `swift test` runs Swift Testing
    // tests concurrently within one process by default, so a modest amount
    // of apparent "growth" here can come from unrelated sibling tests
    // allocating at the same moment rather than from this workload (observed
    // up to ~10 MB of such noise across repeated full-suite runs). Rather
    // than chase that noise with a tight bound, `datagrams` is picked large
    // enough that a correctly-bounded run's real growth (low single-digit MB
    // — cap plus noise) and a regressed run's real growth (tens of MB) are
    // both far outside the other's range, so `grown`'s threshold below has
    // wide margin on both sides.
    //
    // That margin does not make `grown`'s assertion reliable protection,
    // though — it can only ever be too LENIENT, never too strict, and that
    // asymmetry is exactly the problem. Because `ru_maxrss` is a high-water
    // mark rather than a current-usage reading, `before` is not "memory used
    // at the start of this test" — it is "the highest this process's RSS has
    // ever been, including from any earlier test in this same process". If
    // some earlier or concurrent test has already pushed the process peak
    // above whatever this workload — regressed or not — would reach, `after
    // - before` reads as ~0 and `grown < 30_000_000` passes regardless of
    // whether this test's own allocations were actually bounded. It cannot
    // merely flake occasionally; on a process whose peak is already high
    // enough, it silently fails to fail on every run, indefinitely. There is
    // no threshold that fixes this — the failure mode is in what `ru_maxrss`
    // means, not in where the line is drawn.
    //
    // `pendingCount`'s assertion just above is the assertion actually doing
    // the guarding here: it reads `Reassembler`'s own deterministic count,
    // not a process-wide OS statistic, so it cannot be masked by unrelated
    // allocations, and it already separates the fixed and reverted behaviour
    // by two orders of magnitude (283 vs. 50,000 surviving entries measured
    // when the overhead charge below was reverted — see the report's
    // falsification of that fix). `grown` is kept only as an indicative,
    // best-effort cross-check against the real allocator behaviour
    // `pendingCount` cannot see directly — not as a guarantee.
    let memoryLimit = 200_000
    let reassembler = Reassembler(
        clock: ManualClock(), timeout: .seconds(3600), memoryLimit: memoryLimit,
        maximumPendingDatagrams: 1_000_000)

    var frame = ByteBufferAllocator().buffer(capacity: 1500)
    frame.writeRepeatingByte(0xaa, count: 1500)

    let fragmentsPerDatagram = 4
    let datagrams = 70_000
    let before = peakResidentBytes()
    for d in 0..<datagrams {
        for i in 0..<fragmentsPerDatagram {
            let slice = frame.getSlice(at: i * 8, length: 1)!
            var header = IPv4Header(
                source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
                protocolNumber: .udp, payloadLength: 1)
            header.identification = UInt16(d % 65536)
            header.fragmentOffset = i * 8
            header.flags = [.moreFragments]
            _ = reassembler.process(header: header, payload: slice)
        }
    }
    let grown = peakResidentBytes() - before

    // Each surviving entry costs `fragmentsPerDatagram * (1 + perFragmentOverhead)`
    // in the accounting; the cap admits at most `memoryLimit` worth of that,
    // plus one entry's slop for whichever admission last tripped eviction.
    // 70,000 datagrams were offered, so a bounded count here (rather than
    // 70,000) proves eviction actually ran, not merely that everything fit.
    let entryCost = fragmentsPerDatagram * (1 + Reassembler.perFragmentOverhead)
    #expect(reassembler.pendingCount <= memoryLimit / entryCost + 1)

    // A generous ceiling, well above the ~10 MB of ambient noise this
    // workload's own bounded contribution was observed to hide inside, but
    // below the ~52 MB measured for this same input with the overhead
    // charge reverted (at which point the raw, unweighted payload total
    // alone eventually reaches `memoryLimit`, so eviction still runs — just
    // ~177x too late, holding ~50,000 entries' worth of real memory instead
    // of ~283).
    //
    // Indicative only, NOT protection: see the doc comment above for why a
    // process-wide high-water mark can read ~0 growth and pass here even on
    // regressed code, silently, if some earlier test already pushed the
    // peak higher. `pendingCount`'s assertion above is the real guard.
    #expect(grown < 30_000_000)
}

@Test func admissionOrderStaysBoundedWhenOneDatagramPinsTheHead() {
    // `pruneStaleOrderHead`'s head-only scan can be pinned indefinitely by a
    // single never-completing datagram sitting at the front of
    // `admissionOrder`: every OTHER datagram that completes leaves `pending`
    // from the middle, so its own `admissionOrder` appearance goes stale
    // where the head-only scan can never reach it, and the array grows by
    // one `Key` per admission forever — entirely unaccounted by
    // `heldBytes`/`memoryLimit`. Uses the actual attack shape: one
    // never-completing fragment to pin the head, then a flood of ordinary
    // two-fragment datagrams that each complete and are freed.
    //
    // Reviewer's measurement of this exact shape against the unfixed code,
    // `memoryLimit: 4 MiB`: 2,000,000 admission cycles, `pendingCount == 1`,
    // ~58 MB of real RSS growth — `admissionOrder` had grown to roughly one
    // `Key` per completed datagram, none of it ever reclaimed.
    let maximumPendingDatagrams = 8
    let reassembler = Reassembler(
        clock: ManualClock(), timeout: .seconds(3600), memoryLimit: 1_000_000,
        maximumPendingDatagrams: maximumPendingDatagrams)

    // Pin the head: one fragment that never gets a terminator.
    var pin = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: 1)
    pin.identification = 0
    pin.flags = [.moreFragments]
    _ = reassembler.process(header: pin, payload: ByteBuffer(bytes: [0xaa]))
    #expect(reassembler.pendingCount == 1)

    // Flood ordinary two-fragment datagrams, each with a distinct
    // identification (so they never collide with the pin or each other),
    // that complete and leave `pending` immediately.
    let cycles = 50_000
    for i in 0..<cycles {
        let id = UInt16(1 + (i % 65535))
        var head = IPv4Header(
            source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
            protocolNumber: .udp, payloadLength: 1)
        head.identification = id
        head.flags = [.moreFragments]
        _ = reassembler.process(header: head, payload: ByteBuffer(bytes: [0xbb]))

        var tail = head
        tail.fragmentOffset = 1
        tail.flags = []
        #expect(reassembler.process(header: tail, payload: ByteBuffer(bytes: [0xcc]))?.1.readableBytes == 2)
    }

    // Only the pinning datagram is still pending; everything else completed
    // and was freed.
    #expect(reassembler.pendingCount == 1)
    // The periodic full-pass compaction bounds `admissionOrder` to a small
    // constant multiple of `maximumPendingDatagrams` regardless of how the
    // head is pinned. Falsifies to ~50,001 (one `Key` per admission,
    // unbounded) against the pre-fix, head-only scan.
    #expect(reassembler.admissionOrderCountForTesting <= 4 * maximumPendingDatagrams + 1)
}

@Test func rejectsFragmentsBeyondThePerDatagramCap() {
    // `maximumFragmentsPerDatagram` bounds one datagram's own fragment count
    // independently of `memoryLimit` — insurance against `perFragmentOverhead`
    // ever being mis-measured or mis-tuned again. Cap set to 5 contiguous
    // 8-byte fragments; a 6th, terminating fragment must be rejected outright
    // rather than complete the datagram, proving admission actually stopped
    // at the cap rather than merely still waiting for more data.
    let reassembler = Reassembler(clock: ManualClock(), maximumFragmentsPerDatagram: 5)
    for i in 0..<5 {
        let f = fragment(id: 77, offset: i * 8, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
        #expect(reassembler.process(header: f.0, payload: f.1) == nil)
    }
    #expect(reassembler.pendingCount == 1)

    // The 6th fragment would complete the datagram (offsets 0..<40) if
    // admitted, so a nil result here — with the entry still pending, not
    // gone — proves it was rejected by the cap, not merely incomplete.
    let sixth = fragment(id: 77, offset: 40, more: false, bytes: Array(repeating: UInt8(0xbb), count: 8))
    #expect(reassembler.process(header: sixth.0, payload: sixth.1) == nil)
    #expect(reassembler.pendingCount == 1)
}

@Test func pendingCountIsBoundedIndependentlyOfTheByteCap() {
    // Even with the storage-pinning fix above, a flood of minimal fragments
    // spread across many different datagram IDs barely moves `heldBytes`
    // (the byte cap) while still creating one full entry — header, array,
    // dictionary slot — per datagram. Only a count cap closes that: 2,000
    // single-byte fragments across 2,000 distinct IDs, a table capped at 128.
    let reassembler = Reassembler(clock: ManualClock(), maximumPendingDatagrams: 128)
    for id in UInt16(0)..<2000 {
        var header = IPv4Header(
            source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
            protocolNumber: .udp, payloadLength: 1)
        header.identification = id
        header.flags = [.moreFragments]
        _ = reassembler.process(header: header, payload: ByteBuffer(bytes: [0xff]))
    }
    #expect(reassembler.pendingCount == 128)
}

@Test func pendingCountCapEvictsOldestFirstAndAcceptsNewDatagrams() {
    // The count cap must actually make room for new datagrams, not merely
    // refuse to grow — and it must evict the oldest entry, consistent with
    // the byte cap's own eviction policy, not an arbitrary one.
    let clock = ManualClock()
    let reassembler = Reassembler(clock: clock, maximumPendingDatagrams: 2)
    let fragment: (UInt16) -> (IPv4Header, ByteBuffer) = { id in
        var header = IPv4Header(
            source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
            protocolNumber: .udp, payloadLength: 1)
        header.identification = id
        header.flags = [.moreFragments]
        return (header, ByteBuffer(bytes: [0xaa]))
    }

    let first = fragment(1)
    _ = reassembler.process(header: first.0, payload: first.1)
    clock.advance(by: .milliseconds(1))
    let second = fragment(2)
    _ = reassembler.process(header: second.0, payload: second.1)
    clock.advance(by: .milliseconds(1))
    #expect(reassembler.pendingCount == 2)

    // A third distinct datagram must be admitted by evicting the oldest (1).
    let third = fragment(3)
    _ = reassembler.process(header: third.0, payload: third.1)
    #expect(reassembler.pendingCount == 2)

    // Datagrams 2 and 3 — the two that must have survived, since only the
    // oldest (1) was evicted — both still complete normally. (Probing
    // datagram 1's own fate is deliberately not done here: a late tail for
    // an evicted, or simply unknown, identification starts a fresh
    // reassembly attempt of its own — see `expiresIncompleteDatagrams` —
    // which would itself consume a slot and confuse what this test is
    // isolating.)
    var tail2 = fragment(2)
    tail2.0.fragmentOffset = 1
    tail2.0.flags = []
    #expect(reassembler.process(header: tail2.0, payload: ByteBuffer(bytes: [0xbb]))?.1.readableBytes == 2)

    var tail3 = fragment(3)
    tail3.0.fragmentOffset = 1
    tail3.0.flags = []
    #expect(reassembler.process(header: tail3.0, payload: ByteBuffer(bytes: [0xcc]))?.1.readableBytes == 2)
}

@Test func evictionUnderTheByteCapDoesNotScanEveryPendingEntry() {
    // `enforceMemoryLimit` used to find the oldest entry via
    // `pending.min(by: startedAt)` — an O(pendingCount) scan of the WHOLE
    // table, run again on every single admission once at the cap. With the
    // table held near its cap by a sustained flood (as this input does),
    // that made total admission cost O(pendingCount * fragments), not
    // O(fragments). This does not assert a specific complexity class
    // directly — Swift Testing has no profiler hook for that — but a
    // generous wall-clock ceiling is a real regression guard here: the O(n)
    // version of this same workload was measured at ~9 seconds; the
    // O(1)-amortized version this replaces it with finishes in well under
    // one, a ~20x difference that only widens as the flood grows.
    let clock = ManualClock()
    // Sized for exactly 3000 entries' worth under the new per-fragment
    // overhead charge (see `Reassembler.perFragmentOverhead`), matching the
    // original 8-byte-payload x 3000 intent.
    let entryCost = 8 + Reassembler.perFragmentOverhead
    let reassembler = Reassembler(
        clock: clock, timeout: .seconds(3600), memoryLimit: entryCost * 3000, maximumPendingDatagrams: 1_000_000)

    let elapsed = ContinuousClock().measure {
        for id in 0..<50_000 {
            var header = IPv4Header(
                source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
                protocolNumber: .udp, payloadLength: 8)
            header.identification = UInt16(id % 65536)
            header.flags = [.moreFragments]
            _ = reassembler.process(header: header, payload: ByteBuffer(bytes: Array(repeating: UInt8(0), count: 8)))
        }
    }

    #expect(elapsed < .seconds(5))
    // The byte cap is doing its job regardless of how it got there.
    #expect(reassembler.pendingCount <= 3000)
}

@Test func rejectsEmptyFragments() {
    // Zero-length fragments evade the overlap test and the memory cap, so
    // a peer could repeat one indefinitely to grow the pending table.
    let reassembler = Reassembler(clock: ManualClock())
    for _ in 0..<100 {
        let empty = fragment(id: 50, offset: 0, more: true, bytes: [])
        #expect(reassembler.process(header: empty.0, payload: empty.1) == nil)
    }
    #expect(reassembler.pendingCount == 0)

    // A non-fragmented packet with an empty payload is still delivered.
    let bare = fragment(id: 51, offset: 0, more: false, bytes: [])
    #expect(reassembler.process(header: bare.0, payload: bare.1) != nil)
}

@Test func admissionOrderStaysBoundedWhenOneKeyIsReadmittedUnderAPinnedHead() {
    // The narrower half of the pinned-head fix, and the half
    // `admissionOrderStaysBoundedWhenOneDatagramPinsTheHead` cannot see.
    //
    // That test floods DISTINCT identifications, so every completed
    // datagram's key really has left `pending` by the time compaction runs —
    // which a staleness test as weak as `pending[key] != nil` gets right by
    // accident. It stays green with `Pending.admissionSequence` deleted and
    // `isLive` reduced to bare key membership.
    //
    // The attack that separates them reuses ONE key. `process` returns early
    // when a datagram completes, so the compaction pass only ever runs on the
    // non-completing path — i.e. immediately after the first fragment of the
    // next cycle has re-admitted that same key. At that instant
    // `pending[key] != nil` is true, so a membership-only check reads EVERY
    // earlier appearance of the key as live, keeps them all, and the bound it
    // is supposed to enforce never fires. Comparing each appearance against
    // the `admissionSequence` its own `Pending` was stamped with is what tells
    // one admission of a key apart from the next.
    let maximumPendingDatagrams = 8
    let reassembler = Reassembler(
        clock: ManualClock(), timeout: .seconds(3600), memoryLimit: 1_000_000,
        maximumPendingDatagrams: maximumPendingDatagrams)

    // Pin the head with a datagram that never terminates, so the head-only
    // scan can never advance and the full pass is the only thing that can
    // reclaim anything.
    var pin = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: 1)
    pin.identification = 0
    pin.flags = [.moreFragments]
    _ = reassembler.process(header: pin, payload: ByteBuffer(bytes: [0xaa]))
    #expect(reassembler.pendingCount == 1)

    // One identification, re-admitted and completed over and over. Every
    // cycle appends a fresh appearance for the identical key.
    let cycles = 20_000
    for _ in 0..<cycles {
        var head = IPv4Header(
            source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
            protocolNumber: .udp, payloadLength: 1)
        head.identification = 1
        head.flags = [.moreFragments]
        _ = reassembler.process(header: head, payload: ByteBuffer(bytes: [0xbb]))

        var tail = head
        tail.fragmentOffset = 1
        tail.flags = []
        #expect(reassembler.process(header: tail, payload: ByteBuffer(bytes: [0xcc]))?.1.readableBytes == 2)
    }

    // Positive control: the flood really did run through this reassembler and
    // really did leave only the pin behind, so the bound below is not
    // satisfied by an empty structure.
    #expect(reassembler.pendingCount == 1)
    #expect(reassembler.admissionOrderCountForTesting >= 1)
    // Falsifies to ~20,001 with `isLive` weakened to `pending[key] != nil`.
    #expect(reassembler.admissionOrderCountForTesting <= 4 * maximumPendingDatagrams + 1)
}
