import Testing

@testable import Netstack

@Test func comparesCorrectlyAcrossTheWrap() {
    // RFC 1982 serial arithmetic: "less than" means the forward distance is
    // less than half the space. Plain UInt32 `<` gets this backwards near 2^32.
    let high = SequenceNumber(0xFFFF_FF00)
    let low = SequenceNumber(0x0000_0100)
    #expect(high.lessThan(low), "0xFFFFFF00 precedes 0x00000100 after wrapping")
    #expect(!low.lessThan(high))
    // For illustration only (plain UInt32 comparison says the opposite of
    // lessThan here): high.value (4294967040) > low.value (256). This is not
    // an assertion because it would hold under any implementation of
    // lessThan — it does not test SequenceNumber's behavior.
}

@Test func neitherValuePrecedesTheOtherAtExactlyHalfTheSpace() {
    // RFC 1982 leaves ordering undefined at exactly 2^31 apart. The naive
    // translation of the bit-pattern trick would report both directions as
    // "less than", which breaks asymmetry and can cycle a sort. The choice
    // made here is `false` in both directions -- neither precedes the other.
    //
    // This used to be an exit test asserting that lessThan *trapped* here.
    // It must not: both operands of every comparison in TCPStateMachine come
    // off the wire, and we hand the peer our ISS in the SYN-ACK, so a guest
    // can pick `iss + 2^31` and hit this branch deliberately (see
    // `aHalfSpaceAcknowledgementFromTheGuestIsHandledNotTrapped`). Calling
    // lessThan directly here is itself part of the check: were the trap
    // reintroduced, this test would abort the process rather than fail.
    #expect(!SequenceNumber(0).lessThan(SequenceNumber(0x8000_0000)))
    #expect(!SequenceNumber(0x8000_0000).lessThan(SequenceNumber(0)))
    // And asymmetry holds either side of the boundary, so the special case
    // is genuinely a point and not a region.
    #expect(SequenceNumber(0).lessThan(SequenceNumber(0x7FFF_FFFF)))
    #expect(!SequenceNumber(0x7FFF_FFFF).lessThan(SequenceNumber(0)))
    #expect(!SequenceNumber(0).lessThan(SequenceNumber(0x8000_0001)))
    #expect(SequenceNumber(0x8000_0001).lessThan(SequenceNumber(0)))
}

@Test func theHalfSpaceOrderingHelperReturnsFalse() {
    // SequenceNumber.halfSpaceOrdering() is the decision that lessThan
    // defers to at exactly 2^31 apart, so it is what a future edit would
    // actually have to change to alter the outcome -- e.g. flipping it to
    // `true` would silently restore the asymmetry bug that started this fix.
    // Checking it directly here names the decision as a decision.
    #expect(!SequenceNumber.halfSpaceOrdering())
}

@Test func theRangePredicatesRejectTheUndefinedPointThatNegatedOrderingAdmits() {
    // The whole reason these predicates exist. `!a.lessThan(b)` answers
    // `true` at exactly 2^31 apart, because `lessThan` answers `false`
    // there -- so a guard written as a negated ordering admits precisely the
    // value whose ordering is undefined, which is precisely the value a peer
    // holding one of our sequence numbers can compute. These are built on
    // `-`, which is total and yields a negative distance there, so the same
    // value is rejected with no special case.
    let low = SequenceNumber(100)
    let high = SequenceNumber(200)
    let halfSpace = SequenceNumber(100 &+ 0x8000_0000)
    #expect(!halfSpace.isInRange(after: low, throughAndIncluding: high))
    #expect(!halfSpace.isInRange(from: low, throughAndIncluding: high))
    #expect(!halfSpace.isAtOrAfter(low))
    // ...and in the other direction too: `-` saturates to Int32.min from
    // both sides, so neither is "at or after" the other.
    #expect(!low.isAtOrAfter(halfSpace))
    // The negated ordering these replace would have said yes to all four.
    #expect(!low.lessThan(halfSpace) && !halfSpace.lessThan(low))
}

@Test func theRangePredicatesAgreeWithTheirWrittenBounds() {
    let low = SequenceNumber(100)
    let high = SequenceNumber(200)
    #expect(!SequenceNumber(99).isInRange(after: low, throughAndIncluding: high))
    #expect(!SequenceNumber(100).isInRange(after: low, throughAndIncluding: high), "the low bound is exclusive here")
    #expect(SequenceNumber(101).isInRange(after: low, throughAndIncluding: high))
    #expect(SequenceNumber(200).isInRange(after: low, throughAndIncluding: high), "the high bound is inclusive")
    #expect(!SequenceNumber(201).isInRange(after: low, throughAndIncluding: high))

    #expect(!SequenceNumber(99).isInRange(from: low, throughAndIncluding: high))
    #expect(SequenceNumber(100).isInRange(from: low, throughAndIncluding: high), "the low bound is inclusive here")
    #expect(SequenceNumber(200).isInRange(from: low, throughAndIncluding: high))
    #expect(!SequenceNumber(201).isInRange(from: low, throughAndIncluding: high))

    #expect(SequenceNumber(100).isAtOrAfter(low))
    #expect(SequenceNumber(101).isAtOrAfter(low))
    #expect(!SequenceNumber(99).isAtOrAfter(low))
}

@Test func theRangePredicatesWorkAcrossTheWrap() {
    let low = SequenceNumber(0xFFFF_FFC0)   // 64 below the wrap
    let high = SequenceNumber(0x0000_0040)  // 64 above it
    #expect(SequenceNumber(0xFFFF_FFFF).isInRange(after: low, throughAndIncluding: high))
    #expect(SequenceNumber(0x0000_0000).isInRange(after: low, throughAndIncluding: high))
    #expect(SequenceNumber(0x0000_0040).isInRange(after: low, throughAndIncluding: high))
    #expect(!SequenceNumber(0x0000_0041).isInRange(after: low, throughAndIncluding: high))
    #expect(!SequenceNumber(0xFFFF_FFBF).isInRange(after: low, throughAndIncluding: high))
    #expect(SequenceNumber(0x0000_0000).isAtOrAfter(low))
    #expect(!low.isAtOrAfter(SequenceNumber(0x0000_0000)))
}

@Test func anInvertedRangeContainsNothingRatherThanEverything() {
    // A range whose high bound precedes its low bound is self-contradictory:
    // no correct caller builds one, but an upstream bug that advanced one
    // TCB variable without the other would. It must fail closed -- admitting
    // there would convert one bug into an accept-anything hole exactly when
    // the state is already known to be corrupt. The negated-ordering shape
    // these replace did admit a band of values in this case.
    let low = SequenceNumber(200)
    let high = SequenceNumber(100)
    #expect(!SequenceNumber(150).isInRange(after: low, throughAndIncluding: high))
    #expect(!SequenceNumber(150).isInRange(from: low, throughAndIncluding: high))
    #expect(!SequenceNumber(200).isInRange(from: low, throughAndIncluding: high), "not even the low bound itself")
    #expect(!SequenceNumber(100 &+ 0x8000_0000).isInRange(after: low, throughAndIncluding: high))
}

@Test func addsAndSubtractsAcrossTheWrap() {
    #expect((SequenceNumber(0xFFFF_FFFF) + 1).value == 0)
    #expect((SequenceNumber(0xFFFF_FF00) + 512).value == 0x100)
    #expect(SequenceNumber(0x0000_0100) - SequenceNumber(0xFFFF_FF00) == 512)
    #expect(SequenceNumber(100) - SequenceNumber(60) == 40)
}

@Test func windowMembership() {
    let start = SequenceNumber(1000)
    #expect(SequenceNumber(1000).inWindow(start: start, size: 100))
    #expect(SequenceNumber(1099).inWindow(start: start, size: 100))
    #expect(!SequenceNumber(1100).inWindow(start: start, size: 100), "the window is half-open")
    #expect(!SequenceNumber(999).inWindow(start: start, size: 100))
}

@Test func windowMembershipAcrossTheWrap() {
    let start = SequenceNumber(0xFFFF_FFC0)   // 64 below the wrap
    #expect(SequenceNumber(0xFFFF_FFC0).inWindow(start: start, size: 128))
    #expect(SequenceNumber(0x0000_003F).inWindow(start: start, size: 128), "63 past the wrap is inside")
    #expect(!SequenceNumber(0x0000_0040).inWindow(start: start, size: 128), "64 past is outside")
}

@Test func aZeroSizedWindowAcceptsNothing() {
    // A zero window is a real TCP state (the peer's receive buffer is full),
    // and every sequence number must fall outside it.
    #expect(!SequenceNumber(1000).inWindow(start: SequenceNumber(1000), size: 0))
}

@Test func aLegitimatelyLargeWindowStillAccepts() {
    // RFC 7323's maximum window scale (14) caps a real advertised window
    // around 2^30. inWindow's domain assert (size < 2^31) must not be
    // tightened later into rejecting sizes that legitimate peers can send.
    let start = SequenceNumber(0)
    let size = 1 << 30
    #expect(SequenceNumber(0).inWindow(start: start, size: size))
    #expect(SequenceNumber(UInt32(size - 1)).inWindow(start: start, size: size))
    #expect(!SequenceNumber(UInt32(size)).inWindow(start: start, size: size))
}
