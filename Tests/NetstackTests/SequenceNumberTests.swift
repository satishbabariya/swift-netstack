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

@Test func exactlyHalfTheSpaceApartNeitherPrecedes() async {
    // RFC 1982 leaves ordering undefined at exactly 2^31 apart. The naive
    // translation of the bit-pattern trick would report both directions as
    // "less than", which breaks asymmetry and can cycle a sort. The chosen
    // behavior instead traps in debug builds (via assertionFailure) and then
    // returns false in both directions -- neither precedes the other.
    //
    // assertionFailure aborts the process the instant it is reached in a
    // debug build; control never returns to execute anything after it, so no
    // in-process #expect can observe the eventual `false` return value
    // without also crashing this entire test binary (confirmed empirically:
    // a plain #expect(!a.lessThan(b)) here took down the whole suite). An
    // exit test is the correct tool for this: it runs each call in its own
    // subprocess and checks that the subprocess terminates abnormally, which
    // is exactly what "surfaces during development" means and is a genuine,
    // falsifiable regression check -- if the special case is ever removed,
    // neither call traps and both expectations below fail. This proves the
    // trap fires; it does not and cannot prove what the function would
    // return once the trap is compiled out (a release build). See
    // `theHalfSpaceOrderingHelperReturnsFalse` below for that half: it calls
    // the assert-free decision helper directly, so it is checkable -- and
    // falsifiable -- in any build configuration, including this one.
    await #expect(processExitsWith: .failure) {
        _ = SequenceNumber(0).lessThan(SequenceNumber(0x8000_0000))
    }
    await #expect(processExitsWith: .failure) {
        _ = SequenceNumber(0x8000_0000).lessThan(SequenceNumber(0))
    }
}

@Test func theHalfSpaceOrderingHelperReturnsFalse() {
    // lessThan cannot be probed for its release-path return value directly:
    // assertionFailure aborts a debug build the instant it is reached, so
    // nothing after it is reachable in-process (see the exit test above).
    // SequenceNumber.halfSpaceOrdering() is the assert-free decision that
    // lessThan defers to once past the diagnostic, so it is what a future
    // edit would actually have to change to alter the release-path outcome
    // -- e.g. flipping this to `true` would silently restore the asymmetry
    // bug that started this fix. Checking it directly here closes that gap:
    // this test would catch that edit even though nothing else in the suite
    // can.
    #expect(!SequenceNumber.halfSpaceOrdering())
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
