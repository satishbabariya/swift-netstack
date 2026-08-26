import Testing

@testable import Netstack

@Test func comparesCorrectlyAcrossTheWrap() {
    // RFC 1982 serial arithmetic: "less than" means the forward distance is
    // less than half the space. Plain UInt32 `<` gets this backwards near 2^32.
    let high = SequenceNumber(0xFFFF_FF00)
    let low = SequenceNumber(0x0000_0100)
    #expect(high.lessThan(low), "0xFFFFFF00 precedes 0x00000100 after wrapping")
    #expect(!low.lessThan(high))
    #expect(high.value > low.value, "and plain UInt32 comparison says the opposite")
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
