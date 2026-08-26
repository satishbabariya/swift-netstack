import NIOCore
import Testing

@testable import Netstack

@Test func manualClockOnlyMovesWhenAdvanced() {
    let clock = ManualClock(start: NIODeadline.uptimeNanoseconds(0))
    #expect(clock.now() == NIODeadline.uptimeNanoseconds(0))
    #expect(clock.now() == NIODeadline.uptimeNanoseconds(0))
    clock.advance(by: .milliseconds(250))
    #expect(clock.now() == NIODeadline.uptimeNanoseconds(250_000_000))
    clock.advance(by: .milliseconds(250))
    #expect(clock.now() == NIODeadline.uptimeNanoseconds(500_000_000))
}

@Test func realClockMovesForward() {
    let clock = RealClock()
    let first = clock.now()
    let second = clock.now()
    #expect(second >= first)
}
