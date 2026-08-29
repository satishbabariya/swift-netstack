import Testing

@testable import Netstack

// RFC 5681. Windows are in BYTES here, not segments, and every expected value
// is worked by hand and asserted exactly -- the differential against gVisor
// compares these numbers, so "roughly half" is not a useful assertion.

private let mss = 1460
private let initialWindow = 10 * mss  // 14_600; see Reno's initialisation comment.

@Test func renoStartsInSlowStartWithTheInitialWindow() {
    let reno = Reno(maximumSegmentSize: mss)
    #expect(reno.congestionWindow == initialWindow)
    #expect(reno.slowStartThreshold == Int.max, "RFC 5681 §3.1: ssthresh starts arbitrarily high, so the connection starts in slow start")
}

@Test func slowStartDoublesTheWindowEachRoundTrip() {
    // §3.1: cwnd += min(bytesAcked, SMSS) per ACK. A window of ten segments,
    // acknowledged segment by segment, adds ten segments -- one round trip,
    // one doubling.
    var reno = Reno(maximumSegmentSize: mss)
    for _ in 0..<10 {
        reno.acked(bytes: mss, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    }
    #expect(reno.congestionWindow == 29_200, "14_600 doubled")
    #expect(reno.slowStartThreshold == Int.max, "no loss, so the threshold is untouched")
}

@Test func aCumulativeAckGrowsSlowStartByAtMostOneSegment() {
    // The `min` in `cwnd += min(bytesAcked, SMSS)` is the ABC-safe form and it
    // is the whole difference between this test and the one above: a single
    // ACK covering ten segments must add ONE segment, not ten. Without the min
    // a delayed or lost-ACK-recovered cumulative acknowledgement doubles the
    // window in one step and produces a burst the path never agreed to.
    var reno = Reno(maximumSegmentSize: mss)
    reno.acked(bytes: initialWindow, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    #expect(reno.congestionWindow == 16_060, "14_600 + 1_460, not 29_200")
}

@Test func slowStartStopsAtTheThresholdAndCongestionAvoidanceTakesOver() {
    // Drop the threshold with a timeout, then walk back up. cwnd < ssthresh is
    // slow start (one segment per ACK); at or above it, congestion avoidance
    // adds SMSS*SMSS/cwnd per ACK, which is ~one segment per ROUND TRIP.
    var reno = Reno(maximumSegmentSize: mss)
    reno.timeout(flightSize: initialWindow)
    #expect(reno.slowStartThreshold == 7_300)
    #expect(reno.congestionWindow == mss)

    // 1_460 -> 2_920 -> 4_380 -> 5_840 -> 7_300: still below the threshold each
    // time the ACK arrives, so still slow start.
    for expected in [2_920, 4_380, 5_840, 7_300] {
        reno.acked(bytes: mss, flightSize: reno.congestionWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
        #expect(reno.congestionWindow == expected)
    }

    // cwnd == ssthresh now, so this ACK is congestion avoidance:
    // 1_460 * 1_460 / 7_300 = 292 exactly. Slow start would have said 8_760.
    reno.acked(bytes: mss, flightSize: reno.congestionWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    #expect(reno.congestionWindow == 7_592, "+292, not +1_460")
    // 1_460 * 1_460 / 7_592 = 280.
    reno.acked(bytes: mss, flightSize: reno.congestionWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    #expect(reno.congestionWindow == 7_872, "+280: the increment shrinks as the window grows")
}

@Test func theLossThresholdFollowsTheFlightSizeNotTheCongestionWindow() {
    // THE application-limited case, and the reason lossDetected takes a
    // flightSize at all. RFC 5681 §3.2 says ssthresh = max(FlightSize/2,
    // 2*SMSS), where FlightSize is what is actually outstanding. An
    // application that has only six segments' worth of data to send leaves
    // cwnd at twenty segments and FlightSize at six; halving cwnd there sets
    // the threshold from a window the path has never demonstrated it can
    // carry, and the sender leaves loss recovery still overshooting.
    var reno = Reno(maximumSegmentSize: mss)
    for _ in 0..<10 {
        reno.acked(bytes: mss, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    }
    let flightSize = 6 * mss  // 8_760
    #expect(reno.congestionWindow == 29_200)
    #expect(reno.congestionWindow > flightSize, "without this the substitution below is indistinguishable")

    reno.lossDetected(flightSize: flightSize)
    // max(8_760 / 2, 2 * 1_460) = max(4_380, 2_920) = 4_380.
    // Substituting cwnd would give max(29_200 / 2, 2_920) = 14_600.
    #expect(reno.slowStartThreshold == 4_380, "half the FLIGHT size, not half the window")
    // §3.2 fast recovery: cwnd = ssthresh + 3*SMSS, the three segments the
    // duplicate ACKs proved have left the network.
    #expect(reno.congestionWindow == 8_760, "4_380 + 3 * 1_460; the cwnd substitution would give 18_980")
}

@Test func theTimeoutThresholdAlsoFollowsTheFlightSize() {
    // Same substitution, the other entry point. §3.1's timeout rule uses the
    // same max(FlightSize/2, 2*SMSS); cwnd collapses to one segment either
    // way, so ssthresh is the only place the error would show.
    var reno = Reno(maximumSegmentSize: mss)
    for _ in 0..<10 {
        reno.acked(bytes: mss, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    }
    #expect(reno.congestionWindow == 29_200)
    #expect(reno.congestionWindow > 6 * mss)

    reno.timeout(flightSize: 6 * mss)
    #expect(reno.slowStartThreshold == 4_380, "cwnd would give 14_600")
    #expect(reno.congestionWindow == mss)
}

@Test func aTimeoutCollapsesTheWindowToOneSegment() {
    // Not to half. A timeout means the pipe's state is unknown, and Reno
    // restarts slow start from one MSS -- halving instead keeps an estimate
    // we have just learned is wrong.
    var reno = Reno(maximumSegmentSize: 1460)
    reno.acked(bytes: 14_600, flightSize: 14_600, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    let beforeTimeout = reno.congestionWindow
    #expect(beforeTimeout > 1460)  // without this the test is vacuous
    reno.timeout(flightSize: 14_600)
    #expect(reno.congestionWindow == 1460)
    #expect(reno.slowStartThreshold == max(14_600 / 2, 2 * 1460))
}

@Test func theThresholdNeverFallsBelowTwoSegments() {
    // The 2*SMSS floor in max(FlightSize/2, 2*SMSS). With a single segment in
    // flight, half of it is 730 bytes -- half a segment, a threshold no
    // sender can ever be at.
    var reno = Reno(maximumSegmentSize: mss)
    reno.lossDetected(flightSize: mss)
    #expect(reno.slowStartThreshold == 2_920, "2 * SMSS, not 730")
    #expect(reno.congestionWindow == 7_300, "2_920 + 3 * 1_460")
}

@Test func aDegenerateFlightSizeDoesNotProduceADegenerateWindow() {
    // A zero or negative flightSize can reach here from a sender whose
    // accounting has gone wrong, or from a loss signalled with nothing
    // outstanding. It must not divide badly or leave a window below one
    // segment -- a cwnd of 0 wedges the connection permanently.
    var afterLoss = Reno(maximumSegmentSize: mss)
    afterLoss.lossDetected(flightSize: 0)
    #expect(afterLoss.slowStartThreshold == 2_920)
    #expect(afterLoss.congestionWindow == 7_300)

    var afterTimeout = Reno(maximumSegmentSize: mss)
    afterTimeout.timeout(flightSize: -100)
    #expect(afterTimeout.slowStartThreshold == 2_920)
    #expect(afterTimeout.congestionWindow == mss)
}

@Test func aZeroSegmentSizeDoesNotDivideByZeroOrEmptyTheWindow() {
    // SMSS 0 is nonsense, but it arrives from a peer-influenced MSS option, so
    // it must degrade rather than trap. The segment size is clamped to one
    // byte: every window below stays >= 1, and the congestion-avoidance
    // division has a non-zero divisor.
    var reno = Reno(maximumSegmentSize: 0)
    #expect(reno.congestionWindow == 10, "ten one-byte segments")

    reno.timeout(flightSize: 0)
    #expect(reno.congestionWindow == 1)
    #expect(reno.slowStartThreshold == 2)

    reno.acked(bytes: 10, flightSize: 10, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))  // slow start: cwnd 1 < ssthresh 2
    #expect(reno.congestionWindow == 2)
    reno.acked(bytes: 10, flightSize: 10, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))  // congestion avoidance: 1*1/2 = 0
    #expect(reno.congestionWindow == 3, "the increment floor keeps the window moving")
}

@Test func congestionAvoidanceStillAdvancesWhenTheWindowExceedsTheSquareOfTheSegmentSize() {
    // SMSS*SMSS/cwnd truncates to zero once cwnd > SMSS^2, and a literal
    // reading of §3.1 then freezes the window forever. A four-byte SMSS makes
    // that reachable in one line (SMSS^2 = 16, cwnd = 62); at a real 1460 it
    // takes a 2.1MB window, which is rare but not unreachable.
    var reno = Reno(maximumSegmentSize: 4)
    reno.lossDetected(flightSize: 100)
    #expect(reno.slowStartThreshold == 50)
    #expect(reno.congestionWindow == 62, "50 + 3 * 4, and 62 > 16 = SMSS^2")

    reno.acked(bytes: 4, flightSize: 62, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    #expect(reno.congestionWindow == 63, "16 / 62 truncates to 0, floored to 1")
}

@Test func aNonPositiveAcknowledgementDoesNotMoveTheWindow() {
    // Nothing was acknowledged, so nothing about the path was learned.
    var reno = Reno(maximumSegmentSize: mss)
    #expect(reno.congestionWindow == initialWindow, "positive control: the window is non-zero to begin with")

    reno.acked(bytes: 0, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    reno.acked(bytes: -5, flightSize: initialWindow, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
    #expect(reno.congestionWindow == initialWindow, "unchanged")
    #expect(reno.slowStartThreshold == Int.max, "unchanged")
}

@Test func renoIsUsableThroughTheCongestionControlProtocol() {
    // Task 12's Sender holds a CongestionControl, not a Reno. The mutating
    // requirements have to be reachable through the abstraction or the
    // protocol is decoration.
    func drive(_ control: inout some CongestionControl) {
        control.acked(bytes: 1460, flightSize: 14_600, now: .uptimeNanoseconds(0), smoothedRoundTrip: .milliseconds(100))
        control.lossDetected(flightSize: 14_600)
    }
    var reno = Reno(maximumSegmentSize: mss)
    drive(&reno)
    #expect(reno.slowStartThreshold == 7_300)
    #expect(reno.congestionWindow == 11_680, "7_300 + 3 * 1_460")
}
