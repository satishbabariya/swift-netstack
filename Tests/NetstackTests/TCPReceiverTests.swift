import NIOCore
import Testing

@testable import Netstack

// MARK: - Test fixtures

private func segment(sequence: UInt32, payload: Int = 0, fill: UInt8 = 0xaa, flags: TCPFlags = []) -> Segment {
    var buffer = ByteBuffer()
    if payload > 0 {
        buffer.writeBytes([UInt8](repeating: fill, count: payload))
    }
    return Segment(sequence: SequenceNumber(sequence), flags: flags, payload: buffer)
}

private func stateMachineSegment(
    sequence: UInt32, ack: UInt32 = 100, flags: TCPFlags = [.ack], payload: Int = 0, fill: UInt8 = 0xaa
) -> TCPSegment {
    let header = TCPHeader(
        sourcePort: 55000,
        destinationPort: 80,
        sequence: SequenceNumber(sequence),
        acknowledgement: SequenceNumber(ack),
        dataOffset: 5,
        flags: flags,
        window: 4096,
        checksum: 0,
        urgentPointer: 0,
        options: [])
    var buffer = ByteBuffer()
    if payload > 0 {
        buffer.writeBytes([UInt8](repeating: fill, count: payload))
    }
    return TCPSegment(header: header, payload: buffer)
}

private func establishedTCB(rcvNxt: UInt32 = 1000, rcvWnd: Int = 4096, sndUna: UInt32 = 100, sndNxt: UInt32 = 100) -> TCB {
    TCB(
        state: .established,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndNxt),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

private func receivedBytes(_ buffers: [ByteBuffer]) -> [UInt8] {
    buffers.flatMap { Array($0.readableBytesView) }
}

private func deliveredBytes(_ actions: [TCPAction]) -> [UInt8] {
    actions.flatMap { action -> [UInt8] in
        if case .deliver(let buffer) = action { return Array(buffer.readableBytesView) }
        return []
    }
}

private func hasSendAck(_ actions: [TCPAction]) -> Bool {
    actions.contains {
        if case .sendAck = $0 { return true }
        return false
    }
}

private func hasDeliver(_ actions: [TCPAction]) -> Bool {
    actions.contains {
        if case .deliver = $0 { return true }
        return false
    }
}

/// The right edge of the receive window: the highest sequence number the peer
/// has been told it may send. Retracting this is what RFC 9293 §3.8.6.2.2
/// forbids.
private func rightEdge(_ tcb: TCB, window: UInt16) -> SequenceNumber {
    tcb.rcvNxt + Int(window)
}

// MARK: - In-order delivery

@Test func theReceiverAdvancesRcvNxtAndDeliversAnInOrderSegment() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)

    #expect(receivedBytes(outcome.delivered) == Array(repeating: 0xaa, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1010), "RCV.NXT advances over exactly the bytes delivered")
    #expect(outcome.shouldAck)
}

@Test func theReceiverAdvancesRcvNxtAcrossTheSequenceSpaceWrap() {
    // RCV.NXT ten bytes below 2^32: the second half of this segment sits at
    // numerically smaller sequence numbers than the first. Anything that adds
    // in `Int` and clamps, rather than wrapping in `UInt32`, lands elsewhere.
    var tcb = establishedTCB(rcvNxt: 0xffff_fff6)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 0xffff_fff6, payload: 20, fill: 0xcc), tcb: &tcb)

    #expect(receivedBytes(outcome.delivered) == Array(repeating: 0xcc, count: 20))
    #expect(tcb.rcvNxt == SequenceNumber(0x0000_000a))
}

// MARK: - Out-of-order data

@Test func anOutOfOrderSegmentDoesNotAdvanceRcvNxt() {
    // "Does not advance" and "delivers nothing" are both satisfied by a
    // receiver that does nothing whatever -- this test passed against a stub
    // returning empty from every call. The second half is the floor under it:
    // the same receiver must go on to deliver those exact bytes, in that
    // order, once the gap in front of them closes. Held, not dropped.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb)

    #expect(outcome.delivered.isEmpty)
    #expect(tcb.rcvNxt == SequenceNumber(1000))

    let filled = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)
    #expect(receivedBytes(filled.delivered) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1020), "the held bytes were kept, and RCV.NXT covers both segments")
}

@Test func anOutOfOrderSegmentIsStillAcknowledged() {
    // The duplicate ACK. RFC 5681 §3.2: a receiver MUST send an immediate ACK
    // for an out-of-order segment, and the sender's fast retransmit counts
    // those duplicates. Suppress this and fast retransmit (Task 11) never
    // fires -- the connection still works, waiting on the retransmission
    // timer instead, so only a throughput measurement would ever notice.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb)

    #expect(outcome.shouldAck, "an out-of-order segment must be acknowledged immediately")
}

@Test func aSegmentThatOccupiesNoSequenceSpaceIsNotAcknowledged() {
    // A receiver that never asks for an ACK at all satisfies the first
    // expectation -- it passed against a do-nothing stub. The second is the
    // floor: the same receiver, one line later, must ask for one when the
    // segment does occupy sequence space. What is being pinned down is the
    // distinction, not the `false`.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    #expect(
        !receiver.accept(segment(sequence: 1000), tcb: &tcb).shouldAck,
        "acknowledging a bare ACK would put two peers in an ACK loop")
    #expect(receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb).shouldAck, "one byte is enough to owe an ACK")
    #expect(receiver.accept(segment(sequence: 1001, flags: .fin), tcb: &tcb).shouldAck, "and so is a FIN carrying no data at all")
}

@Test func aSegmentFillingAGapDeliversItselfAndEverythingQueuedBehindIt() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    #expect(receiver.accept(segment(sequence: 1020, payload: 10, fill: 0xcc), tcb: &tcb).delivered.isEmpty)
    #expect(receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb).delivered.isEmpty)

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)

    #expect(
        receivedBytes(outcome.delivered)
            == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10) + Array(repeating: 0xcc, count: 10),
        "the whole run, in sequence order, not just the arriving segment")
    #expect(tcb.rcvNxt == SequenceNumber(1030))
}

// MARK: - The advertised window

@Test func theAdvertisedWindowShrinksAsTheQueueFillsAndRecoversWhenTheGapCloses() {
    // Both halves matter. A window that never shrinks promises a peer room
    // the reassembly queue does not have; a window that never recovers
    // strangles a connection that has already drained.
    let control = {
        var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
        var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))
        return receiver.accept(segment(sequence: 1000, payload: 400), tcb: &tcb).advertisedWindow
    }()
    #expect(control == 4096, "with nothing queued, 400 in-order bytes cost the window nothing")

    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    _ = receiver.accept(segment(sequence: 2000, payload: 1000, fill: 0xbb), tcb: &tcb)
    let shrunk = receiver.accept(segment(sequence: 1000, payload: 400, fill: 0xaa), tcb: &tcb)
    // 1000 payload bytes plus one segment's overhead are held, so 2840 of the
    // 4096-byte queue is free; RCV.NXT has moved 400 and the right edge may
    // not move back, so 3696 is what can be offered.
    #expect(shrunk.advertisedWindow == 3696)
    #expect(shrunk.advertisedWindow < control, "the queued segment is what costs the window")

    let recovered = receiver.accept(segment(sequence: 1400, payload: 600, fill: 0xaa), tcb: &tcb)
    #expect(tcb.rcvNxt == SequenceNumber(3000), "the gap closing delivers the queued bytes too")
    #expect(recovered.advertisedWindow == 4096, "and the queue they leave is empty again")
}

@Test func theAdvertisedWindowNeverShrinksBelowWhatWasAlreadyOffered() {
    // Retracting the right window edge is forbidden (RFC 9293 3.8.6.2.2): the
    // peer may already have data in flight for space we advertised, and taking
    // it back makes that data unacceptable on arrival -- the connection stalls
    // with both sides believing the other owes them something.
    //
    // Driven over a sequence rather than a single in-order segment. With one
    // in-order segment and an empty queue the free-space figure is the whole
    // cap, so a receiver that advertised free space with no clamp at all would
    // pass -- the retraction only becomes visible once something is queued.
    // The first step below is that something.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))
    var edge = rightEdge(tcb, window: UInt16(tcb.rcvWnd))

    // Queued out-of-order bytes consume capacity without advancing RCV.NXT,
    // so free space falls while the edge may not.
    for step in [(sequence: UInt32(2000), payload: 1000), (sequence: 1000, payload: 400), (sequence: 1400, payload: 600)] {
        let outcome = receiver.accept(segment(sequence: step.sequence, payload: step.payload), tcb: &tcb)
        let newEdge = rightEdge(tcb, window: outcome.advertisedWindow)
        #expect(newEdge.isAtOrAfter(edge), "the right window edge moved backwards at sequence \(step.sequence)")
        edge = newEdge
    }
}

@Test func theAdvertisedWindowFitsTheWireFieldWithoutBeingTruncatedToIt() {
    // `<= 65535` is satisfied by advertising zero -- this test, in that form,
    // passed against a receiver that returned nothing from every call. The
    // point is not the ceiling but that the receiver clamps rather than
    // truncates: the default reassembler holds 256 KiB, which does not fit a
    // UInt16, and `UInt16(truncatingIfNeeded:)` of 262144 is 0 -- a receiver
    // that truncated would advertise a closed window on a completely empty
    // queue and stall the connection immediately. So the assertion is on the
    // exact value.
    //
    // 65535 is also the real ceiling today, not a placeholder: no window scale
    // is negotiated anywhere in the stack yet. See `Receiver`'s doc comment on
    // the seam Task 13 opens.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10), tcb: &tcb)

    #expect(outcome.advertisedWindow == 65535)
    #expect(tcb.rcvWnd == 65535, "and the TCB records what was advertised, since it is what the next acceptability test uses")
}

// MARK: - FIN

@Test func anOutOfOrderFinIsNotActedOnUntilTheGapFills() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let held = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb, flags: .fin), tcb: &tcb)
    #expect(!held.finReached, "the FIN's sequence has not been reached: 1000..<1010 is still missing")
    #expect(tcb.rcvNxt == SequenceNumber(1000))

    let filled = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)
    #expect(filled.finReached, "the gap-filling segment carries no FIN of its own, but it is what reaches one")
    #expect(tcb.rcvNxt == SequenceNumber(1021), "RCV.NXT covers 20 payload bytes and the FIN's own sequence number")
}

@Test func theFinIsReportedExactlyOnce() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let first = receiver.accept(segment(sequence: 1000, flags: .fin), tcb: &tcb)
    #expect(first.finReached)
    #expect(tcb.rcvNxt == SequenceNumber(1001), "a bare FIN consumes one sequence number")

    let retransmitted = receiver.accept(segment(sequence: 1000, flags: .fin), tcb: &tcb)
    #expect(!retransmitted.finReached, "a retransmitted FIN must not re-fire the transition")
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

// MARK: - The seam with the state machine

@Test func theStateMachineLeavesRcvNxtEntirelyToTheReceiver() {
    // The double-ownership test. Both this machine and the receiver once
    // advanced RCV.NXT over in-order payload and over a FIN; if both still do,
    // every arriving byte moves it twice and the connection acknowledges data
    // it has never seen. Exact equality is what catches that -- an assertion
    // that RCV.NXT merely "advanced" is satisfied by advancing it twice.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = TCPStateMachine.receive(segment: stateMachineSegment(sequence: 1000, payload: 10), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1010), "ten bytes, advanced once")

    _ = TCPStateMachine.receive(segment: stateMachineSegment(sequence: 1010, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1011), "and the FIN's one sequence number, also once")
    #expect(tcb.state == .closeWait)
}

@Test func theStateMachineDeliversDataThatArrivedOutOfOrderOnceTheGapFills() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outOfOrder = TCPStateMachine.receive(
        segment: stateMachineSegment(sequence: 1010, payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(!hasDeliver(outOfOrder), "nothing is deliverable while 1000..<1010 is missing")
    #expect(tcb.rcvNxt == SequenceNumber(1000))
    #expect(hasSendAck(outOfOrder), "but it is acknowledged -- this is the duplicate ACK fast retransmit counts")

    let inOrder = TCPStateMachine.receive(
        segment: stateMachineSegment(sequence: 1000, payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(deliveredBytes(inOrder) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1020))
}

@Test func aFinBehindAGapClosesTheConnectionOnlyWhenTheGapFills() {
    // The case the previous implementation could not reach at all: it tested
    // the arriving segment's own sequence against RCV.NXT, so a FIN behind a
    // gap was seen once, found out of order, and never looked at again.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = TCPStateMachine.receive(
        segment: stateMachineSegment(sequence: 1010, flags: [.fin, .ack], payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "the FIN is behind a gap; the connection is not closing yet")

    let actions = TCPStateMachine.receive(
        segment: stateMachineSegment(sequence: 1000, payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closeWait)
    #expect(tcb.rcvNxt == SequenceNumber(1021))
    #expect(hasSendAck(actions))
}

@Test func anUnacceptableSegmentNeverReachesTheReassembler() {
    // Ordering property: the receiver is driven only after RFC 9293's
    // acceptability test. Run the other way round, a peer could queue -- and
    // ultimately have delivered -- data far outside the window it was offered.
    //
    // "Nothing was queued" on its own is satisfied by a receiver that queues
    // nothing ever, which is how this passed against a do-nothing stub. The
    // control below is the floor: an out-of-order segment that IS acceptable,
    // offered to the same machine, must reach the queue. Without it this test
    // would still pass if step 5 stopped calling the receiver altogether --
    // which would suppress every out-of-order segment, not just the hostile
    // one, and look identical from here.
    let rejected = TCPReassembler()
    var farOutOfWindow = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var rejecting = Receiver(reassembler: rejected)
    _ = TCPStateMachine.receive(segment: stateMachineSegment(sequence: 50_000, payload: 10), on: &farOutOfWindow, receiver: &rejecting)
    #expect(rejected.pendingSegments == 0)
    #expect(farOutOfWindow.rcvNxt == SequenceNumber(1000))

    let accepted = TCPReassembler()
    var inWindow = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var accepting = Receiver(reassembler: accepted)
    _ = TCPStateMachine.receive(segment: stateMachineSegment(sequence: 1050, payload: 10), on: &inWindow, receiver: &accepting)
    #expect(accepted.pendingSegments == 1, "an acceptable out-of-order segment is held, not discarded")
}
