import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// How fast is it, actually?
//
// Nothing else here measures that. Every other test asks whether the stack does
// the right thing; this one asks how much it can do, which is a different
// question and the one a user hits second.
//
// ## This is a BENCHMARK, not a gate, and the difference is deliberate
//
// It is skipped unless `NETSTACK_THROUGHPUT` is set, and it asserts almost
// nothing. A throughput floor is a wall-clock assertion, and a wall-clock
// assertion on shared hardware is the flakiest thing this suite could contain --
// `evictionUnderTheByteCapDoesNotScanEveryPendingEntry` already had to be
// rewritten from a five-second ceiling into a ratio for exactly that reason.
// What this produces is a NUMBER, printed, for a human to compare against the
// last one.
//
// The milestone's own criterion is `iperf3` guest-to-host at 1 Gbit/s through a
// real VM. This is not that, and it does not satisfy it: there is no guest
// kernel here, so what it measures is this stack's datapath and the splice
// behind it, with a synthetic peer that acknowledges everything immediately.
// Expect it to be optimistic about the network and honest about the stack.
//
// ## What it measured, so the next number has something to be compared against
//
// 618 Mbit/s in a release build, 85 in debug, on an Apple-silicon laptop — 32
// MiB of 1400-byte segments through the whole gateway to a real loopback
// listener.
//
// **Most of that time is syscalls, and that is measured rather than assumed.**
// This note first said "profile before optimising rather than assume the
// syscalls dominate"; the profile was then run, and they do. `sample` over a
// 1.5 GB run, by top of stack:
//
// ```
// write     2146      TCPHeader.serialize   101
// sendto    1855      TCPHeader.parse        70
// recvfrom  1355
// read       750
// ```
//
// The stack's own header work is around two per cent of what the socket calls
// cost. So this measures the harness at least as much as the stack — one `send`
// per 1400-byte segment, serialised with the work being measured on a single
// thread — and the figure is still the one worth tracking, because it is what a
// caller doing the same thing would see.
//
// `swift_beginAccess` and `AccessSet::insert` together take another 207 samples,
// which is exclusivity checking that a plain release build does not do: this has
// to be built with `-enable-testing` to reach `@testable` internals, so even the
// release figure is conservative.

private let benchGuest = IPv4Address("192.168.127.2")!
private let benchGateway = IPv4Address("192.168.127.1")!
private let benchGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let benchGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class BenchHolder: @unchecked Sendable {
    var gateway: Gateway?
}

/// Counts what arrives without copying it, so the listener is not the thing
/// being measured.
private final class ByteCounter: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let received = NIOLockedValueBox(0)

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let count = unwrapInboundIn(data).readableBytes
        received.withLockedValue { $0 += count }
    }
}

/// One TCP segment from the guest, framed for the wire.
private func benchFrame(
    to destination: IPv4Address, destinationPort: UInt16, sequence: UInt32, acknowledgement: UInt32,
    flags: TCPFlags, window: UInt16 = 65535, payload: ByteBuffer = ByteBuffer(), sourcePort: UInt16 = 50000
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: window, checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: payload, source: benchGuest, destination: destination, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(
        source: benchGuest, destination: destination, protocolNumber: .tcp,
        payloadLength: segment.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: benchGatewayMAC, source: benchGuestMAC, etherType: .ipv4)
        .prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

@Test func measureGuestToHostThroughput() async throws {
    guard ProcessInfo.processInfo.environment["NETSTACK_THROUGHPUT"] != nil else { return }

    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    var size: Int32 = 8 * 1024 * 1024
    _ = setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
    _ = setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    let counter = ByteCounter()
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.pipeline.addHandler(counter) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    let holder = BenchHolder()
    holder.gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()
    try await holder.gateway!.eventLoop.submit {
        holder.gateway!.stack.arpCache.record(benchGuest, benchGuestMAC)
    }.get()

    // Handshake, driven by hand: there is no guest kernel here.
    let guestISS: UInt32 = 1_000_000
    var bytes = benchFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: guestISS,
        acknowledgement: 0, flags: [.syn])
    _ = bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }

    var gatewayISS: UInt32 = 0
    var back = [UInt8](repeating: 0, count: 4096)
    for _ in 0..<800 where gatewayISS == 0 {
        let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
        if read > 0 {
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp else { continue }
            guard let tcp = TCPHeader.parse(&packet, header: ip), tcp.flags.contains(.syn) else { continue }
            gatewayISS = tcp.sequence.value
        } else {
            try await Task.sleep(nanoseconds: 2_000_000)
        }
    }
    #expect(gatewayISS != 0, "the connection was never accepted")

    bytes = benchFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: guestISS + 1,
        acknowledgement: gatewayISS &+ 1, flags: [.ack])
    _ = bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }

    // Bulk. One MSS-sized segment per frame, with a window the gateway's own
    // receive buffer will bound long before this does.
    let payloadSize = 1400
    // Configurable, because 32 MiB finishes in under half a second in a release
    // build -- too fast to attach a sampling profiler to, which is the first
    // thing anyone chasing the number will want to do.
    let total =
        (ProcessInfo.processInfo.environment["NETSTACK_THROUGHPUT_MB"].flatMap(Int.init) ?? 32)
        * 1024 * 1024
    var payload = ByteBufferAllocator().buffer(capacity: payloadSize)
    payload.writeBytes([UInt8](repeating: 0x5a, count: payloadSize))
    var sequence = guestISS + 1
    var sent = 0

    let started = ContinuousClock.now
    while sent < total {
        let frame = benchFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: sequence,
            acknowledgement: gatewayISS &+ 1, flags: [.ack, .psh], payload: payload)
        let wrote = frame.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        if wrote < 0 {
            // The wire is full: drain what came back and try again. This is the
            // gateway applying backpressure, which is the thing working rather
            // than the thing failing.
            for _ in 0..<64 {
                if back.withUnsafeMutableBytes({ recv(pair[1], $0.baseAddress, $0.count, dontWait) }) <= 0 {
                    break
                }
            }
            continue
        }
        sequence = sequence &+ UInt32(payloadSize)
        sent += payloadSize
        // Drain the return path every so often, so the guest's receive buffer
        // does not fill and stall the wire for a reason that is not the stack's.
        if sent % (64 * payloadSize) == 0 {
            for _ in 0..<64 {
                if back.withUnsafeMutableBytes({ recv(pair[1], $0.baseAddress, $0.count, dontWait) }) <= 0 {
                    break
                }
            }
        }
    }

    // Wait for the host listener to have seen it all, draining as we go.
    var delivered = 0
    for _ in 0..<4000 where delivered < sent {
        for _ in 0..<256 {
            if back.withUnsafeMutableBytes({ recv(pair[1], $0.baseAddress, $0.count, dontWait) }) <= 0 {
                break
            }
        }
        delivered = counter.received.withLockedValue { $0 }
        if delivered < sent { try await Task.sleep(nanoseconds: 2_000_000) }
    }
    let elapsed = ContinuousClock.now - started

    let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
    let megabits = Double(delivered) * 8 / 1_000_000
    print(
        """
        THROUGHPUT guest→host: \(delivered) bytes in \(String(format: "%.2f", seconds)) s \
        = \(String(format: "%.0f", megabits / seconds)) Mbit/s
        """)

    // The only assertion, and it is about correctness rather than speed: every
    // byte the guest sent reached the host listener. A throughput number from a
    // run that lost data is a number about something else.
    // Against what was SENT, not against the target: the loop stops once it has
    // passed the target, so it overshoots by up to one segment. Comparing with
    // the target instead fails on a run that lost nothing, which is a test
    // reporting its own arithmetic as a defect.
    #expect(delivered == sent, "\(delivered) of \(sent) bytes arrived")

    try? await listener.close()
    _ = try? await holder.gateway?.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}
