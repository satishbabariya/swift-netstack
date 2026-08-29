import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// A capture is a guest-reachable resource with an unusual cost: the guest spends
// the HOST's disk, which no other bound in this package covers, and at whatever
// rate it can send. So the interesting tests here are the bound and the format.

private func capturePath(_ tag: String) -> String {
    "/tmp/netstack-capture-\(tag)-\(UInt32.random(in: 0...UInt32.max)).pcap"
}

private func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 | UInt32(bytes[offset + 2]) << 16
        | UInt32(bytes[offset + 3]) << 24
}

/// The frames in a pcap file, as (captured, original) lengths plus the bytes.
private func records(in path: String) throws -> [(captured: Int, original: Int, bytes: [UInt8])] {
    let data = try [UInt8](Data(contentsOf: URL(fileURLWithPath: path)))
    guard data.count >= 24 else { return [] }
    var out: [(Int, Int, [UInt8])] = []
    var offset = 24
    while offset + 16 <= data.count {
        let captured = Int(read32(data, offset + 8))
        let original = Int(read32(data, offset + 12))
        guard offset + 16 + captured <= data.count else { break }
        out.append((captured, original, Array(data[(offset + 16)..<(offset + 16 + captured)])))
        offset += 16 + captured
    }
    return out
}

@Test func aCaptureWritesAFileWiresharkCanRead() throws {
    let path = capturePath("format")
    defer { try? FileManager.default.removeItem(atPath: path) }
    let capture = try PacketCapture(path: path, now: { (1_700_000_000, 123_456) })

    capture.record(ByteBuffer(bytes: [UInt8](repeating: 0xaa, count: 60)))
    capture.record(ByteBuffer(bytes: [UInt8](repeating: 0xbb, count: 100)))
    capture.close()

    let data = try [UInt8](Data(contentsOf: URL(fileURLWithPath: path)))
    // The magic is what tells a reader the byte order: read the other way round
    // it is the same value, which is the whole trick.
    #expect(read32(data, 0) == 0xa1b2_c3d4)
    #expect(data[4] == 2 && data[5] == 0, "version major is not 2")
    #expect(data[6] == 4 && data[7] == 0, "version minor is not 4")
    #expect(read32(data, 20) == 1, "link type is not Ethernet")

    let frames = try records(in: path)
    #expect(frames.count == 2)
    #expect(frames[0].captured == 60)
    #expect(frames[0].bytes.allSatisfy { $0 == 0xaa })
    #expect(frames[1].captured == 100)
    // The timestamp is the injected one, so this is the writer rather than the
    // clock being checked.
    #expect(read32(data, 24) == 1_700_000_000)
    #expect(read32(data, 28) == 123_456)
}

@Test func aTruncatedFrameStillReportsItsRealLength() throws {
    // `orig_len` is how a reader knows it is looking at a truncated frame rather
    // than a short one. Without it a snapshot-limited capture silently claims
    // every frame was small, which is a different packet trace.
    let path = capturePath("snaplen")
    defer { try? FileManager.default.removeItem(atPath: path) }
    let capture = try PacketCapture(path: path, snapshotLength: 40)

    capture.record(ByteBuffer(bytes: [UInt8](repeating: 0xcc, count: 1200)))
    capture.close()

    let frames = try records(in: path)
    #expect(frames.count == 1)
    #expect(frames[0].captured == 40, "the snapshot length was not applied")
    #expect(frames[0].original == 1200, "the real length was lost")
}

@Test func aCaptureStopsAtItsSizeLimitRatherThanFillingTheDisk() throws {
    // The bound. A guest sends as fast as it can and every frame it sends is a
    // record here, so without this the guest chooses how much of the host's disk
    // to occupy -- a resource nothing else in this package covers.
    let path = capturePath("bound")
    defer { try? FileManager.default.removeItem(atPath: path) }
    // Room for the 24-byte global header and a handful of 116-byte records.
    let capture = try PacketCapture(path: path, maximumBytes: 24 + 116 * 5)

    for _ in 0..<500 {
        capture.record(ByteBuffer(bytes: [UInt8](repeating: 0xdd, count: 100)))
    }
    capture.close()

    let size = try FileManager.default.attributesOfItem(atPath: path)[.size] as? Int ?? 0
    #expect(size <= 24 + 116 * 5, "the capture grew past its limit: \(size)")
    // A floor, because a capture that wrote nothing at all also satisfies the
    // bound above.
    let frames = try records(in: path)
    #expect(frames.count == 5, "expected five frames, got \(frames.count)")
    #expect(capture.isFull)
    #expect(capture.dropped == 495)
}

@Test func theRecordHeaderCountsAgainstTheLimitToo() throws {
    // A limit that counted only payloads would admit a record whose header then
    // pushes the file past it -- an overshoot of up to sixteen bytes per frame.
    //
    // The limit here is chosen to land BETWEEN two record boundaries, and that
    // is the whole test. With a limit on a boundary both rules stop at the same
    // record and the file is the same size either way: the first version of this
    // used 24 + 76*10 and passed with the header dropped from the check.
    //
    // 60-byte frames make 76-byte records. After ten, the file is 784 bytes. A
    // limit of 850 leaves room for 60 more payload bytes but not for a whole
    // eleventh record, so counting the header stops at ten and not counting it
    // admits an eleventh and ends at 860 -- past the limit.
    let path = capturePath("header-bound")
    defer { try? FileManager.default.removeItem(atPath: path) }
    let limit = 850
    let capture = try PacketCapture(path: path, maximumBytes: limit)

    for _ in 0..<200 {
        capture.record(ByteBuffer(bytes: [UInt8](repeating: 0xee, count: 60)))
    }
    capture.close()

    let size = try FileManager.default.attributesOfItem(atPath: path)[.size] as? Int ?? 0
    #expect(size <= limit, "the capture overshot its limit by \(size - limit) bytes")
    #expect(size == 24 + 76 * 10, "expected ten whole records, got \(size) bytes")
    #expect(try records(in: path).count == 10)
}

@Test func aCapturingLinkSeesBothDirections() throws {
    // The decorator sits where the frames already pass, which is the only place
    // that sees both. A capture of one direction is the failure mode worth
    // guarding: it looks like a working capture of a silent peer.
    let path = capturePath("directions")
    defer { try? FileManager.default.removeItem(atPath: path) }
    let loop = EmbeddedEventLoop()
    let channel = EmbeddedChannel(loop: loop)
    let wire = WireLinkEndpoint(channel: channel, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: wire))
    let capture = try PacketCapture(path: path)
    let link = CapturingLink(wrapping: wire, capture: capture)

    let collector = CaptureCollector()
    link.attach(collector)

    // Outbound.
    link.write([PacketBuffer(received: ByteBuffer(bytes: [UInt8](repeating: 0x11, count: 64)))])
    channel.flush()
    _ = try channel.readOutbound(as: ByteBuffer.self)
    // Inbound.
    try channel.writeInbound(ByteBuffer(bytes: [UInt8](repeating: 0x22, count: 80)))

    capture.flush()
    let frames = try records(in: path)
    #expect(frames.count == 2, "the capture saw \(frames.count) frames, not both directions")
    #expect(frames.contains { $0.bytes.first == 0x11 }, "the outbound frame was not captured")
    #expect(frames.contains { $0.bytes.first == 0x22 }, "the inbound frame was not captured")
    // And the wrapped link still does its job: the frame reached the dispatcher.
    #expect(collector.frames.count == 1, "wrapping the link swallowed the inbound frame")

    capture.close()
    _ = try? channel.finish()
}

private final class CaptureCollector: LinkDispatcher, @unchecked Sendable {
    var frames: [ByteBuffer] = []
    func deliverInbound(_ frame: PacketBuffer) { frames.append(frame.frame) }
}
