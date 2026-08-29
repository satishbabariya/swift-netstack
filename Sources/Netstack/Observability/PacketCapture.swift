import Foundation
import NIOCore

/// Every frame in and out, written to a file Wireshark can open.
///
/// Upstream's `CaptureFile`. When a guest's network misbehaves this is the tool
/// that settles what actually happened, and it is worth having precisely because
/// the alternative -- reasoning from counters -- is how the `host.containers.internal`
/// bug survived: everything looked right and nothing was.
///
/// ## The bound, again
///
/// A capture is a guest-reachable resource, and an unusual one: the guest spends
/// the **host's disk**, which no other bound in this package covers, and it does
/// so at whatever rate it can send. So the file has a size limit, and reaching it
/// stops the capture rather than rotating it. Stopping is the right end: a
/// rotating capture of a flood keeps the flood and discards the beginning, which
/// is the part that explains it.
///
/// ## Buffering, and what it costs
///
/// Frames are buffered and written in batches. A write syscall per frame would
/// cost more than the stack spends on the frame itself -- the throughput
/// benchmark says the socket calls already dominate everything -- so a capture
/// that did that would change the behaviour it was opened to observe.
///
/// The price is the tail: if the process dies, whatever is still buffered is
/// lost, and that is exactly the part someone debugging a crash wants. `flush()`
/// is public for that reason, and `close()` calls it.
public final class PacketCapture {
    /// Microseconds since the epoch. Injectable because `NetstackClock` is
    /// monotonic -- right for timers, useless in a capture file, where the whole
    /// point is correlating with something outside this process.
    public typealias WallClock = @Sendable () -> (seconds: UInt32, microseconds: UInt32)

    private let handle: FileHandle
    private let snapshotLength: Int
    private let maximumBytes: Int
    private let bufferLimit: Int
    private let now: WallClock

    private var buffer = [UInt8]()
    private var written = 0

    /// Frames not written because the size limit had been reached.
    public private(set) var dropped = 0
    /// Whether the capture has stopped because it reached `maximumBytes`.
    public private(set) var isFull = false

    /// - Parameters:
    ///   - path: created, or truncated if it exists.
    ///   - snapshotLength: the most of each frame to keep. The default keeps a
    ///     whole ethernet frame at the usual MTU; a smaller value records
    ///     headers only, which is enough to follow a conversation and much
    ///     smaller.
    ///   - maximumBytes: the file stops growing here. 64 MiB by default, which
    ///     is minutes of ordinary traffic and seconds of a flood.
    public init(
        path: String, snapshotLength: Int = 1514, maximumBytes: Int = 64 * 1024 * 1024,
        bufferLimit: Int = 64 * 1024, now: @escaping WallClock = PacketCapture.systemTime
    ) throws {
        FileManager.default.createFile(atPath: path, contents: nil)
        guard let handle = FileHandle(forWritingAtPath: path) else {
            throw StackError.notConnected
        }
        self.handle = handle
        self.snapshotLength = max(1, snapshotLength)
        self.maximumBytes = max(Self.globalHeaderLength, maximumBytes)
        self.bufferLimit = max(1024, bufferLimit)
        self.now = now
        try handle.truncate(atOffset: 0)
        writeGlobalHeader()
    }

    public static let systemTime: WallClock = {
        var time = timeval()
        gettimeofday(&time, nil)
        return (UInt32(truncatingIfNeeded: time.tv_sec), UInt32(truncatingIfNeeded: time.tv_usec))
    }

    private static let globalHeaderLength = 24

    /// The classic libpcap header: magic, version 2.4, no timezone correction,
    /// and link type 1 for Ethernet.
    ///
    /// Written little-endian with the `0xa1b2c3d4` magic, which is how a reader
    /// discovers the byte order -- it is the same value read the other way round
    /// if the writer was big-endian.
    private func writeGlobalHeader() {
        append32(0xa1b2_c3d4)
        append16(2)
        append16(4)
        append32(0)  // thiszone
        append32(0)  // sigfigs
        append32(UInt32(snapshotLength))
        append32(1)  // LINKTYPE_ETHERNET
        written += Self.globalHeaderLength
    }

    /// Record one frame. Safe to call for every frame on the datapath.
    public func record(_ frame: ByteBuffer) {
        guard !isFull else {
            dropped += 1
            return
        }
        let original = frame.readableBytes
        let kept = min(original, snapshotLength)
        // The record's own header is counted against the limit as well as its
        // payload: a limit that ignored it would be exceeded by 16 bytes per
        // frame, which for a capture of small frames is most of the overshoot.
        guard written + 16 + kept <= maximumBytes else {
            isFull = true
            dropped += 1
            flush()
            return
        }
        let stamp = now()
        append32(stamp.seconds)
        append32(stamp.microseconds)
        append32(UInt32(kept))
        // `orig_len` is the frame's real length even when only `kept` bytes were
        // saved, which is how a reader knows it is looking at a truncated frame
        // rather than a short one.
        append32(UInt32(original))
        if let bytes = frame.getBytes(at: frame.readerIndex, length: kept) {
            buffer.append(contentsOf: bytes)
        }
        written += 16 + kept
        if buffer.count >= bufferLimit { flush() }
    }

    /// Write what is buffered. Call before reading the file from anywhere else.
    public func flush() {
        guard !buffer.isEmpty else { return }
        try? handle.write(contentsOf: Data(buffer))
        buffer.removeAll(keepingCapacity: true)
    }

    public func close() {
        flush()
        try? handle.close()
    }

    private func append32(_ value: UInt32) {
        buffer.append(UInt8(truncatingIfNeeded: value))
        buffer.append(UInt8(truncatingIfNeeded: value >> 8))
        buffer.append(UInt8(truncatingIfNeeded: value >> 16))
        buffer.append(UInt8(truncatingIfNeeded: value >> 24))
    }

    private func append16(_ value: UInt16) {
        buffer.append(UInt8(truncatingIfNeeded: value))
        buffer.append(UInt8(truncatingIfNeeded: value >> 8))
    }
}

/// A link that records everything crossing it, and is otherwise the link it
/// wraps.
///
/// A decorator rather than a flag on each link type, because there are two of
/// them -- `WireLinkEndpoint` and `NetworkSwitch` -- and a capture belongs to
/// neither. It sits where the frames already pass, which is the only place that
/// sees both directions.
public final class CapturingLink: GatewayLink, @unchecked Sendable {
    private var wrapped: GatewayLink
    private let capture: PacketCapture
    private weak var dispatcher: (any LinkDispatcher)?

    public var mtu: UInt32 { wrapped.mtu }
    public var linkAddress: MACAddress { wrapped.linkAddress }
    public var capabilities: LinkCapabilities { wrapped.capabilities }
    public var eventLoop: EventLoop { wrapped.eventLoop }
    public var inboundDropped: Int { wrapped.inboundDropped }
    public var outboundDropped: Int { wrapped.outboundDropped }
    public var bytesReceived: Int { wrapped.bytesReceived }
    public var bytesSent: Int { wrapped.bytesSent }

    public var log: RateLimitedLogger? {
        get { wrapped.log }
        set { wrapped.log = newValue }
    }

    public init(wrapping link: GatewayLink, capture: PacketCapture) {
        self.wrapped = link
        self.capture = capture
    }

    public func attach(_ dispatcher: LinkDispatcher) {
        self.dispatcher = dispatcher
        wrapped.attach(self)
    }

    public func write(_ packets: [PacketBuffer]) {
        for packet in packets { capture.record(packet.frame) }
        wrapped.write(packets)
    }

    public func close() -> EventLoopFuture<Void> {
        capture.close()
        return wrapped.close()
    }
}

extension CapturingLink: LinkDispatcher {
    public func deliverInbound(_ frame: PacketBuffer) {
        capture.record(frame.frame)
        dispatcher?.deliverInbound(frame)
    }
}
