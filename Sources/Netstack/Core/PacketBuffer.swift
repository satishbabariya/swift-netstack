import NIOCore

/// A frame under construction or under inspection.
///
/// Backed by a single `ByteBuffer` with reserved headroom in front of the
/// payload. Building an egress frame prepends the transport, then network,
/// then link header into that headroom, so a complete frame is assembled with
/// no reallocation and no copy. Parsing an ingress frame walks the reader
/// index forward and records how long each header was; it never slices.
public struct PacketBuffer: Sendable {
    /// Sized for the worst case this stack actually emits:
    ///   ethernet 14 + IPv4 20 + TCP 60 (full options: MSS, window scale,
    ///   SACK-permitted, timestamps, and SACK blocks) = 94 bytes.
    /// Rounded up to 128 for slack. `prepend` enforces this with a
    /// `precondition`, which is live in release builds — undersizing it is a
    /// crash, not a slow path, and UDP-only tests would never reveal it.
    /// This stack never emits IPv4 options; headers are built at minimum length.
    public static let defaultHeadroom = 128

    private var storage: ByteBuffer

    /// Length of each header consumed or prepended, for callers that need to
    /// step back up a layer (ICMP errors quote the offending IP header).
    public private(set) var linkHeaderLength = 0
    public private(set) var networkHeaderLength = 0
    public private(set) var transportHeaderLength = 0

    /// Which layer the next `prepend` or `consumeHeader` refers to.
    private enum Layer { case transport, network, link, done }
    private var prependLayer: Layer = .transport
    private var consumeLayer: Layer = .link

    /// A buffer for an outgoing packet, with headroom reserved.
    public init(allocator: ByteBufferAllocator, headroom: Int = PacketBuffer.defaultHeadroom, payload: ByteBuffer) {
        var storage = allocator.buffer(capacity: headroom + payload.readableBytes)
        storage.writeRepeatingByte(0, count: headroom)
        storage.moveReaderIndex(to: headroom)
        storage.writeImmutableBuffer(payload)
        self.storage = storage
    }

    /// A frame just off the wire. No headroom; it is only ever parsed.
    public init(received frame: ByteBuffer) {
        self.storage = frame
    }

    public var readableBytes: Int { storage.readableBytes }

    /// The whole frame as it stands, ready to hand to a link endpoint.
    public var frame: ByteBuffer { storage }

    /// What remains after the headers consumed so far.
    public var payload: ByteBuffer { storage }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeReadableBytes(body)
    }

    /// Prepend a header, recording its length against the current layer.
    public mutating func prepend(_ bytes: [UInt8]) {
        prepend(count: bytes.count) { buffer, index in
            buffer.setBytes(bytes, at: index)
        }
    }

    /// Prepend `count` bytes and fill them in place, avoiding a temporary array.
    /// `writer` receives the storage and the absolute index the header starts at.
    public mutating func prepend(count: Int, _ writer: (inout ByteBuffer, Int) -> Void) {
        let start = storage.readerIndex - count
        precondition(start >= 0, "PacketBuffer headroom exhausted: needed \(count), had \(storage.readerIndex)")
        writer(&storage, start)
        storage.moveReaderIndex(to: start)
        record(count, at: prependLayer)
        prependLayer = next(afterPrepend: prependLayer)
    }

    /// Take `count` bytes off the front as this layer's header.
    /// Returns nil, leaving the buffer untouched, if the frame is short.
    public mutating func consumeHeader(_ count: Int) -> ByteBuffer? {
        guard let header = storage.readSlice(length: count) else { return nil }
        record(count, at: consumeLayer)
        consumeLayer = next(afterConsume: consumeLayer)
        return header
    }

    /// An independent copy. `ByteBuffer` is copy-on-write, so this is cheap
    /// until one of the two is written to.
    public func clone() -> PacketBuffer {
        self
    }

    private mutating func record(_ count: Int, at layer: Layer) {
        switch layer {
        case .transport: transportHeaderLength = count
        case .network: networkHeaderLength = count
        case .link: linkHeaderLength = count
        case .done:
            // Four headers on one packet is a programmer error in this stack:
            // link, network, and transport are all there are. Trap in debug
            // rather than silently dropping the length.
            assertionFailure("PacketBuffer: more than three header layers recorded")
        }
    }

    /// Prepend visits layers in build order: transport, then network, then link.
    private func next(afterPrepend layer: Layer) -> Layer {
        switch layer {
        case .transport: return .network
        case .network: return .link
        case .link: return .done
        case .done: return .done
        }
    }

    /// Consume visits layers in wire order: link, then network, then transport.
    private func next(afterConsume layer: Layer) -> Layer {
        switch layer {
        case .link: return .network
        case .network: return .transport
        case .transport: return .done
        case .done: return .done
        }
    }
}
