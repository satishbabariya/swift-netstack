import NIOCore
import NIOPosix

/// The gateway's resolver: names it owns, answered here; everything else
/// forwarded to a real resolver on the host.
///
/// ## Why the gateway is the resolver at all
///
/// The guest is told to ask this address by the DHCP offer, which means every
/// name the guest looks up passes through here. That is what makes
/// `gateway.containers.internal` resolvable inside a VM whose host has no such
/// name, and it is also the only place a policy about what a guest may resolve
/// could ever be applied.
///
/// ## What bounds a hostile guest
///
/// - **Outstanding forwarded queries are bounded.** A guest can send queries
///   faster than any resolver answers them, and each one held here is a pending
///   entry plus the datagram it has to be answered from. Past the bound a query
///   is refused rather than queued, which tells the guest something and costs
///   this process nothing.
/// - **A reply is matched before it is believed.** The upstream socket is one
///   this process opened, so anything arriving on it that does not match a
///   pending query -- by transaction id AND by the question asked -- is
///   discarded. Matching on the id alone is the classic cache-poisoning
///   opening: sixteen bits is a number an attacker can simply try.
/// - **Pending queries expire.** An upstream that never answers must not hold a
///   slot forever, or a guest with a route to an unresponsive resolver fills the
///   table once and it never empties.
/// `@unchecked Sendable` for the same reason the rest of this package's
/// datapath types are: everything here runs on `stack.eventLoop`, including the
/// upstream channel, which is bootstrapped onto that same loop precisely so this
/// stays true.
public final class DNSServer: @unchecked Sendable {
    /// A name this gateway answers itself.
    public struct StaticRecord: Sendable {
        public var name: String
        public var address: IPv4Address

        public init(name: String, address: IPv4Address) {
            // Lowercased once here rather than compared case-insensitively at
            // every lookup: DNS names are case-insensitive by RFC 4343, and a
            // guest varying the case of a name is exactly the input that finds
            // a comparison someone forgot to fold.
            self.name = name.lowercased()
            self.address = address
        }
    }

    private struct Pending {
        let source: IPv4Address
        let port: UInt16
        let originalID: UInt16
        let question: DNSQuestion
        let deadline: NIODeadline
    }

    private let stack: Stack
    private let endpoint: UDPEndpoint
    private let allocator = ByteBufferAllocator()
    private let records: [String: IPv4Address]
    private let upstream: [SocketAddress]
    private let maximumPending: Int
    private let timeout: TimeAmount
    private let ttl: UInt32

    private var upstreamChannel: Channel?
    private var pending: [UInt16: Pending] = [:]
    /// The id this gateway uses upstream, which is deliberately not the guest's.
    private var nextUpstreamID: UInt16 = 0

    public private(set) var answeredLocally = 0
    public private(set) var forwarded = 0
    public private(set) var refusedForLimit = 0
    public private(set) var unmatchedReplies = 0

    public static let port: UInt16 = 53

    public init(
        stack: Stack, records: [StaticRecord], upstream: [SocketAddress] = [],
        maximumPending: Int = 256, timeout: TimeAmount = .seconds(5), ttl: UInt32 = 60
    ) throws {
        self.stack = stack
        self.records = Dictionary(records.map { ($0.name, $0.address) }, uniquingKeysWith: { first, _ in first })
        self.upstream = upstream
        self.maximumPending = max(1, maximumPending)
        self.timeout = timeout
        self.ttl = ttl
        self.endpoint = UDPEndpoint(stack: stack)
        try endpoint.bind(address: .any, port: Self.port)
        endpoint.onDatagram = { [weak self] payload, source, port in
            self?.handle(payload, from: source, port: port)
        }
    }

    /// Open the socket this gateway forwards from. Separate from `init` because
    /// it is asynchronous and because a gateway with only static records does
    /// not need one at all.
    public func startForwarding(group: EventLoopGroup) -> EventLoopFuture<Void> {
        guard !upstream.isEmpty else { return stack.eventLoop.makeSucceededVoidFuture() }
        return DatagramBootstrap(group: stack.eventLoop)
            .channelInitializer { [weak self] channel in
                guard let self else { return channel.eventLoop.makeSucceededVoidFuture() }
                return channel.pipeline.addHandler(UpstreamReplyHandler(server: self))
            }
            .bind(host: "0.0.0.0", port: 0)
            .map { [weak self] channel in
                self?.upstreamChannel = channel
            }
    }

    private func handle(_ payload: ByteBuffer, from source: IPv4Address, port: UInt16) {
        guard let query = DNSCodec.parseQuery(payload) else { return }

        if query.question.klass == DNSQuestion.classIN, query.question.type == DNSQuestion.typeA,
            let address = records[query.question.name]
        {
            answeredLocally += 1
            if let reply = DNSCodec.answer(
                to: query, in: payload, address: address, ttl: ttl, allocator: allocator)
            {
                try? endpoint.send(reply, to: source, port: port)
            }
            return
        }

        // A name inside a zone this gateway owns and does not have is NXDOMAIN,
        // not a question for the internet. Forwarding it would leak the guest's
        // internal names to a public resolver, and would wait out a timeout to
        // return the same answer.
        if isOwnedZone(query.question.name) {
            answeredLocally += 1
            if let reply = DNSCodec.failure(
                to: query, in: payload, code: DNSCodec.responseCodeNameError, allocator: allocator)
            {
                try? endpoint.send(reply, to: source, port: port)
            }
            return
        }

        forward(query, payload: payload, to: source, port: port)
    }

    private func isOwnedZone(_ name: String) -> Bool {
        // Every static record's parent zone. With `gateway.containers.internal`
        // configured, `anything.containers.internal` is this gateway's to answer
        // -- and to say no to.
        for owned in records.keys {
            guard let dot = owned.firstIndex(of: ".") else { continue }
            let zone = String(owned[owned.index(after: dot)...])
            if name == zone || name.hasSuffix("." + zone) { return true }
        }
        return false
    }

    private func forward(_ query: DNSQuery, payload: ByteBuffer, to source: IPv4Address, port: UInt16) {
        guard let channel = upstreamChannel, let server = upstream.first else {
            refuse(query, payload: payload, to: source, port: port)
            return
        }
        expirePending()
        guard pending.count < maximumPending else {
            refusedForLimit += 1
            refuse(query, payload: payload, to: source, port: port)
            return
        }

        // A transaction id of this gateway's own choosing, not the guest's.
        //
        // Reusing the guest's id would let a guest pick the id an upstream reply
        // has to carry, which is half of what an off-path attacker needs and all
        // of what an on-path guest needs to answer its own neighbours' queries.
        let upstreamID = allocateID()
        pending[upstreamID] = Pending(
            source: source, port: port, originalID: query.id, question: query.question,
            deadline: stack.clock.now() + timeout)

        var outgoing = payload
        outgoing.setInteger(upstreamID, at: outgoing.readerIndex, endianness: .big)
        forwarded += 1
        channel.writeAndFlush(AddressedEnvelope(remoteAddress: server, data: outgoing), promise: nil)
    }

    private func refuse(_ query: DNSQuery, payload: ByteBuffer, to source: IPv4Address, port: UInt16) {
        guard let reply = DNSCodec.failure(
            to: query, in: payload, code: DNSCodec.responseCodeRefused, allocator: allocator)
        else { return }
        try? endpoint.send(reply, to: source, port: port)
    }

    private func allocateID() -> UInt16 {
        // Sequential rather than random, and the comment says so rather than the
        // name implying otherwise. Randomising the id is a defence against an
        // OFF-path attacker guessing it; the peer here is the guest, which is
        // on-path by construction and can read whatever id it likes off the
        // wire. What actually protects this table is matching the question as
        // well as the id, which `deliver` does.
        for _ in 0..<UInt16.max {
            nextUpstreamID &+= 1
            if pending[nextUpstreamID] == nil { return nextUpstreamID }
        }
        return nextUpstreamID
    }

    private func expirePending() {
        let now = stack.clock.now()
        pending = pending.filter { $0.value.deadline > now }
    }

    /// Called by `UpstreamReplyHandler` when a datagram arrives on the socket
    /// this gateway forwards from.
    fileprivate func deliverUpstream(_ payload: ByteBuffer) {
        guard let reply = DNSCodec.parseQuery(replyAsQuery: payload) else {
            unmatchedReplies += 1
            return
        }
        guard let entry = pending[reply.id], entry.question == reply.question else {
            // Either nobody asked this, or somebody answered a different
            // question with a stolen id. Matching on the id alone is the classic
            // cache-poisoning opening: sixteen bits is a number an attacker can
            // simply try.
            unmatchedReplies += 1
            return
        }
        pending.removeValue(forKey: reply.id)

        var outgoing = payload
        outgoing.setInteger(entry.originalID, at: outgoing.readerIndex, endianness: .big)
        try? endpoint.send(outgoing, to: entry.source, port: entry.port)
    }

    public func close() {
        endpoint.close()
        upstreamChannel?.close(promise: nil)
        upstreamChannel = nil
        pending.removeAll()
    }
}

/// Hands upstream replies back to the server, weakly: the server owns the
/// channel and the channel's pipeline owns this.
private final class UpstreamReplyHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private weak var server: DNSServer?

    init(server: DNSServer) {
        self.server = server
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        server?.deliverUpstream(unwrapInboundIn(data).data)
    }
}

extension DNSCodec {
    /// Parse a REPLY far enough to match it against a pending query.
    ///
    /// Separate from `parseQuery` only in the QR bit it requires. Sharing the
    /// rest matters: the question is what the match is made on, so a reply whose
    /// question this cannot read the same way a query's was read is a reply that
    /// must not match anything.
    static func parseQuery(replyAsQuery payload: ByteBuffer) -> DNSQuery? {
        guard payload.readableBytes >= headerLength,
            let flags = payload.getInteger(at: payload.readerIndex + 2, endianness: .big, as: UInt16.self),
            flags & 0x8000 != 0
        else { return nil }
        var rewritten = payload
        rewritten.setInteger(flags & ~UInt16(0x8000), at: rewritten.readerIndex + 2, endianness: .big)
        return parseQuery(rewritten)
    }
}
