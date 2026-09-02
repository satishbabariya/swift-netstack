import Foundation
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

    /// A name this gateway answers, and everything under it.
    ///
    /// Upstream's `types.Zone`, and the model is worth stating because it is not
    /// the obvious one: a zone's record names are **relative to the zone**, so
    /// the record `gateway` in the zone `containers.internal` answers
    /// `gateway.containers.internal`. A zone with a `defaultAddress` answers
    /// every name under it that no record matches, which is the wildcard; a zone
    /// without one answers those NXDOMAIN, because a name inside a zone this
    /// gateway owns and does not have is not a question for the internet.
    public struct Zone: Sendable {
        public struct Record: Sendable {
            /// Relative to the zone, lowercased. Empty matches the zone apex.
            public var name: String
            public var address: IPv4Address?
            /// Matched against the relative name when `name` does not equal it.
            ///
            /// The pattern comes from whoever configured the gateway, never from
            /// the guest -- upstream's `/add` cannot carry one either, because
            /// Go's `regexp.Regexp` will not decode from JSON. That is the line
            /// that matters: a backtracking engine on a pattern an attacker
            /// chooses is a denial of service, and on a pattern an operator
            /// chooses it is a configuration decision. What the guest supplies
            /// is the subject, and DNS already caps that at 255 bytes.
            public var pattern: String?

            public init(name: String, address: IPv4Address? = nil, pattern: String? = nil) {
                self.name = name.lowercased()
                self.address = address
                self.pattern = pattern
            }
        }

        /// Lowercased, with no trailing dot. Upstream spells zone names as
        /// fully-qualified with the dot; it is stripped on the way in so that
        /// every comparison here is against one spelling.
        public var name: String
        public var records: [Record]
        /// Answered for any name in the zone no record matches. Upstream's
        /// `DefaultIP`.
        public var defaultAddress: IPv4Address?
        /// A protected zone cannot be replaced over the control API. The zones
        /// built from `Gateway.Configuration.dnsRecords` are protected, so a
        /// guest-reachable API cannot take `gateway.containers.internal` away
        /// from the guests that depend on it.
        public var isProtected: Bool

        public init(
            name: String, records: [Record] = [], defaultAddress: IPv4Address? = nil,
            isProtected: Bool = false
        ) {
            var normalised = name.lowercased()
            while normalised.hasSuffix(".") { normalised.removeLast() }
            self.name = normalised
            self.records = records
            self.defaultAddress = defaultAddress
            self.isProtected = isProtected
        }

        /// The address this zone gives `name`, which must be inside it.
        func answer(for name: String) -> IPv4Address? {
            let relative: String
            if name == self.name {
                relative = ""
            } else if name.hasSuffix("." + self.name) {
                relative = String(name.dropLast(self.name.count + 1))
            } else {
                return nil
            }
            for record in records {
                if !record.name.isEmpty, record.name == relative, let address = record.address {
                    return address
                }
                if let pattern = record.pattern, let address = record.address,
                    Zone.matches(pattern, relative)
                {
                    return address
                }
            }
            return defaultAddress
        }

        /// Whether `subject` is inside this zone at all.
        func contains(_ name: String) -> Bool {
            name == self.name || name.hasSuffix("." + self.name)
        }

        private static func matches(_ pattern: String, _ subject: String) -> Bool {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return false }
            let range = NSRange(subject.startIndex..., in: subject)
            return regex.firstMatch(in: subject, range: range) != nil
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
    private var records: [String: IPv4Address]
    /// Zones, most specific first. See `zone(owning:)`.
    private var zones: [Zone]
    private let upstream: [SocketAddress]
    private let maximumPending: Int
    private let timeout: TimeAmount
    /// The TTL on an answer this gateway makes itself. Zero, as upstream's is.
    ///
    /// These records are mutable while the gateway runs -- `/services/dns/add`
    /// is how podman points a name at a container that has just started -- so an
    /// answer cached by a guest is an answer that can be wrong, and there is no
    /// second lookup to correct it until the cache expires. It defaulted to 60
    /// here, which is a minute of a guest resolving a name to wherever it used
    /// to point.
    ///
    /// Every answer gvproxy builds carries `Ttl: 0`, in all four places it
    /// builds one. The cost is a query per lookup, answered from a table in this
    /// process without touching the network.
    private let ttl: UInt32

    private var upstreamChannel: Channel?
    private var pending: [UInt16: Pending] = [:]
    /// The id this gateway uses upstream, which is deliberately not the guest's.
    private var nextUpstreamID: UInt16 = 0

    public private(set) var answeredLocally = 0
    public private(set) var forwarded = 0
    public private(set) var refusedForLimit = 0

    /// Queries refused for want of anywhere to forward them. Separate from
    /// `refusedForLimit` because they mean different things: one is a gateway
    /// with no resolver configured, the other is a guest asking faster than one
    /// can answer.
    public private(set) var refusedForNoUpstream = 0
    public private(set) var unmatchedReplies = 0

    /// Where refusals are reported, if anywhere. `Gateway` sets this; a
    /// hand-assembled arrangement opts in by setting it too.
    public var log: RateLimitedLogger?

    public static let port: UInt16 = 53

    public init(
        stack: Stack, records: [StaticRecord], upstream: [SocketAddress] = [],
        maximumPending: Int = 256, timeout: TimeAmount = .seconds(5), ttl: UInt32 = 0
    ) throws {
        self.stack = stack
        self.records = Dictionary(records.map { ($0.name, $0.address) }, uniquingKeysWith: { first, _ in first })
        // Every configured record's parent zone, owned and protected. This is
        // what makes `anything.containers.internal` this gateway's to answer --
        // and to say no to -- rather than a question for a public resolver, and
        // protecting them keeps the control API from taking a name the guests
        // depend on away from them.
        var derived: [String: Zone] = [:]
        for record in records {
            guard let dot = record.name.firstIndex(of: ".") else { continue }
            let zone = String(record.name[record.name.index(after: dot)...])
            derived[zone] = Zone(name: zone, isProtected: true)
        }
        self.zones = Self.ordered(Array(derived.values))
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
        if let owner = zone(owning: query.question.name) {
            answeredLocally += 1
            // A zone with a default address answers everything under it; one
            // without says the name does not exist. Either way the question does
            // not leave this process: forwarding a name from a zone this gateway
            // owns leaks the guest's internal names to a public resolver, and
            // waits out a timeout to return the same answer.
            let reply: ByteBuffer?
            if query.question.klass == DNSQuestion.classIN, query.question.type == DNSQuestion.typeA,
                let address = owner.answer(for: query.question.name)
            {
                reply = DNSCodec.answer(
                    to: query, in: payload, address: address, ttl: ttl, allocator: allocator)
            } else {
                // NXDOMAIN says the name does not exist, for every type at
                // once, and a resolver caches that. A name this gateway holds an
                // address for exists -- it just has no record of the type asked
                // for, which is NODATA: NOERROR with no answers.
                //
                // Found by asking a real Linux guest rather than a synthetic
                // one. Every check here asked for A, and a real resolver asks
                // for AAAA as well:
                //
                //     nslookup host.containers.internal
                //     ** server can't find host.containers.internal: NXDOMAIN
                //
                // while the A query beside it answered 192.168.127.254. This
                // package does not do IPv6 and says so; a guest asking for it
                // should be told this name has no AAAA, not that the name it
                // just resolved does not exist.
                let known =
                    records[query.question.name] != nil
                    || owner.answer(for: query.question.name) != nil
                reply = DNSCodec.failure(
                    to: query, in: payload,
                    code: known ? DNSCodec.responseCodeNoError : DNSCodec.responseCodeNameError,
                    allocator: allocator)
            }
            if let reply { try? endpoint.send(reply, to: source, port: port) }
            return
        }

        forward(query, payload: payload, to: source, port: port)
    }

    /// The zone that owns `name`, most specific first.
    ///
    /// Most specific rather than first-configured, which is where this departs
    /// from upstream: upstream walks its zone list in order and takes the first
    /// suffix match, so with both `containers.internal` and
    /// `sub.containers.internal` configured, which one answers
    /// `x.sub.containers.internal` depends on the order they were added. The
    /// more specific zone is the authoritative one -- that is what delegation
    /// means -- and making it depend on insertion order turns a DNS question
    /// into a configuration accident.
    private func zone(owning name: String) -> Zone? {
        zones.first { $0.contains(name) }
    }

    /// Longest zone name first, so `zone(owning:)` can take the first match.
    private static func ordered(_ zones: [Zone]) -> [Zone] {
        zones.sorted { first, second in
            first.name.count == second.name.count
                ? first.name < second.name : first.name.count > second.name.count
        }
    }

    /// Every zone this gateway answers for. Upstream serves this on
    /// `GET /services/dns/all`.
    public var allZones: [Zone] { zones }

    /// Add a zone, or merge into one that exists. Upstream's
    /// `POST /services/dns/add`.
    ///
    /// Merging rather than replacing is upstream's behaviour and the useful one:
    /// a tool adding one name to a zone should not have to know, or resend,
    /// every name already in it. A record whose relative name is already present
    /// is replaced, which is how the same call updates an address.
    ///
    /// Returns false for a protected zone, which is the only refusal: the zones
    /// built from the gateway's own configuration are the guests' route to the
    /// host, and an API that could redirect them is an API that can cut every
    /// guest off from the thing it was pointed at.
    @discardableResult
    public func addZone(_ zone: Zone) -> Bool {
        stack.eventLoop.preconditionInEventLoop()
        guard !zone.name.isEmpty else { return false }
        if let index = zones.firstIndex(where: { $0.name == zone.name }) {
            guard !zones[index].isProtected else { return false }
            var merged = zones[index]
            for record in zone.records {
                if let existing = merged.records.firstIndex(where: { $0.name == record.name }) {
                    merged.records[existing] = record
                } else {
                    merged.records.append(record)
                }
            }
            if let address = zone.defaultAddress { merged.defaultAddress = address }
            zones[index] = merged
            return true
        }
        zones = Self.ordered(zones + [zone])
        return true
    }

    private func forward(_ query: DNSQuery, payload: ByteBuffer, to source: IPv4Address, port: UInt16) {
        guard let channel = upstreamChannel, let server = upstream.first else {
            // Logged at a higher level than the rest, and named so it reads
            // as what it nearly always is: nobody configured an upstream, and
            // every query the guest makes is being refused because of it.
            refusedForNoUpstream += 1
            log?.record(.dnsRefusedNoUpstream, ["name": .string(sanitizedForLog(query.question.name))])
            refuse(query, payload: payload, to: source, port: port)
            return
        }
        expirePending()
        guard pending.count < maximumPending else {
            refusedForLimit += 1
            log?.record(.dnsRefusedByLimit, ["outstanding": .stringConvertible(maximumPending), "name": .string(sanitizedForLog(query.question.name))])
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
        guard
            let reply = DNSCodec.failure(
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
            log?.record(.dnsUnmatchedReply)
            return
        }
        guard let entry = pending[reply.id], entry.question == reply.question else {
            // Either nobody asked this, or somebody answered a different
            // question with a stolen id. Matching on the id alone is the classic
            // cache-poisoning opening: sixteen bits is a number an attacker can
            // simply try.
            unmatchedReplies += 1
            log?.record(.dnsUnmatchedReply)
            return
        }
        pending.removeValue(forKey: reply.id)

        var outgoing = payload
        outgoing.setInteger(entry.originalID, at: outgoing.readerIndex, endianness: .big)
        try? endpoint.send(outgoing, to: entry.source, port: entry.port)
    }

    /// Close, and complete when the **upstream socket** is closed too.
    ///
    /// The future is the whole point. `upstreamChannel` is a real host socket on
    /// a real event loop, and closing it is asynchronous: a caller that shuts
    /// its `EventLoopGroup` down as soon as this returns kills the loop with the
    /// close still in progress, and NIO's channel teardown then schedules its
    /// last step -- `removeHandlers` -- onto a loop that is gone.
    @discardableResult
    /// Callable from anywhere.
    ///
    /// Everything below is loop-confined state, and this is handed to callers
    /// who have no reason to be on that loop. `NetworkSwitch.close` had the same
    /// shape and a bare `preconditionInEventLoop` made its ordinary use a trap;
    /// on the loop this still runs inline, because deferring would reorder it
    /// against the caller's own closing work.
    public func close() -> EventLoopFuture<Void> {
        guard stack.eventLoop.inEventLoop else {
            return stack.eventLoop.flatSubmit { self.closeOnLoop() }
        }
        return closeOnLoop()
    }

    private func closeOnLoop() -> EventLoopFuture<Void> {
        stack.eventLoop.preconditionInEventLoop()
        endpoint.close()
        pending.removeAll()
        guard let channel = upstreamChannel else {
            return stack.eventLoop.makeSucceededVoidFuture()
        }
        upstreamChannel = nil
        return channel.close().recover { _ in () }
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

extension DNSServer {
    /// The search list in a `resolv.conf`, sanitised the way upstream sanitises
    /// it.
    ///
    /// A guest gets this in DHCP option 119, and without it a short name the
    /// host can resolve is a name the guest cannot: gvproxy reads the host's
    /// `/etc/resolv.conf` for every gateway it starts without a config file, and
    /// this port sent an empty list unless somebody wrote one out.
    ///
    /// The limits are macOS's and upstream applies them there only: at most six
    /// domains, and at most 256 characters in the line they came from, cut back
    /// to the last space rather than through the middle of a name.
    ///
    /// Parsing here and reading the file in the executable, because a library
    /// that reads `/etc/resolv.conf` has decided something for every program
    /// that links it -- and because a pure function over the text is one a test
    /// can put every shape into.
    public static func searchDomains(inResolvConf text: String, applyingDarwinLimits: Bool) -> [String] {
        let prefix = "search "
        guard
            var line = text.split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
                .first(where: { $0.hasPrefix(prefix) })
        else { return [] }

        if applyingDarwinLimits, line.count > 256 {
            line = String(line.prefix(256))
            if let lastSpace = line.lastIndex(of: " ") { line = String(line[..<lastSpace]) }
        }

        // Empty fields dropped, which upstream's split does not do: two spaces
        // between two domains would otherwise become a zero-length label, and
        // option 119 encodes labels by length.
        var domains = line.dropFirst(prefix.count).split(separator: " ").map(String.init)
        if applyingDarwinLimits, domains.count > 6 { domains = Array(domains.prefix(6)) }
        return domains
    }
}
