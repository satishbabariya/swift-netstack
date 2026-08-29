import NIOCore
import NIOPosix

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// A guest's ping, sent for real.
///
/// Without this the gateway answers every echo request itself, for any address
/// at all -- so a guest that pings 8.8.8.8 gets a reply whether or not 8.8.8.8
/// is reachable, and `ping` stops being a reachability test and becomes a test
/// of whether the guest's own stack works. Upstream installs its ICMP forwarder
/// unconditionally; this is that, and it is why the local answer is now a
/// fallback rather than the policy.
///
/// ## Unprivileged ICMP
///
/// `SOCK_DGRAM` with `IPPROTO_ICMP` sends echo without root on macOS and Linux,
/// which is the whole reason this can exist in a process nobody wants to run as
/// root. The kernel owns the identifier on Linux -- it rewrites it with the
/// socket's port -- so nothing here may rely on the one it sent coming back.
/// Matching is by socket instead: one socket per outstanding request, and
/// whatever arrives on it is that request's answer.
///
/// If the socket cannot be opened at all -- a sandbox that forbids it, a host
/// that does not allow unprivileged ICMP -- the request is declined and the
/// gateway answers locally, as it did before. A ping that works badly is better
/// than a network feature that fails to start.
///
/// ## What bounds a hostile guest
///
/// - **`maximumOutstanding` bounds sockets.** A guest can ping every address on
///   the internet as fast as it can write frames, and each one held here is a
///   file descriptor. Past the bound a request is dropped rather than queued.
/// - **Every request expires.** A destination that never answers must not hold a
///   descriptor forever, or a guest with a list of black-holed addresses fills
///   the table once and it never empties.
/// - **Loopback and broadcast are never forwarded**, matching upstream: those
///   are the host's own addresses, and a guest that pings them is asking this
///   process about itself rather than about the network.
public final class ICMPForwarder: @unchecked Sendable {
    private let stack: Stack
    private let eventLoop: EventLoop
    private let maximumOutstanding: Int
    private let timeout: TimeAmount
    private let nat: [IPv4Address: IPv4Address]
    private let allowsLinkLocal: Bool
    private let allocator = ByteBufferAllocator()

    private var outstanding = 0

    /// Echo requests sent to a real destination.
    public private(set) var forwarded = 0
    /// Requests dropped because too many were already in flight.
    public private(set) var refusedForLimit = 0
    /// Requests that got no answer before the timeout.
    public private(set) var timedOut = 0
    /// Replies carried back to the guest.
    public private(set) var answered = 0
    /// Requests declined, so the gateway answered them itself: its own
    /// addresses, loopback, broadcast, and -- if the host will not open an
    /// unprivileged ICMP socket -- everything.
    public private(set) var declined = 0

    public var log: RateLimitedLogger?

    /// In flight right now.
    public var outstandingCount: Int { outstanding }

    public init(
        stack: Stack, maximumOutstanding: Int = 64, timeout: TimeAmount = .seconds(5),
        nat: [IPv4Address: IPv4Address] = [:], allowsLinkLocal: Bool = false
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.maximumOutstanding = max(1, maximumOutstanding)
        self.timeout = timeout
        self.nat = nat
        self.allowsLinkLocal = allowsLinkLocal
        stack.ipv4.echoRequestHandler = { [weak self] header, icmp, payload in
            self?.handle(header, icmp, payload) ?? false
        }
    }

    deinit {
        stack.ipv4.echoRequestHandler = nil
    }

    /// Returns true when the request has been taken.
    private func handle(_ header: IPv4Header, _ icmp: ICMPv4Header, _ payload: ByteBuffer) -> Bool {
        eventLoop.preconditionInEventLoop()

        // The gateway's own address is answered by the gateway: pinging the
        // router is a question about the router, and it is the one address here
        // that genuinely belongs to this process.
        //
        // Not every address the NIC holds, which is the tempting check and the
        // wrong one. The host address is on the NIC so that ARP for it is
        // answered, but it stands for the *host* -- and `nat` exists to turn a
        // packet for it into a packet for the host's loopback. Declining it
        // would make `ping host.containers.internal` answer from this process
        // again, which is the exact fiction this type was written to end.
        if header.destination == stack.configuration.gatewayAddress { return decline() }
        if header.destination == .broadcast || header.destination.bytes[0] == 127 { return decline() }
        if !allowsLinkLocal, header.destination.isLinkLocal { return decline() }

        guard outstanding < maximumOutstanding else {
            refusedForLimit += 1
            log?.record(.icmpRefusedByLimit, ["limit": .stringConvertible(maximumOutstanding)])
            // Taken, and dropped. Answering locally instead would tell the guest
            // an unreachable address answered.
            return true
        }

        let destination = nat[header.destination] ?? header.destination
        guard let target = try? SocketAddress(ipAddress: destination.description, port: 0),
            let descriptor = Self.openEchoSocket()
        else { return decline() }

        outstanding += 1
        let source = header.source
        let pinged = header.destination
        let identifier = icmp.identifier ?? 0
        let sequence = icmp.sequence ?? 0
        var message = allocator.buffer(capacity: payload.readableBytes + ICMPv4Header.length)
        message.writeInteger(ICMPv4Type.echoRequest.rawValue)
        message.writeInteger(UInt8(0))
        message.writeInteger(UInt16(0))
        message.writeInteger(identifier, endianness: .big)
        message.writeInteger(sequence, endianness: .big)
        var body = payload
        message.writeBuffer(&body)
        // Computed here even though some kernels recompute it. One that does
        // overwrites this; one that does not would otherwise send a checksum of
        // zero, which every host on the far side discards.
        let checksum = message.readableBytesView.withUnsafeBytes { Checksum.compute($0) }
        message.setInteger(checksum, at: message.readerIndex + 2, endianness: .big)
        // `let` from here: the closure below runs when the channel comes up, and
        // a captured `var` crossing that boundary is not something the compiler
        // will vouch for.
        let outgoing = message

        forwarded += 1
        let request = EchoRequest(
            forwarder: self, source: source, pinged: pinged, identifier: identifier,
            sequence: sequence, expecting: destination)
        // A datagram channel, not `ClientBootstrap.withConnectedSocket`.
        //
        // That one sets `TCP_NODELAY` on whatever it adopts, and an ICMP socket
        // answers `setsockopt` with EINVAL -- so the channel never comes up and
        // every ping is silently declined. Measured; the failure is invisible
        // otherwise, because declining looks exactly like a gateway that chose
        // to answer locally.
        DatagramBootstrap(group: eventLoop)
            .channelInitializer { channel in
                channel.pipeline.addHandler(EchoReplyHandler(request: request))
            }
            .withBoundSocket(descriptor)
            .whenComplete { outcome in
                guard case .success(let channel) = outcome else {
                    request.finish()
                    return
                }
                request.channel = channel
                channel.writeAndFlush(AddressedEnvelope(remoteAddress: target, data: outgoing), promise: nil)
                // An answer or a deadline, whichever comes first. Without the
                // deadline a black-holed address holds a descriptor forever,
                // which is a list a guest can supply.
                request.expiry = self.eventLoop.scheduleTask(in: self.timeout) {
                    request.expire()
                }
            }
        return true
    }

    private func decline() -> Bool {
        declined += 1
        return false
    }

    /// Called by a request when it ends, however it ended.
    fileprivate func release() {
        outstanding -= 1
    }

    fileprivate func noteTimeout() {
        timedOut += 1
    }

    /// Put an echo reply on the wire, sourced from the address the guest pinged.
    fileprivate func deliver(
        _ reply: ByteBuffer, to source: IPv4Address, from pinged: IPv4Address,
        identifier: UInt16, sequence: UInt16
    ) {
        var incoming = reply
        // What arrives is not the same shape on every platform, and upstream's
        // comment on this is wrong: it says Linux and macOS both hand back just
        // the ICMP message, and macOS hands back the whole IP packet. Measured,
        // not assumed -- a reply here begins 0x45, which is IPv4 version 4 with
        // a five-word header, and the parse below read it as an ICMP type of 69
        // and discarded every reply.
        //
        // Detected rather than compiled in, because it is a property of the
        // kernel this is running on rather than of the platform it was built
        // for.
        if let first = incoming.getInteger(at: incoming.readerIndex, as: UInt8.self), first >> 4 == 4 {
            let headerLength = Int(first & 0x0F) * 4
            guard headerLength >= 20, incoming.readableBytes > headerLength else { return }
            incoming.moveReaderIndex(forwardBy: headerLength)
        }

        // The reply is an ICMP message. Its identifier is whatever the kernel
        // chose -- Linux rewrites it -- so the guest's own values are put back,
        // or its ping will not match the reply to anything it sent.
        guard incoming.readableBytes >= ICMPv4Header.length,
            let type = incoming.readInteger(as: UInt8.self), type == ICMPv4Type.echoReply.rawValue,
            incoming.readInteger(as: UInt8.self) != nil,
            incoming.readInteger(endianness: .big, as: UInt16.self) != nil,
            incoming.readInteger(endianness: .big, as: UInt16.self) != nil,
            incoming.readInteger(endianness: .big, as: UInt16.self) != nil
        else { return }

        var message = allocator.buffer(capacity: incoming.readableBytes + ICMPv4Header.length)
        message.writeInteger(ICMPv4Type.echoReply.rawValue)
        message.writeInteger(UInt8(0))
        message.writeInteger(UInt16(0))
        message.writeInteger(identifier, endianness: .big)
        message.writeInteger(sequence, endianness: .big)
        message.writeBuffer(&incoming)
        let checksum = message.readableBytesView.withUnsafeBytes { Checksum.compute($0) }
        message.setInteger(checksum, at: message.readerIndex + 2, endianness: .big)

        answered += 1
        try? stack.ipv4.send(payload: message, to: source, from: pinged, protocolNumber: .icmp)
    }

    /// An unprivileged ICMP socket, bound and unconnected.
    ///
    /// Left unconnected because a datagram channel sends with an explicit
    /// destination, and `sendto` on a connected socket is refused on some
    /// platforms. What that gives up is the kernel filtering replies to the host
    /// that was asked, so the filtering is done here instead -- see
    /// `EchoRequest.expecting`, which is checked before a reply is believed.
    private static func openEchoSocket() -> NIOBSDSocket.Handle? {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard descriptor >= 0 else { return nil }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_port = 0
        address.sin_addr.s_addr = INADDR_ANY.bigEndian
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            close(descriptor)
            return nil
        }
        return descriptor
    }
}

/// One outstanding echo, and everything needed to answer the guest that sent it.
private final class EchoRequest: @unchecked Sendable {
    private weak var forwarder: ICMPForwarder?
    let source: IPv4Address
    let pinged: IPv4Address
    let identifier: UInt16
    let sequence: UInt16
    /// The address this request was sent to. A reply from anywhere else is
    /// discarded: the socket is unconnected, so the kernel is not doing that
    /// filtering and anything on the machine could otherwise answer a guest's
    /// ping.
    let expecting: IPv4Address
    var channel: Channel?
    var expiry: Scheduled<Void>?
    private var finished = false

    init(
        forwarder: ICMPForwarder, source: IPv4Address, pinged: IPv4Address, identifier: UInt16,
        sequence: UInt16, expecting: IPv4Address
    ) {
        self.expecting = expecting
        self.forwarder = forwarder
        self.source = source
        self.pinged = pinged
        self.identifier = identifier
        self.sequence = sequence
    }

    func answer(_ reply: ByteBuffer, from responder: IPv4Address?) {
        guard !finished else { return }
        guard responder == nil || responder == expecting else { return }
        forwarder?.deliver(
            reply, to: source, from: pinged, identifier: identifier, sequence: sequence)
        finish()
    }

    func expire() {
        guard !finished else { return }
        forwarder?.noteTimeout()
        finish()
    }

    /// Exactly once, however the request ended: answered, expired, or never
    /// started. The slot is returned here and nowhere else.
    func finish() {
        guard !finished else { return }
        finished = true
        expiry?.cancel()
        expiry = nil
        channel?.close(promise: nil)
        channel = nil
        forwarder?.release()
    }
}

/// Hands the first reply on a socket to its request. Weak, because the request
/// owns the channel and the channel's pipeline owns this.
private final class EchoReplyHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let request: EchoRequest

    init(request: EchoRequest) {
        self.request = request
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let responder = envelope.remoteAddress.ipAddress.flatMap(IPv4Address.init)
        request.answer(envelope.data, from: responder)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        request.finish()
    }
}
