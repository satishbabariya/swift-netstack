import NIOCore

/// Every connection the peer opens, as accepted child `Channel`s.
///
/// ## This is not a listening socket, and the difference is the point
///
/// A gateway does not know which ports its guest will dial, so it cannot bind
/// them. `TCPForwarder` sees every SYN instead; this channel is that forwarder
/// wearing NIO's server-channel shape, and it accepts connections to *any*
/// destination unless `bind` narrows it to one port.
///
/// Two consequences a reader should have in front of them:
///
/// - **`bind` to port 0 means "everything", not "pick a port for me".** The
///   inversion is deliberate: the wildcard is the forwarder's natural state and
///   a specific port is the restriction, which is the opposite of a socket.
/// - **Only one of these can be active per `Stack`.** The demuxer has a single
///   protocol slot, so a second forwarder silently displaces the first. `bind`
///   fails rather than letting that happen quietly -- a displaced gateway does
///   not error, it just stops seeing connections, which is the worst way to
///   find out.
///
/// ## Accepting is backpressured, and adds no queue to do it
///
/// With `autoRead` off, an unaccepted request is simply not settled: the SYN
/// goes unanswered and the peer retransmits. The bound on how many can pile up
/// is `TCPForwarder.maximumInFlight`, which already exists as a SYN-flood
/// bound. Nothing here needed a queue of its own, and a queue of its own would
/// have been a second, weaker bound on the same guest-controlled quantity.
public final class NetstackServerChannel: Channel, ChannelCore, @unchecked Sendable {
    public let allocator = ByteBufferAllocator()
    public let eventLoop: EventLoop
    public let parent: Channel? = nil

    private let stack: Stack
    private let maximumInFlight: Int
    private var forwarder: TCPForwarder?
    private var restrictedToPort: UInt16?
    private var waiting: [ForwarderRequest] = []
    private var state: State = .idle
    private var autoRead = true
    private var readPending = false
    private var boundAddress: SocketAddress?

    private enum State { case idle, active, closed }

    public private(set) lazy var pipeline = ChannelPipeline(channel: self)
    private lazy var closePromise: EventLoopPromise<Void> = eventLoop.makePromise()

    public var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    public var isActive: Bool { state == .active }
    public var isWritable: Bool { false }
    public var localAddress: SocketAddress? { boundAddress }
    public var remoteAddress: SocketAddress? { nil }
    public var _channelCore: ChannelCore { self }

    public init(stack: Stack, maximumInFlight: Int = 512) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.maximumInFlight = maximumInFlight
    }

    // MARK: Options

    public func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if let value = value as? Bool, option is ChannelOptions.Types.AutoReadOption {
            autoRead = value
            if autoRead { read0() }
        }
        return eventLoop.makeSucceededVoidFuture()
    }

    public func getOption<Option: ChannelOption>(_ option: Option) -> EventLoopFuture<Option.Value> {
        if option is ChannelOptions.Types.AutoReadOption {
            return eventLoop.makeSucceededFuture(autoRead as! Option.Value)
        }
        return eventLoop.makeFailedFuture(ChannelError.operationUnsupported)
    }

    // MARK: ChannelCore

    public func localAddress0() throws -> SocketAddress {
        guard let boundAddress else { throw ChannelError.operationUnsupported }
        return boundAddress
    }

    public func remoteAddress0() throws -> SocketAddress { throw ChannelError.operationUnsupported }

    public func register0(promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
        pipeline.fireChannelRegistered()
    }

    public func registerAlreadyConfigured0(promise: EventLoopPromise<Void>?) {
        register0(promise: promise)
    }

    public func bind0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        guard state == .idle, let port = address.port else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        guard !stack.transportDemuxer.hasProtocolHandler(.tcp) else {
            // See the type comment: displacing another forwarder is silent, so
            // it is refused here where it is still visible.
            promise?.fail(StackError.portInUse)
            return
        }
        restrictedToPort = port == 0 ? nil : UInt16(port)
        boundAddress = address
        forwarder = TCPForwarder(stack: stack, maximumInFlight: maximumInFlight) { [weak self] request in
            self?.arrived(request)
        }
        state = .active
        promise?.succeed(())
        pipeline.fireChannelActive()
        if autoRead { read0() }
    }

    public func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    public func flush0() {}

    public func read0() {
        readPending = true
        acceptWaiting()
    }

    public func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        guard case .all = mode else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        let wasActive = state == .active
        state = .closed
        // Refused, not abandoned. A request dropped here leaves the peer
        // waiting out a connect timeout for a gateway that has already gone;
        // the reset tells it now.
        let unanswered = waiting
        waiting.removeAll()
        for request in unanswered { request.refuse() }
        forwarder = nil
        promise?.succeed(())
        if wasActive { pipeline.fireChannelInactive() }
        pipeline.fireChannelUnregistered()
        eventLoop.execute {
            self.removeHandlers(pipeline: self.pipeline)
            self.closePromise.succeed(())
        }
    }

    public func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
    }

    public func channelRead0(_ data: NIOAny) {
        // A child nobody in the pipeline took. Closing it is the only safe
        // reading of that: the connection is established and would otherwise sit
        // there with no handler, holding an endpoint, until the peer gave up.
        if let child = unwrapData(data, as: NetstackStreamChannel.self) as NetstackStreamChannel? {
            child.close(promise: nil)
        }
    }

    public func errorCaught0(error: Error) {}

    // MARK: Accepting

    private func arrived(_ request: ForwarderRequest) {
        guard state == .active else {
            request.refuse()
            return
        }
        if let restrictedToPort, request.destinationPort != restrictedToPort {
            // Reset rather than ignore. Nothing else in this process is going to
            // answer for that port -- the forwarder consumed the segment -- so
            // silence here is a hang on the peer, not a fallthrough.
            request.refuse()
            return
        }
        waiting.append(request)
        acceptWaiting()
    }

    private func acceptWaiting() {
        guard state == .active, readPending else { return }
        var accepted = false
        while !waiting.isEmpty {
            let request = waiting.removeFirst()
            guard let child = makeChild(for: request) else { continue }
            accepted = true
            // Consumed only when something is actually handed up. Clearing it
            // on entry instead disarms the channel on the empty pass that
            // `bind` makes before any SYN has arrived -- after which nothing
            // re-arms it, and an `autoRead` server accepts nothing, ever.
            readPending = false
            pipeline.fireChannelRead(child)
            // One per read, as a server channel does. `autoRead` is what turns
            // that into "all of them"; without it the caller decides when the
            // next SYN gets answered, which is the whole of accept
            // backpressure.
            if !autoRead { break }
        }
        if accepted { pipeline.fireChannelReadComplete() }
        // `autoRead` means "always want the next one", which is a standing
        // request rather than a repeated one: re-arming here is what makes a
        // request arriving later find the channel still listening.
        if autoRead, state == .active { readPending = true }
    }

    private func makeChild(for request: ForwarderRequest) -> NetstackStreamChannel? {
        // Two failures collapse here and they mean different things: `complete`
        // throws when the endpoint cannot be built, and returns nil when the
        // request was already settled. Neither leaves anything to hand upward,
        // and in both cases the request has been consumed, so there is nothing
        // left to refuse either.
        guard let endpoint = (try? request.complete()) ?? nil else { return nil }
        let child = NetstackStreamChannel(eventLoop: eventLoop, endpoint: endpoint, owns: false, parent: self)
        child.installCallbacks()
        child.acceptedAddresses(
            local: try? SocketAddress(ipAddress: request.destination.description, port: Int(request.destinationPort)),
            remote: try? SocketAddress(ipAddress: request.source.description, port: Int(request.sourcePort)))
        child.registerAlreadyConfigured0(promise: nil)
        return child
    }
}
