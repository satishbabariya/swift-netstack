import NIOCore

/// A NIO `Channel` over a netstack UDP endpoint.
///
/// Reads and writes `AddressedEnvelope<ByteBuffer>`, exactly as
/// `DatagramBootstrap` does, so a handler written against a real UDP socket
/// works here unchanged.
public final class NetstackDatagramChannel: Channel, ChannelCore, @unchecked Sendable {
    public let allocator = ByteBufferAllocator()
    public let eventLoop: EventLoop
    public let parent: Channel? = nil

    private let stack: Stack
    private let endpoint: UDPEndpoint
    private var boundAddress: SocketAddress?
    private var state: State = .idle
    private var pendingWrites: [(envelope: AddressedEnvelope<ByteBuffer>, promise: EventLoopPromise<Void>?)] = []
    private var autoRead = true

    private enum State { case idle, active, closed }

    public private(set) lazy var pipeline = ChannelPipeline(channel: self)
    private lazy var closePromise: EventLoopPromise<Void> = eventLoop.makePromise()

    public var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    public var isActive: Bool { state == .active }
    public var isWritable: Bool { true }
    public var localAddress: SocketAddress? { boundAddress }
    public var remoteAddress: SocketAddress? { nil }
    public var _channelCore: ChannelCore { self }

    init(stack: Stack) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.endpoint = UDPEndpoint(stack: stack)
    }

    // MARK: Options

    public func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if let value = value as? Bool, option is ChannelOptions.Types.AutoReadOption {
            autoRead = value
        }
        // Everything else is a socket concern that does not apply here.
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

    public func remoteAddress0() throws -> SocketAddress {
        throw ChannelError.operationUnsupported
    }

    public func register0(promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
        pipeline.fireChannelRegistered()
    }

    public func registerAlreadyConfigured0(promise: EventLoopPromise<Void>?) {
        state = .active
        register0(promise: promise)
        pipeline.fireChannelActive()
    }

    public func bind0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        guard state == .idle else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        guard let host = address.ipAddress, let local = IPv4Address(host), let port = address.port else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        do {
            try endpoint.bind(address: local, port: UInt16(port))
            endpoint.onDatagram = { [weak self] payload, peer, peerPort in
                self?.deliverInbound(payload, from: peer, port: peerPort)
            }
            boundAddress = address
            state = .active
            promise?.succeed(())
            pipeline.fireChannelActive()
        } catch {
            promise?.fail(error)
        }
    }

    public func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard state == .active else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }
        // The promise is not completed here: it stands for "this datagram
        // was written to the wire", which is only known once `flush0`
        // actually attempts the send. Succeeding it early would tell the
        // caller a write landed when it might still fail — e.g. because the
        // envelope's address is not IPv4, or the send itself errors.
        pendingWrites.append((unwrapData(data, as: AddressedEnvelope<ByteBuffer>.self), promise))
    }

    public func flush0() {
        guard state == .active else { return }
        let outgoing = pendingWrites
        pendingWrites.removeAll(keepingCapacity: true)

        for (envelope, promise) in outgoing {
            guard let host = envelope.remoteAddress.ipAddress,
                let peer = IPv4Address(host),
                let port = envelope.remoteAddress.port
            else {
                promise?.fail(ChannelError.operationUnsupported)
                continue
            }
            do {
                try endpoint.send(envelope.data, to: peer, port: UInt16(port))
                promise?.succeed(())
            } catch {
                promise?.fail(error)
            }
        }
    }

    public func read0() {
        // Inbound delivery is push-driven from the stack; there is no read
        // syscall to arm.
    }

    public func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        guard case .all = mode else {
            // Half-close has no meaning for a datagram endpoint.
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        state = .closed
        endpoint.close()
        let abandoned = pendingWrites
        pendingWrites.removeAll()
        for (_, writePromise) in abandoned {
            writePromise?.fail(ChannelError.ioOnClosedChannel)
        }
        promise?.succeed(())
        pipeline.fireChannelInactive()
        pipeline.fireChannelUnregistered()
        eventLoop.execute {
            // Deferred, as real NIO channels do (see `BaseSocketChannel.close0`
            // and `EmbeddedChannel.close0`), so any pipeline traversal still
            // in flight from the callouts above completes first. This is
            // also what breaks the channel<->pipeline retain cycle:
            // `ChannelPipeline.init(channel:)` holds `self` strongly, and
            // `removeHandlers(pipeline:)` is what nils `_channel` on the
            // pipeline. Without this call, a closed channel — and the
            // `Stack`/`UDPEndpoint` it captures — is retained forever.
            self.removeHandlers(pipeline: self.pipeline)
            self.closePromise.succeed(())
        }
    }

    public func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
    }

    public func channelRead0(_ data: NIOAny) {
        // Terminal handler: nothing downstream wanted it.
    }

    public func errorCaught0(error: Error) {}

    // MARK: Inbound

    private func deliverInbound(_ payload: ByteBuffer, from peer: IPv4Address, port: UInt16) {
        guard state == .active else { return }
        guard let remote = try? SocketAddress(ipAddress: peer.description, port: Int(port)) else { return }
        pipeline.fireChannelRead(AddressedEnvelope(remoteAddress: remote, data: payload))
        pipeline.fireChannelReadComplete()
    }
}
