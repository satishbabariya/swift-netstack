import NIOCore

/// A TCP connection as a NIO `Channel`.
///
/// ## What this type is for
///
/// Everything under `Transport/TCP/` speaks in callbacks: `onData` says bytes
/// are ready, `send` refuses when there is no room, `read` takes what is held.
/// That interface is the right one for the stack and the wrong one for an
/// application, which already knows how to write a `ChannelHandler`. This type
/// is the translation, and the whole of its value is that the translation is
/// **lossless in the direction that matters**: NIO's backpressure and TCP's
/// window are the same mechanism here, not two mechanisms bridged by a queue.
///
/// ## Backpressure, which is the only interesting part
///
/// - **Inbound.** With `autoRead` off, a handler that does not call `read()`
///   causes nothing to be drained from the endpoint. Bytes stay in the
///   receive buffer, the advertised window shrinks by exactly what is held,
///   and the peer stops. No queue grows anywhere. This is the property the
///   endpoint's `read`/`onData` split was built for, and it is the reason this
///   channel does not "deliver" on `onData`.
/// - **Outbound.** `send` refuses rather than truncating. A refused write
///   leaves this channel holding the bytes, marks it not writable, and waits
///   for `onWritable`. A handler that respects `isWritable` never grows the
///   pending list past the one write in progress.
///
/// A channel that ignored either signal would be correct and unbounded; the
/// signals are what make it correct and bounded.
public final class NetstackStreamChannel: Channel, ChannelCore, @unchecked Sendable {
    public let allocator = ByteBufferAllocator()
    public let eventLoop: EventLoop
    public let parent: Channel?

    private let endpoint: TCPEndpoint
    private let ownsEndpoint: Bool
    private var state: State = .idle
    private var pendingWrites: [(buffer: ByteBuffer, promise: EventLoopPromise<Void>?)] = []

    /// Set by a `flush` that arrived before the channel was active, and honoured
    /// by `activate`. Without it the queued bytes would sit there until some
    /// later write happened to flush them, which for a request/response protocol
    /// is never.
    private var flushPending = false
    private var autoRead = true
    private var readPending = false
    private var writable = true
    private var connectPromise: EventLoopPromise<Void>?
    private var local: SocketAddress?
    private var remote: SocketAddress?

    private enum State { case idle, connecting, active, closed }

    public private(set) lazy var pipeline = ChannelPipeline(channel: self)
    private lazy var closePromise: EventLoopPromise<Void> = eventLoop.makePromise()

    public var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    public var isActive: Bool { state == .active }
    public var isWritable: Bool { writable }
    public var localAddress: SocketAddress? { local }
    public var remoteAddress: SocketAddress? { remote }
    public var _channelCore: ChannelCore { self }

    /// A channel that will open its own connection.
    public convenience init(stack: Stack) {
        self.init(eventLoop: stack.eventLoop, endpoint: TCPEndpoint(stack: stack), owns: true, parent: nil)
    }

    /// A channel over a connection that is already established -- what
    /// `NetstackServerChannel` builds for each accepted request.
    ///
    /// `owns: false` records that the endpoint outlives this channel's failure
    /// to close it cleanly. The forwarder is holding the same endpoint in its
    /// own table and will tear it down when the connection finishes; closing it
    /// twice is not the hazard, but pretending this channel is the only owner
    /// would make the forwarder's table the thing that leaks.
    init(eventLoop: EventLoop, endpoint: TCPEndpoint, owns: Bool, parent: Channel?) {
        self.eventLoop = eventLoop
        self.endpoint = endpoint
        self.ownsEndpoint = owns
        self.parent = parent
    }

    // MARK: Options

    public func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if let value = value as? Bool, option is ChannelOptions.Types.AutoReadOption {
            autoRead = value
            // Turning it off also disarms any read already outstanding. Real
            // NIO cannot do that -- an armed read there is a registration with
            // the selector -- but here the read is just this flag, and leaving
            // it set would deliver one more burst to a handler that had just
            // said stop. The burst would be exactly the one a handler disabling
            // `autoRead` on its first `channelRead` was trying to prevent.
            readPending = value
            if autoRead { read0() }
        }
        // Everything else is a socket concern that does not apply here. Note
        // what this quietly includes: the write-buffer watermarks. They are not
        // ignored out of laziness -- this channel's writability is not a
        // function of a byte count it chose, it is the send buffer's own
        // refusal, and a watermark layered on top would be a second, looser
        // answer to a question already answered exactly.
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
        guard let local else { throw ChannelError.operationUnsupported }
        return local
    }

    public func remoteAddress0() throws -> SocketAddress {
        guard let remote else { throw ChannelError.operationUnsupported }
        return remote
    }

    public func register0(promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
        pipeline.fireChannelRegistered()
    }

    public func registerAlreadyConfigured0(promise: EventLoopPromise<Void>?) {
        register0(promise: promise)
        activate()
    }

    public func bind0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        guard state == .idle, let host = address.ipAddress, let source = IPv4Address(host),
            let port = address.port
        else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        do {
            try endpoint.bind(address: source, port: UInt16(port))
            local = address
            promise?.succeed(())
        } catch {
            promise?.fail(error)
        }
    }

    public func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        guard state == .idle else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        guard let host = address.ipAddress, let destination = IPv4Address(host), let port = address.port else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        state = .connecting
        connectPromise = promise
        installCallbacks()
        do {
            try endpoint.connect(to: destination, port: UInt16(port))
            remote = address
        } catch {
            state = .idle
            connectPromise = nil
            promise?.fail(error)
        }
    }

    public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }
        // Queued, not sent. The promise means "these bytes were accepted by the
        // send buffer", which `flush0` is the first thing in a position to know.
        //
        // A write before the channel is active is queued rather than refused,
        // which is what NIO's own channels do and what anything spliced onto
        // this one assumes. Refusing it here failed the promise -- and the
        // splice writes with no promise, so the bytes went nowhere and said
        // nothing. That is a real connection losing real data: a host client
        // that connects to a forwarded port and writes at once, which is every
        // HTTP client there is, had its request dropped while the guest-side
        // handshake was still in flight.
        pendingWrites.append((unwrapData(data, as: ByteBuffer.self), promise))
    }

    public func flush0() {
        guard state == .active else {
            // Remembered rather than discarded: these bytes have been asked for,
            // and `activate` owes them to the peer as soon as there is somewhere
            // to send them.
            flushPending = !pendingWrites.isEmpty
            return
        }
        drainPendingWrites()
    }

    public func read0() {
        readPending = true
        deliverAvailable()
    }

    public func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        guard case .all = mode else {
            // Half-close is not offered rather than being faked. The endpoint's
            // `close` sends a FIN and stops accepting writes in one step; there
            // is no "stop writing, keep reading" beneath this to expose, and a
            // `.output` close that silently closed both directions would break
            // exactly the protocols that ask for one.
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        finish(error: error, promise: promise)
    }

    public func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.succeed(())
    }

    public func channelRead0(_ data: NIOAny) {
        // Terminal handler: nothing downstream wanted it.
    }

    public func errorCaught0(error: Error) {}

    // MARK: Wiring

    /// The four-tuple of an accepted connection, which the child cannot ask its
    /// endpoint for: the endpoint holds it, but the request is what named it.
    func acceptedAddresses(local: SocketAddress?, remote: SocketAddress?) {
        self.local = local
        self.remote = remote
    }

    func installCallbacks() {
        endpoint.onEstablished = { [weak self] in self?.activate() }
        endpoint.onData = { [weak self] in self?.deliverAvailable() }
        endpoint.onWritable = { [weak self] in self?.drainPendingWrites() }
        endpoint.onClosed = { [weak self] in self?.peerClosed() }
    }

    private func activate() {
        guard state == .idle || state == .connecting else { return }
        state = .active
        let promise = connectPromise
        connectPromise = nil
        promise?.succeed(())
        pipeline.fireChannelActive()
        if flushPending {
            flushPending = false
            drainPendingWrites()
        }
        if autoRead { read0() }
    }

    private func deliverAvailable() {
        guard state == .active else { return }
        // The guard is the backpressure. Without a pending read this returns
        // having taken nothing, the bytes stay in the endpoint's receive
        // buffer, and the window it advertises falls by that much. Draining
        // here "so they are not lost" is precisely how a channel turns a
        // bounded receive buffer into an unbounded one.
        guard readPending else { return }
        let chunk = endpoint.read()
        guard chunk.readableBytes > 0 else { return }
        // Cleared before the callout, not after: a handler that calls `read()`
        // from inside `channelRead` is asking for the next burst, and clearing
        // afterwards would erase that request.
        readPending = false
        pipeline.fireChannelRead(chunk)
        pipeline.fireChannelReadComplete()
        if autoRead { read0() }
    }

    private func drainPendingWrites() {
        guard state == .active else { return }
        while let next = pendingWrites.first {
            do {
                try endpoint.send(next.buffer)
            } catch StackError.wouldBlock {
                // Nothing was queued -- `send` refuses whole writes -- so the
                // entry stays at the head, untouched, and `onWritable` brings
                // us back. This is the one place the channel goes unwritable,
                // and it is the send buffer's own answer rather than a count
                // this type maintains in parallel.
                setWritable(false)
                return
            } catch {
                pendingWrites.removeFirst()
                next.promise?.fail(error)
                continue
            }
            pendingWrites.removeFirst()
            next.promise?.succeed(())
        }
        setWritable(true)
    }

    private func setWritable(_ value: Bool) {
        guard writable != value, state == .active else { return }
        writable = value
        pipeline.fireChannelWritabilityChanged()
    }

    private func peerClosed() {
        // A connection that never became active ended before it began: the peer
        // reset the SYN, or the endpoint gave up on it. That has to fail the
        // CONNECT, not merely close the channel -- a caller waiting on the
        // connect promise would otherwise wait forever, and the port forwarder
        // is exactly such a caller. The first version guarded on `.active` alone
        // and left a refused connection stuck in `.connecting` for good.
        if state == .connecting {
            finish(error: StackError.connectionRefused, promise: nil)
            return
        }
        guard state == .active else { return }
        // The peer's FIN with bytes still held is not a reason to drop them:
        // `onClosed` says no MORE will arrive, not that what arrived is void.
        // A handler with `autoRead` on gets them here; one driving reads itself
        // has its last `read()` answered before inactive.
        readPending = readPending || autoRead
        deliverAvailable()
        finish(error: ChannelError.eof, promise: nil)
    }

    private func finish(error: Error, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        let wasActive = state == .active
        state = .closed
        if ownsEndpoint { endpoint.close() }
        endpoint.onData = nil
        endpoint.onWritable = nil
        endpoint.onEstablished = nil
        let abandoned = pendingWrites
        pendingWrites.removeAll()
        for (_, writePromise) in abandoned { writePromise?.fail(ChannelError.ioOnClosedChannel) }
        connectPromise?.fail(error)
        connectPromise = nil
        promise?.succeed(())
        if wasActive { pipeline.fireChannelInactive() }
        pipeline.fireChannelUnregistered()
        eventLoop.execute {
            // Deferred for the same two reasons as the datagram channel: any
            // pipeline traversal still in flight from the callouts above
            // completes first, and `removeHandlers` is what breaks the
            // channel<->pipeline retain cycle. Without it a closed channel
            // holds its endpoint, and its endpoint holds the stack, forever.
            self.removeHandlers(pipeline: self.pipeline)
            self.closePromise.succeed(())
        }
    }
}
