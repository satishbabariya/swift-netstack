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
    private var allowRemoteHalfClosure = false
    /// The peer's FIN arrived and was reported as `inputClosed` rather than as
    /// the end of the channel. Only reachable with half-closure allowed.
    private var inputClosed = false
    /// This side's FIN has been sent, or is waiting on the queued writes that
    /// have to go out in front of it.
    private var outputClosed = false
    /// A `.output` close that arrived with writes still queued. The FIN has to
    /// follow the bytes it terminates, so it waits here until they drain.
    private var pendingOutputClose: EventLoopPromise<Void>??
    /// A full close that arrived with writes still queued, for the same reason
    /// and with a larger consequence: closing discards them.
    private var pendingClose: EventLoopPromise<Void>??
    private var closeLingerTask: Scheduled<Void>?
    private var lingerWatermark = 0

    /// How long a deferred close will wait without the queue moving.
    ///
    /// Not a deadline on the close: it is reset every time bytes actually
    /// leave, so a slow transfer that is still making progress is never
    /// truncated, however long it takes. What it bounds is a close waiting on a
    /// peer that has stopped taking anything at all.
    ///
    /// That bound has to exist, and it has to be here rather than in the
    /// connection. RFC 1122 §4.2.2.17 makes timing out a zero-window connection
    /// a MUST NOT, which this package honours -- so persist probes go on for as
    /// long as the peer keeps its window shut, and the counterweight RFC 6429 §4
    /// names is that such a connection "needs to allow ... to be closed or
    /// aborted by their applications". Waiting here for the peer's window would
    /// take that escape away and hold the channel, its endpoint and, on a
    /// gateway, the host socket spliced to it, at the choice of a guest that has
    /// only to stop reading.
    ///
    /// Sixty seconds because that is the persist timer's own steady-state
    /// interval: a peer that has taken nothing across a full probe interval is
    /// not being slow.
    static let closeLinger = TimeAmount.seconds(60)
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
        if let value = value as? Bool, option is ChannelOptions.Types.AllowRemoteHalfClosureOption {
            allowRemoteHalfClosure = value
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
        if option is ChannelOptions.Types.AllowRemoteHalfClosureOption {
            return eventLoop.makeSucceededFuture(allowRemoteHalfClosure as! Option.Value)
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
        // The send half is finished. Queueing this would be worse than
        // refusing it: the FIN either has already gone -- making these bytes
        // data past the end of the stream -- or is still waiting on the queue
        // this write would join, which postpones the close for as long as the
        // writer keeps writing.
        guard !outputClosed else {
            promise?.fail(ChannelError.outputClosed)
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
        switch mode {
        case .all:
            closeGracefully(error: error, promise: promise)
        case .output:
            closeOutput(promise: promise)
        case .input:
            // Nothing beneath this can refuse bytes the peer has already been
            // given a window for. Faking it by dropping what arrives would be
            // worse than refusing: the peer would keep sending into a stream
            // nobody reads, and only a full close tells it to stop.
            promise?.fail(ChannelError.operationUnsupported)
        }
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

    /// Turns on half-closure without going through the pipeline.
    ///
    /// The option exists too, and does the same thing; this is for the callers
    /// that have to set it before `installCallbacks`, since a FIN the endpoint
    /// has already processed is reported the moment the callbacks are armed and
    /// a channel that has not yet been told to allow half-closure would answer
    /// it by closing.
    func allowHalfClosure() {
        allowRemoteHalfClosure = true
    }

    func installCallbacks() {
        endpoint.onEstablished = { [weak self] in self?.established() }
        endpoint.onData = { [weak self] in self?.deliverAvailable() }
        endpoint.onWritable = { [weak self] in self?.drainPendingWrites() }
        endpoint.onClosed = { [weak self] in self?.peerClosed() }
        endpoint.onPeerFinished = { [weak self] in self?.peerFinished() }
    }

    /// The handshake completed. For a channel that dialled, this is activation;
    /// for one registered over an endpoint that was still in SYN-RECEIVED, the
    /// channel is long since active and what this brings is the first moment
    /// the connection can actually carry the bytes already queued on it.
    private func established() {
        activate()
        drainPendingWrites()
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
        // A FIN that arrived before this channel existed. The forwarder adopts
        // an established endpoint -- it only builds the guest channel once the
        // host side has been dialled -- so the guest's FIN can be older than
        // the pipeline that needs to hear about it, and nothing re-sends one.
        if allowRemoteHalfClosure, !inputClosed, state == .active, endpoint.adoptPeerFinished() {
            deliverInputClosed()
        }
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
            } catch StackError.notConnected {
                // Not "gone" -- "not yet". A channel is active from the moment
                // it is registered, but the endpoint under an accepted
                // connection can still be in SYN-RECEIVED: the forwarder dials
                // the host the instant the guest's SYN arrives, so a host that
                // speaks first -- SMTP, IMAP, SSH, every protocol with a
                // greeting -- can have its first bytes ready before the guest's
                // third leg lands. Dropping them here dropped exactly the
                // greeting the client was waiting for, and the promise the
                // splice writes with is nil, so it was silent. `established`
                // brings us back.
                //
                // Nothing waits forever on this: an endpoint that dies instead
                // of connecting reports through `onClosed`, and `finish` fails
                // every queued write.
                setWritable(false)
                return
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
        if case .some(let promise) = pendingOutputClose {
            pendingOutputClose = nil
            finishOutput(promise: promise)
        }
        // The queue is empty and someone is waiting to close on that.
        if case .some(let promise) = pendingClose {
            pendingClose = nil
            finish(error: ChannelError.eof, promise: promise)
        }
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

    /// A close is not a discard.
    ///
    /// Bytes this channel has already accepted are owed to the peer, and the
    /// splice writes with no promise -- so failing them lost the data and said
    /// nothing about it. That is the ordinary end of a proxied connection, not
    /// an edge: the far side finishes, the glue closes this side, and whatever
    /// the peer's window had not yet allowed out went with it. Measured against
    /// a real guest: a host sent 1,000,000 bytes and the guest received
    /// 400,160, with ten chunks failed on the way out.
    ///
    /// So a close with a queue waits for it. What bounds the wait is TCP
    /// itself, not a timer invented here: a peer that stops reading is met by
    /// the persist timer, then the keep-alive, then the FIN retry budget, and
    /// each of those ends in `onClosed` -- which finishes this channel and
    /// fails what is left. Nothing waits for a peer that is gone.
    ///
    /// Only a graceful close waits. `peerClosed` and a refused connect still
    /// go straight to `finish`, because there is nowhere left to send to.
    private func closeGracefully(error: Error, promise: EventLoopPromise<Void>?) {
        // A second close, while the first is still waiting. NIO's own answer
        // for closing twice is `alreadyClosed`, and this is that -- overwriting
        // the stored promise would leave the first caller's on nothing, waiting
        // for a completion that had been discarded.
        if pendingClose != nil {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        // One attempt before deferring, because the caller may not have
        // flushed. Bytes the send buffer can take should go now rather than
        // wait on a window that has nothing to do with them -- and if the queue
        // empties here, there is nothing to defer for.
        if state == .active { drainPendingWrites() }
        guard state == .active, !pendingWrites.isEmpty else {
            finish(error: error, promise: promise)
            return
        }
        // Refuse anything further, exactly as a `.output` close does: the
        // caller has said it is done, and a write accepted now would be one
        // more thing the close is waiting on.
        outputClosed = true
        pendingClose = promise
        armCloseLinger()
    }

    private func armCloseLinger() {
        closeLingerTask?.cancel()
        lingerWatermark = outstandingBytes
        closeLingerTask = endpoint.schedule(after: Self.closeLinger) { [weak self] in
            guard let self, case .some(let promise) = self.pendingClose else { return }
            // Re-armed rather than fired if anything moved. Progress is not the
            // channel's own queue draining -- that can be empty while the
            // connection is still working through the send buffer -- it is the
            // whole pipeline owing less than it did.
            guard self.outstandingBytes >= self.lingerWatermark else {
                self.armCloseLinger()
                return
            }
            // Nothing has left in a full probe interval. The bytes are owed and
            // they are lost, which is what the caller's close asked for; what is
            // not acceptable is holding a channel, an endpoint and the socket
            // spliced to it for a peer that has stopped taking anything.
            self.pendingClose = nil
            self.finish(error: ChannelError.ioOnClosedChannel, promise: promise)
        }
    }

    /// Keep a closed endpoint alive until it has finished what it was given.
    ///
    /// `close()` is asynchronous -- its own documentation says so, and says
    /// `onClosed` is the only way to learn it finished -- because a FIN waits
    /// behind the payload it terminates and the payload waits on the peer's
    /// window. Meanwhile the demuxer holds its delegates weakly, deliberately,
    /// so this channel is usually the last strong reference. Dropping it the
    /// instant the channel's own queue empties deallocates a connection with
    /// bytes still to send: transmission stops mid-stream, no FIN is ever sent,
    /// and the peer waits on a connection nothing will end.
    ///
    /// A real guest saw exactly that. A host reset a 600,000-byte transfer, the
    /// gateway had handed 539,085 bytes on and still owed 212,168, and it then
    /// sent nothing at all -- no FIN, no reset -- until the guest's own timeout
    /// gave up forty seconds later.
    ///
    /// The reference is the closure itself, and it is broken by the callback it
    /// waits for. Nothing waits forever: every route out of a connection ends in
    /// `onClosed`, including the FIN retry budget and the keep-alive.
    private func retainUntilFinished(_ endpoint: TCPEndpoint) {
        var held: TCPEndpoint? = endpoint
        endpoint.onClosed = {
            held?.onClosed = nil
            held = nil
        }
    }

    /// Everything still owed to the peer: what this channel holds, plus what it
    /// has already handed to the connection.
    private var outstandingBytes: Int {
        pendingWrites.reduce(0) { $0 + $1.buffer.readableBytes } + endpoint.owedBytes
    }

    /// Sends this side's FIN and leaves the channel active for reading.
    ///
    /// The FIN has to arrive behind every byte it terminates, so a close that
    /// finds writes still queued waits for them: `drainPendingWrites` finishes
    /// the job. A `.output` close that jumped the queue would truncate exactly
    /// the response a half-closing protocol was in the middle of sending.
    private func closeOutput(promise: EventLoopPromise<Void>?) {
        guard state == .active else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        guard !outputClosed else {
            promise?.fail(ChannelError.outputClosed)
            return
        }
        outputClosed = true
        guard pendingWrites.isEmpty else {
            pendingOutputClose = promise
            return
        }
        finishOutput(promise: promise)
    }

    private func finishOutput(promise: EventLoopPromise<Void>?) {
        endpoint.shutdownWrite()
        promise?.succeed(())
        pipeline.fireUserInboundEventTriggered(ChannelEvent.outputClosed)
    }

    /// The peer's FIN, on a channel that asked to hear about it as the end of
    /// the inbound half rather than the end of the connection.
    private func peerFinished() {
        guard allowRemoteHalfClosure, state == .active, !inputClosed else {
            // Not asked for, or too late to matter: the old meaning, where
            // either FIN ends the stream.
            peerClosed()
            return
        }
        deliverInputClosed()
    }

    private func deliverInputClosed() {
        inputClosed = true
        // The same reason `peerClosed` delivers before finishing: the FIN says
        // no MORE will arrive, not that what arrived is void.
        readPending = readPending || autoRead
        deliverAvailable()
        pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
    }

    private func finish(error: Error, promise: EventLoopPromise<Void>?) {
        guard state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        let wasActive = state == .active
        state = .closed
        if ownsEndpoint {
            endpoint.close()
            // Only when there is something left to finish. `close()` deletes
            // the TCB outright from LISTEN and SYN-SENT -- nothing was ever
            // established -- and reports closed on the way out, so the callback
            // this retention waits for has already fired. Installing it then
            // would hold the endpoint for a callback that never comes again,
            // which is a leak rather than a safeguard.
            if endpoint.hasConnections { retainUntilFinished(endpoint) }
        }
        endpoint.onData = nil
        endpoint.onWritable = nil
        endpoint.onEstablished = nil
        endpoint.onPeerFinished = nil
        let abandoned = pendingWrites
        pendingWrites.removeAll()
        for (_, writePromise) in abandoned { writePromise?.fail(ChannelError.ioOnClosedChannel) }
        // A `.output` close still waiting for those writes. The bytes it was
        // ordered behind have just been failed, so the FIN it wanted will
        // never be sent, and a caller holding this promise would otherwise
        // wait on a close that already happened by another route.
        if case .some(let outputPromise) = pendingOutputClose {
            pendingOutputClose = nil
            outputPromise?.fail(ChannelError.ioOnClosedChannel)
        }
        // And a full close still waiting on writes that will now never go. It
        // SUCCEEDS rather than fails: the caller asked for a close and is
        // getting one. What failed is the data, and those promises are failed
        // just above.
        if case .some(let closePromise) = pendingClose {
            pendingClose = nil
            closePromise?.succeed(())
        }
        closeLingerTask?.cancel()
        closeLingerTask = nil
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
