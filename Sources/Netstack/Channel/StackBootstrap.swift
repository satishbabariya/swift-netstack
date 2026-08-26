import NIOCore

/// Entry point for building channels on a stack. Shaped like NIO's own
/// bootstraps so it reads the same at the call site.
public struct StackBootstrap {
    private let stack: Stack
    private var initializer: (@Sendable (Channel) -> EventLoopFuture<Void>)?

    public init(stack: Stack) {
        self.stack = stack
    }

    public func channelInitializer(_ initializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> StackBootstrap {
        var copy = self
        copy.initializer = initializer
        return copy
    }

    /// Bind a datagram channel. Port 0 allocates an ephemeral port.
    ///
    /// `bind` is the package's one public entry point that a caller may
    /// invoke from any thread, so — unlike everything else in this package,
    /// which relies entirely on loop confinement instead of locks — it must
    /// marshal onto `stack.eventLoop` itself before touching anything
    /// loop-confined. `NetstackDatagramChannel`'s `init` only stores
    /// references (no shared mutable state is read or written), so
    /// constructing it here, before any hop, is safe; what actually mutates
    /// loop-confined state — the channel initializer, `register0`, and
    /// `bind0` — all run inside `bindOnLoop` below, which only ever runs on
    /// the loop. `channel` is the only loop-confined value that closure
    /// captures, and it is `@unchecked Sendable` for exactly this reason: it
    /// is fully constructed before being handed across, and nothing touches
    /// it concurrently from here on.
    ///
    /// This checks `eventLoop.inEventLoop` rather than unconditionally
    /// calling `flatSubmit`, and that check is load-bearing, not an
    /// optimisation: `EventLoop.submit`/`flatSubmit` always go through
    /// `execute` even when already on the loop (see
    /// `NIOCore/EventLoop.swift`'s default `submit` — it never checks
    /// `inEventLoop` itself), and on `EmbeddedEventLoop`, `execute` only
    /// enqueues — it runs nothing until the test drives the loop with
    /// `run()`/`advanceTime()`. Every test in `NetstackChannelTests` binds
    /// and then immediately `.wait()`s from the same thread that created the
    /// loop without ever driving it, so an unconditional `flatSubmit` here
    /// deadlocks every one of them: the calling thread blocks in `.wait()`
    /// while the bind it's waiting on sits queued, and nothing left to run
    /// it. `ChannelPipeline`'s own `close`/`flush`/`read` avoid exactly this
    /// by checking `inEventLoop` and calling straight through when already
    /// there; this follows the same pattern. Under a real
    /// `MultiThreadedEventLoopGroup`, `inEventLoop` is only ever true when
    /// `bind` happens to be called from the loop's own thread, so the
    /// off-loop case still always marshals through `flatSubmit`, which is
    /// what actually closes the race this method exists to prevent.
    public func bind(host: IPv4Address, port: UInt16) -> EventLoopFuture<Channel> {
        let channel = NetstackDatagramChannel(stack: stack)
        let eventLoop = channel.eventLoop
        let address: SocketAddress
        do {
            address = try SocketAddress(ipAddress: host.description, port: Int(port))
        } catch {
            return eventLoop.makeFailedFuture(error)
        }

        let initializer = self.initializer
        let bindOnLoop: @Sendable () -> EventLoopFuture<Channel> = {
            let setup = initializer?(channel) ?? eventLoop.makeSucceededVoidFuture()
            return setup.flatMap {
                let promise = eventLoop.makePromise(of: Void.self)
                channel.register0(promise: nil)
                channel.bind0(to: address, promise: promise)
                return promise.futureResult.map { channel }
            }
        }

        if eventLoop.inEventLoop {
            return bindOnLoop()
        } else {
            return eventLoop.flatSubmit(bindOnLoop)
        }
    }
}
