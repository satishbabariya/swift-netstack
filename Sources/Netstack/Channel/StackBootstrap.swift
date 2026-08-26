import NIOCore

/// Entry point for building channels on a stack. Shaped like NIO's own
/// bootstraps so it reads the same at the call site.
public struct StackBootstrap {
    private let stack: Stack
    private var initializer: ((Channel) -> EventLoopFuture<Void>)?

    public init(stack: Stack) {
        self.stack = stack
    }

    // Deliberately not `@Sendable`: a channel initializer runs synchronously,
    // entirely on `stack.eventLoop`, while `bind(host:port:)` is still
    // executing. It never crosses a thread boundary, so it is free to
    // capture non-Sendable handler state (as `NetstackChannelTests` does).
    public func channelInitializer(_ initializer: @escaping (Channel) -> EventLoopFuture<Void>) -> StackBootstrap {
        var copy = self
        copy.initializer = initializer
        return copy
    }

    /// Bind a datagram channel. Port 0 allocates an ephemeral port.
    public func bind(host: IPv4Address, port: UInt16) -> EventLoopFuture<Channel> {
        let channel = NetstackDatagramChannel(stack: stack)
        let address: SocketAddress
        do {
            address = try SocketAddress(ipAddress: host.description, port: Int(port))
        } catch {
            return stack.eventLoop.makeFailedFuture(error)
        }

        let eventLoop = stack.eventLoop
        let setup = initializer?(channel) ?? eventLoop.makeSucceededVoidFuture()
        return setup.flatMap {
            let promise = eventLoop.makePromise(of: Void.self)
            channel.register0(promise: nil)
            channel.bind0(to: address, promise: promise)
            return promise.futureResult.map { channel }
        }
    }
}
