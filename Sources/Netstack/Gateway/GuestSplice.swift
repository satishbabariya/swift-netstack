import NIOCore

/// Dial a guest and glue a host channel to it.
///
/// Extracted because two things need it and they must not drift: `PortForwarder`
/// does this for every connection to a published port, and the control plane's
/// `/tunnel` does it once for a connection the caller already has. The ordering
/// below is the part worth having in one place -- it is not obvious, and getting
/// it wrong produces a connection that works until it doesn't.
enum GuestSplice {
    /// Connect `host` to `address:port` inside the virtual network.
    ///
    /// Returns the guest-side channel, or `nil` if the pipeline could not be
    /// built -- in which case nothing has been registered and the caller still
    /// owns `host`.
    ///
    /// `host` must already be on `stack.eventLoop`. Both channels of a splice
    /// have to share a loop (see `GlueHandler`), and this is not the place that
    /// can arrange it.
    static func connect(
        stack: Stack, host: Channel, to address: IPv4Address, port: UInt16,
        keepAlive: TCPEndpoint.KeepAliveConfiguration?
    ) -> NetstackStreamChannel? {
        let eventLoop = stack.eventLoop
        eventLoop.preconditionInEventLoop()
        guard let destination = try? SocketAddress(ipAddress: address.description, port: Int(port)) else {
            return nil
        }

        let endpoint = TCPEndpoint(stack: stack)
        endpoint.keepAlive = keepAlive
        let guestChannel = NetstackStreamChannel(
            eventLoop: eventLoop, endpoint: endpoint, owns: true, parent: nil)
        guestChannel.allowHalfClosure()
        guestChannel.installCallbacks()

        let (guestGlue, hostGlue) = GlueHandler.matchedPair()
        do {
            // `autoRead` off on both sides: the glue's backpressure is exactly
            // the reads it declines to issue. With it on the reads happen anyway
            // and the queue moves one layer down, where nothing bounds it.
            try guestChannel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
            // Half-closure on both sides of the splice, so a FIN in one
            // direction is forwarded as a FIN rather than acted on as a
            // teardown. A client that writes its request and closes its send
            // side -- `echo … | nc`, busybox `nc` with no stdin, every
            // HTTP/0.9-shaped protocol -- is still waiting for the answer.
            try host.syncOptions?.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            try guestChannel.pipeline.syncOperations.addHandler(guestGlue)
            try host.pipeline.syncOperations.addHandler(hostGlue)
        } catch {
            guestChannel.close(promise: nil)
            return nil
        }

        // Registered first, connected second, and the order matters: `connect`
        // makes the guest-side channel active as soon as the handshake
        // completes, and a channel that becomes active before its pipeline is
        // registered delivers `channelActive` to nobody.
        guestChannel.register0(promise: nil)
        let connected = eventLoop.makePromise(of: Void.self)
        guestChannel.connect0(to: destination, promise: connected)
        connected.futureResult.whenFailure { _ in
            // The guest is not listening, or is gone. The dialler on the host
            // side is told by the only means a TCP server has: the connection it
            // made goes away.
            host.close(promise: nil)
        }
        return guestChannel
    }
}
