import NIOCore

/// Pumps bytes between two channels, in one direction, without a queue.
///
/// Two of these, installed head to tail, make a bidirectional splice: this is
/// what carries a guest's TCP connection out to a real socket on the host.
///
/// ## Backpressure is the whole design, and it needs no buffer of its own
///
/// Reading is driven by the *other* channel's writability, not by this one's
/// data:
///
/// - Every read is written straight through and the source is only asked for
///   more once the sink says it has room. Nothing is held here, so there is no
///   queue for a fast source and a slow sink to grow.
/// - When the sink goes unwritable, no `read()` is issued. The source's own
///   receive buffer fills, and on the netstack side that shrinks the window the
///   guest sees -- so the guest stops, which is the only place backpressure can
///   actually be applied.
///
/// **Both channels must have `autoRead` off.** With it on the source reads
/// whether or not anyone asked, and the backpressure above becomes decoration:
/// the reads keep arriving, the writes keep queuing inside the sink channel, and
/// the queue this design avoids reappears one layer down where nothing bounds
/// it.
///
/// ## Both channels must be on the same event loop
///
/// Not a simplification -- a requirement. Everything here touches the partner's
/// channel directly, and this package has no locks in its datapath by rule.
/// Crossing loops would need either a lock or a hop per chunk, and a hop per
/// chunk is a queue in the scheduler.
final class GlueHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var partner: GlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead = false

    /// This channel's peer has finished sending, and this channel has finished
    /// sending to it. A splice ends when both are true and not before -- the
    /// two halves of a TCP connection close independently, and treating the
    /// first of them as the end throws away the other direction's traffic.
    private var inputClosed = false
    private var outputClosed = false

    /// Set while this side is closing, so a partner closing back does not bounce
    /// the close between the two handlers.
    private var closing = false

    private init() {}

    /// Build the pair. Install the first on one channel and the second on the
    /// other; which is which does not matter, since each is the other's sink.
    static func matchedPair() -> (GlueHandler, GlueHandler) {
        let first = GlueHandler()
        let second = GlueHandler()
        first.partner = second
        second.partner = first
        return (first, second)
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        partner = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        partner?.partnerWrite(unwrapInboundIn(data))
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        partner?.partnerFlush()
        // Ask for the next burst here rather than after every `channelRead`: a
        // read burst is one unit of work, and asking mid-burst would interleave
        // requests with deliveries for no gain.
        if partner?.isWritable ?? false {
            context.read()
        } else {
            pendingRead = true
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        partner?.partnerCloseFromPeer()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case ChannelEvent.inputClosed = event {
            inputClosed = true
            // The source is done sending, so this sink has nothing left to
            // write -- but it may still have plenty left to read. Passing the
            // half-close through, rather than closing, is what lets `echo hi |
            // nc host port` and busybox `nc` with no stdin see their answers.
            partner?.partnerInputClosed()
            closeIfFinished(context)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        partner?.partnerCloseFromPeer()
        context.close(promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        // This channel became writable, so its SOURCE -- the partner -- may read
        // again. The direction is worth reading twice: a handler that resumed
        // its own reading here would be asking the wrong channel for more.
        if context.channel.isWritable {
            partner?.partnerBecameWritable()
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        // Nothing reads until something asks. With `autoRead` off this is the
        // first read of the connection, and without it the splice never starts.
        context.read()
    }

    // MARK: Partner-facing

    var isWritable: Bool { context?.channel.isWritable ?? false }

    private func partnerWrite(_ data: ByteBuffer) {
        context?.write(wrapOutboundOut(data), promise: nil)
    }

    private func partnerFlush() {
        context?.flush()
    }

    private func partnerBecameWritable() {
        guard pendingRead else { return }
        pendingRead = false
        context?.read()
    }

    /// The partner's peer has finished sending, so this side's send half is
    /// done: pass the FIN on and stop there.
    private func partnerInputClosed() {
        guard !closing, !outputClosed, let context else { return }
        guard context.channel.isActive else {
            // There is no half to close. This channel has not connected yet --
            // the port forwarder installs the glue and then dials the guest --
            // so the source hanging up is not "I have finished sending", it is
            // the whole reason the dial existed going away. Half-closing here
            // did nothing at all, and the dial ran on to its own timeout
            // holding a connection slot for a client that had left.
            partnerCloseFromPeer()
            return
        }
        outputClosed = true
        // Flushed first for the same reason a close is: the source's last bytes
        // were written here, and a FIN that overtakes them truncates the stream
        // at the one point where losing the tail is least acceptable.
        context.flush()
        context.close(mode: .output, promise: nil)
        closeIfFinished(context)
    }

    /// Both halves are finished, so nothing more can happen on this channel and
    /// holding it open holds a file descriptor and an endpoint for nobody. A
    /// half-closed channel does not close itself -- that is the point of it --
    /// so this is the only thing that releases it.
    private func closeIfFinished(_ context: ChannelHandlerContext) {
        guard inputClosed, outputClosed, !closing else { return }
        closing = true
        context.close(promise: nil)
    }

    private func partnerCloseFromPeer() {
        guard !closing, let context else { return }
        closing = true
        // Flushed before closing: the peer's last bytes were written here, and a
        // close without a flush discards them. The end of a stream is exactly
        // when losing the tail is least acceptable and easiest to do.
        context.flush()
        context.close(promise: nil)
    }
}
