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
