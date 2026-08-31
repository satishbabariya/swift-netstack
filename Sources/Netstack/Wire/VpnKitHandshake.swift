import NIOCore

/// hyperkit's opening exchange, before a vpnkit socket carries any frames.
///
/// `--listen-vpnkit` is the one wire whose connection does not begin with a
/// frame. hyperkit sends a fixed-size init message and a fixed-size command,
/// and expects a reply that tells it the MTU and the hardware address it should
/// use. Only after that does the connection become an ordinary hyperkit wire:
/// two little-endian length bytes and then the frame.
///
/// The sizes are hyperkit's, not this package's, and they are exact -- 49, 41
/// and 258 bytes. They come from `pci_virtio_net_vpnkit.c` and upstream
/// implements the same three steps against the same three numbers. There is
/// nothing to negotiate and no version to check: a peer that sends something
/// else is not hyperkit.
///
/// ## Why a handler rather than a few reads
///
/// A socket does not deliver messages, it delivers bytes, so "read 49 bytes"
/// means "keep reading until 49 have arrived". Doing that with blocking reads
/// would need a thread per pending guest; doing it in the pipeline costs
/// nothing and puts the partial-read case where it cannot be forgotten.
///
/// The handler removes itself when the exchange is done, and the frame codec is
/// installed behind it -- so the first frame arrives at a pipeline that has
/// never seen the handshake bytes.
///
/// ## The deadline is not a nicety
///
/// A peer that connects and says nothing holds a place on the switch it has not
/// earned. Thirty-two of those -- the default guest limit -- and no real guest
/// can join, for as long as the attacker leaves the sockets open, which is
/// forever. Measured before it was fixed:
///
///     silent connections held open: 32
///     a real guest was CLOSED OUT by peers that never spoke
///
/// Everything else guest-reachable in this package is bounded, on the premise
/// that a connection held open is a resource; this was written without one and
/// is the counterexample. The deadline is generous and the peer is not being
/// asked for much: hyperkit sends its init as its first act, so a connection
/// that has not produced forty-nine bytes in ten seconds is not hyperkit.
final class VpnKitHandshakeHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    /// hyperkit's message sizes, in the order they appear.
    static let initialLength = 49
    static let commandLength = 41
    static let replyLength = 258

    private enum Step {
        case awaitingInitial
        case awaitingCommand
        case done
    }

    private var step = Step.awaitingInitial
    private var deadline: Scheduled<Void>?
    private let allowance: TimeAmount
    private var held: ByteBuffer
    private let mtu: UInt16
    private let macForUUID: @Sendable (String) -> MACAddress
    private let finished: (MACAddress) -> Void

    /// - Parameters:
    ///   - allocator: where the buffer holding a partial handshake comes from.
    ///   - mtu: what the guest is told it may send. hyperkit is also told the
    ///     frame size, which is this plus an ethernet header.
    ///   - allowance: how long the peer has to complete the exchange before the
    ///     connection is closed and its place given back.
    ///   - macForUUID: the address to give the guest, chosen from the UUID it
    ///     sends. Upstream looks it up in a configured map and invents one when
    ///     the UUID is not in it.
    ///   - finished: called with the address handed out, once, when the exchange
    ///     completes. The caller installs the rest of the pipeline here.
    init(
        allocator: ByteBufferAllocator, mtu: UInt16, allowance: TimeAmount = .seconds(10),
        macForUUID: @escaping @Sendable (String) -> MACAddress,
        finished: @escaping (MACAddress) -> Void
    ) {
        self.allowance = allowance
        self.held = allocator.buffer(capacity: Self.initialLength + Self.commandLength)
        self.mtu = mtu
        self.macForUUID = macForUUID
        self.finished = finished
    }

    func handlerAdded(context: ChannelHandlerContext) {
        arm(context)
    }

    func channelActive(context: ChannelHandlerContext) {
        arm(context)
        context.fireChannelActive()
    }

    private func arm(_ context: ChannelHandlerContext) {
        guard deadline == nil, step != .done, context.channel.isActive else { return }
        // The channel and nothing else. A scheduled task's closure is
        // `@Sendable`, and neither this handler -- which holds a buffer of half
        // a handshake -- nor a `ChannelHandlerContext` can honestly be sent
        // anywhere. `Channel` can, and closing it is the whole job.
        //
        // There is no "has it finished?" check inside, because a task that has
        // been cancelled does not run: completing the exchange, leaving the
        // pipeline and the connection going away each cancel it.
        let channel = context.channel
        deadline = context.eventLoop.scheduleTask(in: allowance) {
            // Closed, not merely abandoned: closing is what returns the place on
            // the switch, and a handler that only stopped listening would leave
            // the connection and the reservation exactly where they were.
            channel.close(promise: nil)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        held.writeBuffer(&incoming)
        advance(context: context)
    }

    private func advance(context: ChannelHandlerContext) {
        while true {
            switch step {
            case .awaitingInitial:
                guard held.readableBytes >= Self.initialLength else { return }
                // Echoed back exactly, which is what hyperkit expects: the
                // message is its own acknowledgement.
                let initial = held.readSlice(length: Self.initialLength)!
                context.writeAndFlush(wrapInboundOut(initial), promise: nil)
                step = .awaitingCommand

            case .awaitingCommand:
                guard held.readableBytes >= Self.commandLength else { return }
                let command = held.readSlice(length: Self.commandLength)!
                // Bytes 1..<37 are the UUID as text. Anything else in the
                // message is hyperkit's business.
                let uuid = command.getString(at: command.readerIndex + 1, length: 36) ?? ""
                let mac = macForUUID(uuid)

                var reply = context.channel.allocator.buffer(capacity: Self.replyLength)
                reply.writeInteger(UInt8(0x01))
                reply.writeInteger(mtu, endianness: .little)
                // The frame size, which is the MTU plus an ethernet header --
                // hyperkit sizes its own buffers from this, so a value that
                // forgot the header would truncate every full-sized frame.
                reply.writeInteger(mtu &+ UInt16(EthernetHeader.length), endianness: .little)
                reply.writeBytes(mac.bytes)
                reply.writeBytes([UInt8](repeating: 0, count: Self.replyLength - reply.readableBytes))
                context.writeAndFlush(wrapInboundOut(reply), promise: nil)

                step = .done
                deadline?.cancel()
                deadline = nil
                finished(mac)
                // Whatever arrived after the command is the first frame, or part
                // of one. It is passed on rather than dropped, and it is passed
                // on AFTER the pipeline behind this handler exists -- `finished`
                // installs it.
                if held.readableBytes > 0 {
                    let rest = held.readSlice(length: held.readableBytes)!
                    context.fireChannelRead(wrapInboundOut(rest))
                }
                context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
                return

            case .done:
                // Reached only if a read lands between `finished` and this
                // handler leaving the pipeline. Forwarded, not held.
                guard held.readableBytes > 0 else { return }
                let rest = held.readSlice(length: held.readableBytes)!
                context.fireChannelRead(wrapInboundOut(rest))
                return
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        deadline?.cancel()
        deadline = nil
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        // The exchange finished and this handler is leaving. A timer left armed
        // here would fire on a connection that is now a working wire and close
        // a guest that did nothing wrong.
        deadline?.cancel()
        deadline = nil
    }
}
