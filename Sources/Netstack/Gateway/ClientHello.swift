import NIOCore

/// Reads the server name out of the first bytes a guest sends on a TLS port.
///
/// ## A hello can arrive in more than one record
///
/// TLS lets a client split one handshake message across several records, and
/// servers put it back together: crypto/tls, OpenSSL and BoringSSL all read
/// records until the message is whole. A reader that looked at one record would
/// find no name in a hello whose name is in the second. If the gate then treated
/// "no name" as "nothing to check", a guest could get past it just by splitting
/// its hello. sandbox's patch 0013 fixed exactly that in Go, and this reads the
/// same way. Records are reassembled until the ClientHello is complete. Only the
/// first byte decides whether the stream is TLS at all. After that, anything
/// that stops the hello being read is `.unreadable`, never `.notTLS`.
///
/// ## Bounds
///
/// The message is capped at 16 KiB and the records carrying it at 32 KiB. The
/// second cap is there because each record costs a five-byte header. A guest
/// that splits a hello into one-byte records would otherwise make the gateway
/// hold six bytes for every byte of hello. Both caps are patch 0013's. While
/// this returns `.needMore`, `consumed` is always under 32 KiB.
///
/// Every byte fed is kept in `consumed`, in order, so a connection that passes
/// can be handed on exactly as the guest sent it.
struct ClientHelloReassembler {
    /// The largest ClientHello message read, header included. A real one is
    /// normally under 2 KiB, even with a post-quantum key share.
    static let maximumHello = 16 * 1024
    /// The most bytes of records read to carry it.
    static let maximumRecordBytes = 32 * 1024
    /// TLSPlaintext's own limit on one record (RFC 8446 §5.1).
    static let maximumRecord = 16 * 1024

    enum Outcome: Hashable {
        /// The hello is not complete yet.
        case needMore
        /// The first byte is not a handshake record, or the stream ended before
        /// it sent anything.
        case notTLS
        /// A complete, valid ClientHello with no `server_name`. Legal: a
        /// connection to an IP literal has no name to send.
        case noServerName
        /// Lowercased, with no trailing dot.
        case serverName(String)
        /// Started as TLS, and no name can be read from it.
        case unreadable(Unreadable)
    }

    enum Unreadable: Hashable {
        /// A length, a type or a name that a ClientHello cannot have, or a hello
        /// over the bounds.
        case malformed
        /// The guest finished sending before the hello was complete.
        case ended
        /// The deadline passed before the hello was complete.
        case timedOut
    }

    private(set) var consumed = ByteBuffer()
    /// Offset in `consumed` of the next record header.
    private var nextRecord = 0
    /// The handshake bytes carried by the records read so far.
    private var message: [UInt8] = []

    mutating func feed(_ bytes: ByteBuffer) -> Outcome {
        var bytes = bytes
        consumed.writeBuffer(&bytes)
        return examine()
    }

    /// What a stream that has finished sending comes to, when the last `feed`
    /// said `.needMore`.
    func streamEnded() -> Outcome {
        consumed.readableBytes == 0 ? .notTLS : .unreadable(.ended)
    }

    private mutating func examine() -> Outcome {
        let base = consumed.readerIndex
        let available = consumed.readableBytes
        while true {
            // Decided on the first byte, not the first five. A protocol that
            // sends one byte and waits for an answer is not TLS, and holding it
            // for four more would stall it until the deadline.
            if nextRecord == 0, available > 0, consumed.getInteger(at: base, as: UInt8.self) != 0x16 {
                return .notTLS
            }
            guard nextRecord + 5 <= Self.maximumRecordBytes else { return .unreadable(.malformed) }
            guard available - nextRecord >= 5 else { return .needMore }
            // Any record type other than handshake before the hello is whole is
            // something no client sends. The first record already passed the
            // check above, so this can only be a later one.
            guard consumed.getInteger(at: base + nextRecord, as: UInt8.self) == 0x16,
                let length = consumed.getInteger(at: base + nextRecord + 3, as: UInt16.self).map(Int.init),
                // A zero-length handshake record is forbidden (RFC 8446 §5.1).
                length > 0, length <= Self.maximumRecord,
                nextRecord + 5 + length <= Self.maximumRecordBytes
            else { return .unreadable(.malformed) }
            guard available - nextRecord - 5 >= length else { return .needMore }
            message += consumed.getBytes(at: base + nextRecord + 5, length: length) ?? []
            nextRecord += 5 + length

            guard message.count >= 4 else { continue }
            guard message[0] == 0x01 else { return .unreadable(.malformed) }
            let helloLength = 4 + (Int(message[1]) << 16 | Int(message[2]) << 8 | Int(message[3]))
            guard helloLength <= Self.maximumHello else { return .unreadable(.malformed) }
            if message.count >= helloLength {
                return Self.serverName(in: message[4..<helloLength])
            }
        }
    }

    /// Walks a complete ClientHello body to its `server_name` extension. Every
    /// length is checked against what is left, because the guest chose them.
    static func serverName(in body: ArraySlice<UInt8>) -> Outcome {
        var hello = Cursor(body)
        // legacy_version, random, legacy_session_id, cipher_suites,
        // legacy_compression_methods.
        guard hello.skip(2 + 32),
            let session = hello.byte(), hello.skip(Int(session)),
            let suites = hello.uint16(), hello.skip(Int(suites)),
            let compression = hello.byte(), hello.skip(Int(compression))
        else { return .unreadable(.malformed) }
        // No extensions at all is legal before TLS 1.3, and it is nameless.
        guard let extensionsLength = hello.uint16() else { return .noServerName }
        guard var extensions = hello.take(Int(extensionsLength)) else { return .unreadable(.malformed) }
        // Every extension is walked, not just up to the first `server_name`. A
        // hello with two is forbidden (RFC 8446 §4.2), and judging the first
        // while an upstream honours the second would let the guest pick the
        // name the policy sees.
        var serverNameExtension: Cursor?
        while extensions.remaining >= 4 {
            let type = extensions.uint16()!
            let length = extensions.uint16()!
            guard let body = extensions.take(Int(length)) else { return .unreadable(.malformed) }
            guard type == 0 else { continue }
            guard serverNameExtension == nil else { return .unreadable(.malformed) }
            serverNameExtension = body
        }
        guard var body = serverNameExtension else { return .noServerName }
        return hostName(in: &body)
    }

    /// The one `host_name` in a `server_name` extension (RFC 6066 §3). A second
    /// is forbidden by the same section, and refused for the same reason as a
    /// second extension.
    private static func hostName(in body: inout Cursor) -> Outcome {
        guard let listLength = body.uint16(), var list = body.take(Int(listLength)) else {
            return .unreadable(.malformed)
        }
        var hostName: Cursor?
        while list.remaining >= 3 {
            let type = list.byte()!
            let length = list.uint16()!
            guard let name = list.take(Int(length)) else { return .unreadable(.malformed) }
            // 0 is host_name, and no other type has ever been defined.
            guard type == 0 else { continue }
            guard hostName == nil else { return .unreadable(.malformed) }
            hostName = name
        }
        guard let name = hostName else { return .noServerName }
        var bytes = name.bytes
        if bytes.last == UInt8(ascii: ".") { bytes = bytes.dropLast() }
        // Empty is treated as absent, as the Go patch does.
        guard !bytes.isEmpty else { return .noServerName }
        // RFC 6066 makes a host_name an ASCII DNS name. A NUL, a space or a
        // byte over 0x7E is not one, and a policy that matches suffixes
        // should not be handed "evil\0.allowed.example" to judge.
        guard bytes.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { return .unreadable(.malformed) }
        return .serverName(String(decoding: bytes, as: UTF8.self).lowercased())
    }

    private struct Cursor {
        var bytes: ArraySlice<UInt8>
        init(_ bytes: ArraySlice<UInt8>) { self.bytes = bytes }
        var remaining: Int { bytes.count }

        mutating func byte() -> UInt8? {
            guard let first = bytes.first else { return nil }
            bytes = bytes.dropFirst()
            return first
        }

        mutating func uint16() -> UInt16? {
            guard bytes.count >= 2 else { return nil }
            let value = UInt16(bytes[bytes.startIndex]) << 8 | UInt16(bytes[bytes.startIndex + 1])
            bytes = bytes.dropFirst(2)
            return value
        }

        mutating func skip(_ count: Int) -> Bool {
            guard bytes.count >= count else { return false }
            bytes = bytes.dropFirst(count)
            return true
        }

        mutating func take(_ count: Int) -> Cursor? {
            guard bytes.count >= count else { return nil }
            defer { bytes = bytes.dropFirst(count) }
            return Cursor(bytes.prefix(count))
        }
    }
}

/// Holds a guest's first bytes on an inspected port until the ClientHello in
/// them can be judged, then passes them on or refuses the connection.
///
/// Installed ahead of the splice's `GlueHandler`, so nothing reaches the
/// upstream before `judge` has answered. On a pass the held bytes go on as one
/// read, followed by any FIN that arrived while they were held, and this
/// handler removes itself. After that the splice is exactly what it would have
/// been without inspection. On a refusal the bytes are dropped and `refuse`
/// runs.
///
/// While holding, this asks for reads itself rather than leaving it to the glue.
/// The glue only asks when the upstream is writable, and the upstream has been
/// sent nothing. What bounds the reading is the reassembler, which gives up at
/// 32 KiB.
final class ClientHelloInspector: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private enum State {
        case holding
        case passing
        case dropping
    }

    private var state = State.holding
    private var reassembler = ClientHelloReassembler()
    private var heldInputClosed = false
    private var deadline: Scheduled<Void>?
    private var context: ChannelHandlerContext?

    private let timeout: TimeAmount
    private let schedule: (TimeAmount, @escaping () -> Void) -> Scheduled<Void>
    private let judge: (ClientHelloReassembler.Outcome) -> Bool
    private let refuse: () -> Void

    /// - Parameters:
    ///   - timeout: how long the guest has to send a complete hello, from when
    ///     this is added.
    ///   - schedule: how the deadline is set. The forwarder passes the guest
    ///     endpoint's, so it runs on the stack's clock (conventions rule 2).
    ///   - judge: `true` to pass the connection on. Called at most once, and
    ///     never with `.needMore`.
    ///   - refuse: ends the connection. Called at most once, after `judge` has
    ///     said `false`.
    init(
        timeout: TimeAmount, schedule: @escaping (TimeAmount, @escaping () -> Void) -> Scheduled<Void>,
        judge: @escaping (ClientHelloReassembler.Outcome) -> Bool, refuse: @escaping () -> Void
    ) {
        self.timeout = timeout
        self.schedule = schedule
        self.judge = judge
        self.refuse = refuse
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        deadline = schedule(timeout) { [weak self] in
            self?.conclude(.unreadable(.timedOut))
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        deadline?.cancel()
        deadline = nil
        self.context = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch state {
        case .holding:
            let outcome = reassembler.feed(unwrapInboundIn(data))
            if outcome != .needMore { conclude(outcome) }
        case .passing:
            context.fireChannelRead(data)
        case .dropping:
            break
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        switch state {
        case .holding: context.read()
        case .passing: context.fireChannelReadComplete()
        case .dropping: break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard case ChannelEvent.inputClosed = event else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        switch state {
        case .holding:
            // The guest has finished sending, so the hello is as complete as it
            // will ever be. Held rather than passed, because the glue would pass
            // the FIN upstream ahead of the bytes this is still holding.
            heldInputClosed = true
            conclude(reassembler.streamEnded())
        case .passing:
            context.fireUserInboundEventTriggered(event)
        case .dropping:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        // The guest is gone, so nothing is left to judge or send. What was held
        // is dropped, and the glue closes the upstream.
        if state == .holding {
            state = .dropping
            deadline?.cancel()
            deadline = nil
        }
        context.fireChannelInactive()
    }

    private func conclude(_ outcome: ClientHelloReassembler.Outcome) {
        guard state == .holding, let context else { return }
        deadline?.cancel()
        deadline = nil
        let held = reassembler.consumed
        reassembler = ClientHelloReassembler()
        guard judge(outcome) else {
            state = .dropping
            refuse()
            return
        }
        state = .passing
        if held.readableBytes > 0 {
            context.fireChannelRead(wrapInboundOut(held))
            context.fireChannelReadComplete()
        }
        if heldInputClosed {
            context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        }
        context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
    }
}
