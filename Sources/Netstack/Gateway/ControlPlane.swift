import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

/// The HTTP API upstream exposes for managing port forwards while the gateway
/// is running.
///
/// Three routes, and the paths are upstream's so that a tool written against
/// `gvproxy` works here unchanged:
///
/// - `GET /services/forwarder/all` — the ports currently published.
/// - `POST /services/forwarder/expose` — `{"local": ":8080", "remote": "192.168.127.2:80"}`
/// - `POST /services/forwarder/unexpose` — `{"local": ":8080"}`
///
/// ## Why this listens on a unix socket by default
///
/// Anything that can reach this API can publish any guest port on the host, and
/// can publish it to the whole network by asking. A TCP default would put that
/// behind nothing but a port number; a unix socket puts it behind the
/// filesystem, where an operator can see and set who may use it. Upstream binds
/// a unix socket for the same reason.
///
/// A caller that wants it on TCP can say so, and should think about who else is
/// on that interface first.
///
/// ## What bounds a request
///
/// - **The body is capped.** A request body is chosen by whatever can reach the
///   socket, and a handler that accumulates until the end of a request will
///   accumulate whatever it is sent. Past the cap the connection is answered and
///   closed rather than read further.
/// - **Nothing is parsed before the route matches.** An unknown path is answered
///   404 without its body being kept, so the cheapest thing to send is also the
///   cheapest thing to answer.
public final class ControlPlane: @unchecked Sendable {
    /// The largest request body this will assemble. Generous for the JSON these
    /// routes take -- the longest legitimate one is under a hundred bytes -- and
    /// small enough that a thousand concurrent requests are megabytes rather
    /// than gigabytes.
    public static let maximumBodyBytes = 16 * 1024

    private let gateway: Gateway
    private var channel: Channel?

    /// The framing a guest joining over `/connect` speaks.
    ///
    /// Upstream's default is hyperkit's two-byte little-endian length, which is
    /// what its own `cmd/vm` writes, so that is the default here. Nothing on the
    /// wire says which framing is in use -- a mismatch shows up as a frame that
    /// claims an impossible length -- so this has to agree with the client out
    /// of band.
    public var connectFraming: StreamFraming = .hyperkit

    /// How long a connection may go without completing a request.
    ///
    /// A peer that opens a connection and sends half a request holds it forever
    /// otherwise: the framer is waiting for the rest of the headers and the peer
    /// is waiting for an answer, and neither is wrong. This package claims every
    /// reachable resource is bounded, and a connection held open is a resource.
    ///
    /// It applies until the request is answered, not to the connection's whole
    /// life -- `/tunnel` and `/connect` hand the connection to the network and
    /// it is expected to stay open for as long as the guest is there.
    public var requestTimeout: TimeAmount = .seconds(10)

    /// Whether `/connect` has anywhere to put a guest.
    fileprivate var gatewayHasSwitch: Bool { gateway.networkSwitch != nil }

    /// Whether this endpoint will attach a guest at all.
    ///
    /// Upstream publishes two endpoints from one API: `--listen`, which can do
    /// everything, and `--services`, which is the same API "without the
    /// /connect endpoint". The difference is who is on the other end. A guest
    /// may be given the services endpoint so it can publish its own ports; a
    /// guest that could also reach `/connect` could put another guest on the
    /// network, which is a different privilege entirely.
    public var allowsGuestAttach = true

    public init(gateway: Gateway) {
        self.gateway = gateway
    }

    /// Listen on a unix socket at `path`.
    ///
    /// An existing socket file at that path is removed first. That is the
    /// conventional behaviour for a unix-socket server and it is also a small
    /// hazard worth naming: the path is deleted before it is bound, so pointing
    /// this at a path holding something other than a stale socket deletes it.
    public func listen(unixSocketPath path: String) -> EventLoopFuture<Void> {
        removeStaleSocket(at: path)
        return bootstrap().bind(unixDomainSocketPath: path).map { [weak self] channel in
            self?.channel = channel
        }
    }

    /// Listen on TCP. Defaults to loopback for the reason the type comment
    /// gives; passing anything else is a decision about who may publish guest
    /// ports.
    public func listen(host: String = "127.0.0.1", port: Int) -> EventLoopFuture<Void> {
        bootstrap().bind(host: host, port: port).map { [weak self] channel in
            self?.channel = channel
        }
    }

    /// Where the listener ended up, which is how a caller learns the port when
    /// it asked for zero.
    public var listeningAddress: SocketAddress? { channel?.localAddress }

    public func close() {
        channel?.close(promise: nil)
        channel = nil
    }

    private func bootstrap() -> ServerBootstrap {
        ServerBootstrap(group: gateway.eventLoop)
            .serverChannelOption(.backlog, value: 32)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [weak self] channel in
                guard let self else { return channel.close() }
                // Named handlers rather than `configureHTTPServerPipeline`,
                // because `/tunnel` and `/connect` take the connection away from
                // HTTP and hand it to the network -- and removing handlers by
                // name is the only way to do that without knowing what a
                // convenience method happened to install.
                //
                // Added through `syncOperations` on the channel's own loop, the
                // way `WireBootstrap.configure` does: NIO's HTTP handlers are
                // not `Sendable`, so chaining `addHandler` futures would carry
                // them across a boundary the compiler is right to object to.
                return channel.eventLoop.submit {
                    let sync = channel.pipeline.syncOperations
                    try sync.addHandler(
                        IdleStateHandler(readTimeout: self.requestTimeout), name: Self.idleName)
                    try sync.addHandler(HTTPMessageFramer(), name: Self.framerName)
                    try sync.addHandler(HTTPResponseEncoder(), name: Self.encoderName)
                    try sync.addHandler(
                        ByteToMessageHandler(HTTPRequestDecoder()), name: Self.decoderName)
                    try sync.addHandler(ControlPlaneHandler(plane: self), name: Self.handlerName)
                }
            }
    }

    static let idleName = "netstack.http.idle"
    static let framerName = "netstack.http.framer"
    static let encoderName = "netstack.http.encoder"
    static let decoderName = "netstack.http.decoder"
    static let handlerName = "netstack.control"

    // MARK: Hijacking

    /// Take a connection away from HTTP and give it to the network.
    ///
    /// Upstream calls this hijacking, and both of its raw endpoints need it:
    /// `/tunnel` splices the connection to a guest's port, and `/connect` makes
    /// it a port on the switch. Neither can be expressed as a request and a
    /// response, because after the handshake the bytes are not HTTP any more.
    ///
    /// ## Why this is not three `removeHandler` calls
    ///
    /// A client with no reason to wait writes its request and its first frame in
    /// one call, and both arrive in one read. `ByteToMessageHandler` decodes the
    /// whole buffer in that one `channelRead`: it finishes the request, then
    /// carries straight on and tries to parse the frame as a *second* HTTP
    /// request. Removals scheduled from here are futures and land a tick later,
    /// by which time the frame is gone -- consumed as a malformed request.
    ///
    /// So the decoder's removal is started first and synchronously, which stops
    /// it decoding further and makes it forward what it has not parsed. Those
    /// bytes arrive at `ControlPlaneHandler`, which is still in the pipeline and
    /// buffers them; once the wire handlers are in, it replays them forward and
    /// removes itself.
    ///
    /// Upstream has the same race and loses the same frame: Go's `Hijack` hands
    /// back a `bufrw` holding the buffered read bytes, and upstream uses the raw
    /// `conn` instead -- so anything already buffered is dropped. Nothing errors
    /// either way. The guest has simply sent a DISCOVER that never arrived and,
    /// DHCP being what it is, waits seconds before trying again.
    fileprivate func hijack(
        _ channel: Channel, carrying framer: HTTPMessageFramer,
        then install: @escaping @Sendable (Channel) -> EventLoopFuture<Void>
    ) {
        let pipeline = channel.pipeline
        // Decoder first, and its removal is what stops the parse. The encoder
        // next, because everything written from here is raw bytes and
        // `HTTPResponseEncoder` would be handed a `ByteBuffer` where it expects
        // an `HTTPServerResponsePart`.
        // The idle handler goes too: `/tunnel` and `/connect` hand the
        // connection to the network, where a guest that is quiet for ten seconds
        // is an ordinary guest rather than a stalled request.
        pipeline.removeHandler(name: Self.idleName)
            .flatMap { pipeline.removeHandler(name: Self.handlerName) }
            .flatMap { pipeline.removeHandler(name: Self.decoderName) }
            .flatMap { pipeline.removeHandler(name: Self.encoderName) }
            // `install` returns a future because building a wire adds its
            // handlers on a later tick; not awaiting it would replay the guest's
            // first frame into a pipeline that cannot yet read it.
            .flatMap { install(channel) }
            .flatMap { framer.replayAndRemove() }
            .whenComplete { outcome in
                switch outcome {
                case .failure: channel.close(promise: nil)
                // Reads were held while the pipeline was rebuilt; whatever
                // `install` put in owns them from here.
                case .success: channel.read()
                }
            }
    }

    /// `GET /tunnel?ip=<guest>&port=<port>`: splice this connection to a guest.
    ///
    /// A port forward for one connection and without a listener. `expose`
    /// publishes a host port and leaves it published; this is for a caller that
    /// already has a connection and wants it carried, which is how upstream's
    /// own ssh client reaches a guest.
    fileprivate func tunnel(
        _ channel: Channel, carrying framer: HTTPMessageFramer, to address: IPv4Address, port: UInt16
    ) {
        hijack(channel, carrying: framer) { [weak self] channel -> EventLoopFuture<Void> in
            guard let self else { return channel.eventLoop.makeFailedFuture(StackError.notConnected) }
            // Upstream writes a bare `OK` -- not an HTTP response, because the
            // connection stopped being HTTP a moment ago. A client waits for it
            // before sending, so it has to come before the splice.
            var acknowledgement = channel.allocator.buffer(capacity: 2)
            acknowledgement.writeString("OK")
            return channel.writeAndFlush(acknowledgement).flatMapThrowing {
                guard
                    GuestSplice.connect(
                        stack: self.gateway.stack, host: channel, to: address, port: port,
                        keepAlive: nil) != nil
                else { throw StackError.notConnected }
            }
        }
    }

    /// `POST /connect`: make this connection a port on the switch.
    ///
    /// How a guest joins a network it can reach only over this socket --
    /// upstream's `cmd/vm` does exactly this. It needs a switch: a gateway on a
    /// single wire has one guest already and nowhere to put a second.
    fileprivate func connectGuest(
        _ channel: Channel, carrying framer: HTTPMessageFramer, framing: StreamFraming
    ) {
        guard let netSwitch = gateway.networkSwitch else {
            channel.close(promise: nil)
            return
        }
        hijack(channel, carrying: framer) { channel -> EventLoopFuture<Void> in
            WireBootstrap.configure(
                channel: channel, linkAddress: netSwitch.linkAddress, mtu: netSwitch.mtu,
                framed: true, framing: framing
            ).map { link in
                let id = netSwitch.addPort(link)
                channel.closeFuture.whenComplete { _ in _ = netSwitch.removePort(id) }
            }
        }
    }

    // MARK: Routes

    /// Answers a request, asynchronously.
    ///
    /// A future rather than a value because `expose` binds a listener, and a
    /// bind is asynchronous. Answering synchronously would mean waiting on it --
    /// **on the event loop**, which NIO traps rather than deadlocking, and
    /// rightly. The caller is told the port is published only once it is:
    /// answering "done" before the bind completes would report success for a
    /// port that may fail to bind a millisecond later, with nowhere for the
    /// caller to learn that.
    fileprivate func handle(
        method: HTTPMethod, path: String, body: ByteBuffer?
    ) -> EventLoopFuture<(status: HTTPResponseStatus, body: String)> {
        let loop = gateway.eventLoop
        switch (method, path) {
        case (.GET, "/stats"):
            // Read on the gateway's own loop, which `handle` is already on, so
            // the numbers in one response are numbers that coexisted. See
            // `Gateway.Statistics`.
            return loop.makeSucceededFuture((.ok, gateway.statisticsOnLoop().json))

        case (.GET, "/services/dns/all"):
            let zones = gateway.dns.allZones.map { zone -> String in
                let records = zone.records.map { record -> String in
                    var fields = ["\"name\":\"\(record.name)\""]
                    if let address = record.address { fields.append("\"ip\":\"\(address)\"") }
                    if let pattern = record.pattern {
                        fields.append("\"regexp\":\"\(ControlPlane.escaped(pattern))\"")
                    }
                    return "{" + fields.joined(separator: ",") + "}"
                }
                var fields = ["\"name\":\"\(zone.name)\"", "\"records\":[" + records.joined(separator: ",") + "]"]
                if let address = zone.defaultAddress { fields.append("\"defaultIP\":\"\(address)\"") }
                fields.append("\"protected\":\(zone.isProtected)")
                return "{" + fields.joined(separator: ",") + "}"
            }
            return loop.makeSucceededFuture((.ok, "[" + zones.joined(separator: ",") + "]"))

        case (.POST, "/services/dns/add"):
            guard let body, let zone = ZoneRequest(body)?.zone else {
                return loop.makeSucceededFuture(
                    (.badRequest, "{\"error\":\"expected a zone with a name and at least one record or a defaultIP\"}"))
            }
            guard gateway.dns.addZone(zone) else {
                // The only refusal. A protected zone is one the gateway's own
                // configuration created, and the guests were pointed at it.
                return loop.makeSucceededFuture(
                    (.conflict, "{\"error\":\"cannot modify protected zone \(zone.name)\"}"))
            }
            return loop.makeSucceededFuture((.ok, "{}"))

        case (.GET, "/cam"):
            // Upstream serves the switch's learned address table here. A gateway
            // on a single wire has no switch and no table, and says so with an
            // empty object rather than a 404: the route exists, the table is
            // empty, and a tool polling it should not have to tell those apart.
            let table = gateway.networkSwitch?.addressTable ?? [:]
            let entries = table.map { "\"\($0.key.description)\":\($0.value)" }.sorted()
            return loop.makeSucceededFuture((.ok, "{" + entries.joined(separator: ",") + "}"))

        // Both spellings, because upstream serves both: `/leases` at the top
        // level and `/services/dhcp/leases` under the services mux -- and its
        // own client library calls the second. A gateway that served only the
        // first would be one that `pkg/client` cannot talk to, which is a
        // narrow and very concrete definition of not being a port.
        case (.GET, "/leases"), (.GET, "/services/dhcp/leases"):
            // Upstream's, and the one a caller needs to find a guest before it
            // can forward a port to it.
            let leases = gateway.dhcp.allLeases.map { "\"\($0.value.description)\":\"\($0.key.description)\"" }.sorted()
            return loop.makeSucceededFuture((.ok, "{" + leases.joined(separator: ",") + "}"))

        case (.GET, "/services/forwarder/all"):
            // Each entry names its protocol, because a host port is only unique
            // within one: 8080/tcp and 8080/udp are different forwards and both
            // may be published at once. Upstream's own listing carries the same
            // field for the same reason.
            var entries = gateway.forwardedPorts.map { "{\"local\":\":\($0)\",\"protocol\":\"tcp\"}" }
            entries += gateway.forwardedUDPPorts.map { "{\"local\":\":\($0)\",\"protocol\":\"udp\"}" }
            entries += gateway.forwardedUnixPaths.map {
                "{\"local\":\"\(ControlPlane.escaped($0))\",\"protocol\":\"unix\"}"
            }
            return loop.makeSucceededFuture((.ok, "[" + entries.joined(separator: ",") + "]"))

        case (.POST, "/services/forwarder/expose"):
            guard let body, let request = ExposeRequest(body) else {
                return loop.makeSucceededFuture(
                    (.badRequest, "{\"error\":\"expected local and remote as host:port\"}"))
            }
            switch request.transport {
            case .tcp:
                return gateway.forward(
                    hostPort: request.hostPort, toGuest: request.guestAddress, port: request.guestPort,
                    host: request.hostInterface
                ).map { forwarder -> (status: HTTPResponseStatus, body: String) in
                    let bound = forwarder.listeningAddress?.port ?? request.hostPort
                    return (.ok, "{\"local\":\":\(bound)\",\"protocol\":\"tcp\"}")
                }.flatMapError { error in
                    loop.makeSucceededFuture((.conflict, "{\"error\":\"\(error)\"}"))
                }
            case .udp:
                return gateway.forwardUDP(
                    hostPort: request.hostPort, toGuest: request.guestAddress, port: request.guestPort,
                    host: request.hostInterface
                ).map { forwarder -> (status: HTTPResponseStatus, body: String) in
                    let bound = forwarder.listeningAddress?.port ?? request.hostPort
                    return (.ok, "{\"local\":\":\(bound)\",\"protocol\":\"udp\"}")
                }.flatMapError { error in
                    loop.makeSucceededFuture((.conflict, "{\"error\":\"\(error)\"}"))
                }
            case .unix:
                return gateway.forward(
                    unixSocketPath: request.socketPath, toGuest: request.guestAddress,
                    port: request.guestPort
                ).map { _ -> (status: HTTPResponseStatus, body: String) in
                    (.ok, "{\"local\":\"\(ControlPlane.escaped(request.socketPath))\",\"protocol\":\"unix\"}")
                }.flatMapError { error in
                    loop.makeSucceededFuture((.conflict, "{\"error\":\"\(error)\"}"))
                }
            }

        case (.POST, "/services/forwarder/unexpose"):
            guard let body, let request = UnexposeRequest(body) else {
                return loop.makeSucceededFuture((.badRequest, "{\"error\":\"expected local as :port\"}"))
            }
            // Dispatched on the protocol, because a host port is only unique
            // within one: withdrawing ":8080" without saying which would take
            // down whichever table happened to be looked at first.
            let stopped: Bool
            switch request.transport {
            case .tcp: stopped = gateway.stopForwarding(hostPort: request.hostPort)
            case .udp: stopped = gateway.stopForwardingUDP(hostPort: request.hostPort)
            case .unix: stopped = gateway.stopForwarding(unixSocketPath: request.socketPath)
            }
            guard stopped else {
                return loop.makeSucceededFuture(
                    (
                        .notFound,
                        "{\"error\":\"no \(request.transport.rawValue) forward on \(ControlPlane.escaped(request.local))\"}"
                    ))
            }
            return loop.makeSucceededFuture((.ok, "{}"))

        default:
            return loop.makeSucceededFuture((.notFound, "{\"error\":\"no such route\"}"))
        }
    }
}

/// A JSON object field, found however it was capitalised.
///
/// Go's `encoding/json` matches field names case-insensitively, and upstream's
/// `types.Zone` carries no json tags at all -- so its own client sends `Name`,
/// `Records`, `IP` and `DefaultIP`, while its YAML config and its documentation
/// use `name`, `records`, `ip` and `defaultIP`. Both are the same request to
/// upstream and only one of them was to this, which meant `pkg/client` could
/// read from this gateway and not write to it.
///
/// Matching the reference implementation's leniency is the interoperable
/// choice, and it is leniency about spelling rather than about meaning: an
/// unknown field is still ignored and a missing one is still an error.
public func jsonField(_ fields: [String: Any], _ name: String) -> Any? {
    if let exact = fields[name] { return exact }
    let wanted = name.lowercased()
    for (key, value) in fields where key.lowercased() == wanted { return value }
    return nil
}

extension ControlPlane {
    /// Enough JSON string escaping for the values this API emits, which are
    /// names and patterns rather than arbitrary text. Quotes and backslashes
    /// because they end the string, and control characters because a name that
    /// carried one would produce output no parser has to accept.
    fileprivate static func escaped(_ text: String) -> String {
        var out = String()
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}

/// `{"name": "my.zone.", "records": [{"name": "host", "ip": "1.2.3.4"}], "defaultIP": "1.2.3.4"}`
/// -- upstream's `types.Zone` on the wire.
private struct ZoneRequest {
    let zone: DNSServer.Zone

    init?(_ body: ByteBuffer) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(body.readableBytesView)),
            let fields = object as? [String: Any],
            let name = jsonField(fields, "name") as? String
        else { return nil }
        // Upstream's validation, and each rule is one an operator can hit by
        // accident: the root zone would make this gateway authoritative for the
        // whole internet, and a zone with neither records nor a default answers
        // NXDOMAIN for everything under it -- which is a way to break name
        // resolution that looks like a way to configure it.
        var trimmed = name.lowercased()
        while trimmed.hasSuffix(".") { trimmed.removeLast() }
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" })
        else { return nil }

        var records: [DNSServer.Zone.Record] = []
        for entry in (jsonField(fields, "records") as? [[String: Any]]) ?? [] {
            guard let recordName = jsonField(entry, "name") as? String, !recordName.isEmpty else { return nil }
            let address = (jsonField(entry, "ip") as? String).flatMap(IPv4Address.init)
            let pattern = jsonField(entry, "regexp") as? String
            guard address != nil || pattern != nil else { return nil }
            records.append(
                DNSServer.Zone.Record(name: recordName, address: address, pattern: pattern))
        }
        let defaultAddress = (jsonField(fields, "defaultIP") as? String).flatMap(IPv4Address.init)
        guard !records.isEmpty || defaultAddress != nil else { return nil }
        zone = DNSServer.Zone(name: trimmed, records: records, defaultAddress: defaultAddress)
    }
}

/// Forwards exactly one HTTP message to the decoder and holds everything after
/// it.
///
/// ## Why the HTTP decoder cannot be trusted with those bytes
///
/// A client with no reason to wait writes its request and its first ethernet
/// frame in one call, and both arrive in one read. `ByteToMessageHandler` hands
/// the whole buffer to llhttp in a single pass: llhttp finishes the request,
/// fires `.end`, and then -- still inside that same call -- carries on into the
/// frame and fails with "invalid HTTP method". The bytes are consumed by the
/// failed parse.
///
/// Nothing downstream can prevent that. Removing the decoder from the handler
/// that receives `.end` is already too late, whether the removal is a future or
/// synchronous: llhttp is mid-pass and will not be interrupted. So the decoder
/// must never be given the bytes in the first place, which is what this does.
///
/// It frames rather than parses: everything up to and including the blank line
/// that ends the headers, then `Content-Length` bytes of body, and not one byte
/// more. What is left is the client's, held here until a hijack asks for it.
///
/// Upstream loses these bytes. Go's `Hijack` returns a `bufrw` holding whatever
/// was already buffered and upstream uses the raw `conn` instead, so a guest
/// that pipelines its first frame sends a DHCP DISCOVER that never arrives.
/// Nothing errors; the network simply takes a retransmit to come up.
///
/// Holding rather than forwarding also means this API cannot be
/// request-smuggled: a second request pipelined behind the first is never
/// parsed, and the connection closes after one answer.
final class HTTPMessageFramer: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private enum State {
        case headers
        case body(remaining: Int)
        /// A chunked body, whose end this does not attempt to find. See
        /// `advance`.
        case streaming
        case holding
    }

    private var state = State.headers
    private var pending = ByteBuffer()
    private var held: [ByteBuffer] = []
    private var context: ChannelHandlerContext?

    /// The most a request's headers may occupy before this gives up. The body
    /// has its own cap in `ControlPlaneHandler`; this one is about the bytes
    /// that arrive before anything has said how long the message is.
    static let maximumHeaderBytes = 16 * 1024

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        pending.writeBuffer(&incoming)
        advance(context: context)
    }

    private func advance(context: ChannelHandlerContext) {
        while true {
            switch state {
            case .headers:
                guard let end = Self.endOfHeaders(in: pending) else {
                    if pending.readableBytes > Self.maximumHeaderBytes { context.close(promise: nil) }
                    return
                }
                guard var headers = pending.readSlice(length: end) else { return }
                // A chunked body has no `Content-Length` and its end is only
                // findable by walking the chunks. Rather than write a second
                // chunked parser to sit in front of the one NIO already has --
                // two parsers that must agree is exactly the desync this type
                // exists to prevent -- everything after the headers is
                // forwarded and the decoder frames it.
                //
                // Holding is what `/tunnel` and `/connect` need, and neither is
                // ever sent chunked: they carry no body at all. What this gives
                // up is the anti-smuggling property for chunked requests, and it
                // is not given up to anything -- NIO's decoder frames them
                // correctly, which the previous behaviour did not let it do.
                // Before this, a chunked request hung: the framer forwarded the
                // headers, decided the body was empty, and held the chunks the
                // decoder was waiting for.
                if Self.isChunked(headers) {
                    state = .streaming
                    context.fireChannelRead(wrapInboundOut(headers))
                    headers.clear()
                    continue
                }
                let length = Self.contentLength(in: headers)
                state = length > 0 ? .body(remaining: length) : .holding
                context.fireChannelRead(wrapInboundOut(headers))
                headers.clear()
            case .body(let remaining):
                guard pending.readableBytes > 0 else { return }
                let take = min(remaining, pending.readableBytes)
                guard let chunk = pending.readSlice(length: take) else { return }
                state = take == remaining ? .holding : .body(remaining: remaining - take)
                context.fireChannelRead(wrapInboundOut(chunk))
            case .streaming:
                guard pending.readableBytes > 0 else { return }
                if let rest = pending.readSlice(length: pending.readableBytes) {
                    context.fireChannelRead(wrapInboundOut(rest))
                }
                return
            case .holding:
                // Whatever is left belongs to whoever hijacks this connection.
                if pending.readableBytes > 0, let rest = pending.readSlice(length: pending.readableBytes) {
                    held.append(rest)
                }
                pending.clear()
                return
            }
        }
    }

    /// The offset just past the blank line ending the headers, if it has
    /// arrived.
    private static func endOfHeaders(in buffer: ByteBuffer) -> Int? {
        let bytes = buffer.readableBytesView
        guard bytes.count >= 4 else { return nil }
        var index = bytes.startIndex
        let limit = bytes.index(bytes.endIndex, offsetBy: -4)
        while index <= limit {
            if bytes[index] == 0x0D, bytes[bytes.index(index, offsetBy: 1)] == 0x0A,
                bytes[bytes.index(index, offsetBy: 2)] == 0x0D,
                bytes[bytes.index(index, offsetBy: 3)] == 0x0A
            {
                return bytes.distance(from: bytes.startIndex, to: index) + 4
            }
            index = bytes.index(after: index)
        }
        return nil
    }

    /// Whether the request says its body is chunked.
    private static func isChunked(_ headers: ByteBuffer) -> Bool {
        let text = String(decoding: headers.readableBytesView, as: UTF8.self)
        for line in text.split(separator: "\r\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            guard line[line.startIndex..<colon].lowercased() == "transfer-encoding" else { continue }
            return line[line.index(after: colon)...].lowercased().contains("chunked")
        }
        return false
    }

    /// `Content-Length`, read case-insensitively from the header block. Absent
    /// or unparseable means no body, which for this API is the ordinary case.
    private static func contentLength(in headers: ByteBuffer) -> Int {
        let text = String(decoding: headers.readableBytesView, as: UTF8.self)
        for line in text.split(separator: "\r\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            guard line[line.startIndex..<colon].lowercased() == "content-length" else { continue }
            return Int(line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)) ?? 0
        }
        return 0
    }

    /// Hand the held bytes to whatever replaced HTTP, then leave.
    func replayAndRemove() -> EventLoopFuture<Void> {
        guard let context else {
            return MultiThreadedEventLoopGroup.singleton.any().makeSucceededVoidFuture()
        }
        let carried = held
        held.removeAll()
        for buffer in carried {
            context.fireChannelRead(wrapInboundOut(buffer))
        }
        if !carried.isEmpty { context.fireChannelReadComplete() }
        return context.pipeline.syncOperations.removeHandler(context: context)
    }
}

/// `?ip=192.168.127.2&port=22`, upstream's query for `/tunnel`.
private struct TunnelRequest {
    let address: IPv4Address
    let port: UInt16

    init?(_ query: String) {
        var fields: [String: String] = [:]
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            fields[String(parts[0])] = String(parts[1])
        }
        guard let ip = fields["ip"], let address = IPv4Address(ip),
            let text = fields["port"], let port = UInt16(text)
        else { return nil }
        self.address = address
        self.port = port
    }
}

/// The transports a forward can be published on. Upstream's
/// `types.TransportProtocol`, less `npipe`, which is a Windows named pipe and
/// has no meaning on the platforms this package targets.
enum ForwardTransport: String {
    case tcp
    case udp
    case unix
}

/// `{"local": ":8080", "remote": "192.168.127.2:80", "protocol": "tcp"}`, in
/// upstream's shape.
///
/// `protocol` is optional and defaults to `tcp`, which is upstream's default and
/// keeps every request written before this existed working unchanged.
private struct ExposeRequest {
    let transport: ForwardTransport
    let hostInterface: String
    let hostPort: Int
    /// For `unix`, `local` is a filesystem path rather than a host and port.
    let socketPath: String
    let guestAddress: IPv4Address
    let guestPort: UInt16

    init?(_ body: ByteBuffer) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(body.readableBytesView)),
            let fields = object as? [String: Any],
            let local = jsonField(fields, "local") as? String,
            let remote = jsonField(fields, "remote") as? String
        else { return nil }
        let transport = ForwardTransport(rawValue: (jsonField(fields, "protocol") as? String) ?? "tcp")
        guard let transport else { return nil }
        self.transport = transport

        guard let (guestHost, guestText) = ExposeRequest.split(remote),
            let address = IPv4Address(guestHost), let guest = UInt16(guestText)
        else { return nil }
        guestAddress = address
        guestPort = guest

        if transport == .unix {
            // A path, not an address. Rejected if it is empty or relative: a
            // relative path is resolved against whatever directory this process
            // happens to be in, which is not something the caller can know.
            guard local.hasPrefix("/") else { return nil }
            socketPath = local
            hostInterface = ""
            hostPort = 0
            return
        }
        socketPath = ""
        // `":8080"` means loopback, `"0.0.0.0:8080"` means everywhere. The empty
        // host is upstream's spelling and it is also the safe one, which is why
        // it maps to loopback rather than to the wildcard.
        guard let (host, port) = ExposeRequest.split(local), let hostPort = Int(port), hostPort >= 0,
            hostPort <= 65535
        else { return nil }
        hostInterface = host.isEmpty ? "127.0.0.1" : host
        self.hostPort = hostPort
    }

    /// Split on the LAST colon, so an address containing one is not cut in the
    /// middle. IPv6 is not supported here and this is not what would make it
    /// work, but splitting on the first colon would make the failure a wrong
    /// answer rather than a rejected one.
    static func split(_ text: String) -> (String, String)? {
        guard let separator = text.lastIndex(of: ":") else { return nil }
        return (String(text[text.startIndex..<separator]), String(text[text.index(after: separator)...]))
    }
}

/// `{"local": ":8080", "protocol": "tcp"}`.
private struct UnexposeRequest {
    let transport: ForwardTransport
    let hostPort: Int
    let socketPath: String
    let local: String

    init?(_ body: ByteBuffer) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(body.readableBytesView)),
            let fields = object as? [String: Any],
            let local = jsonField(fields, "local") as? String
        else { return nil }
        guard let transport = ForwardTransport(rawValue: (jsonField(fields, "protocol") as? String) ?? "tcp")
        else { return nil }
        self.transport = transport
        self.local = local
        if transport == .unix {
            guard local.hasPrefix("/") else { return nil }
            socketPath = local
            hostPort = 0
            return
        }
        socketPath = ""
        guard let (_, port) = ExposeRequest.split(local), let hostPort = Int(port) else { return nil }
        self.hostPort = hostPort
    }
}

private final class ControlPlaneHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private weak var plane: ControlPlane?
    private var head: HTTPRequestHead?
    private var body: ByteBuffer?
    /// Set when the body passed its cap. The rest of the request is read and
    /// discarded rather than the connection being dropped mid-request, so the
    /// client gets an answer it can act on.
    private var overlong = false

    init(plane: ControlPlane) {
        self.plane = plane
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            self.head = head
            body = nil
            overlong = false
        case .body(var chunk):
            guard !overlong else { return }
            if body == nil { body = context.channel.allocator.buffer(capacity: chunk.readableBytes) }
            guard (body?.readableBytes ?? 0) + chunk.readableBytes <= ControlPlane.maximumBodyBytes else {
                overlong = true
                body = nil
                return
            }
            body?.writeBuffer(&chunk)
        case .end:
            guard let head, let plane else { return }
            if overlong {
                respond(context: context, status: .payloadTooLarge, json: "{\"error\":\"request body too large\"}")
                return
            }
            let channel = context.channel
            // The hijacking routes are dispatched here rather than in `handle`,
            // because `handle` answers with a status and a body and these two do
            // neither: they take the connection off HTTP entirely.
            let path = head.uri.split(separator: "?", maxSplits: 1)
            switch String(path[0]) {
            case "/tunnel":
                let query = path.count > 1 ? String(path[1]) : ""
                guard let target = TunnelRequest(query) else {
                    respond(
                        context: context, status: .badRequest,
                        json: "{\"error\":\"tunnel wants ip and port\"}")
                    return
                }
                guard let framer = hijackFramer(context) else { return }
                plane.tunnel(channel, carrying: framer, to: target.address, port: target.port)
                return
            case "/connect":
                guard plane.allowsGuestAttach else {
                    respond(
                        context: context, status: .notFound,
                        json: "{\"error\":\"this endpoint does not attach guests\"}")
                    return
                }
                guard plane.gatewayHasSwitch else {
                    respond(
                        context: context, status: .conflict,
                        json: "{\"error\":\"this gateway is on a single wire and has no switch\"}")
                    return
                }
                guard let framer = hijackFramer(context) else { return }
                plane.connectGuest(channel, carrying: framer, framing: plane.connectFraming)
                return
            default:
                break
            }
            plane.handle(method: head.method, path: head.uri, body: body).whenSuccess { outcome in
                // Written through the CHANNEL rather than the context: the
                // answer arrives after the read that provoked it has returned,
                // and a handler context is not valid to hold across that.
                ControlPlaneHandler.respond(on: channel, status: outcome.status, json: outcome.body)
            }
        }
    }

    /// The framer at the head of this pipeline, which is holding whatever the
    /// client sent after its request.
    private func hijackFramer(_ context: ChannelHandlerContext) -> HTTPMessageFramer? {
        guard
            let found = try? context.pipeline.syncOperations.context(name: ControlPlane.framerName),
            let framer = found.handler as? HTTPMessageFramer
        else {
            context.close(promise: nil)
            return nil
        }
        return framer
    }

    /// Answer and close when the decoder rejects a request.
    ///
    /// Without this the connection is simply held: NIO's HTTP decoder throws,
    /// nothing responds, nothing closes, and the client waits forever. Every
    /// malformed request was therefore an unauthenticated way to occupy a
    /// connection to the control socket -- found by sending a `Content-Length`
    /// that is not a number, which is not an exotic thing to send.
    /// A connection that has gone quiet without completing a request.
    ///
    /// Answered rather than merely dropped, so a client learns why -- and closed,
    /// which is the part that matters: half a request otherwise holds a
    /// connection for as long as the peer cares to leave it open. A fuzzer found
    /// 59 of 160 mutated requests doing exactly that, nearly all of them simply
    /// truncated.
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard event is IdleStateHandler.IdleStateEvent else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        Self.respond(
            on: context.channel, status: .requestTimeout,
            json: "{\"error\":\"request was not completed in time\"}")
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        Self.respond(
            on: context.channel, status: .badRequest, json: "{\"error\":\"malformed request\"}")
    }

    private func respond(context: ChannelHandlerContext, status: HTTPResponseStatus, json: String) {
        Self.respond(on: context.channel, status: status, json: json)
    }

    fileprivate static func respond(on channel: Channel, status: HTTPResponseStatus, json: String) {
        var buffer = channel.allocator.buffer(capacity: json.utf8.count)
        buffer.writeString(json)
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Content-Length", value: String(buffer.readableBytes))
        // `Connection: close`, and one request per connection.
        //
        // Keep-alive would be free to implement and is deliberately not: this
        // API is used a handful of times over a gateway's life, and a connection
        // held open is a resource whose bound would then need thinking about.
        headers.add(name: "Connection", value: "close")
        channel.write(
            HTTPServerResponsePart.head(
                HTTPResponseHead(version: .http1_1, status: status, headers: headers)), promise: nil)
        channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
        let flushed = channel.eventLoop.makePromise(of: Void.self)
        flushed.futureResult.whenComplete { _ in channel.close(promise: nil) }
        channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: flushed)
    }
}
