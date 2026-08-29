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
        try? FileManager.default.removeItem(atPath: path)
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
                return channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(ControlPlaneHandler(plane: self))
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

        case (.GET, "/leases"):
            // Upstream's, and the one a caller needs to find a guest before it
            // can forward a port to it.
            let leases = gateway.dhcp.allLeases.map { "\"\($0.value.description)\":\"\($0.key.description)\"" }.sorted()
            return loop.makeSucceededFuture((.ok, "{" + leases.joined(separator: ",") + "}"))

        case (.GET, "/services/forwarder/all"):
            let ports = gateway.forwardedPorts
            let json = "[" + ports.map { "{\"local\":\":\($0)\"}" }.joined(separator: ",") + "]"
            return loop.makeSucceededFuture((.ok, json))

        case (.POST, "/services/forwarder/expose"):
            guard let body, let request = ExposeRequest(body) else {
                return loop.makeSucceededFuture(
                    (.badRequest, "{\"error\":\"expected local and remote as host:port\"}"))
            }
            return gateway.forward(
                hostPort: request.hostPort, toGuest: request.guestAddress, port: request.guestPort,
                host: request.hostInterface
            ).map { forwarder -> (status: HTTPResponseStatus, body: String) in
                let bound = forwarder.listeningAddress?.port ?? request.hostPort
                return (.ok, "{\"local\":\":\(bound)\"}")
            }.flatMapError { error in
                loop.makeSucceededFuture((.conflict, "{\"error\":\"\(error)\"}"))
            }

        case (.POST, "/services/forwarder/unexpose"):
            guard let body, let port = UnexposeRequest(body)?.hostPort else {
                return loop.makeSucceededFuture((.badRequest, "{\"error\":\"expected local as :port\"}"))
            }
            guard gateway.stopForwarding(hostPort: port) else {
                return loop.makeSucceededFuture(
                    (.notFound, "{\"error\":\"no forward on port \(port)\"}"))
            }
            return loop.makeSucceededFuture((.ok, "{}"))

        default:
            return loop.makeSucceededFuture((.notFound, "{\"error\":\"no such route\"}"))
        }
    }
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
            let name = fields["name"] as? String
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
        for entry in (fields["records"] as? [[String: Any]]) ?? [] {
            guard let recordName = entry["name"] as? String, !recordName.isEmpty else { return nil }
            let address = (entry["ip"] as? String).flatMap(IPv4Address.init)
            let pattern = entry["regexp"] as? String
            guard address != nil || pattern != nil else { return nil }
            records.append(
                DNSServer.Zone.Record(name: recordName, address: address, pattern: pattern))
        }
        let defaultAddress = (fields["defaultIP"] as? String).flatMap(IPv4Address.init)
        guard !records.isEmpty || defaultAddress != nil else { return nil }
        zone = DNSServer.Zone(name: trimmed, records: records, defaultAddress: defaultAddress)
    }
}

/// `{"local": ":8080", "remote": "192.168.127.2:80"}`, in upstream's shape.
private struct ExposeRequest {
    let hostInterface: String
    let hostPort: Int
    let guestAddress: IPv4Address
    let guestPort: UInt16

    init?(_ body: ByteBuffer) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(body.readableBytesView)),
            let fields = object as? [String: Any],
            let local = fields["local"] as? String, let remote = fields["remote"] as? String
        else { return nil }
        // `":8080"` means loopback, `"0.0.0.0:8080"` means everywhere. The empty
        // host is upstream's spelling and it is also the safe one, which is why
        // it maps to loopback rather than to the wildcard.
        guard let (host, port) = ExposeRequest.split(local), let hostPort = Int(port), hostPort >= 0,
            hostPort <= 65535
        else { return nil }
        guard let (guestHost, guestPort) = ExposeRequest.split(remote),
            let address = IPv4Address(guestHost), let guest = UInt16(guestPort)
        else { return nil }
        hostInterface = host.isEmpty ? "127.0.0.1" : host
        self.hostPort = hostPort
        guestAddress = address
        self.guestPort = guest
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

/// `{"local": ":8080"}`.
private struct UnexposeRequest {
    let hostPort: Int

    init?(_ body: ByteBuffer) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(body.readableBytesView)),
            let fields = object as? [String: Any],
            let local = fields["local"] as? String,
            let (_, port) = ExposeRequest.split(local), let hostPort = Int(port)
        else { return nil }
        self.hostPort = hostPort
    }
}

private final class ControlPlaneHandler: ChannelInboundHandler, @unchecked Sendable {
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
            plane.handle(method: head.method, path: head.uri, body: body).whenSuccess { outcome in
                // Written through the CHANNEL rather than the context: the
                // answer arrives after the read that provoked it has returned,
                // and a handler context is not valid to hold across that.
                ControlPlaneHandler.respond(on: channel, status: outcome.status, json: outcome.body)
            }
        }
    }

    private func respond(context: ChannelHandlerContext, status: HTTPResponseStatus, json: String) {
        Self.respond(on: context.channel, status: status, json: json)
    }

    private static func respond(on channel: Channel, status: HTTPResponseStatus, json: String) {
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
        channel.write(HTTPServerResponsePart.head(
            HTTPResponseHead(version: .http1_1, status: status, headers: headers)), promise: nil)
        channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
        let flushed = channel.eventLoop.makePromise(of: Void.self)
        flushed.futureResult.whenComplete { _ in channel.close(promise: nil) }
        channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: flushed)
    }
}
