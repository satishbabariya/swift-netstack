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
