import NIOCore
import NIOPosix

/// Something worth telling the process that started this gateway.
///
/// Upstream's `types.NotificationMessage`. The audience is a supervisor -- the
/// thing that launched the VM and wants to know when its network came up and
/// when a guest arrived or left -- rather than an operator reading logs, which
/// is why this exists alongside `RateLimitedLogger` rather than inside it.
public struct NetstackNotification: Sendable, Equatable {
    public enum Kind: String, Sendable {
        /// The gateway is assembled and serving.
        case ready
        /// A guest's hardware address was seen for the first time.
        case connectionEstablished = "connection_established"
        /// A guest went away, and everything learned on its port with it.
        case connectionClosed = "connection_closed"
        /// The hypervisor failed. Never sent from inside this package -- there
        /// is no hypervisor here, the embedder owns the VM -- and carried so an
        /// embedder can send it on the same channel as the rest.
        case hypervisorError = "hypervisor_error"
    }

    public var kind: Kind
    public var macAddress: MACAddress?

    public init(kind: Kind, macAddress: MACAddress? = nil) {
        self.kind = kind
        self.macAddress = macAddress
    }

    /// Upstream's shape: `{"notification_type":"ready"}`, with `mac_address`
    /// omitted rather than null when there is none.
    public var json: String {
        var fields = ["\"notification_type\":\"\(kind.rawValue)\""]
        if let macAddress { fields.append("\"mac_address\":\"\(macAddress)\"") }
        return "{" + fields.joined(separator: ",") + "}"
    }
}

/// Delivers notifications to a unix socket, one JSON object per connection.
///
/// ## Dropping rather than blocking
///
/// `send` is called from the datapath -- `connection_established` comes off a
/// frame arriving on a port -- so it must never wait. The queue is bounded and
/// a full queue **drops**, which is upstream's behaviour and the right one: the
/// alternative is that a supervisor which stops reading its socket slows down,
/// and eventually stops, the network. A dropped notification is a supervisor
/// that missed an event; a blocked datapath is a guest with no network because
/// something else is busy.
///
/// Drops are counted, so "did I miss one" has an answer.
///
/// ## One connection per notification
///
/// Wasteful, and matched to upstream deliberately: a listener written against
/// gvisor-tap-vsock reads one JSON object and expects the connection to end.
/// Holding one open would also mean deciding what to do when it breaks, and a
/// supervisor that restarts is the ordinary case rather than the exception.
///
/// They are sent **one at a time and in order**. `connection_established`
/// arriving after the `connection_closed` for the same guest would tell a
/// supervisor the opposite of what happened, and dialling concurrently is
/// exactly how that ordering is lost.
/// `@unchecked Sendable` on the same terms as everything else on this datapath:
/// every stored property is confined to `eventLoop` and `send` preconditions on
/// it. The conformance is needed because the delivery future's completion is a
/// `@Sendable` closure that has to reach back to count the outcome.
public final class NotificationSender: @unchecked Sendable {
    private let socketPath: String
    private let eventLoop: EventLoop
    private let queueLimit: Int

    private var queue: [NetstackNotification] = []
    private var sending = false

    /// Notifications dropped because the queue was full.
    public private(set) var dropped = 0
    /// Notifications the socket refused or could not take.
    public private(set) var failed = 0
    /// Notifications delivered.
    public private(set) var delivered = 0

    public var log: RateLimitedLogger?

    /// How many notifications are waiting. For tests.
    public var queuedCountForTesting: Int { queue.count }

    /// Replaces the delivery for a test.
    ///
    /// The queue bound is only reached when delivery is slower than the
    /// datapath, and that is precisely what a test cannot arrange with a real
    /// socket: a dial to a path nothing is listening on fails, and on the event
    /// loop it fails *inline*, so the queue drains as fast as it fills and the
    /// bound is never approached. That is also why the bound is not
    /// hypothetical -- the case it exists for is a supervisor that is slow
    /// rather than absent, which is the harder one to notice.
    var deliverForTesting: ((NetstackNotification) -> EventLoopFuture<Void>)?

    public init(socketPath: String, eventLoop: EventLoop, queueLimit: Int = 100) {
        self.socketPath = socketPath
        self.eventLoop = eventLoop
        self.queueLimit = max(1, queueLimit)
    }

    /// Queue a notification. Never blocks, and never fails loudly.
    public func send(_ notification: NetstackNotification) {
        eventLoop.preconditionInEventLoop()
        guard queue.count < queueLimit else {
            dropped += 1
            log?.record(.notificationDropped, ["kind": .string(notification.kind.rawValue)])
            return
        }
        queue.append(notification)
        pump()
    }

    private func pump() {
        guard !sending, !queue.isEmpty else { return }
        sending = true
        let notification = queue.removeFirst()
        let sent = deliverForTesting?(notification) ?? deliver(notification)
        sent.whenComplete { [weak self] outcome in
            guard let self else { return }
            switch outcome {
            case .success: self.delivered += 1
            case .failure:
                self.failed += 1
                // Not logged per failure: a supervisor that is not running makes
                // every notification fail, and one line per guest frame is the
                // flood `RateLimitedLogger` exists to prevent. The counter is
                // the record.
                self.log?.record(.notificationFailed)
            }
            self.sending = false
            self.pump()
        }
    }

    private func deliver(_ notification: NetstackNotification) -> EventLoopFuture<Void> {
        let address: SocketAddress
        do {
            address = try SocketAddress(unixDomainSocketPath: socketPath)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
        let payload = notification.json
        return ClientBootstrap(group: eventLoop)
            .connect(to: address)
            .flatMap { channel -> EventLoopFuture<Void> in
                var buffer = channel.allocator.buffer(capacity: payload.utf8.count + 1)
                buffer.writeString(payload)
                // A trailing newline, so a reader can take a line at a time.
                // Upstream's Go encoder writes one too.
                buffer.writeString("\n")
                return channel.writeAndFlush(buffer).flatMap { channel.close() }
            }
    }
}
