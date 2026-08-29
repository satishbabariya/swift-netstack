import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// Notifications go to a supervisor -- the thing that started the VM and wants to
// know when its network came up and when a guest arrived or left. The audience
// is a program rather than a person, which is why they exist alongside logging
// rather than inside it.

private func notificationPath(_ tag: String) -> String {
    "/tmp/netstack-notify-\(tag)-\(UInt32.random(in: 0...UInt32.max)).sock"
}

/// A unix socket that accepts connections and collects one JSON object from
/// each, the way a supervisor would.
private final class NotificationListener: @unchecked Sendable {
    private let fd: Int32
    private let queue = DispatchQueue(label: "netstack.test.notifications")
    private let box = NIOLockedValueBox<[String]>([])
    private var running = true

    init(path: String) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafeMutablePointer(to: &address.sun_path) { raw in
            path.withCString { source in
                raw.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, source, 103) }
            }
        }
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        listen(fd, 32)
        queue.async { [weak self] in self?.accept() }
    }

    private func accept() {
        while running {
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { break }
            var buffer = [UInt8](repeating: 0, count: 4096)
            let read = buffer.withUnsafeMutableBytes { recv(client, $0.baseAddress, $0.count, 0) }
            if read > 0 {
                let text = String(decoding: buffer[0..<read], as: UTF8.self)
                box.withLockedValue { $0.append(text.trimmingCharacters(in: .whitespacesAndNewlines)) }
            }
            close(client)
        }
    }

    var received: [String] { box.withLockedValue { $0 } }

    /// Wait until `predicate` holds or the deadline passes.
    func waitFor(_ predicate: @escaping ([String]) -> Bool) async -> [String] {
        for _ in 0..<400 {
            let current = received
            if predicate(current) { return current }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return received
    }

    func stop() {
        running = false
        close(fd)
    }
}

@Test func aGatewayTellsItsSupervisorWhenItIsReady() async throws {
    // A supervisor usually starts the VM when it sees this, so it has to arrive
    // after the services the VM will talk to are listening -- not when the
    // object was constructed.
    let path = notificationPath("ready")
    defer { try? FileManager.default.removeItem(atPath: path) }
    let listener = NotificationListener(path: path)
    defer { listener.stop() }

    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group,
        configuration: .init(notificationSocketPath: path)
    ).get()

    let received = await listener.waitFor { !$0.isEmpty }
    #expect(received.contains("{\"notification_type\":\"ready\"}"), "no ready: \(received)")

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func aGuestArrivingAndLeavingIsAnnouncedWithItsAddress() async throws {
    // What a supervisor actually watches for. The switch already knew both --
    // it learns an address and forgets it when the port goes -- and this is
    // those two moments reaching somebody.
    let path = notificationPath("guests")
    let socketPath = notificationPath("guests-wire")
    defer {
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.removeItem(atPath: socketPath)
    }
    let listener = NotificationListener(path: path)
    defer { listener.stop() }

    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        switchListeningOnStreamSocketAt: socketPath, group: group,
        configuration: .init(notificationSocketPath: path)
    ).get()

    let mac = MACAddress("0a:00:00:00:12:34")!
    let guest = swgDial(socketPath)
    swgSend(guest, swgArpRequest(from: mac, sender: IPv4Address("192.168.127.9")!, target: IPv4Address("192.168.127.1")!))

    let established = await listener.waitFor { $0.contains { $0.contains("connection_established") } }
    #expect(
        established.contains("{\"notification_type\":\"connection_established\",\"mac_address\":\"\(mac)\"}"),
        "no established with the guest's address: \(established)")

    close(guest)

    let closed = await listener.waitFor { $0.contains { $0.contains("connection_closed") } }
    #expect(
        closed.contains("{\"notification_type\":\"connection_closed\",\"mac_address\":\"\(mac)\"}"),
        "no closed with the guest's address: \(closed)")

    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
}

@Test func aFullQueueDropsRatherThanBlockingTheDatapath() async throws {
    // `send` is called from the datapath, so it must never wait. A supervisor
    // that stops reading its socket would otherwise slow down, and eventually
    // stop, the network -- a guest with no network because something else is
    // busy.
    //
    // Delivery is replaced with one that never completes, because that is the
    // case the bound exists for and the one a real socket cannot produce here:
    // a dial to a path nothing is listening on fails, and on the event loop it
    // fails inline, so the queue drains as fast as it fills. The dangerous
    // supervisor is the slow one, not the absent one.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let loop = group.next()
    let sender = NotificationSender(
        socketPath: notificationPath("stalled"), eventLoop: loop, queueLimit: 8)
    let stalled = loop.makePromise(of: Void.self)
    sender.deliverForTesting = { _ in stalled.futureResult }

    let counts = try await loop.submit { () -> (dropped: Int, queued: Int) in
        for index in 0..<200 {
            sender.send(
                .init(
                    kind: .connectionEstablished,
                    macAddress: MACAddress(bytes: [0x0a, 0, 0, 0, 0, UInt8(index % 256)])!))
        }
        return (sender.dropped, sender.queuedCountForTesting)
    }.get()

    #expect(counts.queued <= 8, "the queue grew to \(counts.queued) against a limit of 8")
    // One is in flight and eight are queued, so 191 were dropped. Asserted
    // exactly, because "some were dropped" is also true of a sender that drops
    // everything.
    #expect(counts.dropped == 191, "expected 191 drops, got \(counts.dropped)")

    stalled.succeed(())
    try? await group.shutdownGracefully()
}

@Test func theJsonIsUpstreamsShapeAndOmitsAnAbsentAddress() {
    // A supervisor written against gvisor-tap-vsock parses these, so the field
    // names and the omission are interface rather than detail: `"mac_address":
    // null` is a different document from one without the key, and Go's encoder
    // omits it.
    #expect(NetstackNotification(kind: .ready).json == "{\"notification_type\":\"ready\"}")
    #expect(
        NetstackNotification(kind: .connectionClosed, macAddress: MACAddress("0a:0b:0c:0d:0e:0f")!).json
            == "{\"notification_type\":\"connection_closed\",\"mac_address\":\"0a:0b:0c:0d:0e:0f\"}")
    #expect(NetstackNotification.Kind.hypervisorError.rawValue == "hypervisor_error")
}
