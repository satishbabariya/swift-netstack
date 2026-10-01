import NIOCore

/// The address a forwarded connection should come from inside the guest.
///
/// Upstream's `sourceBindAddr` (gvisor-tap-vsock f9306b96). Without it the
/// guest sees every forwarded connection come from the gateway, so a service
/// behind a published port cannot log, rate-limit or allow-list the client
/// that actually dialled it. With it the guest-side end is bound to the host
/// client's own address and port, and the guest answers that address through
/// its default route -- this gateway -- where the stack picks it up again.
enum ForwardedSource {
    /// Where to bind the guest-side end for a client at `client`, or `nil` to
    /// keep the gateway's address.
    ///
    /// `nil` for loopback, unspecified and non-IPv4 clients, as upstream. The
    /// loopback case is the one that matters: the guest replies to the source
    /// address through the gateway, and a reply addressed to 127.0.0.1 on a
    /// non-loopback link is a martian a real guest kernel drops. That is the
    /// most common forward there is, `127.0.0.1:2222 -> guest:22`, and it has to
    /// keep working exactly as before.
    ///
    /// Also `nil` when the stack may not send from an address it does not own,
    /// or will not accept a packet addressed to one. Upstream's stack always
    /// has both on; this one makes them configuration, and with either off the
    /// connection would be bound to an address it can neither speak from nor
    /// hear on.
    static func binding(for client: SocketAddress?, on stack: Stack) -> (address: IPv4Address, port: UInt16)? {
        guard stack.configuration.allowsAnySource, stack.configuration.acceptsAnyDestination else { return nil }
        guard let client, let text = client.ipAddress, let port = client.port, (0...Int(UInt16.max)).contains(port)
        else { return nil }
        // A dual-stack listener sees IPv4 clients as `::ffff:a.b.c.d`. Go's
        // `To4` reads those as IPv4, so upstream propagates them; so does this.
        let lowered = text.lowercased()
        let dotted = lowered.hasPrefix("::ffff:") ? String(lowered.dropFirst(7)) : lowered
        guard let address = IPv4Address(dotted) else { return nil }
        guard address != .any, address.bytes[0] != 127 else { return nil }
        return (address, UInt16(port))
    }
}
