import NIOCore

/// The four-tuple identifying a transport flow.
///
/// `.any` in an address field, or zero in a port field, is a wildcard: it is
/// how a listening endpoint says it will take any peer.
public struct TransportEndpointID: Hashable, Sendable, CustomStringConvertible {
    public var localAddress: IPv4Address
    public var localPort: UInt16
    public var remoteAddress: IPv4Address
    public var remotePort: UInt16

    public init(localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16) {
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
    }

    public var description: String {
        "\(localAddress):\(localPort) <- \(remoteAddress):\(remotePort)"
    }
}

/// Anything that can receive delivered packets for a flow.
///
/// The ports are passed alongside the IP header because the transport header
/// has already been consumed by the time delivery happens, and every endpoint
/// needs to know which peer port a datagram came from.
public protocol TransportEndpointDelegate: AnyObject {
    func deliver(header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16)
}
