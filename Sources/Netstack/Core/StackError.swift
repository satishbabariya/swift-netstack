/// Every failure the stack surfaces to a caller.
///
/// Deliberately flat and closed: these map onto what a socket API would
/// report, so a consumer handles a netstack failure the same way it handles a
/// socket failure.
public enum StackError: Error, Hashable, Sendable, CustomStringConvertible {
    case connectionRefused
    case connectionReset
    case connectionAborted
    case timeout
    case noRoute
    case networkUnreachable
    case portInUse
    case noPortsAvailable
    case wouldBlock
    case notConnected
    case alreadyConnected
    case messageTooLong
    case invalidEndpointState
    case malformedPacket(String)
    case aborted

    public var description: String {
        switch self {
        case .connectionRefused: return "connection refused"
        case .connectionReset: return "connection reset by peer"
        case .connectionAborted: return "connection aborted"
        case .timeout: return "operation timed out"
        case .noRoute: return "no route to host"
        case .networkUnreachable: return "network unreachable"
        case .portInUse: return "address already in use"
        case .noPortsAvailable: return "no ephemeral ports available"
        case .wouldBlock: return "operation would block"
        case .notConnected: return "endpoint is not connected"
        case .alreadyConnected: return "endpoint is already connected"
        case .messageTooLong: return "message too long"
        case .invalidEndpointState: return "endpoint is in an invalid state for this operation"
        case .malformedPacket(let detail): return "malformed packet: \(detail)"
        case .aborted: return "aborted"
        }
    }
}
