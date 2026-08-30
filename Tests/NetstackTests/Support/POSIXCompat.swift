import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// The handful of POSIX spellings that differ between Darwin and Linux, in one
// place rather than at each of the twenty call sites that needed them.
//
// This exists because the tests did not compile on Linux while the library did.
// Three differences, all trivial and all fatal:
//
//   - `sockaddr_in` and `sockaddr_un` carry a length byte on BSD and not on
//     Linux, so `sin_len` is an error there rather than a field.
//   - `SOCK_STREAM` and `SOCK_DGRAM` are `Int32` on Darwin and `__socket_type`
//     on Linux.
//   - `IPPROTO_ICMP` is `Int32` on Darwin and `Int` on Linux.
//
// Wrapping them is worth more than guarding each site: every test that wanted a
// socket was building `sockaddr_in` by hand, so the duplication was already
// there and the platform difference only made it visible.

/// `SOCK_STREAM` and `SOCK_DGRAM`, spelled the same on both platforms.
enum SocketKind {
    case stream
    case datagram

    var rawType: Int32 {
        #if canImport(Darwin)
            switch self {
            case .stream: return SOCK_STREAM
            case .datagram: return SOCK_DGRAM
            }
        #else
            switch self {
            case .stream: return Int32(SOCK_STREAM.rawValue)
            case .datagram: return Int32(SOCK_DGRAM.rawValue)
            }
        #endif
    }
}

/// `socket(2)`, with the type spelled portably.
func makeSocket(_ domain: Int32, _ kind: SocketKind, _ protocolNumber: Int32 = 0) -> Int32 {
    socket(domain, kind.rawType, protocolNumber)
}

/// An unprivileged ICMP socket, or a negative descriptor where the platform
/// will not open one.
func makeICMPSocket() -> Int32 {
    #if canImport(Darwin)
        return socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
    #else
        return socket(AF_INET, Int32(SOCK_DGRAM.rawValue), Int32(IPPROTO_ICMP))
    #endif
}

/// A `sockaddr_in` for `127.0.0.1:port`, with the BSD length byte where there
/// is one.
func loopbackAddress(port: UInt16) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_family = sa_family_t(AF_INET)
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
    address.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    return address
}

/// A `sockaddr_un` for a filesystem path.
///
/// `sun_path` is a fixed C array and its length differs by platform, so the
/// copy is bounded by the array itself rather than by a constant. 104 was
/// hard-coded at every site here, which is macOS's size and not Linux's 108.
func unixAddress(path: String) -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    #if canImport(Darwin)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    #endif
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    _ = withUnsafeMutablePointer(to: &address.sun_path) { raw in
        path.withCString { source in
            raw.withMemoryRebound(to: CChar.self, capacity: capacity) { destination in
                strncpy(destination, source, capacity - 1)
            }
        }
    }
    return address
}

/// `connect(2)` to a `sockaddr_in`, taking the address by value.
func connectTo(_ descriptor: Int32, _ address: sockaddr_in) -> Int32 {
    var address = address
    return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

/// `connect(2)` to a `sockaddr_un`.
func connectTo(_ descriptor: Int32, _ address: sockaddr_un) -> Int32 {
    var address = address
    return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

/// `bind(2)` to a `sockaddr_un`.
func bindTo(_ descriptor: Int32, _ address: sockaddr_un) -> Int32 {
    var address = address
    return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

/// `sendto(2)` a payload to a `sockaddr_in`.
func sendTo(_ descriptor: Int32, _ payload: [UInt8], _ address: sockaddr_in) -> Int {
    var address = address
    return withUnsafePointer(to: &address) { raw in
        raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
            payload.withUnsafeBytes {
                sendto(descriptor, $0.baseAddress, $0.count, 0, addr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
}

/// `sendto(2)` a payload to a `sockaddr_un`.
func sendTo(_ descriptor: Int32, _ payload: [UInt8], _ address: sockaddr_un) -> Int {
    var address = address
    return withUnsafePointer(to: &address) { raw in
        raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { addr in
            payload.withUnsafeBytes {
                sendto(descriptor, $0.baseAddress, $0.count, 0, addr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }
}

/// `socketpair(2)`, with the type spelled portably.
///
/// This is how nearly every test here builds a wire: the host keeps one end and
/// the other stands in for the VM, exactly as Virtualization.framework hands one
/// over.
func makeSocketPair(_ domain: Int32, _ kind: SocketKind, _ pair: inout [Int32]) -> Int32 {
    socketpair(domain, kind.rawType, 0, &pair)
}

// `Darwin.send` and `Darwin.accept` were written with the module qualifier to
// disambiguate from a same-named symbol in scope -- `send` collides with NIO's,
// and `accept` with a local. The qualifier is the module name, so it does not
// exist on Linux. These two wrappers say the same thing portably.

/// `send(2)` on a connected socket.
func sendBytes(_ descriptor: Int32, _ bytes: [UInt8]) -> Int {
    bytes.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
}

/// `accept(2)`, discarding the peer address.
func acceptConnection(_ descriptor: Int32) -> Int32 {
    accept(descriptor, nil, nil)
}

/// `MSG_DONTWAIT`, which is `Int32` on Darwin and `Int` on Linux.
///
/// Every test here that drains a wire polls it non-blocking, so this is the
/// most-used of the lot.
let dontWait: Int32 = {
    #if canImport(Darwin)
        return MSG_DONTWAIT
    #else
        return Int32(MSG_DONTWAIT)
    #endif
}()

/// `recv(2)` into a buffer, non-blocking.
func receiveNonBlocking(_ descriptor: Int32, into buffer: inout [UInt8]) -> Int {
    buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, dontWait) }
}
