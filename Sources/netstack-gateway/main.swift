import Foundation
import Netstack
import NIOCore
import NIOPosix

// A gateway as a program, for the hosts that cannot link a Swift library:
// vfkit, qemu, and anything else that hands a network device a socket. Upstream
// ships `gvproxy` for exactly this, and the arguments here are the same shape.
//
// Everything this does is available as an API -- `Gateway.start` and
// `ControlPlane` -- and a Swift host process should use that instead. This is
// for the other kind of host.

struct Options {
    var listenPath: String?
    var listenStream: String?
    var controlPath: String?
    var upstreamResolver: String?
    var gateway = "192.168.127.1"
    var subnet = "192.168.127.0/24"
    var mtu: UInt32 = 1500
    var forwards: [(host: Int, guest: String, guestPort: UInt16)] = []

    /// Hand-rolled rather than a dependency. The whole surface is six flags, and
    /// an argument parser would be a package this library does not otherwise
    /// need in the dependency graph of everything that links it.
    static func parse(_ arguments: [String]) throws -> Options {
        var options = Options()
        var index = 0
        func value(_ flag: String) throws -> String {
            index += 1
            guard index < arguments.count else { throw OptionError.missingValue(flag) }
            return arguments[index]
        }
        while index < arguments.count {
            let flag = arguments[index]
            switch flag {
            case "--listen": options.listenPath = try value(flag)
            case "--listen-stream": options.listenStream = try value(flag)
            case "--control": options.controlPath = try value(flag)
            case "--dns": options.upstreamResolver = try value(flag)
            case "--gateway": options.gateway = try value(flag)
            case "--subnet": options.subnet = try value(flag)
            case "--mtu":
                let text = try value(flag)
                guard let mtu = UInt32(text), mtu >= 576, mtu <= 65535 else {
                    throw OptionError.badValue(flag, text)
                }
                options.mtu = mtu
            case "--forward":
                // `8080:192.168.127.2:80`
                let text = try value(flag)
                let parts = text.split(separator: ":", omittingEmptySubsequences: false)
                guard parts.count == 3, let host = Int(parts[0]), let guestPort = UInt16(parts[2]),
                    IPv4Address(String(parts[1])) != nil
                else { throw OptionError.badValue(flag, text) }
                options.forwards.append((host, String(parts[1]), guestPort))
            case "--help", "-h":
                throw OptionError.help
            default:
                throw OptionError.unknown(flag)
            }
            index += 1
        }
        guard options.listenPath != nil || options.listenStream != nil else {
            throw OptionError.missingValue("--listen or --listen-stream")
        }
        guard options.listenPath == nil || options.listenStream == nil else {
            throw OptionError.conflictingWires
        }
        return options
    }
}

enum OptionError: Error, CustomStringConvertible {
    case missingValue(String)
    case badValue(String, String)
    case unknown(String)
    case conflictingWires
    case help

    var description: String {
        switch self {
        case .missingValue(let flag): return "\(flag) needs a value"
        case .badValue(let flag, let text): return "\(flag) does not accept \(text)"
        case .unknown(let flag): return "unknown option \(flag)"
        case .conflictingWires: return "--listen and --listen-stream are two different wires; pick one"
        case .help: return usage
        }
    }
}

let usage = """
netstack-gateway — a userspace network for a VM, over a socket.

  --listen <path>         Datagram socket to serve (vfkit, Virtualization.framework)
  --listen-stream <path>  Stream socket with length-prefixed frames (qemu -netdev socket)
  --control <path>        Unix socket for the forwarding control API
  --dns <address:port>    Resolver to forward names this gateway does not own
  --gateway <address>     The gateway's own address (default 192.168.127.1)
  --subnet <cidr>         The subnet leased to guests (default 192.168.127.0/24)
  --mtu <bytes>           Link MTU (default 1500)
  --forward <h:addr:g>    Publish guest addr:g on host port h, repeatable

Exactly one of --listen or --listen-stream is required: they are two different
wires, and a socket is one or the other.
"""

let arguments = Array(CommandLine.arguments.dropFirst())
let options: Options
do {
    options = try Options.parse(arguments)
} catch let error as OptionError {
    if case .help = error {
        print(usage)
        exit(0)
    }
    FileHandle.standardError.write(Data("error: \(error)\n\n\(usage)\n".utf8))
    exit(2)
}

guard let gatewayAddress = IPv4Address(options.gateway), let subnet = IPv4Subnet(cidr: options.subnet) else {
    FileHandle.standardError.write(Data("error: --gateway or --subnet is not an address\n".utf8))
    exit(2)
}

var resolvers: [SocketAddress] = []
if let resolver = options.upstreamResolver {
    guard let separator = resolver.lastIndex(of: ":"),
        let port = Int(resolver[resolver.index(after: separator)...]),
        let address = try? SocketAddress(ipAddress: String(resolver[resolver.startIndex..<separator]), port: port)
    else {
        FileHandle.standardError.write(Data("error: --dns wants address:port\n".utf8))
        exit(2)
    }
    resolvers = [address]
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let configuration = Gateway.Configuration(
    gatewayAddress: gatewayAddress, subnet: subnet, mtu: options.mtu, upstreamResolvers: resolvers)

do {
    // The wire is a socket this process creates and listens on: the VM connects
    // to it. That is the shape vfkit and qemu expect -- they are given a path and
    // dial it -- and it is why this waits for a connection rather than adopting a
    // descriptor the way an embedding host does.
    let path = options.listenPath ?? options.listenStream!
    let stream = options.listenStream != nil

    print("netstack-gateway: waiting for a guest on \(path)")
    let gateway = try (stream
        ? Gateway.start(listeningOnStreamSocketAt: path, group: group, configuration: configuration)
        : Gateway.start(listeningOnDatagramSocketAt: path, group: group, configuration: configuration)).wait()

    for forward in options.forwards {
        guard let address = IPv4Address(forward.guest) else { continue }
        _ = try gateway.forward(hostPort: forward.host, toGuest: address, port: forward.guestPort).wait()
        print("netstack-gateway: publishing \(forward.guest):\(forward.guestPort) on 127.0.0.1:\(forward.host)")
    }

    var control: ControlPlane?
    if let controlPath = options.controlPath {
        let plane = ControlPlane(gateway: gateway)
        try plane.listen(unixSocketPath: controlPath).wait()
        control = plane
        print("netstack-gateway: control API on \(controlPath)")
    }
    _ = control

    print("netstack-gateway: running")
    // Nothing to do but let the loop run. The gateway is entirely event-driven,
    // so the main thread's only job is to not exit.
    try group.next().scheduleTask(in: .hours(24 * 365)) {}.futureResult.wait()
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
