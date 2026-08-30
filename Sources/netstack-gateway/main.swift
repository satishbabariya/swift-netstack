import Foundation
import Logging
import NIOCore
import NIOPosix
import Netstack

// A gateway as a program, for the hosts that cannot link a Swift library:
// vfkit, qemu, and anything else that hands a network device a socket. Upstream
// ships `gvproxy` for exactly this, and the arguments here are the same shape.
//
// Everything this does is available as an API -- `Gateway.start` and
// `ControlPlane` -- and a Swift host process should use that instead. This is
// for the other kind of host.

struct Options {
    var configPath: String?
    var listenPath: String?
    var listenStream: String?
    var controlPath: String?
    var upstreamResolver: String?
    var gateway = "192.168.127.1"
    var subnet = "192.168.127.0/24"
    var mtu: UInt32 = 1500
    var logLevel = "notice"
    var captureFile: String?
    var notifySocket: String?
    var host = "192.168.127.254"
    var allowsLinkLocal = false
    var forwards: [(host: Int, guest: String, guestPort: UInt16)] = []

    /// Hand-rolled rather than a dependency: an argument parser would be a
    /// package in the dependency graph of everything that links this library.
    ///
    /// The names are gvproxy's, because a program that is upstream's shape and
    /// spells its flags differently is a program somebody has to translate for
    /// -- and the translation is silent when the same name means two different
    /// things, which `--listen` did.
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
            // gvproxy's spellings. `--listen` is the CONTROL endpoint there and
            // the guest wire is `--listen-vfkit` or `--listen-qemu`; this had
            // them the other way round, so a command line moved across from
            // gvproxy would have pointed the control API at the VM's socket and
            // the VM at the control socket. Nothing would have said so.
            case "--config": options.configPath = try value(flag)
            case "--listen": options.controlPath = try value(flag).replacingOccurrences(of: "unix://", with: "")
            case "--listen-vfkit": options.listenPath = try value(flag)
            case "--listen-qemu": options.listenStream = try value(flag)
            case "--listen-stdio", "--listen-bess", "--listen-vpnkit":
                throw OptionError.unsupportedWire(flag)
            case "--dns": options.upstreamResolver = try value(flag)
            case "--gatewayIP": options.gateway = try value(flag)
            case "--hostIP": options.host = try value(flag)
            case "--subnet": options.subnet = try value(flag)
            case "--log-level": options.logLevel = try value(flag)
            case "--debug": options.logLevel = "debug"
            case "--pcap": options.captureFile = try value(flag)
            case "--notification": options.notifySocket = try value(flag)
            case "--ec2-metadata-access": options.allowsLinkLocal = true
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
        // Deliberately NOT checked here. The configuration file is read after
        // parsing, and a file that is missing, malformed or YAML has to be
        // reported as that rather than as "no guest wire" -- which is what
        // happened, because this check fired first and every config mistake came
        // back wearing the same message.
        return options
    }
}

enum OptionError: Error, CustomStringConvertible {
    case missingValue(String)
    case badValue(String, String)
    case unknown(String)
    /// A wire upstream has and this does not, named so the failure says which
    /// rather than "unknown option".
    case unsupportedWire(String)
    case conflictingWires
    /// No guest wire at all. Its own case rather than a missing value, because
    /// `--listen` is present and valid and still leaves nothing for a guest to
    /// connect to -- which is the mistake somebody moving a gvproxy command line
    /// across is most likely to make.
    case noWire
    case help

    var description: String {
        switch self {
        case .missingValue(let flag): return "\(flag) needs a value"
        case .badValue(let flag, let text): return "\(flag) does not accept \(text)"
        case .unknown(let flag): return "unknown option \(flag)"
        case .unsupportedWire(let flag):
            return
                "\(flag) is not supported: bess is SOCK_SEQPACKET, stdio is a pipe, and vpnkit needs "
                + "hyperkit's handshake. Use --listen-vfkit for a datagram socket or --listen-qemu for a "
                + "stream one."
        case .conflictingWires:
            return "--listen-vfkit and --listen-qemu are two different wires; pick one"
        case .noWire:
            return
                "no guest wire: pass --listen-vfkit <path> for a datagram socket or --listen-qemu "
                + "<path> for a stream one. (--listen is the control API, as in gvproxy.)"
        case .help: return usage
        }
    }
}

let usage = """
    netstack-gateway — a userspace network for a VM, over a socket.

    Flag names are gvproxy's, so a command line moves across unchanged.

      --config <path>            Configuration file, in gvproxy's shape as JSON
      --listen <path>            Unix socket for the HTTP control API
      --listen-vfkit <path>      Datagram socket the guest dials (vfkit, unixgram)
      --listen-qemu <path>       Stream socket with length-prefixed frames (qemu)
      --gatewayIP <address>      The gateway's own address (default 192.168.127.1)
      --hostIP <address>         The address that means the host (default .254)
      --subnet <cidr>            The subnet leased to guests (default 192.168.127.0/24)
      --mtu <bytes>              Link MTU (default 1500)
      --pcap <path>              Write every frame to a pcap file (capped at 64 MiB)
      --notification <path>      Socket told when the network is ready and guests join
      --ec2-metadata-access      Let guests reach 169.254.0.0/16. Off by default: that
                                 is where the cloud instance metadata service lives.
      --debug                    Shorthand for --log-level debug
      --log-level <level>        trace|debug|info|notice|warning|error (default notice)

    Also settable in the configuration file, which is the only way to reach zones,
    static leases, NAT and virtual addresses. Flags win over the file.

    Not gvproxy's, because it takes them from the configuration file:

      --dns <address:port>       Resolver for names this gateway does not own
      --forward <h:addr:g>       Publish guest addr:g on host port h, repeatable

    Exactly one of --listen-vfkit or --listen-qemu is required: they are two
    different wires, and a socket is one or the other.
    """

let arguments = Array(CommandLine.arguments.dropFirst())
var options: Options
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

// A flag that was left at its default loses to the file; one that was given
// wins. Comparing against the default is how that is decided without a second
// optional per setting.
let gatewayAddress = options.gateway == "192.168.127.1" ? (file.gatewayAddress ?? IPv4Address("192.168.127.1")!) : IPv4Address(options.gateway)
let hostAddress = options.host == "192.168.127.254" ? (file.hostAddress ?? IPv4Address("192.168.127.254")!) : IPv4Address(options.host)
let subnet = options.subnet == "192.168.127.0/24" ? (file.subnet ?? IPv4Subnet(cidr: "192.168.127.0/24")!) : IPv4Subnet(cidr: options.subnet)
guard let gatewayAddress, let subnet, let hostAddress else {
    FileHandle.standardError.write(Data("error: --gatewayIP, --hostIP or --subnet is not an address\n".utf8))
    exit(2)
}

// The file first, then the flags over it. gvproxy documents the same order --
// "configuration file with command line override" -- and it is the order that
// makes a file useful: a shared file plus one flag for what differs.
var file = FileConfiguration()
if let path = options.configPath {
    do {
        file = try FileConfiguration(contentsOf: path)
    } catch {
        FileHandle.standardError.write(Data("error: \(error)\n".utf8))
        exit(2)
    }
}
if file.debug, options.logLevel == "notice" { options.logLevel = "debug" }

// The wire is checked now: after the file has had its chance to be wrong about
// something more specific.
if options.listenPath == nil, options.listenStream == nil {
    FileHandle.standardError.write(Data("error: \(OptionError.noWire)\n\n\(usage)\n".utf8))
    exit(2)
}
if options.listenPath != nil, options.listenStream != nil {
    FileHandle.standardError.write(Data("error: \(OptionError.conflictingWires)\n".utf8))
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

guard let logLevel = Logger.Level(rawValue: options.logLevel) else {
    FileHandle.standardError.write(Data("error: --log-level is not a level\n".utf8))
    exit(2)
}
// Bootstrapped here rather than in the library: a library that installs a
// global log handler decides for every other library in the process, and this
// is the one place in the package that is entitled to, because it is the
// process.
LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardError(label: label)
    handler.logLevel = logLevel
    return handler
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let configuration = Gateway.Configuration(
    gatewayAddress: gatewayAddress, subnet: subnet,
    linkAddress: file.linkAddress ?? MACAddress("5a:94:ef:e4:0c:ee")!,
    hostAddress: hostAddress, nat: file.nat,
    gatewayVirtualAddresses: file.virtualAddresses,
    allowsLinkLocal: options.allowsLinkLocal || (file.allowsLinkLocal ?? false),
    captureFile: options.captureFile ?? file.captureFile,
    notificationSocketPath: options.notifySocket,
    mtu: options.mtu == 1500 ? (file.mtu ?? 1500) : options.mtu,
    dnsRecords: nil, upstreamResolvers: resolvers,
    dhcpStaticLeases: file.staticLeases, dnsSearchDomains: file.searchDomains,
    maximumHalfOpenConnections: file.maximumHalfOpen ?? 512,
    logger: Logger(label: "netstack"))

do {
    // The wire is a socket this process creates and listens on: the VM connects
    // to it. That is the shape vfkit and qemu expect -- they are given a path and
    // dial it -- and it is why this waits for a connection rather than adopting a
    // descriptor the way an embedding host does.
    let path = options.listenPath ?? options.listenStream!
    let stream = options.listenStream != nil

    print("netstack-gateway: waiting for a guest on \(path)")
    let gateway = try
        (stream
        ? Gateway.start(listeningOnStreamSocketAt: path, group: group, configuration: configuration)
        : Gateway.start(listeningOnDatagramSocketAt: path, group: group, configuration: configuration)).wait()

    // Zones from the file, added before any guest can ask.
    //
    // Copied into a local first: `file` is main-actor isolated as a top-level
    // binding, and the closure below runs on the event loop.
    let configuredZones = file.zones
    if !configuredZones.isEmpty {
        try gateway.eventLoop.submit {
            for zone in configuredZones { gateway.dns.addZone(zone) }
        }.wait()
    }

    for forward in options.forwards + file.forwards {
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
