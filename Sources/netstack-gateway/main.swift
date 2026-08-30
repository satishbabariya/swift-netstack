import Dispatch
import Foundation
import Logging
import NIOConcurrencyHelpers
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
    var listenSwitch: String?
    var controlEndpoints: [String] = []
    var servicesEndpoints: [String] = []
    var pidFile: String?
    var logFile: String?
    var upstreamResolver: String?
    var gateway: String?
    var subnet: String?
    var mtu: UInt32 = 1500
    var logLevel = "notice"
    var captureFile: String?
    var notifySocket: String?
    var host: String?
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
            case "--listen": options.controlEndpoints.append(try value(flag))
            case "--services": options.servicesEndpoints.append(try value(flag))
            case "--pid-file": options.pidFile = try value(flag)
            case "--log-file": options.logFile = try value(flag)
            case "--listen-vfkit": options.listenPath = try value(flag)
            case "--listen-qemu": options.listenStream = try value(flag)
            case "--listen-switch": options.listenSwitch = try value(flag)
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
            return "--listen-vfkit, --listen-qemu and --listen-switch are different wires; pick one"
        case .noWire:
            return
                "no guest wire: pass --listen-vfkit <path> for a datagram socket, --listen-qemu "
                + "<path> for a stream one, or --listen-switch <path> for a stream socket that "
                + "carries several guests. (--listen is the control API, as in gvproxy.)"
        case .help: return usage
        }
    }
}

let usage = """
    netstack-gateway — a userspace network for a VM, over a socket.

    Flag names are gvproxy's, so a command line moves across unchanged.

      --config <path>            Configuration file, in gvproxy's shape as JSON
      --listen <endpoint>        HTTP control API: unix://<path>, tcp://<host>:<port>
                                 or a bare path. Repeatable
      --services <endpoint>      The same API without /connect, for an endpoint a
                                 guest may reach. Repeatable
      --pid-file <path>          Write this process's PID there, and remove it on
                                 a clean stop
      --log-file <path>          Append log messages there as well as to stderr
      --listen-vfkit <path>      Datagram socket the guest dials (vfkit, unixgram)
      --listen-qemu <path>       Stream socket with length-prefixed frames (qemu),
                                 carrying one guest
      --listen-switch <path>     The same framing, carrying every guest that
                                 connects, each on its own port of a switch.
                                 Guests reach each other directly
      --gatewayIP <address>      The gateway's own address (default: the first
                                 usable address of the subnet)
      --hostIP <address>         The address that means the host (default: the
                                 last usable address of the subnet)
      --subnet <cidr>            The subnet leased to guests (default 192.168.127.0/24)
      --mtu <bytes>              Link MTU (default 1500)
      --pcap <path>              Write every frame to a pcap file (capped at 64 MiB).
                                 Buffered: end the gateway with Ctrl-C or SIGTERM
                                 rather than SIGKILL, or the tail is lost
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

// A flag that was left at its default loses to the file; one that was given
// wins. Comparing against the default is how that is decided without a second
// optional per setting.
//
// This has to come AFTER `file` is declared and loaded, and the order is
// load-bearing in the worst way: in the main file, top-level variables are
// initialized in execution order, and reading one above its declaration does
// not trap -- it reads zeroed storage. `file.gatewayAddress` read early was a
// non-nil 0.0.0.0, every `??` default was skipped, and the gateway came up
// believing it was 0.0.0.0 on 0.0.0.0/0: bound, running, and answering ARP
// for nobody. Nothing named the problem; the guest simply never got a reply.
// Not given anywhere means "derive it from the subnet", which is what
// `Gateway.Configuration` does with nil and what upstream documents its
// --gatewayIP and --hostIP defaults as.
//
// This used to compare against the default string, which cannot tell "the user
// asked for 192.168.127.1" from "the user asked for nothing" -- and got the
// second wrong for every subnet but the default one. `--subnet 10.7.0.0/24`
// produced a gateway whose host.containers.internal answered 192.168.127.254,
// an address the guest cannot route to, while the control API answered
// perfectly and nothing said a word.
func parsedAddress(_ text: String?, _ flag: String) -> IPv4Address? {
    guard let text else { return nil }
    guard let parsed = IPv4Address(text) else {
        FileHandle.standardError.write(Data("error: \(flag) is not an address: \(text)\n".utf8))
        exit(2)
    }
    return parsed
}

let gatewayAddress = parsedAddress(options.gateway, "--gatewayIP") ?? file.gatewayAddress
let hostAddress = parsedAddress(options.host, "--hostIP") ?? file.hostAddress
let subnet: IPv4Subnet
if let text = options.subnet {
    guard let parsed = IPv4Subnet(cidr: text) else {
        FileHandle.standardError.write(Data("error: --subnet is not a CIDR block: \(text)\n".utf8))
        exit(2)
    }
    subnet = parsed
} else {
    subnet = file.subnet ?? IPv4Subnet(cidr: "192.168.127.0/24")!
}

// The wire is checked now: after the file has had its chance to be wrong about
// something more specific.
let wires = [options.listenPath, options.listenStream, options.listenSwitch].compactMap { $0 }
if wires.isEmpty {
    FileHandle.standardError.write(Data("error: \(OptionError.noWire)\n\n\(usage)\n".utf8))
    exit(2)
}
if wires.count > 1 {
    FileHandle.standardError.write(Data("error: \(OptionError.conflictingWires)\n".utf8))
    exit(2)
}

/// Block until the operator interrupts, and say which signal did it.
///
/// A free function rather than inline top-level code, and that is the whole
/// point of it. Every top-level binding in a `main.swift` is main-actor
/// isolated, so a Dispatch handler written up there captures main-actor state
/// and the runtime's isolation check trips the moment it runs -- and a signal
/// source runs on a Dispatch queue, never on the main one. The failure is a
/// `dispatch_assert_queue` trap with nothing on stderr, at the exact instant the
/// operator presses Ctrl-C. Written inline first; found by pressing Ctrl-C.
///
/// `SIG_IGN` first is not decoration either: a Dispatch signal source is *in
/// addition* to the disposition, so without it the default action kills the
/// process before the handler is ever reached.
func awaitTerminationSignal() -> Int32 {
    let received = NIOLockedValueBox<Int32>(SIGTERM)
    let arrived = DispatchSemaphore(value: 0)
    var sources: [DispatchSourceSignal] = []
    for number in [SIGINT, SIGTERM] {
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
        source.setEventHandler {
            received.withLockedValue { $0 = number }
            arrived.signal()
        }
        source.resume()
        sources.append(source)
    }
    arrived.wait()
    for source in sources { source.cancel() }
    return received.withLockedValue { $0 }
}

/// Where a control endpoint listens.
///
/// Upstream's `--listen` takes a URL, so a command line moved across carries
/// `unix:///run/gvproxy.sock` or `tcp://127.0.0.1:7070`. A bare path is accepted
/// too, because that is what this program took before it took a URL.
enum ControlEndpoint {
    case unix(String)
    case tcp(String, Int)
}

func controlEndpoint(_ text: String) throws -> ControlEndpoint {
    if text.hasPrefix("unix://") {
        return .unix(String(text.dropFirst("unix://".count)))
    }
    if text.hasPrefix("tcp://") {
        let rest = String(text.dropFirst("tcp://".count))
        guard let separator = rest.lastIndex(of: ":"), let port = Int(rest[rest.index(after: separator)...]),
            port > 0, port < 65536
        else { throw OptionError.badValue("--listen", text) }
        let host = String(rest[rest.startIndex..<separator])
        return .tcp(host.isEmpty ? "127.0.0.1" : host, port)
    }
    guard !text.contains("://") else { throw OptionError.badValue("--listen", text) }
    return .unix(text)
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
let logFile = options.logFile
if let logFile, FileLogHandler(label: "probe", path: logFile) == nil {
    FileHandle.standardError.write(Data("error: --log-file cannot be written: \(logFile)\n".utf8))
    exit(2)
}
LoggingSystem.bootstrap { label in
    if let logFile, var handler = FileLogHandler(label: label, path: logFile) {
        handler.logLevel = logLevel
        return handler
    }
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
    let path = wires[0]

    print("netstack-gateway: waiting for a guest on \(path)")
    let starting: EventLoopFuture<Gateway>
    if options.listenSwitch != nil {
        starting = Gateway.start(
            switchListeningOnStreamSocketAt: path, group: group, configuration: configuration)
    } else if options.listenStream != nil {
        starting = Gateway.start(listeningOnStreamSocketAt: path, group: group, configuration: configuration)
    } else {
        starting = Gateway.start(
            listeningOnDatagramSocketAt: path, group: group, configuration: configuration)
    }
    let gateway = try starting.wait()

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

    // One plane per endpoint. `--listen` is repeatable upstream, and the planes
    // are stateless over the gateway, so this is a listener each rather than
    // anything shared.
    var planes: [ControlPlane] = []
    for (endpoint, attaches) in options.controlEndpoints.map({ ($0, true) }) + options.servicesEndpoints.map({ ($0, false) }) {
        let plane = ControlPlane(gateway: gateway)
        plane.allowsGuestAttach = attaches
        switch try controlEndpoint(endpoint) {
        case .unix(let path):
            try plane.listen(unixSocketPath: path).wait()
        case .tcp(let host, let port):
            try plane.listen(host: host, port: port).wait()
        }
        planes.append(plane)
        print("netstack-gateway: \(attaches ? "control API" : "services API") on \(endpoint)")
    }
    _ = planes

    // Written after everything is listening, so a supervisor that reads it as
    // "ready" is not told so before the sockets exist.
    if let pidFile = options.pidFile {
        do {
            try Data("\(getpid())\n".utf8).write(to: URL(fileURLWithPath: pidFile))
        } catch {
            FileHandle.standardError.write(Data("error: --pid-file cannot be written: \(error)\n".utf8))
            exit(2)
        }
    }

    // Logged as well as printed, and this is the reason: a log file that stays
    // empty until something goes wrong is indistinguishable from a log file that
    // was never opened. One line at startup tells an operator which they have,
    // at the only moment they can still do something about it.
    Logger(label: "netstack").notice(
        "running",
        metadata: [
            "wire": .string(path),
            "gateway": .string(configuration.gatewayAddress.description),
            "subnet": .string(configuration.subnet.description),
        ])
    print("netstack-gateway: running")

    // Interrupted rather than killed.
    //
    // The gateway is entirely event-driven, so the main thread's only job is to
    // wait for a reason to stop. It used to park for a year and there was no
    // such reason: the process only ever ended by dying where it stood, which
    // for `--pcap` meant the operator got an empty file. The capture buffers
    // frames -- a write syscall per frame would cost more than the stack spends
    // on the frame -- and nothing flushed it, not even its own header. Ctrl-C on
    // a capture is not an unusual way to end one; it is the usual way.
    //
    // `close()` walks the same path as any other shutdown and flushes the
    // capture on the way through, so this needs no knowledge of what is being
    // closed.
    let received = awaitTerminationSignal()
    print("netstack-gateway: stopping on \(received == SIGINT ? "SIGINT" : "SIGTERM")")
    try? gateway.close().wait()
    try? group.syncShutdownGracefully()
    // Removed only on a clean stop. A PID file left behind by a crash is how a
    // supervisor finds out there was one.
    if let pidFile = options.pidFile { try? FileManager.default.removeItem(atPath: pidFile) }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
