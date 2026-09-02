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
    var listenStdio = false
    var listenVpnKit: String?
    var listenBess: String?
    var controlEndpoints: [String] = []
    var servicesEndpoints: [String] = []
    var pidFile: String?
    var logFile: String?
    var upstreamResolver: String?
    var gateway: String?
    var subnet: String?
    // Optional, not 1500, for the reason `parsedAddress` records below: a
    // default stored in the field cannot tell "the user asked for 1500" from
    // "the user asked for nothing", and the merge below has to. `--mtu 1500`
    // against a config file saying 9000 told the guest 9000.
    var mtu: UInt32?
    var logLevel = "notice"
    var captureFile: String?
    var notifySocket: String?
    var host: String?
    var allowsLinkLocal = false
    typealias Forward = (host: Int, guest: String, guestPort: UInt16, transport: FileConfiguration.Transport)
    var forwards: [Forward] = []

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
        // A value attached with `=`, when the caller wrote one.
        var attached: String?
        func value(_ flag: String) throws -> String {
            if let attached { return attached }
            index += 1
            guard index < arguments.count else { throw OptionError.missingValue(flag) }
            return arguments[index]
        }
        while index < arguments.count {
            let argument = arguments[index]

            // One dash or two, and a value beside the flag or after it.
            //
            // Go's `flag` package treats `-x` and `--x` as the same flag and
            // accepts `-x=v` as well as `-x v`, so every gvproxy command line
            // in the wild uses whichever its author preferred -- its own README
            // uses one dash, and so does the `sandbox` that spawns it:
            //
            //     "-listen-vfkit", "unixgram://\(gatewaySocket.path)",
            //
            // This took two dashes and a separate value, and answered anything
            // else with `unknown option -listen-vfkit`. The flag names were
            // gvproxy's and the command lines still did not move across.
            attached = nil
            var flag = argument
            if let equals = flag.firstIndex(of: "="), flag.hasPrefix("-") {
                attached = String(flag[flag.index(after: equals)...])
                flag = String(flag[flag.startIndex..<equals])
            }
            if flag.hasPrefix("-"), !flag.hasPrefix("--"), flag.count > 1 {
                flag = "-" + flag
            }
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
            case "--listen-vfkit":
                options.listenPath = try wirePath(value(flag), flag, datagram: true)
            case "--listen-qemu":
                options.listenStream = try wirePath(value(flag), flag, datagram: false)
            case "--listen-switch":
                options.listenSwitch = try wirePath(value(flag), flag, datagram: false)
            case "--listen-stdio":
                // Upstream takes a value here and only checks that it is not
                // empty, so the value is consumed and ignored the same way.
                _ = try value(flag)
                options.listenStdio = true
            case "--listen-vpnkit":
                options.listenVpnKit = try wirePath(value(flag), flag, datagram: false)
            case "--listen-bess":
                options.listenBess = try wirePath(value(flag), flag, datagram: false)
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
                // `8080:192.168.127.2:80`, or `udp:5353:192.168.127.2:53`.
                //
                // The prefix is the same one the config file's forwards take,
                // and it is here for that reason: an operator who can ask for a
                // datagram forward in a file and not on the command line has to
                // discover that, and the way they discover it is a forward that
                // listens on the right port over the wrong transport.
                let text = try value(flag)
                let transport: FileConfiguration.Transport =
                    text.hasPrefix("udp:") ? .udp : .tcp
                let body = transport == .udp ? String(text.dropFirst("udp:".count)) : text
                let parts = body.split(separator: ":", omittingEmptySubsequences: false)
                guard parts.count == 3, let host = Int(parts[0]), let guestPort = UInt16(parts[2]),
                    IPv4Address(String(parts[1])) != nil
                else { throw OptionError.badValue(flag, text) }
                options.forwards.append((host, String(parts[1]), guestPort, transport))
            case "--help", "-h":
                throw OptionError.help
            default:
                // The spelling the caller used, not the one this normalised it
                // to: an error naming `--bogus` when they wrote `-bogus` sends
                // them looking for a flag they did not type.
                throw OptionError.unknown(argument)
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
        case .conflictingWires:
            return "--listen-vfkit, --listen-qemu, --listen-switch, --listen-vpnkit, "
                + "--listen-bess and --listen-stdio are different wires; pick one"
        case .noWire:
            return
                "no guest wire: pass --listen-vfkit <path> for a datagram socket, --listen-qemu "
                + "<path> for a stream one, --listen-switch <path> for a stream socket that "
                + "carries several guests, or --listen-stdio for this process's own pipes. "
                + "(--listen is the control API, as in gvproxy.)"
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
      --listen-bess <path>       SOCK_SEQPACKET socket carrying bare frames, one
                                 per message. Carries several guests. Not on
                                 macOS, which has no SOCK_SEQPACKET for AF_UNIX
      --listen-vpnkit <path>     Stream socket speaking hyperkit's vpnkit
                                 protocol: a handshake, then two little-endian
                                 length bytes per frame. Carries several guests
      --listen-stdio <ignored>   The wire is this process's own stdin and stdout,
                                 framed with two little-endian length bytes. Every
                                 message this program prints goes to stderr then,
                                 because stdout is the wire
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
      --forward <h:addr:g>       Publish guest addr:g on host port h, repeatable.
                                 Prefix with udp: for a datagram forward

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
let wires =
    [
        options.listenPath, options.listenStream, options.listenSwitch, options.listenVpnKit,
        options.listenBess,
    ].compactMap { $0 } + (options.listenStdio ? ["(stdin and stdout)"] : [])
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
/// Send one `hypervisor_error` and wait for it to leave.
///
/// Synchronous, unlike `NotificationSender`, which queues and delivers later:
/// the caller of this is about to exit, and a queued notification would go with
/// it. Same socket, same one-object-per-connection shape and same trailing
/// newline, so a supervisor written against gvproxy reads it the same way.
///
/// Every failure here is silent on purpose. Nothing is listening is the
/// ordinary case -- `--notification` names where to send, not a promise that
/// somebody is there -- and the error being reported has already been printed.
/// The path in a wire endpoint, in either spelling.
///
/// Upstream requires a URL and this took a bare path, so a gvproxy command line
/// did not move across for any wire -- the flag names matched and the values did
/// not parse. `-listen-vfkit unixgram:///run/vm.sock` tried to bind a socket
/// named `unixgram:///run/vm.sock`:
///
///     error: bind unixgram:///.../w.sock: No such file or directory (errno: 2)
///
/// That is what a VM host actually passes. `VZFileHandleNetworkDeviceAttachment`
/// takes a datagram socket, and the tools that drive it hand gvproxy the URL its
/// transport requires: `unixgram://` for the vfkit wire, `unix://` for the
/// stream ones.
///
/// A bare path still works. It is what every example here uses, it is what
/// somebody types by hand, and refusing it to match upstream exactly would be
/// pedantry rather than compatibility.
///
/// A scheme that belongs to neither is refused with the scheme named, because
/// upstream serves the stream wires over `tcp://` as well and this does not: a
/// gateway that bound a file called `tcp://0.0.0.0:1234` would be a worse answer
/// than saying so.
func wirePath(_ text: String, _ flag: String, datagram: Bool) throws -> String {
    let expected = datagram ? "unixgram" : "unix"
    guard let separator = text.range(of: "://") else { return text }
    let scheme = String(text[text.startIndex..<separator.lowerBound])
    guard scheme == expected else {
        throw OptionError.badValue(flag, "\(text) -- \(flag) takes a path or \(expected)://")
    }
    return String(text[separator.upperBound...])
}

/// The host's DNS search list, as a guest should inherit it.
///
/// Reading the file is here rather than in the library: a library that opens
/// `/etc/resolv.conf` has decided something for every program that links it, and
/// this program is the one that is meant to behave like gvproxy. The parsing and
/// the limits are `DNSServer.searchDomains(inResolvConf:applyingDarwinLimits:)`.
///
/// An unreadable file is an empty list rather than an error. A host with no
/// search list is ordinary, and a gateway that refused to start because it could
/// not read one would be worse than a guest with no search domains.
func hostSearchDomains() -> [String] {
    #if canImport(Darwin)
        let darwin = true
    #else
        let darwin = false
    #endif
    guard let text = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) else {
        return []
    }
    return DNSServer.searchDomains(inResolvConf: text, applyingDarwinLimits: darwin)
}

func reportHypervisorError(toSocketAt path: String?, group: EventLoopGroup) {
    guard let path else { return }
    guard let address = try? SocketAddress(unixDomainSocketPath: path) else { return }
    guard let channel = try? ClientBootstrap(group: group).connect(to: address).wait() else {
        return
    }
    var buffer = channel.allocator.buffer(capacity: 64)
    buffer.writeString(NetstackNotification(kind: .hypervisorError).json)
    buffer.writeString("\n")
    try? channel.writeAndFlush(buffer).wait()
    try? channel.close().wait()
}

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

/// Say something, on the right descriptor.
///
/// `--listen-stdio` makes stdout the wire, and a line printed there lands in the
/// middle of a frame -- the guest's decoder reads its first two bytes as a
/// length and everything after that is noise. So every message this program
/// prints goes through here, and goes to stderr when stdout is spoken for.
func announce(_ text: String, toStandardError: Bool) {
    if toStandardError {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    } else {
        print(text)
    }
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
    linkAddress: file.linkAddress ?? MACAddress("5a:94:ef:e4:0c:dd")!,
    hostAddress: hostAddress, nat: file.nat,
    // The file's map when it has one, upstream's default when it does not: the
    // UUID in that default is the one podman sends, and a guest handed an
    // invented address instead gets a different one on every run.
    vpnKitAddresses: file.vpnKitAddresses.isEmpty
        ? Gateway.Configuration.upstreamVpnKitAddresses : file.vpnKitAddresses,
    gatewayVirtualAddresses: file.virtualAddresses,
    allowsLinkLocal: options.allowsLinkLocal || (file.allowsLinkLocal ?? false),
    captureFile: options.captureFile ?? file.captureFile,
    notificationSocketPath: options.notifySocket,
    // Announced by this program once its endpoints are listening, not by
    // assembly: see below.
    announcesReadyWhenAssembled: false,
    mtu: options.mtu ?? file.mtu ?? 1500,
    dnsRecords: nil, upstreamResolvers: resolvers,
    dhcpStaticLeases: file.staticLeases,
    // The host's list when nothing else named one, which is what gvproxy does
    // for every gateway it starts without a config file. Without it a guest
    // resolving a short name the host can resolve gets nothing.
    dnsSearchDomains: file.searchDomains.isEmpty ? hostSearchDomains() : file.searchDomains,
    maximumHalfOpenConnections: file.maximumHalfOpen ?? 512,
    tcpDialTimeout: file.dialTimeout.map { .seconds(Int64($0)) } ?? .seconds(5),
    logger: Logger(label: "netstack"))

do {
    // The wire is a socket this process creates and listens on: the VM connects
    // to it. That is the shape vfkit and qemu expect -- they are given a path and
    // dial it -- and it is why this waits for a connection rather than adopting a
    // descriptor the way an embedding host does.
    // Refused before anything is bound. A gateway that comes up on a
    // configuration like this runs perfectly and serves nobody, which is the
    // hardest kind of failure to be told about later.
    let problems = configuration.inconsistencies
    if !problems.isEmpty {
        for problem in problems {
            FileHandle.standardError.write(Data("error: \(problem)\n".utf8))
        }
        exit(2)
    }

    let path = wires[0]

    announce("netstack-gateway: waiting for a guest on \(path)", toStandardError: options.listenStdio)
    let starting: EventLoopFuture<Gateway>
    if options.listenStdio {
        // Ownership of both descriptors passes to NIO, which closes them with
        // the channel. Nothing may print to stdout from here on -- see
        // `announce`.
        starting = Gateway.start(
            overPipes: STDIN_FILENO, output: STDOUT_FILENO, group: group,
            configuration: configuration)
    } else if options.listenBess != nil {
        starting = Gateway.start(
            bessListeningOnSeqPacketSocketAt: path, group: group, configuration: configuration)
    } else if options.listenVpnKit != nil {
        starting = Gateway.start(
            vpnKitListeningOnStreamSocketAt: path, group: group, configuration: configuration)
    } else if options.listenSwitch != nil {
        starting = Gateway.start(
            switchListeningOnStreamSocketAt: path, group: group, configuration: configuration)
    } else if options.listenStream != nil {
        starting = Gateway.start(listeningOnStreamSocketAt: path, group: group, configuration: configuration)
    } else {
        starting = Gateway.start(
            listeningOnDatagramSocketAt: path, group: group, configuration: configuration)
    }
    let gateway: Gateway
    do {
        gateway = try starting.wait()
    } catch {
        // Tell the supervisor the hypervisor's socket could not be served,
        // which is what gvproxy does on exactly this path:
        //
        //     qemuListener, err := transport.Listen(config.Interfaces.Qemu)
        //     if err != nil {
        //         notificationSender.Send(types.NotificationMessage{
        //             NotificationType: types.HypervisorError})
        //         return fmt.Errorf("qemu listen error: %w", err)
        //     }
        //
        // Only here, not from the outer catch: that one also covers a bad flag
        // and an unreadable config file, and telling a supervisor its
        // hypervisor failed because somebody mistyped an address would be
        // worse than telling it nothing.
        //
        // `ready` is sent by the gateway once it is assembled, so nothing on
        // this path had a sender at all -- a wire that could not bind produced
        // a message on stderr and silence on the socket a supervisor watches.
        reportHypervisorError(toSocketAt: options.notifySocket, group: group)
        throw error
    }

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
        // Reported with the forward that failed, not just the errno.
        //
        // A host port already in use is the ordinary way this goes wrong, and
        // the bare failure -- "bind(descriptor:ptr:bytes:): Address already in
        // use" -- names neither the port nor which of several --forward flags
        // asked for it. An operator publishing four ports learns only that one
        // of them is taken.
        do {
            switch forward.transport {
            case .tcp:
                _ = try gateway.forward(
                    hostPort: forward.host, toGuest: address, port: forward.guestPort
                ).wait()
            case .udp:
                _ = try gateway.forwardUDP(
                    hostPort: forward.host, toGuest: address, port: forward.guestPort
                ).wait()
            }
        } catch {
            let protocolName = forward.transport == .udp ? "udp" : "tcp"
            FileHandle.standardError.write(
                Data(
                    ("error: cannot publish \(forward.guest):\(forward.guestPort) on "
                        + "127.0.0.1:\(forward.host) over \(protocolName): \(error)\n").utf8))
            exit(1)
        }
        announce(
            "netstack-gateway: publishing \(forward.guest):\(forward.guestPort) on "
                + "127.0.0.1:\(forward.host) over \(forward.transport == .udp ? "udp" : "tcp")",
            toStandardError: options.listenStdio)
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
        announce("netstack-gateway: \(attaches ? "control API" : "services API") on \(endpoint)", toStandardError: options.listenStdio)
    }
    // The endpoint the guest reaches, at the gateway's own address inside the
    // virtual network. gvproxy binds one at <gatewayIP>:80 carrying exactly the
    // three forwarding routes, so a container can publish its own port over the
    // network it already has, with no socket on the host. Not behind a flag
    // there, so not behind one here.
    let guestPlane = ControlPlane(gateway: gateway)
    try guestPlane.listenForGuests().wait()
    planes.append(guestPlane)
    _ = planes

    // Logged first of the three, because the two below are what something else
    // waits on and this is what a person reads afterwards.
    //
    // A log file that stays empty until something goes wrong is indistinguishable
    // from one that was never opened. One line at startup tells an operator which
    // they have, at the only moment they can still do something about it.
    //
    // It used to come last. The pid file is written before it and is what a
    // supervisor waits on -- `theOperatorsFlagsDoWhatTheirNamesSay` waits for
    // exactly that and then reads the log -- so there was a window where the pid
    // file was there and the log was empty. Moving `ready` between them widened
    // it from a hop to a hop plus a wait, and the test began failing about one
    // run in three. The window was always there; it was not always wide enough
    // to land in.
    Logger(label: "netstack").notice(
        "running",
        metadata: [
            "wire": .string(path),
            "gateway": .string(configuration.gatewayAddress.description),
            "subnet": .string(configuration.subnet.description),
        ])

    // Then the pid file, which is written after everything is listening so that
    // a supervisor reading it as "ready" is not told so before the sockets
    // exist.
    if let pidFile = options.pidFile {
        do {
            try Data("\(getpid())\n".utf8).write(to: URL(fileURLWithPath: pidFile))
        } catch {
            FileHandle.standardError.write(Data("error: --pid-file cannot be written: \(error)\n".utf8))
            exit(2)
        }
    }

    // And `ready` last of all, for the reason the pid file above is written
    // where it is.
    //
    // It used to be sent at the end of assembly, inside the library, which is
    // before this program binds anything. The comment at that send site said a
    // supervisor acting on `ready` "must not do so before the services it will
    // talk to are listening" -- true, and not something assembly can arrange,
    // because these endpoints are bound out here. Measured before the change:
    //
    //     notification:            {"notification_type":"ready"}
    //     control socket exists:   False
    //
    // The pid file had already been moved down here for exactly this reason.
    // The signal a supervisor actually waits on had not.
    try gateway.eventLoop.submit { gateway.announceReady() }.wait()

    announce("netstack-gateway: running", toStandardError: options.listenStdio)

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
    announce("netstack-gateway: stopping on \(received == SIGINT ? "SIGINT" : "SIGTERM")", toStandardError: options.listenStdio)
    try? gateway.close().wait()
    try? group.syncShutdownGracefully()
    // Removed only on a clean stop. A PID file left behind by a crash is how a
    // supervisor finds out there was one.
    if let pidFile = options.pidFile { try? FileManager.default.removeItem(atPath: pidFile) }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
