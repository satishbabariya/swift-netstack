import Foundation
import NIOCore
import Netstack

/// `--config`, in the shape of upstream's `types.Configuration`.
///
/// ## Why JSON where upstream reads YAML
///
/// gvproxy reads YAML. A YAML parser is a dependency, and every program that
/// links `Netstack` would carry it in its graph to serve a flag only this
/// executable has. JSON is already here -- `ControlPlane` parses it -- and the
/// field names, nesting and meanings are upstream's exactly, so a YAML config
/// converts with any of the one-line tools that do that and nothing has to be
/// re-learned.
///
/// A file that is YAML rather than JSON is refused with a message that says so,
/// rather than "could not parse": the difference between "your file is wrong"
/// and "this program wants the same file in another notation" is the whole
/// content of that error.
struct FileConfiguration {
    var gatewayAddress: IPv4Address?
    var hostAddress: IPv4Address?
    var subnet: IPv4Subnet?
    var linkAddress: MACAddress?
    var mtu: UInt32?
    var searchDomains: [String] = []
    var staticLeases: [MACAddress: IPv4Address] = [:]
    var nat: [IPv4Address: IPv4Address]?
    /// Upstream's `vpnKitUUIDMacAddresses`: the address to hand a vpnkit guest,
    /// by the UUID hyperkit sends during the handshake.
    var vpnKitAddresses: [String: MACAddress] = [:]
    var virtualAddresses: [IPv4Address]?
    var allowsLinkLocal: Bool?
    var maximumHalfOpen: Int?
    var dialTimeout: Int?
    var zones: [DNSServer.Zone] = []
    /// Upstream's `forwards` is host address to guest address, both `host:port`.
    /// A forward's transport, which upstream spells as a prefix on the host side
    /// of the entry: `"udp:127.0.0.1:5353": "192.168.127.2:53"`.
    ///
    /// Without this the prefix was skipped and every entry became a TCP forward,
    /// because the parser took the last colon-separated component as the port
    /// and `udp:127.0.0.1:5353` ends in one. A DNS forward -- the reason the
    /// prefix exists -- listened on TCP and never saw a datagram.
    enum Transport { case tcp, udp }

    var forwards: [(host: Int, guest: String, guestPort: UInt16, transport: Transport)] = []
    var debug = false
    var captureFile: String?

    enum Failure: Error, CustomStringConvertible {
        case unreadable(String)
        case looksLikeYAML(String)
        case malformed(String)
        case badValue(String, String)

        var description: String {
            switch self {
            case .unreadable(let path): return "cannot read \(path)"
            case .looksLikeYAML(let path):
                return
                    "\(path) looks like YAML. gvproxy reads YAML; this reads the same configuration as "
                    + "JSON, because a YAML parser would be a dependency of every program that links "
                    + "this library. The field names are identical."
            case .malformed(let path): return "\(path) is not a JSON object"
            case .badValue(let field, let text): return "\(field) is not valid: \(text)"
            }
        }
    }

    /// Everything defaulted, for the case where no `--config` was given.
    init() {}

    init(contentsOf path: String) throws {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw Failure.unreadable(path)
        }
        let object = try? JSONSerialization.jsonObject(with: data)
        guard let fields = object as? [String: Any] else {
            // A YAML document nearly always starts with a bare key, a comment or
            // a document marker, none of which begin a JSON object.
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.hasPrefix("{") { throw Failure.looksLikeYAML(path) }
            throw Failure.malformed(path)
        }

        func string(_ name: String) -> String? { jsonField(fields, name) as? String }
        func address(_ name: String) throws -> IPv4Address? {
            guard let text = string(name) else { return nil }
            guard let parsed = IPv4Address(text) else { throw Failure.badValue(name, text) }
            return parsed
        }

        gatewayAddress = try address("gatewayIP")
        hostAddress = try address("hostIP")
        if let text = string("subnet") {
            guard let parsed = IPv4Subnet(cidr: text) else { throw Failure.badValue("subnet", text) }
            subnet = parsed
        }
        if let text = string("gatewayMacAddress") {
            guard let parsed = MACAddress(text) else {
                throw Failure.badValue("gatewayMacAddress", text)
            }
            linkAddress = parsed
        }
        // A number that is present and wrong is refused, not dropped.
        //
        // Every structured field below already throws on bad content -- `nat`,
        // `forwards`, `dhcpStaticLeases`, `gatewayVirtualIPs` -- and the scalars
        // did not. The range test on `mtu` was a condition of the `if let`, so
        // `{"mtu": 100}` left the field nil and started a gateway on 1500 while
        // `--mtu 100` was refused outright. The same program given the same
        // value in two places answered two different ways, and the silent one
        // is the one an operator cannot see.
        func integer(_ name: String, atLeast low: Int, atMost high: Int) throws -> Int? {
            guard let value = jsonField(fields, name) else { return nil }
            guard let number = value as? Int else {
                // The type, not just the text. JSON quotes do not survive into
                // the message, so `{"mtu": "1500"}` reported `mtu is not valid:
                // 1500` -- which reads as a complaint about 1500, a perfectly
                // good MTU, rather than about its being a string.
                throw Failure.badValue(name, "\(value), which is not a whole number")
            }
            guard number >= low, number <= high else {
                throw Failure.badValue(name, "\(number), which is outside \(low)...\(high)")
            }
            return number
        }

        mtu = try integer("mtu", atLeast: 576, atMost: 65535).map(UInt32.init)
        debug = (jsonField(fields, "debug") as? Bool) ?? false
        captureFile = string("capture-file") ?? string("captureFile")
        allowsLinkLocal = jsonField(fields, "ec2MetadataAccess") as? Bool
        // Upper bounds are the largest number that is not obviously a mistake
        // rather than anything this program enforces: what matters is that zero
        // and negatives are refused here instead of becoming a gateway that
        // refuses every connection, or a dial that times out before it starts.
        maximumHalfOpen = try integer("tcpMaxInFlight", atLeast: 1, atMost: 1_000_000)
        dialTimeout = try integer("tcpConnectTimeout", atLeast: 1, atMost: 86400)
        searchDomains = (jsonField(fields, "dnsSearchDomains") as? [String]) ?? []

        for (mac, ip) in (jsonField(fields, "dhcpStaticLeases") as? [String: String]) ?? [:] {
            guard let hardware = MACAddress(mac), let leased = IPv4Address(ip) else {
                throw Failure.badValue("dhcpStaticLeases", "\(mac): \(ip)")
            }
            staticLeases[hardware] = leased
        }
        if let table = jsonField(fields, "nat") as? [String: String] {
            var translations: [IPv4Address: IPv4Address] = [:]
            for (from, to) in table {
                guard let source = IPv4Address(from), let target = IPv4Address(to) else {
                    throw Failure.badValue("nat", "\(from): \(to)")
                }
                translations[source] = target
            }
            nat = translations
        }
        if let table = jsonField(fields, "vpnKitUUIDMacAddresses") as? [String: String] {
            var addresses: [String: MACAddress] = [:]
            for (uuid, text) in table {
                guard let address = MACAddress(text) else {
                    throw Failure.badValue("vpnKitUUIDMacAddresses", "\(uuid): \(text)")
                }
                addresses[uuid] = address
            }
            vpnKitAddresses = addresses
        }
        if let list = jsonField(fields, "gatewayVirtualIPs") as? [String] {
            virtualAddresses = try list.map {
                guard let parsed = IPv4Address($0) else { throw Failure.badValue("gatewayVirtualIPs", $0) }
                return parsed
            }
        }
        // `forwards` maps a host endpoint to a guest one, both `host:port`, and
        // upstream's own default omits the host on the left.
        for (local, remote) in (jsonField(fields, "forwards") as? [String: String]) ?? [:] {
            // `udp:` in front of the host side means a datagram forward, which is
            // upstream's spelling. Anything else is TCP.
            let transport: Transport = local.hasPrefix("udp:") ? .udp : .tcp
            let hostSide = transport == .udp ? String(local.dropFirst("udp:".count)) : local
            guard let hostPort = Int(hostSide.split(separator: ":").last ?? ""),
                let separator = remote.lastIndex(of: ":"),
                let guestPort = UInt16(remote[remote.index(after: separator)...]),
                IPv4Address(String(remote[remote.startIndex..<separator])) != nil
            else { throw Failure.badValue("forwards", "\(local): \(remote)") }
            forwards.append(
                (hostPort, String(remote[remote.startIndex..<separator]), guestPort, transport))
        }

        for entry in (jsonField(fields, "dns") as? [[String: Any]]) ?? [] {
            guard let name = jsonField(entry, "name") as? String else {
                throw Failure.badValue("dns", "a zone with no name")
            }
            var records: [DNSServer.Zone.Record] = []
            for record in (jsonField(entry, "records") as? [[String: Any]]) ?? [] {
                guard let recordName = jsonField(record, "name") as? String else {
                    throw Failure.badValue("dns", "a record with no name in \(name)")
                }
                records.append(
                    DNSServer.Zone.Record(
                        name: recordName,
                        address: (jsonField(record, "ip") as? String).flatMap(IPv4Address.init),
                        pattern: jsonField(record, "regexp") as? String))
            }
            zones.append(
                DNSServer.Zone(
                    name: name, records: records,
                    defaultAddress: (jsonField(entry, "defaultIP") as? String).flatMap(IPv4Address.init),
                    // A zone from the configuration file is the operator's, so
                    // it is protected from the control API for the same reason
                    // the built-in ones are: it is what the guests were pointed
                    // at.
                    isProtected: (jsonField(entry, "protected") as? Bool) ?? true))
        }
    }
}
