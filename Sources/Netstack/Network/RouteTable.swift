/// One entry in the route table.
public struct Route: Sendable, Equatable {
    public let destination: IPv4Subnet
    /// nil means the destination is directly reachable on the link.
    public let gateway: IPv4Address?
    public let nicID: Int

    public init(destination: IPv4Subnet, gateway: IPv4Address?, nicID: Int) {
        self.destination = destination
        self.gateway = gateway
        self.nicID = nicID
    }
}

/// A route with everything transmission needs already decided.
public struct ResolvedRoute {
    public let nic: NIC
    public let source: IPv4Address
    /// The address to resolve to a MAC — the destination itself when on-link,
    /// otherwise the gateway.
    public let nextHop: IPv4Address
    public let isLocal: Bool
    /// Whether `source` is the `preferredSource` that was actually asked
    /// for. `false` means `lookup` fell back to the NIC's primary address
    /// because the caller asked for one it neither owns nor is allowed to
    /// spoof — a real request that could not be honoured, not the absence
    /// of a preference. A caller that cares which one happened (`send` does:
    /// answering from the wrong address is worse than not answering at all)
    /// must check this rather than infer it from `source` alone, since a
    /// fallback that happens to equal the primary address is otherwise
    /// indistinguishable from a caller that never asked for anything else.
    public let sourceWasHonoured: Bool
}

/// Longest-prefix route lookup with spoof-aware source selection.
///
/// Loop-confined, so no lock. The table is small enough — a handful of
/// entries — that a linear scan beats any structure with an index to maintain.
public final class RouteTable {
    private var routes: [Route] = []
    // Deliberately strong. `Stack` owns both this table and every `NIC`
    // registered into it, so their lifetimes already coincide — nothing
    // requires `RouteTable` to outlive a `NIC` it looks up, so there is no
    // ownership reason to weaken this. It used to be the other half of a
    // retain cycle (`NIC.handlers` -> `IPv4Protocol` -> `RouteTable.nics` ->
    // `NIC`), but that cycle is closed by making `IPv4Protocol`'s handler
    // closures capture `ipv4` weakly in `Stack.start()` instead — the
    // correct edge to cut, since it is the one closure-captured reference
    // that does not already reflect real ownership. Weakening this
    // dictionary too would be redundant and would let a route resolve to a
    // `nil` NIC the moment nothing else happened to be holding it, which is
    // not a state this table should ever need to represent.
    private var nics: [Int: NIC] = [:]

    public init() {}

    public func register(_ nic: NIC) {
        nics[nic.id] = nic
    }

    public func add(_ route: Route) {
        routes.append(route)
        // Longest prefix first, so the first match is the best match.
        routes.sort { $0.destination.prefixLength > $1.destination.prefixLength }
    }

    /// Resolve how to reach `destination`.
    ///
    /// `preferredSource` is honoured when the NIC owns it, or when the NIC has
    /// `allowsAnySource` set. That second case is spec §4.3: the gateway
    /// terminates a guest connection to an arbitrary host and must answer
    /// wearing that host's address.
    public func lookup(destination: IPv4Address, preferredSource: IPv4Address?) -> ResolvedRoute? {
        for route in routes {
            guard route.destination.contains(destination), let nic = nics[route.nicID] else { continue }

            let source: IPv4Address
            let sourceWasHonoured: Bool
            if let preferred = preferredSource, nic.hasAddress(preferred) || nic.allowsAnySource {
                source = preferred
                sourceWasHonoured = true
            } else if let primary = nic.primaryAddress {
                source = primary
                sourceWasHonoured = preferredSource == nil
            } else {
                continue
            }

            return ResolvedRoute(
                nic: nic,
                source: source,
                nextHop: route.gateway ?? destination,
                isLocal: route.gateway == nil,
                sourceWasHonoured: sourceWasHonoured
            )
        }
        return nil
    }
}
