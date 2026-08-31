import NIOCore

extension Gateway {
    /// Everything this gateway counts, read at one instant.
    ///
    /// A snapshot rather than live accessors on the components, for a reason
    /// that matters to anyone graphing it: the counters live on the event loop
    /// and a monitoring caller does not, so reading them one at a time from
    /// another thread is a data race producing numbers that never coexisted.
    /// `Gateway.statistics()` hops to the loop once and copies all of them,
    /// which makes the result a consistent set -- refusals and establishments
    /// that really do add up.
    ///
    /// These are **monotonic totals**, not rates and not gauges, with two
    /// exceptions named below. Counters that only ever rise are the ones a
    /// monitoring system can handle correctly across a restart; a rate computed
    /// here would be a rate over a window this type does not get to choose.
    public struct Statistics: Sendable, Equatable {
        /// Bytes that crossed the wire, in each direction. Upstream reports the
        /// same two, and they are the first thing anyone asks of a network that
        /// is not working: whether anything is moving at all.
        public var bytesReceived: Int
        public var bytesSent: Int

        /// What happened to the packets that reached the IPv4 layer. Each is a
        /// place a packet is dropped and nothing is said, which is the state an
        /// operator cannot debug.
        public var ipv4Received: Int
        public var ipv4Malformed: Int
        public var ipv4NotForThisStack: Int
        public var ipv4Expired: Int
        public var ipv4AwaitingFragments: Int
        public var ipv4Delivered: Int
        public var ipv4UnknownProtocol: Int

        /// Echo requests sent to a real destination rather than answered here.
        public var icmpForwarded: Int
        /// Echo requests that got no answer before their deadline.
        public var icmpTimedOut: Int

        /// Frames from the guest that this wire would not carry.
        public var inboundFramesRejected: Int
        /// Frames this stack could not put on the wire.
        public var outboundFramesRejected: Int
        /// Frames the wire had nowhere to put because the guest is not reading.
        ///
        /// The one an operator chasing "the network is lossy" actually wants: it
        /// says the loss is at the guest's end of the wire and not this stack's.
        /// It was counted from the day backpressure was added and reported
        /// nowhere until long after.
        public var outboundFramesBackedUp: Int

        /// Guest TCP connections currently spliced to a host socket. A **gauge**.
        public var tcpEstablished: Int
        /// Guest connections refused because the connection limit was reached.
        public var tcpRefusedByLimit: Int
        /// Guest connections refused because the destination did not accept.
        public var tcpDialFailed: Int
        /// Guest connections refused for being to a link-local address --
        /// 169.254.169.254 above all, the cloud instance metadata service.
        ///
        /// Counted separately from every other refusal because it is the one an
        /// operator has to be able to tell apart. "My guest cannot reach the
        /// metadata service" has two answers -- policy, or the service is not
        /// there -- and they call for opposite actions. Without this the two
        /// look identical from outside: a refusal and a failed dial both end as
        /// a reset on the guest's connection.
        public var tcpRefusedLinkLocal: Int

        /// Guest UDP flows currently holding a host socket. A **gauge**.
        public var udpFlows: Int
        /// Host sockets opened for guest flows, ever. Compare with `udpFlows`:
        /// the difference is how much churn the guest is causing.
        public var udpSocketsOpened: Int
        /// Datagrams dropped because the flow limit was reached.
        public var udpRefusedByLimit: Int
        /// Flows closed early to make room for a new one.
        public var udpReclaimed: Int

        /// Queries answered from this gateway's own records.
        public var dnsAnsweredLocally: Int
        /// Queries sent to an upstream resolver.
        public var dnsForwarded: Int
        /// Queries refused because too many were already outstanding.
        public var dnsRefusedByLimit: Int
        /// Queries refused because no upstream resolver is configured. A
        /// non-zero value here is nearly always a configuration mistake rather
        /// than anything the guest did.
        public var dnsRefusedNoUpstream: Int
        /// Replies from upstream that matched no outstanding query.
        public var dnsUnmatchedReplies: Int

        /// Addresses currently leased. A **gauge**.
        public var dhcpLeases: Int
        /// Requests that found no free address in the pool.
        public var dhcpPoolExhausted: Int

        /// Host ports currently published to the guest. A **gauge**.
        public var forwardedPorts: Int

        /// Guests connected to the switch, when there is one. A **gauge**;
        /// always zero for a gateway on a single wire.
        public var switchPorts: Int
        /// Frames dropped for naming an address on no port the switch knows.
        public var switchUnknownUnicastDropped: Int
        /// Source addresses not learned because a port had claimed its limit.
        public var switchAddressesRefused: Int
        /// Addresses that moved between ports: a guest reconnecting, or one
        /// guest claiming another's address.
        public var switchAddressesMoved: Int
    }

    /// Read every counter, on the event loop, as one consistent set.
    public func statistics() -> EventLoopFuture<Statistics> {
        eventLoop.submit { self.statisticsOnLoop() }
    }

    /// The same snapshot for a caller already on the event loop.
    public func statisticsOnLoop() -> Statistics {
        eventLoop.preconditionInEventLoop()
        let ipv4 = stack.ipv4.counters
        return Statistics(
            bytesReceived: link.bytesReceived,
            bytesSent: link.bytesSent,
            ipv4Received: ipv4.received,
            ipv4Malformed: ipv4.malformed,
            ipv4NotForThisStack: ipv4.notForThisStack,
            ipv4Expired: ipv4.expired,
            ipv4AwaitingFragments: ipv4.awaitingFragments,
            ipv4Delivered: ipv4.delivered,
            ipv4UnknownProtocol: ipv4.unknownProtocol,
            icmpForwarded: icmp.forwarded,
            icmpTimedOut: icmp.timedOut,
            inboundFramesRejected: link.inboundDropped,
            outboundFramesRejected: link.outboundDropped,
            outboundFramesBackedUp: link.outboundBackedUp,
            tcpEstablished: tcp.establishedCount,
            tcpRefusedByLimit: tcp.refusedForLimit,
            tcpDialFailed: tcp.refusedForDial,
            tcpRefusedLinkLocal: tcp.refusedForLinkLocal,
            udpFlows: udp.flowCount,
            udpSocketsOpened: udp.openedSockets,
            udpRefusedByLimit: udp.refusedForLimit,
            udpReclaimed: udp.reclaimed,
            dnsAnsweredLocally: dns.answeredLocally,
            dnsForwarded: dns.forwarded,
            dnsRefusedByLimit: dns.refusedForLimit,
            dnsRefusedNoUpstream: dns.refusedForNoUpstream,
            dnsUnmatchedReplies: dns.unmatchedReplies,
            dhcpLeases: dhcp.leaseCount,
            dhcpPoolExhausted: dhcp.exhausted,
            forwardedPorts: forwardedPorts.count,
            switchPorts: networkSwitch?.portCount ?? 0,
            switchUnknownUnicastDropped: networkSwitch?.unknownUnicastDropped ?? 0,
            switchAddressesRefused: networkSwitch?.addressesRefused ?? 0,
            switchAddressesMoved: networkSwitch?.addressesMoved ?? 0)
    }
}

extension Gateway.Statistics {
    /// A flat JSON object, for the control plane's `GET /stats`.
    ///
    /// Hand-written rather than `Codable` to keep the wire names stable and
    /// visible: these are an operator's dashboard keys, and having them follow
    /// from Swift property names means renaming a property silently breaks
    /// somebody's graph.
    public var json: String {
        let fields: [(String, Int)] = [
            // Upstream's spelling for these two, so a tool written against
            // gvisor-tap-vsock finds them under the names it expects.
            ("BytesReceived", bytesReceived),
            ("BytesSent", bytesSent),
            ("ipv4_received", ipv4Received),
            ("ipv4_malformed", ipv4Malformed),
            ("ipv4_not_for_this_stack", ipv4NotForThisStack),
            ("ipv4_expired", ipv4Expired),
            ("ipv4_awaiting_fragments", ipv4AwaitingFragments),
            ("ipv4_delivered", ipv4Delivered),
            ("ipv4_unknown_protocol", ipv4UnknownProtocol),
            ("icmp_forwarded", icmpForwarded),
            ("icmp_timed_out", icmpTimedOut),
            ("inbound_frames_rejected", inboundFramesRejected),
            ("outbound_frames_rejected", outboundFramesRejected),
            ("outbound_frames_backed_up", outboundFramesBackedUp),
            ("tcp_established", tcpEstablished),
            ("tcp_refused_by_limit", tcpRefusedByLimit),
            ("tcp_dial_failed", tcpDialFailed),
            ("tcp_refused_link_local", tcpRefusedLinkLocal),
            ("udp_flows", udpFlows),
            ("udp_sockets_opened", udpSocketsOpened),
            ("udp_refused_by_limit", udpRefusedByLimit),
            ("udp_reclaimed", udpReclaimed),
            ("dns_answered_locally", dnsAnsweredLocally),
            ("dns_forwarded", dnsForwarded),
            ("dns_refused_by_limit", dnsRefusedByLimit),
            ("dns_refused_no_upstream", dnsRefusedNoUpstream),
            ("dns_unmatched_replies", dnsUnmatchedReplies),
            ("dhcp_leases", dhcpLeases),
            ("dhcp_pool_exhausted", dhcpPoolExhausted),
            ("forwarded_ports", forwardedPorts),
            ("switch_ports", switchPorts),
            ("switch_unknown_unicast_dropped", switchUnknownUnicastDropped),
            ("switch_addresses_refused", switchAddressesRefused),
            ("switch_addresses_moved", switchAddressesMoved),
        ]
        return "{" + fields.map { "\"\($0.0)\":\($0.1)" }.joined(separator: ",") + "}"
    }
}
