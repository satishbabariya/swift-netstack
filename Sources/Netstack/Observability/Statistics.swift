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
        /// Frames from the guest that this wire would not carry.
        public var inboundFramesRejected: Int
        /// Frames this stack could not put on the wire.
        public var outboundFramesRejected: Int

        /// Guest TCP connections currently spliced to a host socket. A **gauge**.
        public var tcpEstablished: Int
        /// Guest connections refused because the connection limit was reached.
        public var tcpRefusedByLimit: Int
        /// Guest connections refused because the destination did not accept.
        public var tcpDialFailed: Int

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
    }

    /// Read every counter, on the event loop, as one consistent set.
    public func statistics() -> EventLoopFuture<Statistics> {
        eventLoop.submit { self.statisticsOnLoop() }
    }

    /// The same snapshot for a caller already on the event loop.
    public func statisticsOnLoop() -> Statistics {
        eventLoop.preconditionInEventLoop()
        return Statistics(
            inboundFramesRejected: link.inboundDropped,
            outboundFramesRejected: link.outboundDropped,
            tcpEstablished: tcp.establishedCount,
            tcpRefusedByLimit: tcp.refusedForLimit,
            tcpDialFailed: tcp.refusedForDial,
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
            forwardedPorts: forwardedPorts.count)
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
            ("inbound_frames_rejected", inboundFramesRejected),
            ("outbound_frames_rejected", outboundFramesRejected),
            ("tcp_established", tcpEstablished),
            ("tcp_refused_by_limit", tcpRefusedByLimit),
            ("tcp_dial_failed", tcpDialFailed),
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
        ]
        return "{" + fields.map { "\"\($0.0)\":\($0.1)" }.joined(separator: ",") + "}"
    }
}
