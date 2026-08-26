import NIOCore

/// Splits an oversized IP payload into fragments that fit the link MTU.
public enum Fragmenter {
    /// Returns the fragments to transmit, in order.
    ///
    /// An empty result means the payload could not be sent: it exceeds the MTU
    /// and the Don't Fragment flag forbids splitting it. The caller answers
    /// that with an ICMP fragmentation-needed message, which is what drives
    /// path MTU discovery on the far side.
    public static func fragment(
        payload: ByteBuffer,
        template: IPv4Header,
        mtu: Int,
        allocator: ByteBufferAllocator
    ) -> [PacketBuffer] {
        let headerLength = max(template.headerLength, IPv4Header.minimumLength)
        let available = mtu - headerLength
        guard available > 0 else { return [] }

        if payload.readableBytes <= available {
            var packet = PacketBuffer(allocator: allocator, payload: payload)
            var header = template
            header.flags.remove(.moreFragments)
            header.fragmentOffset = 0
            header.prepend(to: &packet)
            return [packet]
        }

        guard !template.flags.contains(.dontFragment) else { return [] }

        // Every fragment except the last must carry a payload that is a
        // multiple of eight, because the wire encodes the offset in
        // eight-byte units and cannot express anything finer.
        let chunkSize = (available / 8) * 8
        guard chunkSize > 0 else { return [] }

        var fragments: [PacketBuffer] = []
        var offset = 0
        var remaining = payload

        while remaining.readableBytes > 0 {
            let take = min(chunkSize, remaining.readableBytes)
            guard let slice = remaining.readSlice(length: take) else { break }

            var packet = PacketBuffer(allocator: allocator, payload: slice)
            var header = template
            header.fragmentOffset = offset
            if remaining.readableBytes > 0 {
                header.flags.insert(.moreFragments)
            } else {
                header.flags.remove(.moreFragments)
            }
            header.prepend(to: &packet)
            fragments.append(packet)
            offset += take
        }
        return fragments
    }
}
