import NIOCore

/// A DNS question, which is as much of a message as this gateway has to
/// understand.
///
/// Answers, authorities and additionals are never parsed: a query this gateway
/// cannot answer itself is forwarded as the bytes that arrived, and the reply is
/// returned as the bytes that came back. Parsing records in order to re-encode
/// them identically would be work with a defect budget and no benefit.
struct DNSQuestion: Equatable {
    /// Lowercased and without a trailing dot, so a lookup is a dictionary hit
    /// rather than a comparison rule. DNS names are case-insensitive
    /// (RFC 4343), and a guest that varies the case of a name it wants blocked
    /// is the reason that is done here rather than at each use.
    var name: String
    var type: UInt16
    var klass: UInt16

    static let typeA: UInt16 = 1
    static let classIN: UInt16 = 1
}

struct DNSQuery: Equatable {
    var id: UInt16
    var recursionDesired: Bool
    var question: DNSQuestion
    /// Where the question's bytes start and end, so a static answer can copy
    /// them back verbatim rather than re-encoding a name it has lowercased.
    var questionRange: Range<Int>
}

enum DNSCodec {
    /// RFC 1035 §4.1: a 12-byte header, then QDCOUNT questions.
    static let headerLength = 12

    /// RFC 1035 §2.3.4's limit on a whole name, which is also the bound that
    /// makes parsing terminate.
    ///
    /// The per-label limit of 63 has no constant here, and the reason is worth
    /// stating: it is enforced by the pointer check and cannot be violated
    /// separately. A length byte above 63 has one of its top two bits set, and
    /// those are exactly the bits that mark a compression pointer -- so a
    /// too-long label is already refused one line earlier. A guard for it was
    /// written, survived its own falsification, and was removed rather than
    /// left standing as protection that protects nothing.
    static let maximumNameLength = 255

    /// Parse a query far enough to route it.
    ///
    /// Returns nil for anything that is not a single-question query. **Nil
    /// rather than a partial parse**, and nil rather than an error: this is the
    /// first thing a guest reaches on UDP 53, and every malformed datagram it
    /// can construct has to end the same way.
    static func parseQuery(_ buffer: ByteBuffer) -> DNSQuery? {
        guard buffer.readableBytes >= headerLength else { return nil }
        guard let id = buffer.getInteger(at: buffer.readerIndex, endianness: .big, as: UInt16.self),
            let flags = buffer.getInteger(at: buffer.readerIndex + 2, endianness: .big, as: UInt16.self),
            let questions = buffer.getInteger(at: buffer.readerIndex + 4, endianness: .big, as: UInt16.self)
        else { return nil }
        // QR must be 0 -- this is a query, not somebody's reply arriving on the
        // server port -- and exactly one question, which is what every resolver
        // sends and what a static answer can be written for.
        guard flags & 0x8000 == 0, questions == 1 else { return nil }

        let start = buffer.readerIndex + headerLength
        var cursor = start
        guard let name = parseName(buffer, at: &cursor) else { return nil }
        guard let type = buffer.getInteger(at: cursor, endianness: .big, as: UInt16.self),
            let klass = buffer.getInteger(at: cursor + 2, endianness: .big, as: UInt16.self)
        else { return nil }
        cursor += 4

        return DNSQuery(
            id: id, recursionDesired: flags & 0x0100 != 0,
            question: DNSQuestion(name: name, type: type, klass: klass),
            questionRange: (start - buffer.readerIndex)..<(cursor - buffer.readerIndex))
    }

    /// Read a name, advancing `cursor` past it.
    ///
    /// ## Compression pointers are refused here, and that is the point
    ///
    /// RFC 1035 §4.1.4 compression points BACKWARDS, to a name that has already
    /// appeared. In the first question of a query there is nothing before it but
    /// the header, so a pointer here cannot refer to a name at all -- it is
    /// either a mistake or an attempt.
    ///
    /// The attempt is the well-known one: a pointer to itself, or two pointers
    /// to each other, and a parser that follows them walks forever on a datagram
    /// the guest sends once. Every DNS implementation has had this bug at least
    /// once. Refusing pointers outright, rather than following them with a
    /// budget, means there is no loop to bound and no budget to get wrong.
    static func parseName(_ buffer: ByteBuffer, at cursor: inout Int) -> String? {
        var labels: [String] = []
        var total = 0
        while true {
            guard let length = buffer.getInteger(at: cursor, as: UInt8.self) else { return nil }
            // A pointer, a reserved form, or a label longer than 63 -- all one
            // test, because the two bits that mark a pointer are the two bits a
            // length needs to exceed 63. See `maximumNameLength`.
            if length & 0xC0 != 0 { return nil }
            cursor += 1
            if length == 0 { break }
            total += Int(length) + 1
            guard total <= maximumNameLength else { return nil }
            guard let bytes = buffer.getBytes(at: cursor, length: Int(length)) else { return nil }
            cursor += Int(length)
            labels.append(String(decoding: bytes, as: UTF8.self).lowercased())
        }
        return labels.joined(separator: ".")
    }

    /// An answer carrying one A record, built by copying the query's own header
    /// and question bytes.
    ///
    /// Copying rather than re-encoding is deliberate. The name in `DNSQuestion`
    /// has been lowercased for lookup, and RFC 1035 §4.1.2 requires the question
    /// to be echoed **as it was asked**: a resolver that compares the two
    /// byte-for-byte -- and some do, as a spoofing check -- rejects an answer
    /// whose case has been normalised.
    static func answer(
        to query: DNSQuery, in original: ByteBuffer, address: IPv4Address, ttl: UInt32,
        allocator: ByteBufferAllocator
    ) -> ByteBuffer? {
        guard
            let question = original.getSlice(
                at: original.readerIndex + query.questionRange.lowerBound, length: query.questionRange.count)
        else { return nil }
        var out = allocator.buffer(capacity: 64)
        out.writeInteger(query.id, endianness: .big)
        // QR, AA, RD echoed, RA: an answer this gateway made up itself is
        // authoritative for the zone it made it up for, and says recursion is
        // available because it forwards everything else.
        out.writeInteger(UInt16(0x8580 | (query.recursionDesired ? 0x0100 : 0)), endianness: .big)
        out.writeInteger(UInt16(1), endianness: .big)  // QDCOUNT
        out.writeInteger(UInt16(1), endianness: .big)  // ANCOUNT
        out.writeInteger(UInt16(0), endianness: .big)  // NSCOUNT
        out.writeInteger(UInt16(0), endianness: .big)  // ARCOUNT
        out.writeImmutableBuffer(question)
        // The answer's name is a pointer back to the question's, which is where
        // compression is legal and expected -- and is why the question has to be
        // at a known offset.
        out.writeInteger(UInt16(0xC000 | UInt16(headerLength)), endianness: .big)
        out.writeInteger(DNSQuestion.typeA, endianness: .big)
        out.writeInteger(DNSQuestion.classIN, endianness: .big)
        out.writeInteger(ttl, endianness: .big)
        out.writeInteger(UInt16(4), endianness: .big)
        out.writeBytes(address.bytes)
        return out
    }

    /// A reply carrying a response code and no records: NXDOMAIN for a name in a
    /// zone this gateway owns, or REFUSED for a query it will not forward.
    static func failure(
        to query: DNSQuery, in original: ByteBuffer, code: UInt16, allocator: ByteBufferAllocator
    ) -> ByteBuffer? {
        guard
            let question = original.getSlice(
                at: original.readerIndex + query.questionRange.lowerBound, length: query.questionRange.count)
        else { return nil }
        var out = allocator.buffer(capacity: 32)
        out.writeInteger(query.id, endianness: .big)
        out.writeInteger(UInt16(0x8580 | (query.recursionDesired ? 0x0100 : 0) | (code & 0x000F)), endianness: .big)
        out.writeInteger(UInt16(1), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeImmutableBuffer(question)
        return out
    }

    /// A reply that will not fit the datagram the asker offered: the same
    /// header and question with TC set and nothing else.
    ///
    /// RFC 1035 §4.1.1 defines TC as "this message was truncated due to length
    /// greater than that permitted on the transmission channel", and §4.2.1
    /// makes the retry over TCP the asker's answer to it -- which is why this
    /// arrived with the TCP listener rather than before it. Sending a reply
    /// that does not fit is not an alternative: it is fragmented at best and
    /// dropped at worst, and the asker is never told which.
    ///
    /// Every record is dropped rather than as many kept as fit. Upstream keeps
    /// what fits, and doing that means re-encoding a record set this gateway
    /// only ever relays, with a compression pointer table it never built. The
    /// difference is one extra round trip on a reply that was already going to
    /// need TCP.
    static func truncated(
        to query: DNSQuery, in original: ByteBuffer, allocator: ByteBufferAllocator
    ) -> ByteBuffer? {
        guard
            let question = original.getSlice(
                at: original.readerIndex + query.questionRange.lowerBound,
                length: query.questionRange.count)
        else { return nil }
        var out = allocator.buffer(capacity: 32)
        out.writeInteger(query.id, endianness: .big)
        out.writeInteger(
            UInt16(0x8580 | truncatedFlag | (query.recursionDesired ? 0x0100 : 0)), endianness: .big)
        out.writeInteger(UInt16(1), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeImmutableBuffer(question)
        return out
    }

    static let truncatedFlag: UInt16 = 0x0200

    /// How large a datagram the asker said it would accept.
    ///
    /// RFC 1035 §4.2.1 caps a DNS datagram at 512 bytes, and RFC 6891 lets an
    /// asker say otherwise by putting an OPT pseudo-record in the additional
    /// section, whose CLASS field is the size rather than a class. Reading it
    /// matters: without it every reply over 512 bytes would be truncated and
    /// retried over TCP, including the ones the asker was perfectly willing to
    /// receive whole.
    ///
    /// Anything malformed answers 512, which is the floor every asker accepts.
    static func advertisedUDPSize(in original: ByteBuffer, after query: DNSQuery) -> Int {
        let floor = 512
        guard
            // From ANCOUNT, not QDCOUNT: the header is ID, flags, QDCOUNT,
            // ANCOUNT, NSCOUNT, ARCOUNT, and starting one field early read
            // NSCOUNT as the additional count -- which is zero on every query
            // that has an OPT record, so this returned the floor for all of
            // them and the EDNS0 size was never honoured at all.
            let counts = original.getSlice(at: original.readerIndex + 6, length: 6),
            let answers = counts.getInteger(at: counts.readerIndex, as: UInt16.self),
            let authorities = counts.getInteger(at: counts.readerIndex + 2, as: UInt16.self),
            let additional = counts.getInteger(at: counts.readerIndex + 4, as: UInt16.self),
            additional > 0
        else { return floor }

        var index = original.readerIndex + query.questionRange.upperBound
        // A query normally carries neither, but one that did would put the OPT
        // record after them, and a walk that ignored them would read a record
        // boundary in the middle of a name.
        var remaining = Int(answers) + Int(authorities) + Int(additional)
        while remaining > 0 {
            remaining -= 1
            guard let afterName = skipName(in: original, from: index) else { return floor }
            guard let type = original.getInteger(at: afterName, as: UInt16.self),
                let klass = original.getInteger(at: afterName + 2, as: UInt16.self),
                let rdLength = original.getInteger(at: afterName + 8, as: UInt16.self)
            else { return floor }
            if type == optRecordType {
                // Below the floor is a request nothing has to honour, and one
                // that would make every answer a truncation.
                return max(floor, Int(klass))
            }
            index = afterName + 10 + Int(rdLength)
        }
        return floor
    }

    static let optRecordType: UInt16 = 41

    /// Step over one name, whether it is written out or is a pointer.
    ///
    /// A pointer ends the name, so this does not follow it: the caller wants
    /// the byte after the name, and where the name's text lives is a question
    /// only a reader of the name has.
    private static func skipName(in buffer: ByteBuffer, from start: Int) -> Int? {
        var index = start
        // A name is at most 255 bytes, so a well-formed one cannot need more
        // steps than that. The bound is what stops a crafted buffer looping.
        for _ in 0..<256 {
            guard let length = buffer.getInteger(at: index, as: UInt8.self) else { return nil }
            if length == 0 { return index + 1 }
            if length & 0xC0 == 0xC0 { return index + 2 }
            guard length & 0xC0 == 0 else { return nil }
            index += Int(length) + 1
        }
        return nil
    }

    /// The name exists. With no answers beside it this is NODATA: the record
    /// type asked for is not held, which is not the same as the name being
    /// absent and must not be answered as though it were.
    static let responseCodeNoError: UInt16 = 0
    static let responseCodeNameError: UInt16 = 3
    static let responseCodeRefused: UInt16 = 5
}
