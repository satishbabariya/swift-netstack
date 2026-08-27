/// Chooses the initial send sequence number (ISS) for one connection.
///
/// ## Why this is a protocol rather than a constant or a counter
///
/// Nothing else in this package picks an ISS: `TCB.iss` is a plain injected
/// field, so whoever builds the block chooses it, and the obvious choices —
/// zero, or a global counter — are both holes. A predictable ISS lets an
/// **off-path** attacker inject data into a connection it cannot observe: it
/// needs a sequence number inside the receive window, and a counter hands it
/// one from any single connection it *can* observe.
///
/// That matters here even though a guest is on-path for its own connections.
/// It is not on-path for another sandbox's, nor for a connection between the
/// gateway and an external host, and with a counter-based ISS one observed
/// handshake makes every one of those guessable.
///
/// ## Why it is injectable
///
/// The differential vectors (Task 15) are written in absolute sequence
/// numbers — `> S. 0:0(0) ack 1` — and cannot match a hashed ISS. Injecting
/// the generator lets a test pin it to a constant with
/// `FixedInitialSequenceNumbers` while production keeps
/// `RFC6528SequenceNumbers`. The seam is `TCPEndpoint`'s internal
/// `init(stack:initialSequenceNumbers:)`; the public `init(stack:)` takes the
/// stack's own generator, whose secret is made once at stack construction.
protocol InitialSequenceNumbers: Sendable {
    /// The ISS for a connection with this four-tuple.
    ///
    /// - Important: **Deterministic in its arguments** (up to the RFC 6528
    ///   timer term). A retransmitted SYN must reproduce the SYN-ACK that
    ///   answered the first one, or a guest that has already recorded the
    ///   first sequence number either fails to connect or resets. See
    ///   `RFC6528SequenceNumbers` for the one term that is *not* fixed by the
    ///   four-tuple and why it cannot break that.
    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber
}

/// RFC 6528 §3: `ISS = M + F(localip, localport, remoteip, remoteport, secretkey)`.
///
/// `M` is a 4-microsecond timer, read from the injected `NetstackClock` (this
/// package never calls `NIODeadline.now()`). `F` is SHA-256 over the
/// four-tuple and a per-stack secret, truncated to its leading 32 bits.
///
/// ## What each half buys, separately
///
/// `F` is what makes the number **unguessable across connections**: without
/// the secret, observing one connection's ISS says nothing about another's,
/// because the four-tuple that produced it is hashed rather than added.
/// `M` is what makes it **advance for a reused four-tuple**, which is RFC
/// 793's original reason for a clock-driven ISS — an old duplicate segment
/// from a previous incarnation of the same connection must not fall inside
/// the new one's window.
///
/// ## The retransmitted SYN
///
/// `M` moves, so calling this twice for one four-tuple at two different times
/// returns two different numbers. That is *not* a hazard for a retransmitted
/// SYN, because a retransmitted SYN does not reach here: the TCB created by
/// the first SYN is still in SYN-RECEIVED and answers the second one from the
/// `iss` it already holds. Reproducing the SYN-ACK is therefore a property of
/// **reusing the TCB**, not of this function being constant in time, and
/// `aRetransmittedSynReproducesTheSameSynAck` is what pins it.
///
/// ## The secret
///
/// Sixteen bytes from the system CSPRNG, made once per `Stack` and never
/// emitted anywhere. It is `private` and this type exposes no accessor: the
/// whole value of the scheme is that the secret does not leave the process.
struct RFC6528SequenceNumbers: InitialSequenceNumbers {
    private let clock: any NetstackClock
    private let secret: [UInt8]

    /// - Parameters:
    ///   - clock: the stack's clock; RFC 6528's `M` is read from it.
    ///   - secret: for tests that need a reproducible hash. Production callers
    ///     must let this default, which draws from the system CSPRNG.
    init(clock: any NetstackClock, secret: [UInt8] = RFC6528SequenceNumbers.randomSecret()) {
        self.clock = clock
        self.secret = secret
    }

    static func randomSecret() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for _ in 0..<2 {
            let word = UInt64.random(in: UInt64.min...UInt64.max, using: &generator)
            for shift in stride(from: 56, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return bytes
    }

    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber {
        // The secret goes first, so the hash is keyed rather than merely
        // salted: an attacker who could choose a four-tuple suffix cannot
        // extend a digest it has not seen, and length-extension has nothing to
        // work with when the fixed-length secret is the prefix of a
        // fixed-length message.
        var message: [UInt8] = secret
        message.reserveCapacity(secret.count + 12)
        message += localAddress.bytes
        message += [UInt8(truncatingIfNeeded: localPort >> 8), UInt8(truncatingIfNeeded: localPort)]
        message += remoteAddress.bytes
        message += [UInt8(truncatingIfNeeded: remotePort >> 8), UInt8(truncatingIfNeeded: remotePort)]

        let digest = SHA256.hash(message)
        let f =
            UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])

        // RFC 6528 §3's `M`: a timer that increments every 4 microseconds.
        // Truncating to 32 bits is what the RFC's own arithmetic does — the
        // sequence space is 32 bits and wraps.
        let m = UInt32(truncatingIfNeeded: clock.now().uptimeNanoseconds / 4_000)
        return SequenceNumber(m &+ f)
    }
}

/// An ISS generator that always answers the same number.
///
/// Exists for the differential vectors, which are written in absolute sequence
/// numbers and cannot express a hashed ISS. It lives here rather than in a
/// test file because more than one test target needs it (Tasks 15 and 16), and
/// a second copy would be a second thing to keep in step.
///
/// Never construct one in `Sources/Netstack` outside a test: it reinstates
/// exactly the blind-injection hole `RFC6528SequenceNumbers` exists to close.
struct FixedInitialSequenceNumbers: InitialSequenceNumbers {
    let value: SequenceNumber

    init(_ value: UInt32) {
        self.value = SequenceNumber(value)
    }

    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber {
        value
    }
}

/// FIPS 180-4 SHA-256, over a byte array.
///
/// Written out here rather than pulled in, because this package has no
/// dependency beyond SwiftNIO and adding swift-crypto for one 32-byte digest
/// on the connection-setup path is a poor trade. It is the standard
/// implementation, and `sha256MatchesTheFips1804Vectors` checks it against
/// digests produced by `shasum -a 256` — an oracle that shares no code with
/// this file, which is the only kind of check worth making on a hash.
///
/// Not a general-purpose API: it takes and returns arrays, has no streaming
/// interface, and is used on exactly one path (once per connection).
enum SHA256 {
    private static let k: [UInt32] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ]

    static func hash(_ message: [UInt8]) -> [UInt8] {
        var state: [UInt32] = [
            0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
        ]

        // FIPS 180-4 §5.1.1: append 0x80, then zeros, then the 64-bit big-endian
        // bit length, so the padded message is a whole number of 512-bit blocks.
        var padded = message
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0)
        }
        let bitLength = UInt64(message.count) &* 8
        for shift in stride(from: 56, through: 0, by: -8) {
            padded.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
        }

        var w = [UInt32](repeating: 0, count: 64)
        var block = padded.startIndex
        while block < padded.endIndex {
            for index in 0..<16 {
                let base = block + index * 4
                w[index] =
                    UInt32(padded[base]) << 24 | UInt32(padded[base + 1]) << 16
                    | UInt32(padded[base + 2]) << 8 | UInt32(padded[base + 3])
            }
            for index in 16..<64 {
                let s0 = rotate(w[index - 15], 7) ^ rotate(w[index - 15], 18) ^ (w[index - 15] >> 3)
                let s1 = rotate(w[index - 2], 17) ^ rotate(w[index - 2], 19) ^ (w[index - 2] >> 10)
                w[index] = w[index - 16] &+ s0 &+ w[index - 7] &+ s1
            }

            var a = state[0]
            var b = state[1]
            var c = state[2]
            var d = state[3]
            var e = state[4]
            var f = state[5]
            var g = state[6]
            var h = state[7]
            for index in 0..<64 {
                let s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = h &+ s1 &+ ch &+ k[index] &+ w[index]
                let s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj
                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }
            state[0] = state[0] &+ a
            state[1] = state[1] &+ b
            state[2] = state[2] &+ c
            state[3] = state[3] &+ d
            state[4] = state[4] &+ e
            state[5] = state[5] &+ f
            state[6] = state[6] &+ g
            state[7] = state[7] &+ h
            block += 64
        }

        var digest: [UInt8] = []
        digest.reserveCapacity(32)
        for word in state {
            digest += [
                UInt8(truncatingIfNeeded: word >> 24), UInt8(truncatingIfNeeded: word >> 16),
                UInt8(truncatingIfNeeded: word >> 8), UInt8(truncatingIfNeeded: word),
            ]
        }
        return digest
    }

    private static func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value >> count) | (value << (32 - count))
    }
}
