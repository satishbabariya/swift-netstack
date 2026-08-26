import NIOCore

/// RFC 1071 ones-complement checksums.
///
/// Accumulation is 64 bits wide so the carry-folding happens once at the end
/// rather than on every 16-bit word, which is what makes this fast enough to
/// sit on the datapath.
public enum Checksum {
    /// Accumulate `bytes` into a running sum. Composable: feeding the result
    /// back in as `initial` is equivalent to summing the concatenation, which
    /// is how pseudo-header and payload sums are combined.
    public static func partial(_ bytes: UnsafeRawBufferPointer, initial: UInt32 = 0) -> UInt32 {
        var accumulator = UInt64(initial)
        var index = 0
        let count = bytes.count

        while index + 8 <= count {
            accumulator += UInt64(bytes.loadUnaligned(fromByteOffset: index, as: UInt32.self).bigEndian)
            accumulator += UInt64(bytes.loadUnaligned(fromByteOffset: index + 4, as: UInt32.self).bigEndian)
            index += 8
        }
        while index + 2 <= count {
            accumulator += UInt64(bytes.loadUnaligned(fromByteOffset: index, as: UInt16.self).bigEndian)
            index += 2
        }
        if index < count {
            // Odd trailing byte is the high half of a zero-padded word.
            accumulator += UInt64(bytes[index]) << 8
        }

        while accumulator >> 32 != 0 {
            accumulator = (accumulator & 0xffff_ffff) + (accumulator >> 32)
        }
        return UInt32(truncatingIfNeeded: accumulator)
    }

    /// Fold a 32-bit accumulator down to 16 bits, carrying.
    public static func fold(_ sum: UInt32) -> UInt16 {
        var folded = sum
        while folded >> 16 != 0 {
            folded = (folded & 0xffff) + (folded >> 16)
        }
        return UInt16(truncatingIfNeeded: folded)
    }

    /// Fold and complement — the value that goes in a checksum field.
    public static func complete(_ sum: UInt32) -> UInt16 {
        ~fold(sum)
    }

    public static func compute(_ bytes: UnsafeRawBufferPointer) -> UInt16 {
        complete(partial(bytes))
    }
}
