import Testing

@testable import Netstack

@Test func onesComplementOfKnownHeaderIsZero() {
    // A real IPv4 header with a valid checksum. Summing it must yield 0.
    let header: [UInt8] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    ]
    let sum = header.withUnsafeBytes { Checksum.compute($0) }
    #expect(sum == 0)
}

@Test func computingOverHeaderWithZeroedFieldReproducesTheChecksum() {
    var header: [UInt8] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    ]
    let sum = header.withUnsafeBytes { Checksum.compute($0) }
    #expect(sum == 0xb861)
    header[10] = UInt8(sum >> 8)
    header[11] = UInt8(sum & 0xff)
    #expect(header.withUnsafeBytes { Checksum.compute($0) } == 0)
}

@Test func oddLengthBuffersPadWithZero() {
    let odd: [UInt8] = [0x01, 0x02, 0x03]
    let padded: [UInt8] = [0x01, 0x02, 0x03, 0x00]
    let a = odd.withUnsafeBytes { Checksum.compute($0) }
    let b = padded.withUnsafeBytes { Checksum.compute($0) }
    #expect(a == b)
}

@Test func partialSumsCompose() {
    let all: [UInt8] = Array(0..<64)
    let whole = all.withUnsafeBytes { Checksum.partial($0) }
    let first = all[0..<32].withUnsafeBytes { Checksum.partial($0) }
    let second = all[32..<64].withUnsafeBytes { Checksum.partial($0, initial: first) }
    #expect(Checksum.fold(whole) == Checksum.fold(second))
}
