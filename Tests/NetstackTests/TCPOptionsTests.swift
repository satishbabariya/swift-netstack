import NIOCore
import Testing

@testable import Netstack

/// Parse a window-scale option (kind 3, length 3) carrying `shift`, on its
/// own, through `TCPOptionCodec.parse`. The mutating parse is hoisted out of
/// every `#expect` below by living here.
private func parseWindowScale(shift: UInt8) -> [TCPOption]? {
    var bytes = ByteBuffer(bytes: [3, 3, shift])
    return TCPOptionCodec.parse(&bytes)
}

/// Parse a literal options area — for the malformed cases, where the point
/// is the length byte rather than the shift.
private func parseOptions(_ literal: [UInt8]) -> [TCPOption]? {
    var bytes = ByteBuffer(bytes: literal)
    return TCPOptionCodec.parse(&bytes)
}

/// 14 is the largest shift RFC 7323 §2.3 allows, and the value it requires a
/// larger one be replaced with — so it must survive as itself. An off-by-one
/// in the clamp (`> 14` written as `>= 14`, or a bound of 13) shows up here
/// and nowhere else.
@Test func keepsAWindowScaleOfExactlyFourteen() {
    #expect(parseWindowScale(shift: 14) == [.windowScale(14)])
}

/// RFC 7323 §2.3: "If a Window Scale option is received with a shift.cnt
/// value larger than 14, the TCP SHOULD log the error but MUST use 14
/// instead of the specified value." Not reject — the option stays, with a
/// bounded shift. 255 is the largest value the byte can carry.
@Test func clampsAPeerWindowScaleAboveFourteenToFourteen() {
    #expect(parseWindowScale(shift: 15) == [.windowScale(14)])
    #expect(parseWindowScale(shift: 255) == [.windowScale(14)])
}

/// The positive control for the two tests above: a parser that returned a
/// constant `.windowScale(14)` for every input, or one that dropped the
/// option entirely, would satisfy every clamping assertion while being
/// completely wrong. A shift at or below the bound is passed through
/// untouched.
@Test func passesAWindowScaleBelowFourteenThroughUntouched() {
    #expect(parseWindowScale(shift: 0) == [.windowScale(0)])
    #expect(parseWindowScale(shift: 7) == [.windowScale(7)])
    #expect(parseWindowScale(shift: 13) == [.windowScale(13)])
}

/// Clamping happens after the option's shape is validated, not instead of
/// it: a window-scale option with a length other than 3 is still rejected
/// outright. Otherwise a malformed option would be clamped into looking
/// like a well-formed one.
@Test func stillRejectsAMalformedWindowScaleOptionRatherThanClampingIt() {
    #expect(parseOptions([3, 4, 255, 0]) == nil)  // length 4: two value bytes where one is defined
    #expect(parseOptions([3, 2]) == nil)  // length 2: no value byte at all
    #expect(parseOptions([3, 3]) == nil)  // length 3 declared, value byte missing from the buffer
}
