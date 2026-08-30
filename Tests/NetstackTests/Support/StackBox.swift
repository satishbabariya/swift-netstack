@testable import Netstack

/// A `Stack` carried out of an `EventLoop.submit`.
///
/// `Stack` is deliberately not `Sendable` and never will be — it publicly
/// exposes its whole graph and every part of it is loop-confined — so returning
/// one from a `@Sendable` closure needs a carrier. The library does the same
/// thing for the same reason; see `ShutdownBox` in `Stack.swift`.
///
/// The confinement is real here: the closure that builds the stack runs on the
/// loop, and the test that reads it back only touches it through further
/// `submit` calls.
struct StackBox: @unchecked Sendable {
    let stack: Stack
}
