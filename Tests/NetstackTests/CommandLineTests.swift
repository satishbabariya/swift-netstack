import Foundation
import NIOConcurrencyHelpers
import Testing

// The program's flags are gvproxy's, and that is a claim worth a test rather
// than a README line -- it was a README line, and it was wrong.
//
// The names are checked by running the built binary rather than by reading the
// parser, because what matters is what somebody typing a gvproxy command line
// gets. The binary is found next to the test bundle; if it has not been built
// these skip rather than fail, since `swift test` does not build executables on
// every path.

/// The built `netstack-gateway`, found from this file's own path.
///
/// Not from `Bundle.main`, which under swift-testing is the test *helper* and
/// not the directory the products are in -- so the first version of this looked
/// in the wrong place, found nothing, and both tests returned early and asserted
/// nothing. They passed in a millisecond, which is what gave it away.
///
/// A missing binary is a failure rather than a skip, because `swift test` builds
/// every target in the package: if it is not there, something is wrong with the
/// assumption rather than with the environment.
private func gatewayBinary() -> String {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // NetstackTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // package root
    let candidates = [
        root.appendingPathComponent(".build/debug/netstack-gateway"),
        root.appendingPathComponent(".build/release/netstack-gateway"),
    ]
    for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate.path) {
        return candidate.path
    }
    Issue.record("netstack-gateway was not built; looked in \(candidates.map(\.path))")
    return ""
}

private func run(_ arguments: [String]) -> (status: Int32, output: String)? {
    let binary = gatewayBinary()
    guard !binary.isEmpty else { return nil }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    guard (try? process.run()) != nil else { return nil }

    // A watchdog rather than a deadline on the read, and the difference is why
    // this failed on CI and not here.
    //
    // The first version read the pipe on `DispatchQueue.global()` and waited on
    // a semaphore. Swift Testing runs tests in parallel on that same pool, so on
    // a runner with few cores the read was simply never scheduled inside its ten
    // seconds and every invocation was reported as hung -- a test that fails
    // where the machine is small, which is the worst kind.
    //
    // The read happens on this thread now, so the ordinary path does not depend
    // on the pool at all. The watchdog only has to run when the child really
    // does hang, and being late then costs nothing.
    //
    // It is needed because every argument here is meant to be REJECTED: if one
    // is ever accepted, the gateway does what it is for and waits for a guest
    // forever.
    // Whether the watchdog actually fired, which is the only reliable signal.
    // Asking `process.isRunning` after the pipe closes is not: the child has
    // closed stdout but may not have been reaped yet, so it reads as running and
    // every invocation looked hung.
    let fired = NIOLockedValueBox(false)
    let watchdog = DispatchWorkItem {
        guard process.isRunning else { return }
        fired.withLockedValue { $0 = true }
        process.terminate()
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(10), execute: watchdog)
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    watchdog.cancel()
    if fired.withLockedValue({ $0 }) {
        Issue.record("netstack-gateway \(arguments.joined(separator: " ")) did not exit")
    }
    return (process.terminationStatus, String(decoding: data, as: UTF8.self))
}

@Test func theProgramSpellsItsFlagsTheWayGvproxyDoes() throws {
    guard let help = run(["--help"]) else { return }
    #expect(help.status == 0)

    // The ones upstream has and this must match. `--listen` is the important
    // one: it is the CONTROL endpoint in gvproxy, and this had it as the guest
    // wire -- so a command line moved across would have pointed the control API
    // at the VM's socket and the VM at the control socket, with nothing saying
    // so.
    for flag in [
        "--listen", "--listen-vfkit", "--listen-qemu", "--gatewayIP", "--hostIP", "--subnet",
        "--mtu", "--pcap", "--notification", "--ec2-metadata-access", "--debug",
    ] {
        #expect(help.output.contains(flag), "\(flag) is not in the help")
    }

    // And the ones it used to have, which meant something different, are gone
    // rather than quietly still accepted.
    for retired in ["--listen-stream", "--capture-file", "--notify"] {
        #expect(!help.output.contains(retired), "\(retired) is still advertised")
    }
}

@Test func aGvproxyCommandLineIsNotSilentlyMisread() throws {
    // `--listen` alone is a complete and valid gvproxy control endpoint and
    // still leaves no wire for a guest. The failure has to say which, because
    // this is the exact mistake the old naming caused.
    guard let missing = run(["--listen", "/tmp/netstack-cli-check.sock"]) else { return }
    #expect(missing.status != 0)
    #expect(missing.output.contains("no guest wire"), "unhelpful error: \(missing.output)")
    #expect(missing.output.contains("--listen is the control API"), "the error does not say what --listen is")

    // Two wires is a choice, not a combination.
    guard let both = run(["--listen-vfkit", "/tmp/a.sock", "--listen-qemu", "/tmp/b.sock"]) else { return }
    #expect(both.status != 0)
    #expect(both.output.contains("two different wires"))

    // A wire upstream has and this does not says which, rather than "unknown
    // option" -- the difference between "you typed it wrong" and "this does not
    // do that yet".
    guard let bess = run(["--listen-bess", "/tmp/c.sock"]) else { return }
    #expect(bess.status != 0)
    #expect(bess.output.contains("not supported"), "unhelpful error: \(bess.output)")
    #expect(bess.output.contains("--listen-vfkit"), "the error does not say what to use instead")

    // The floor: a genuinely unknown flag is still rejected as unknown, so the
    // messages above are recognition rather than a catch-all.
    guard let nonsense = run(["--not-a-flag"]) else { return }
    #expect(nonsense.output.contains("unknown option"), "unexpected error: \(nonsense.output)")
}
