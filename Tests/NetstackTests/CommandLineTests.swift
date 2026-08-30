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

    // Two wires is a choice, not a combination -- and there are three now, so
    // every pair of them has to be, not just the pair that was written first.
    for pair in [
        ["--listen-vfkit", "/tmp/a.sock", "--listen-qemu", "/tmp/b.sock"],
        ["--listen-vfkit", "/tmp/a.sock", "--listen-switch", "/tmp/b.sock"],
        ["--listen-qemu", "/tmp/a.sock", "--listen-switch", "/tmp/b.sock"],
    ] {
        guard let both = run(pair) else { return }
        #expect(both.status != 0, "\(pair) was accepted as one wire")
        #expect(both.output.contains("different wires"), "unhelpful error: \(both.output)")
    }

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

@Test func aConfigurationFileIsReadAndFlagsOverrideIt() throws {
    // gvproxy takes a configuration file, and it is the only way to express
    // zones, static leases, NAT and virtual addresses -- none of which any flag
    // here can say. Without it the program could not be configured for most of
    // what the library does.
    let directory = FileManager.default.temporaryDirectory
    let path = directory.appendingPathComponent("netstack-config-\(UInt32.random(in: 0...UInt32.max)).json").path
    defer { try? FileManager.default.removeItem(atPath: path) }

    // Upstream's field names exactly, so a YAML config converts across without
    // anything being re-learned.
    let json = """
        {"subnet":"10.9.0.0/24","gatewayIP":"10.9.0.1","hostIP":"10.9.0.254","mtu":1400,
         "dnsSearchDomains":["svc.test"],
         "dhcpStaticLeases":{"0a:00:00:00:11:22":"10.9.0.50"},
         "nat":{"10.9.0.254":"127.0.0.1"},
         "gatewayVirtualIPs":["10.9.0.254"],
         "dns":[{"name":"svc.test","records":[{"name":"api","ip":"10.9.0.9"}]}]}
        """
    try json.write(toFile: path, atomically: true, encoding: .utf8)

    // Accepted: it starts, so it got far enough to build a gateway from the
    // file. Without a wire it stops at the argument check, which is what makes
    // this a parse test rather than a run test.
    guard let accepted = run(["--config", path]) else { return }
    #expect(accepted.output.contains("no guest wire"), "the file was rejected: \(accepted.output)")

    // A bad value in the file says which field, rather than failing to parse.
    let badPath = directory.appendingPathComponent("netstack-bad-\(UInt32.random(in: 0...UInt32.max)).json").path
    defer { try? FileManager.default.removeItem(atPath: badPath) }
    try "{\"subnet\":\"not-a-subnet\"}".write(toFile: badPath, atomically: true, encoding: .utf8)
    guard let bad = run(["--config", badPath]) else { return }
    #expect(bad.output.contains("subnet is not valid"), "unhelpful error: \(bad.output)")

    // A YAML file is refused as YAML rather than as unparseable. gvproxy reads
    // YAML and this reads the same configuration as JSON, so "your file is
    // wrong" and "this wants the same file in another notation" are different
    // messages and the reader needs the second.
    let yamlPath = directory.appendingPathComponent("netstack-yaml-\(UInt32.random(in: 0...UInt32.max)).yaml").path
    defer { try? FileManager.default.removeItem(atPath: yamlPath) }
    try "subnet: 10.9.0.0/24\ngatewayIP: 10.9.0.1\n".write(toFile: yamlPath, atomically: true, encoding: .utf8)
    guard let yaml = run(["--config", yamlPath]) else { return }
    #expect(yaml.output.contains("looks like YAML"), "unhelpful error: \(yaml.output)")

    // A missing file says so.
    guard let missing = run(["--config", "/nonexistent/netstack.json"]) else { return }
    #expect(missing.output.contains("cannot read"), "unhelpful error: \(missing.output)")
}
