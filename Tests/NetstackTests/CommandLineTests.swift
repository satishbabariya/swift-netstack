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

    // Every wire gvproxy has is a wire this has. `--listen-bess` was the last
    // one that was not, and this used to assert that its rejection said so; the
    // assertion is now that it is accepted, since accepting it is the change.
    //
    // Accepted, not "works here": Darwin has no SOCK_SEQPACKET for AF_UNIX, so
    // on this platform the flag parses and the bind fails with the reason. That
    // is a different thing from an option the program does not know, and this
    // checks the difference by requiring the failure to name the socket type
    // rather than the flag.
    if let bess = run(["--listen-bess", "/tmp/netstack-bess-check.sock"]) {
        #expect(
            !bess.output.contains("unknown option"),
            "--listen-bess is a wire this program has: \(bess.output)")
        #if canImport(Darwin)
            #expect(
                bess.output.contains("SOCK_SEQPACKET"),
                "on a platform without seqpacket the failure should name it: \(bess.output)")
        #endif
    }

    // A forward's transport, which is a prefix on the host side in the config
    // file and now on the command line too. An operator who can ask for a
    // datagram forward in a file and not on the command line discovers the
    // difference the hard way: a forward listening on the right port over the
    // wrong transport.
    //
    // Rejected shapes only here -- the accepted ones need a running gateway and
    // are checked by `scripts/frame-smoke.sh`, which reads the transport back
    // through the control API.
    for bad in ["udp:", "udp:8080", "udp:8080:192.168.127.2", "udp:x:192.168.127.2:80"] {
        guard let refused = run(["--listen-vfkit", "/tmp/netstack-fwd.sock", "--forward", bad])
        else { return }
        #expect(refused.status != 0, "--forward \(bad) was accepted")
        #expect(
            refused.output.contains("--forward"),
            "the error does not name the flag: \(refused.output)")
    }

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

// The operator's flags, run rather than read.
//
// gvproxy has --pid-file, --log-file and --services, and it takes --listen more
// than once and as a URL. None of that existed here, so a real command line hit
// "unknown option" on plumbing that has nothing to do with networking. These run
// the gateway and take it apart again, because the interesting half of a PID
// file is whether it is removed.
@Test func theOperatorsFlagsDoWhatTheirNamesSay() async throws {
    let binary = gatewayBinary()
    guard !binary.isEmpty else { return }
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("netstack-ops-\(getpid())-\(UInt32.random(in: 0..<UInt32.max))")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    func path(_ name: String) -> String { directory.appendingPathComponent(name).path }
    let wire = path("wire.sock")
    let control = path("control.sock")
    let pidFile = path("gateway.pid")
    let logFile = path("gateway.log")
    let port = Int.random(in: 20000..<30000)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = [
        "--listen-switch", wire,
        "--listen", "unix://\(control)",
        "--services", "tcp://127.0.0.1:\(port)",
        "--pid-file", pidFile,
        "--log-file", logFile,
    ]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    defer {
        if process.isRunning { process.terminate() }
    }

    // The PID file is written after everything is listening, so waiting for it
    // is waiting for the gateway to be ready -- which is what a supervisor uses
    // it for and therefore what this should depend on.
    var written = ""
    for _ in 0..<400 where written.isEmpty {
        written = (try? String(contentsOfFile: pidFile, encoding: .utf8)) ?? ""
        if written.isEmpty { try await Task.sleep(nanoseconds: 25_000_000) }
    }
    let claimed = written.trimmingCharacters(in: .whitespacesAndNewlines)
    #expect(
        Int32(claimed) == process.processIdentifier,
        "the pid file says \(claimed) and the process is \(process.processIdentifier)")

    // A log file that stays empty until something goes wrong cannot be told from
    // one that was never opened, so there is a line at startup and this is it.
    let logged = (try? String(contentsOfFile: logFile, encoding: .utf8)) ?? ""
    #expect(logged.contains("running"), "the log file has no startup line: \(logged.debugDescription)")

    // Both endpoints answer, one over a unix socket and one over TCP.
    #expect(controlAnswers(unixSocket: control), "the unix control endpoint did not answer")
    #expect(controlAnswers(tcpPort: port), "the tcp services endpoint did not answer")

    // And they are not the same endpoint: --services is documented upstream as
    // the same API "without the /connect endpoint", because a guest that could
    // reach /connect could put another guest on the network.
    #expect(
        statusOf(tcpPort: port, path: "/connect") == 404,
        "--services offered /connect, which is the one thing it is defined not to")

    process.terminate()
    process.waitUntilExit()

    // Removed on a clean stop, and only then: one left behind by a crash is how
    // a supervisor finds out there was one.
    var lingering = true
    for _ in 0..<200 where lingering {
        lingering = FileManager.default.fileExists(atPath: pidFile)
        if lingering { try await Task.sleep(nanoseconds: 25_000_000) }
    }
    #expect(!lingering, "the pid file outlived a clean stop")
}

/// A GET against an HTTP endpoint, by hand.
///
/// `URLSession` cannot dial a unix socket and curl is a dependency this suite
/// does not otherwise have, so both transports go through the same few lines.
private func httpStatus(_ descriptor: Int32, _ path: String) -> Int? {
    // A read deadline, because one of the things being checked is an endpoint
    // that must NOT hijack the connection -- and a hijacked connection answers
    // nothing, ever. Without this the test that catches that hangs instead of
    // failing, which is worse: it takes the whole run with it, and it took a
    // swift-test process and the package's build lock with it here.
    var timeout = timeval(tv_sec: 3, tv_usec: 0)
    setsockopt(
        descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

    let request = "GET \(path) HTTP/1.1\r\nHost: gateway\r\nConnection: close\r\n\r\n"
    guard sendBytes(descriptor, Array(request.utf8)) > 0 else { return nil }

    var deadline = 400
    var answer = [UInt8]()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while deadline > 0, !answer.contains(0x0A) {
        let read = recv(descriptor, &buffer, buffer.count, 0)
        if read > 0 {
            answer.append(contentsOf: buffer[0..<read])
        } else if read == 0 {
            break
        } else if errno == EAGAIN || errno == EWOULDBLOCK {
            // The deadline expired with nothing said. For `/connect` on an
            // endpoint that hijacks, that is the answer.
            return nil
        } else if errno != EINTR {
            return nil
        }
        deadline -= 1
    }
    // "HTTP/1.1 200 OK" -- the status is the second word of the first line.
    let line = String(decoding: answer.prefix(while: { $0 != 0x0D && $0 != 0x0A }), as: UTF8.self)
    let words = line.split(separator: " ")
    guard words.count >= 2 else { return nil }
    return Int(words[1])
}

private func controlAnswers(unixSocket path: String) -> Bool {
    let descriptor = makeSocket(AF_UNIX, .stream)
    guard descriptor >= 0 else { return false }
    defer { close(descriptor) }
    guard connectTo(descriptor, unixAddress(path: path)) == 0 else { return false }
    return httpStatus(descriptor, "/services/forwarder/all") == 200
}

private func controlAnswers(tcpPort port: Int) -> Bool {
    statusOf(tcpPort: port, path: "/services/forwarder/all") == 200
}

private func statusOf(tcpPort port: Int, path: String) -> Int? {
    let descriptor = makeSocket(AF_INET, .stream)
    guard descriptor >= 0 else { return nil }
    defer { close(descriptor) }
    guard connectTo(descriptor, loopbackAddress(port: UInt16(port))) == 0 else { return nil }
    return httpStatus(descriptor, path)
}
