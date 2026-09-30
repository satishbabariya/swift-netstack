import Foundation
import NIOCore
import Testing

/// gVisor's TCP/IP stack as the GUEST: the harness binary in `peer` mode, driven
/// one command at a time.
///
/// `Differential.swift` plays gVisor as the gateway against scripted guest
/// frames, which cannot answer "what does the application at the other end of
/// this connection see?" -- a script has no application, and its acknowledgement
/// numbers are fixed before the other stack has chosen its sequence numbers.
/// This is the live version: frames go in, the frames gVisor answers with come
/// out, and a read reports what gVisor's own syscall layer would hand a program.
final class GVisorPeer {
    struct Read: Decodable {
        let bytes: Int
        /// The Linux errno for the read, 0 for none.
        let errno: Int
        let error: String?
    }

    private struct Reply: Decodable {
        let frames: [String]
        let read: Read?
        let state: String?
        let error: String?
    }

    /// `ECONNRESET` on Linux, which is what gVisor's syscall layer returns.
    static let connectionReset = 104

    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let diagnostics = Pipe()
    private var pending = Data()

    init(harness: String) throws {
        process.executableURL = URL(fileURLWithPath: harness)
        process.arguments = ["peer"]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = diagnostics
        try process.run()
    }

    deinit {
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
    }

    func connect() throws -> [ByteBuffer] { try command(["op": "connect"]).frames.buffers() }

    func inject(_ frame: ByteBuffer) throws -> [ByteBuffer] {
        let bytes = frame.getBytes(at: frame.readerIndex, length: frame.readableBytes) ?? []
        return try command(["op": "inject", "frame": Data(bytes).base64EncodedString()]).frames.buffers()
    }

    func write(bytes count: Int) throws -> [ByteBuffer] { try command(["op": "write", "bytes": count]).frames.buffers() }

    func read() throws -> Read {
        guard let read = try command(["op": "read"]).read else { throw GVisorPeerError.noRead }
        return read
    }

    func state() throws -> String { try command(["op": "state"]).state ?? "" }

    private func command(_ fields: [String: Any]) throws -> Reply {
        var line = try JSONSerialization.data(withJSONObject: fields)
        line.append(0x0a)
        try input.fileHandleForWriting.write(contentsOf: line)
        let reply = try JSONDecoder().decode(Reply.self, from: try nextLine())
        if let error = reply.error { throw GVisorPeerError.refused(error) }
        return reply
    }

    private func nextLine() throws -> Data {
        while true {
            if let newline = pending.firstIndex(of: 0x0a) {
                let line = pending[pending.startIndex..<newline]
                pending = Data(pending[pending.index(after: newline)...])
                return Data(line)
            }
            let chunk = output.fileHandleForReading.availableData
            guard !chunk.isEmpty else {
                let errors = diagnostics.fileHandleForReading.availableData
                throw GVisorPeerError.exited(String(data: errors, encoding: .utf8) ?? "")
            }
            pending.append(chunk)
        }
    }
}

enum GVisorPeerError: Error {
    case noRead
    case refused(String)
    case exited(String)
}

/// The harness speaks base64; the link takes `ByteBuffer`s.
extension Array where Element == String {
    fileprivate func buffers() throws -> [ByteBuffer] {
        try map { encoded in
            guard let data = Data(base64Encoded: encoded) else { throw GVisorPeerError.refused("bad base64") }
            var buffer = ByteBufferAllocator().buffer(capacity: data.count)
            buffer.writeBytes(data)
            return buffer
        }
    }
}
