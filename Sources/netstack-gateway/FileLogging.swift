import Foundation
import Logging
import NIOConcurrencyHelpers

/// A log handler that appends to a file, for `--log-file`.
///
/// An operator running this under a supervisor has no terminal to read, and
/// upstream's `--log-file` is how they get the messages instead. Everything
/// still goes to stderr as well: a log file that silently replaced stderr would
/// make the failure to open it invisible in exactly the case that matters.
///
/// Writes are serialised through a lock. This is the executable, not
/// `Sources/Netstack` -- the no-locks rule is about the datapath, where a lock
/// would be taken per frame; here it is taken per log line, on a handle shared
/// between the event loop and the main thread, and there is nothing to confine
/// it to.
struct FileLogHandler: LogHandler {
    private let label: String
    private let handle: NIOLockedValueBox<FileHandle>
    private let stderrHandler: StreamLogHandler

    var logLevel: Logger.Level = .info
    var metadata: Logger.Metadata = [:]

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    /// Opens `path` for appending, creating it if it is not there.
    ///
    /// Returns nil rather than throwing so the caller can say which path failed
    /// and carry on with stderr, which is the useful behaviour: a gateway that
    /// refuses to start because its log file is unwritable has turned a
    /// diagnostic into an outage.
    init?(label: String, path: String) {
        if !FileManager.default.fileExists(atPath: path) {
            guard FileManager.default.createFile(atPath: path, contents: nil) else { return nil }
        }
        guard let handle = FileHandle(forWritingAtPath: path) else { return nil }
        handle.seekToEndOfFile()
        self.label = label
        self.handle = NIOLockedValueBox(handle)
        self.stderrHandler = StreamLogHandler.standardError(label: label)
    }

    /// `log(event:)` rather than the older per-argument `log(level:message:...)`.
    ///
    /// swift-log deprecated the default implementation that bridges one to the
    /// other, and this package builds with warnings as errors, so satisfying the
    /// protocol the old way does not compile.
    func log(event: LogEvent) {
        var stderrHandler = self.stderrHandler
        stderrHandler.logLevel = logLevel
        stderrHandler.metadata = metadata
        stderrHandler.log(event: event)

        let level = event.level
        let message = event.message
        let merged = metadata.merging(event.metadata ?? [:]) { _, new in new }
        let described =
            merged.isEmpty ? "" : " " + merged.sorted { $0.key < $1.key }.map { "\($0)=\($1)" }.joined(separator: " ")
        let stamp = ISO8601DateFormatter().string(from: Date())
        let text = "\(stamp) \(level) \(label):\(described) \(message)\n"
        handle.withLockedValue { handle in
            try? handle.write(contentsOf: Data(text.utf8))
        }
    }
}
