import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// Remove a socket file left behind by a previous run, and nothing else.
///
/// Every listener here binds a unix socket at a path an operator gave it, and a
/// path holding a socket from a process that is gone must be cleared or the bind
/// fails with EADDRINUSE forever. So each one removed whatever was there.
///
/// Whatever was there. `--listen-vfkit /etc/hosts` deleted `/etc/hosts` and
/// bound a socket in its place, and the only sign was that the gateway started
/// normally. A mistyped path is the ordinary way this happens and the file is
/// gone before anything can say so.
///
/// A socket is removed; anything else is left where it is, and the bind then
/// fails with a message naming the path. The check and the unlink are not atomic
/// -- something could replace the file in between -- and that is not the case
/// this is for: it is for a typo, where nothing is racing anybody.
func removeStaleSocket(at path: String) {
    var info = stat()
    guard stat(path, &info) == 0 else { return }
    guard info.st_mode & S_IFMT == S_IFSOCK else { return }
    try? FileManager.default.removeItem(atPath: path)
}
