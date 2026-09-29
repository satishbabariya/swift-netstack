module interop

go 1.25.6

// Pinned, like the harness pins gVisor. An interop check against a floating
// dependency proves something different every time it runs.
require github.com/containers/gvisor-tap-vsock v0.8.9-0.20260821162340-fca6da3418e8
