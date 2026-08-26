// Command harness drives gVisor's TCP/IP stack from a scripted list of
// frames and reports what it emits, so the pure-Swift reimplementation in
// this repository can be diffed against something nobody on this project
// wrote. See ../README.md for the full rationale and the constraints this
// binary depends on (module-cache build, Reno pinning, both addresses
// fixed).
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The harness always plays the gateway side of the fixed gateway/guest pair
// used throughout this project's differential vectors — see
// Tests/NetstackTests/Support/VectorFrames.swift and the vector scripts
// under Tests/NetstackTests/Vectors on the Swift side, which hardcode the
// same two addresses. A request's frames are expected to already be
// addressed accordingly: this harness does not learn addressing from the
// request, so a script built against different addresses will simply not
// match anything this stack owns.
const (
	nicID = tcpip.NICID(1)

	gatewayIP  = "192.168.127.1"
	gatewayMAC = "\x5a\x94\xef\xe4\x0c\xee"

	guestSubnetCIDR = "192.168.127.0/24"

	linkMTU = 1500

	// tcpForwarderMaxInFlight bounds the number of not-yet-established
	// connections the forwarder will track concurrently; the harness only
	// ever drives one scripted connection at a time; 10 leaves headroom
	// without being unbounded.
	tcpForwarderMaxInFlight = 10

	// handshakeSignalTimeout bounds how long the per-frame loop will wait,
	// in real wall-clock time, for the forwarder's handshake goroutine to
	// signal completion before moving on. gVisor's tcp.Forwarder dispatches
	// its handler with a bare `go f.handler(...)` — not a clock.AfterFunc
	// timer — so ManualClock.Advance has no visibility into it at all; no
	// amount of simulated time will make the goroutine run. This wait is
	// therefore real time standing in for goroutine scheduling latency
	// only (the handler is typically already most of the way done — SYN
	// processing and CreateEndpoint have already run — by the time the
	// main goroutine reaches this wait), not for any simulated protocol
	// delay. 200ms is generous for that under a loaded or sandboxed CI
	// runner while still keeping a script of a realistic size (tens of
	// frames) well under a second of added wall time; every frame pays it
	// when no handshake is pending, since the harness cannot know in
	// advance which frames are SYNs.
	handshakeSignalTimeout = 200 * time.Millisecond
)

// request is the harness's stdin contract: a list of base64-encoded
// ethernet frames to inject, paired index-for-index with how many
// milliseconds to advance the manual clock after injecting each one.
type request struct {
	Frames    []string `json:"frames"`
	AdvanceMs []int64  `json:"advanceMs"`
}

// response is the harness's stdout contract: every frame the stack emitted,
// base64-encoded, in emission order.
type response struct {
	Emitted []string `json:"emitted"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func run(stdin *os.File, stdout *os.File) error {
	var req request
	if err := json.NewDecoder(bufio.NewReader(stdin)).Decode(&req); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if len(req.Frames) != len(req.AdvanceMs) {
		return fmt.Errorf("frames (%d) and advanceMs (%d) must be the same length", len(req.Frames), len(req.AdvanceMs))
	}

	clock := faketime.NewManualClock()
	link := newHarnessLink(tcpip.LinkAddress(gatewayMAC), linkMTU)

	// arp.NewProtocol and tcp.NewProtocol are both required by the brief;
	// tcp.NewProtocol's zero-argument form already defaults to Reno
	// (newProtocol(s, ccReno, nil) internally) — CUBIC is never selected.
	// This is load-bearing for the differential comparison: see
	// ../README.md.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		Clock:              clock,
	})
	defer s.Close()

	if err := s.CreateNIC(nicID, link); err != nil {
		return fmt.Errorf("create NIC: %s", err)
	}

	gatewayAddr := net.ParseIP(gatewayIP).To4()
	if gatewayAddr == nil {
		return fmt.Errorf("gatewayIP %q is not a valid IPv4 address", gatewayIP)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(gatewayAddr).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add protocol address: %s", err)
	}

	// Both spoofing and promiscuous mode, deliberately — see link.go's and
	// this file's doc comments, and ../README.md. Upstream gvisor-tap-vsock
	// sets both and so does the Swift stack; a differential run between a
	// promiscuous stack and a non-promiscuous one diverges on every frame
	// for reasons that have nothing to do with TCP.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("set spoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("set promiscuous mode: %s", err)
	}

	_, guestSubnet, err := net.ParseCIDR(guestSubnetCIDR)
	if err != nil {
		return fmt.Errorf("parse guest subnet: %w", err)
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(guestSubnet.IP), tcpip.MaskFromBytes(guestSubnet.Mask))
	if err != nil {
		return fmt.Errorf("build subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})

	// gVisor's tcp.Forwarder dispatches this handler on its own goroutine
	// (a bare `go f.handler(...)`, not anything ManualClock tracks) as soon
	// as a SYN arrives, and the SYN-ACK is written — synchronously, inside
	// this goroutine — by the time r.CreateEndpoint returns. handshakeDone
	// is how the per-frame loop below finds out that has happened, since
	// clock.Advance cannot: it only waits on clock.AfterFunc-scheduled
	// work, and this goroutine is not that.
	//
	// tcp.NewForwarder(s, 0, 10, handler) matches upstream's
	// pkg/services/forwarder/tcp.go: a handler that completes the endpoint
	// and immediately closes it, rather than proxying it anywhere. The
	// point of this harness is what gVisor's TCP emits on the wire around
	// connection setup and teardown, not any application behavior on top.
	handshakeDone := make(chan struct{}, tcpForwarderMaxInFlight)
	forwarder := tcp.NewForwarder(s, 0, tcpForwarderMaxInFlight, func(r *tcp.ForwarderRequest) {
		defer func() {
			select {
			case handshakeDone <- struct{}{}:
			default:
				// The channel is sized to tcpForwarderMaxInFlight, the same
				// bound the forwarder itself enforces on concurrent
				// in-flight connections, so this default case is a
				// safety net rather than something a normal run can hit.
			}
		}()

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		r.Complete(err != nil)
		if err != nil {
			return
		}
		ep.Close()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	var emitted [][]byte
	for i, encoded := range req.Frames {
		frame, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("frame %d: decode base64: %w", i, err)
		}
		link.Inject(frame)
		clock.Advance(time.Duration(req.AdvanceMs[i]) * time.Millisecond)
		waitForHandshake(handshakeDone, handshakeSignalTimeout)
		emitted = append(emitted, link.TakeEmitted()...)
	}
	// A handshake goroutine triggered by the very last input frame has had
	// no later frame's wait to be caught by; give it the same bounded
	// window here so its SYN-ACK (or close) is not silently dropped from
	// the response.
	waitForHandshake(handshakeDone, handshakeSignalTimeout)
	emitted = append(emitted, link.TakeEmitted()...)

	resp := response{Emitted: make([]string, len(emitted))}
	for i, frame := range emitted {
		resp.Emitted[i] = base64.StdEncoding.EncodeToString(frame)
	}
	return json.NewEncoder(stdout).Encode(resp)
}

// waitForHandshake blocks for up to timeout waiting for a single signal on
// done, then drains any further signals that are already available without
// waiting any further. It is not a poll loop and it does not sleep: a
// signal that arrives promptly is consumed promptly, and a frame that
// provokes no handshake costs exactly one bounded wait rather than hanging.
func waitForHandshake(done <-chan struct{}, timeout time.Duration) {
	select {
	case <-done:
	case <-time.After(timeout):
		return
	}
	for {
		select {
		case <-done:
		default:
			return
		}
	}
}
