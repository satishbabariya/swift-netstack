// Command harness drives gVisor's TCP/IP stack from a scripted list of
// frames and reports what it emits, so the pure-Swift reimplementation in
// this repository can be diffed against something nobody on this project
// wrote. See ../README.md for the full rationale and the constraints this
// binary depends on (module-cache build, Reno pinning, both addresses
// fixed).
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

	// TCPReassembler.defaultMaximumBytes on the Swift side.
	swiftReceiveCapacity = 256 * 1024

	gatewayIP  = "192.168.127.1"
	gatewayMAC = "\x5a\x94\xef\xe4\x0c\xee"

	guestIP  = "192.168.127.2"
	guestMAC = "\x0a\x0b\x0c\x0d\x0e\x0f"

	guestSubnetCIDR = "192.168.127.0/24"

	linkMTU = 1500

	// The port the harness listens on. VectorFrames (the Swift-side codec)
	// fixes every TCP line's ports at 50000 -> 8080, so a listener anywhere
	// else would describe a connection to somewhere the vectors never
	// address.
	listenPort = 8080

	// listenBacklog bounds the accept queue. It is deliberately larger than
	// any generated sequence needs: gVisor switches to SYN cookies once the
	// pending queue reaches capacity-1 (see accept.go's handleListenSegment),
	// and a SYN-cookie SYN-ACK carries a different option set and a different
	// ISS derivation than the ordinary path. A differential run that silently
	// crossed that threshold would be comparing two different gVisor
	// behaviours, not two stacks.
	listenBacklog = 64
)

// step is one entry of a run: an optional frame to inject, how far to
// advance the manual clock afterwards, and an optional application-level
// action to perform. The three lists are index-aligned; `Actions` may be
// absent entirely, and any element may be the empty string for "nothing".
type run struct {
	Frames    []string `json:"frames"`
	AdvanceMs []int64  `json:"advanceMs"`
	Actions   []string `json:"actions,omitempty"`
}

// request is the harness's stdin contract. A request carries either a single
// run inline (the original one-run form, still used by the ARP/ICMP
// validation test) or a batch of independent runs in `Runs`, each played
// against its own freshly built stack.
//
// Batching exists because process spawn dominates: the M4 gate is ten
// thousand generated sequences, and paying a fork+exec and a stack build per
// sequence turns a two-minute run into a twenty-minute one for no gain in
// what is actually compared.
type request struct {
	run
	Runs []run `json:"runs,omitempty"`
}

// response is always the batched shape, one entry per run, each entry one
// list of base64 frames PER STEP.
//
// Per-step rather than one flat list per run, because a flat list cannot tell
// "retransmitted at 1 s" from "retransmitted at 8 s": both stacks would emit
// the same frames in the same order and compare equal while disagreeing about
// the entire RTO ladder. The step boundary is the only timing information a
// frame-level differential has, and throwing it away costs exactly the
// property a retransmission comparison exists to check.
type response struct {
	Runs [][][]string `json:"runs"`
}

func main() {
	if err := execute(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func execute(stdin *os.File, stdout *os.File) error {
	var req request
	if err := json.NewDecoder(bufio.NewReader(stdin)).Decode(&req); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}

	runs := req.Runs
	if len(runs) == 0 {
		runs = []run{req.run}
	}

	resp := response{Runs: make([][][]string, len(runs))}
	for i, r := range runs {
		steps, err := play(r)
		if err != nil {
			return fmt.Errorf("run %d: %w", i, err)
		}
		resp.Runs[i] = steps
	}
	return json.NewEncoder(stdout).Encode(&resp)
}

// play builds a fresh stack, drives it through one run, and returns the
// frames it emitted during each step, base64-encoded, in emission order.
func play(r run) ([][]string, error) {
	if len(r.Frames) != len(r.AdvanceMs) {
		return nil, fmt.Errorf("frames (%d) and advanceMs (%d) must be the same length", len(r.Frames), len(r.AdvanceMs))
	}
	if r.Actions != nil && len(r.Actions) != len(r.Frames) {
		return nil, fmt.Errorf("actions (%d) and frames (%d) must be the same length", len(r.Actions), len(r.Frames))
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

	// Give gVisor the same receive capacity the Swift stack has, so the two
	// derive the same window scale and advertise comparable windows.
	//
	// Without this they diverge on every frame for a reason that is not a
	// defect in either: each side picks its shift from its own buffer size, so
	// gVisor's 1 MiB default gives `wscale 5` against the Swift stack's
	// `wscale 3`, and every window field afterwards is scaled by a different
	// factor. Matching the capacities makes the comparison about behaviour
	// again rather than about configuration.
	//
	// 256 KiB is `TCPReassembler.defaultMaximumBytes` on the Swift side. Both
	// stacks pick the smallest shift that fits their capacity into the 16-bit
	// field, so both should land on 3 — and if gVisor ever stops doing that,
	// the SYN-ACK's option list is where it will show.
	rcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: swiftReceiveCapacity,
		Max:     swiftReceiveCapacity,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBuf); err != nil {
		return nil, fmt.Errorf("set receive buffer: %s", err)
	}

	// And turn off gVisor's receive-buffer auto-tuning. This stack does not
	// auto-tune -- its window is a function of what the reassembler holds and
	// nothing else -- so leaving moderation on compares two different policies
	// and calls the difference a divergence.
	moderate := tcpip.TCPModerateReceiveBufferOption(false)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		return nil, fmt.Errorf("disable receive buffer moderation: %s", err)
	}

	// Turn RACK off, which is a configuration difference and not a permitted
	// divergence -- see ../README.md.
	//
	// This stack now HAS RACK-TLP, and the estimator disagreement that used to
	// be blamed for this is fixed (see ../README.md, RFC 7323 Appendix G). The
	// lift was attempted again afterwards and still does not hold, for a
	// reason that is now precise:
	//
	// gVisor REPLACES its retransmission timer with the probe timer while a
	// probe is armed -- `schedulePTO` disables `resendTimer` and
	// `probeTimerExpired` re-enables it -- so with RACK on, the first
	// retransmission of a flight is owned by a different timer than it is here,
	// where both run side by side and the retransmission timer wins. Loss
	// detection and the reordering timer agree frame for frame; what differs is
	// which timer fires first.
	//
	// Adopting gVisor's structure would change when the RTO fires on every
	// connection with RACK enabled, which is a bigger decision than parity and
	// is not one to take by default. Recorded rather than chased.
	recovery := tcpip.TCPRecovery(0)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		return nil, fmt.Errorf("disable RACK: %s", err)
	}

	if err := s.CreateNIC(nicID, link); err != nil {
		return nil, fmt.Errorf("create NIC: %s", err)
	}

	gatewayAddr := net.ParseIP(gatewayIP).To4()
	if gatewayAddr == nil {
		return nil, fmt.Errorf("gatewayIP %q is not a valid IPv4 address", gatewayIP)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(gatewayAddr).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add protocol address: %s", err)
	}

	// Both spoofing and promiscuous mode, deliberately — see link.go's and
	// this file's doc comments, and ../README.md. Upstream gvisor-tap-vsock
	// sets both and so does the Swift stack; a differential run between a
	// promiscuous stack and a non-promiscuous one diverges on every frame
	// for reasons that have nothing to do with TCP.
	// Pin gVisor's retransmission tuning to the Swift stack's own documented
	// constants, so the differential compares the ALGORITHM rather than two
	// different choices of constant.
	//
	// gVisor ships Linux's numbers: a 200 ms RTO floor, a 120 s ceiling, and
	// fifteen retries. This stack ships RFC 6298 §2.4's 1 s floor
	// (`RTTEstimator.minimumTimeout`), a 60 s ceiling
	// (`RTTEstimator.maximumTimeout`) and an eight-transmission budget
	// (`TCPEndpoint.maximumFinTransmissions`). Both sets are defensible —
	// RFC 6298 §2.4 makes the 1 s floor a SHOULD and explicitly contemplates a
	// lower one — and each is already pinned on its own side by unit tests and
	// by `tcp-data.vec`/`tcp-close.vec`. Left unaligned they would put every
	// retransmission in every generated sequence on a different rung of the
	// ladder, burying whatever the run was actually meant to find.
	for _, opt := range []tcpip.SettableTransportProtocolOption{
		ptr(tcpip.TCPMinRTOOption(1 * time.Second)),
		ptr(tcpip.TCPMaxRTOOption(60 * time.Second)),
		ptr(tcpip.TCPMaxRetriesOption(8)),
		// Auto-tuning makes the advertised window a function of how much the
		// application has read and when, which is a gVisor heuristic with no
		// counterpart here and no RFC behind it. Off, with a receive buffer
		// far wider than the 16-bit window field, the advertised window is
		// pinned at its ceiling — which is exactly where this stack's sits,
		// since it delivers synchronously and holds nothing. See ../README.md.
		ptr(tcpip.TCPModerateReceiveBufferOption(false)),
	} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return nil, fmt.Errorf("set transport protocol option %T: %s", opt, err)
		}
	}

	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}

	_, guestSubnet, err := net.ParseCIDR(guestSubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse guest subnet: %w", err)
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(guestSubnet.IP), tcpip.MaskFromBytes(guestSubnet.Mask))
	if err != nil {
		return nil, fmt.Errorf("build subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})

	// A STATIC neighbour entry for the guest, not a learned one.
	//
	// gVisor's NUD gives a learned entry a reachable lifetime of
	// BaseReachableTime scaled by a factor drawn uniformly from
	// [MinRandomFactor, MaxRandomFactor] — a *random* lifetime, which under a
	// manual clock is a random point at which the stack stops answering with
	// TCP and answers with an ARP request instead. That is correct behaviour
	// and fatal to a comparison: the frame counts and the frame types both
	// change, for reasons that have nothing to do with TCP. A static entry
	// never expires and never probes.
	//
	// The Swift side is held to the same shape by its differential fixture,
	// which records the guest in `Stack.arpCache` and re-asserts it as it
	// advances the clock (`ARPCache` entries live 60 seconds, and an RTO
	// backoff ladder crosses that). Neither stack emits ARP during a
	// generated sequence, so an ARP frame appearing in a diff is a real
	// divergence rather than an expected one.
	guestAddr := net.ParseIP(guestIP).To4()
	if guestAddr == nil {
		return nil, fmt.Errorf("guestIP %q is not a valid IPv4 address", guestIP)
	}
	if err := s.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFrom4Slice(guestAddr), tcpip.LinkAddress(guestMAC)); err != nil {
		return nil, fmt.Errorf("add static neighbor: %s", err)
	}

	// A real listening endpoint, not tcp.Forwarder.
	//
	// The forwarder dispatches its handler on a bare `go f.handler(...)` that
	// nothing observable ever completes, so a harness built on it has to
	// stand a wall-clock sleep in for goroutine scheduling — and the handler
	// it must install can only complete the connection and immediately close
	// it, which tears the connection down one round trip after it opens and
	// makes every data-transfer comparison structurally impossible. A
	// listening endpoint keeps the connection for as long as the script does,
	// and every segment it processes runs on the TCP dispatcher's processor
	// goroutines, which `settle` below drains deterministically. There is no
	// sleep anywhere in this binary.
	var listenQueue waiter.Queue
	listener, tcpErr := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenQueue)
	if tcpErr != nil {
		return nil, fmt.Errorf("new endpoint: %s", tcpErr)
	}
	defer listener.Close()
	if tcpErr := listener.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4Slice(gatewayAddr), Port: listenPort}); tcpErr != nil {
		return nil, fmt.Errorf("bind: %s", tcpErr)
	}
	if tcpErr := listener.Listen(listenBacklog); tcpErr != nil {
		return nil, fmt.Errorf("listen: %s", tcpErr)
	}

	var accepted []tcpip.Endpoint
	defer func() {
		for _, ep := range accepted {
			ep.Close()
		}
	}()

	// settle blocks until every processor goroutine has drained its endpoint
	// queue. Stack.Pause asserts each processor's pause waker; a processor
	// that still has queued endpoints re-asserts and keeps working, and only
	// signals once its queue is empty (dispatcher.go's processor.start). So
	// this is a POSITIVE completion signal, not a timeout — the thing the
	// previous forwarder-based harness had to approximate with a 200 ms wall
	// clock wait on every single frame.
	settle := func() {
		s.Pause()
		s.Resume()
	}

	// harvest accepts whatever the listener has completed and drains every
	// accepted endpoint's receive buffer.
	//
	// The drain models the Swift stack's receive side, which has no socket
	// buffer at all: `TCPEndpoint` hands in-order bytes straight to `onData`
	// and frees the space in the same pass. Leaving gVisor's buffer full
	// instead would make its advertised window fall while ours stayed put, on
	// every data segment, for a reason that is a design difference rather
	// than a defect. See ../README.md.
	harvest := func() {
		for {
			ep, _, tcpErr := listener.Accept(nil)
			if tcpErr != nil {
				break
			}
			accepted = append(accepted, ep)
		}
		live := accepted[:0]
		for _, ep := range accepted {
			for {
				var sink bytes.Buffer
				if _, tcpErr := ep.Read(&sink, tcpip.ReadOptions{}); tcpErr != nil {
					break
				}
			}
			// An endpoint whose connection is over is CLOSED by the
			// application here, which is what releases its four-tuple.
			//
			// Not tidiness: gVisor keeps a dead endpoint registered until the
			// application closes it, so a segment arriving for that tuple
			// afterwards is delivered to the corpse and dropped. The Swift
			// stack deletes the block the moment the connection ends, so the
			// same segment falls through to the LISTENER and is answered with
			// a reset, exactly as RFC 9293 §3.10.7.1 requires. Leaving the
			// corpse registered would report that as a divergence on every
			// sequence whose connection is reset and then probed.
			switch tcp.EndpointState(ep.State()) {
			case tcp.StateClose, tcp.StateError:
				ep.Close()
			default:
				live = append(live, ep)
			}
		}
		accepted = live
	}

	// The gateway-side initial send sequence, learned from the first SYN this
	// stack emits. Every inbound acknowledgement number in a request is
	// expressed in a normalized space where that ISS is zero, and is shifted
	// into this stack's real space here — see shiftAck.
	var gatewayISS uint32
	var gatewayISSKnown bool

	steps := make([][]string, len(r.Frames))
	for i := range r.Frames {
		if encoded := r.Frames[i]; encoded != "" {
			frame, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("frame %d: decode base64: %w", i, err)
			}
			if gatewayISSKnown {
				shiftAck(frame, gatewayISS)
			}
			link.Inject(frame)
			settle()
		}

		clock.Advance(time.Duration(r.AdvanceMs[i]) * time.Millisecond)
		settle()

		harvest()
		settle()

		if r.Actions != nil {
			if err := apply(r.Actions[i], accepted); err != nil {
				return nil, fmt.Errorf("step %d: %w", i, err)
			}
			settle()
		}

		// TEMPORARY DIAGNOSTIC. gVisor's own view of its retransmission timer,
		// per step, on stderr so it cannot disturb the JSON on stdout.
		//
		// This is the tool ../README.md names for the residual RTO
		// disagreement: reasoning about which stack arms what against which
		// instant has produced one wrong answer already ("Linux clears the
		// backoff, so gVisor must"), and the estimator is a thing that can
		// simply be asked.
		if path := os.Getenv("NETSTACK_HARNESS_RTO"); path != "" {
			// A FILE rather than stderr: the Swift side owns the harness's
			// pipes, and a diagnostic that goes somewhere the caller has
			// already redirected is a diagnostic nobody reads.
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				for _, ep := range accepted {
					var info tcpip.TCPInfoOption
					if tcpErr := ep.GetSockOpt(&info); tcpErr == nil {
						fmt.Fprintf(
							f, "RTO step=%d now=%v rto=%v rtt=%v rttvar=%v\n",
							i, clock.NowMonotonic(), info.RTO, info.RTT, info.RTTVar)
					}
				}
				f.Close()
			}
		}

		emitted := link.TakeEmitted()
		steps[i] = make([]string, len(emitted))
		for j, frame := range emitted {
			if !gatewayISSKnown {
				if iss, ok := synSequence(frame); ok {
					gatewayISS, gatewayISSKnown = iss, true
				}
			}
			steps[i][j] = base64.StdEncoding.EncodeToString(frame)
		}
	}

	return steps, nil
}

// ptr is a helper for the option list above: SetTransportProtocolOption wants
// a pointer, and Go has no address-of for a composite literal of a named
// scalar type.
func ptr[T any](v T) *T { return &v }

// tcpOf returns the TCP header of an ethernet frame carrying an
// option-less-or-not IPv4 packet, along with the IPv4 header it sits in, or
// nil for anything that is not TCP over IPv4.
func tcpOf(frame []byte) (header.IPv4, header.TCP) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, nil
	}
	eth := header.Ethernet(frame[:header.EthernetMinimumSize])
	if eth.Type() != header.IPv4ProtocolNumber {
		return nil, nil
	}
	rest := frame[header.EthernetMinimumSize:]
	if len(rest) < header.IPv4MinimumSize {
		return nil, nil
	}
	ip := header.IPv4(rest)
	headerLength := int(ip.HeaderLength())
	if ip.TransportProtocol() != tcp.ProtocolNumber || len(rest) < headerLength+header.TCPMinimumSize {
		return nil, nil
	}
	return ip, header.TCP(rest[headerLength:int(ip.TotalLength())])
}

// synSequence reports the sequence number of a frame carrying a TCP SYN.
//
// The gateway's SYN-ACK is the only place its initial send sequence appears
// on the wire, and two independently implemented stacks never choose the same
// one — that is the first of the three divergences spec §8.2 permits. Rather
// than discard sequence numbers from the comparison because of it, both sides
// of this differential learn their own ISS here and express every sequence
// relative to it, so the sequence SPACE stays fully comparable while only the
// arbitrary origin is allowed to differ.
func synSequence(frame []byte) (uint32, bool) {
	_, t := tcpOf(frame)
	if t == nil || t.Flags()&header.TCPFlagSyn == 0 {
		return 0, false
	}
	return t.SequenceNumber(), true
}

// shiftAck adds iss to a TCP frame's acknowledgement number in place and
// repairs the checksum.
//
// A guest cannot acknowledge a sequence number it has not been told, so a
// script written against one stack's ISS is meaningless against the other's.
// Shifting rather than rewriting preserves every DELIBERATE error: a script
// that acknowledges five bytes too many still does so, against whichever ISS
// the stack under test actually chose.
func shiftAck(frame []byte, iss uint32) {
	ip, t := tcpOf(frame)
	if t == nil || t.Flags()&header.TCPFlagAck == 0 {
		return
	}
	t.SetAckNumber(t.AckNumber() + iss)
	t.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(t)))
	sum = checksum.Checksum(t, sum)
	t.SetChecksum(^sum)
}

// apply performs one application-level action against the accepted
// connection. The vocabulary mirrors the Swift-side vector DSL's application
// lines (`write <n>` and `close`, see Tests/NetstackTests/Support/VectorScript.swift)
// so that a generated sequence drives the same application on both stacks.
//
// An action naming no connection is an error rather than a silent no-op: a
// sequence whose write vanished on one side and not the other would diverge
// several frames later, reporting the wrong step.
func apply(action string, accepted []tcpip.Endpoint) error {
	if action == "" {
		return nil
	}
	if len(accepted) == 0 {
		return fmt.Errorf("action %q has no accepted connection to act on", action)
	}
	ep := accepted[len(accepted)-1]

	switch {
	case action == "close":
		// Shutdown(Write), NOT Close.
		//
		// `close` in the Swift stack's interface — and in RFC 9293 §3.10.4 —
		// closes the SEND direction: it sends a FIN and goes on accepting the
		// peer's data until the peer's own FIN arrives. gVisor's
		// Endpoint.Close is a socket close, which is shutdown(RDWR) plus
		// release: data arriving afterwards draws a RESET, the way Linux
		// resets a socket closed with data still coming. Driving one stack
		// with a half close and the other with a full one is comparing two
		// different programs, and it shows up as a reset on one side and an
		// acknowledgement on the other for every sequence that receives
		// anything after closing.
		return errorOrNil(ep.Shutdown(tcpip.ShutdownWrite))
	case strings.HasPrefix(action, "write:"):
		n, err := strconv.Atoi(strings.TrimPrefix(action, "write:"))
		if err != nil || n <= 0 {
			return fmt.Errorf("malformed action %q", action)
		}
		payload := bytes.NewReader(make([]byte, n))
		written, tcpErr := ep.Write(readerPayloader{payload}, tcpip.WriteOptions{})
		if tcpErr != nil {
			return fmt.Errorf("write %d bytes: %s", n, tcpErr)
		}
		if written != int64(n) {
			return fmt.Errorf("write %d bytes: only %d accepted", n, written)
		}
		return nil
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}

// errorOrNil turns a tcpip.Error (an interface, so a typed nil is not nil)
// into a plain error or nil.
func errorOrNil(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", err)
}

// readerPayloader adapts a *bytes.Reader to tcpip.Payloader, which wants a
// Len() alongside io.Reader.
type readerPayloader struct{ r *bytes.Reader }

func (p readerPayloader) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p readerPayloader) Len() int                   { return p.r.Len() }

var _ tcpip.Payloader = readerPayloader{}
var _ io.Reader = readerPayloader{}
