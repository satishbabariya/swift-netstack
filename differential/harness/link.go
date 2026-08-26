package main

import (
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// harnessLink is the gVisor stack.LinkEndpoint that stands in for a NIC.
// It speaks ethernet directly rather than delegating to gVisor's own
// link/ethernet.Endpoint wrapper: it prepends the ethernet header on egress
// and strips it on ingress itself. That is a deliberate choice, not an
// oversight — the Swift stack under comparison speaks ethernet, so driving
// gVisor at bare IP would make the two stacks structurally incomparable and
// every diff would be noise unrelated to TCP.
//
// It has no goroutines and no queue: WritePackets appends captured frames to
// a slice under a mutex, and Inject (called by the driver in main.go, not
// part of stack.LinkEndpoint) delivers an inbound frame synchronously on the
// calling goroutine. That keeps the harness's notion of "what did the stack
// emit in response to this frame" exact rather than racing a worker.
type harnessLink struct {
	mu         sync.Mutex
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress
	mtu        uint32
	emitted    [][]byte
}

func newHarnessLink(linkAddr tcpip.LinkAddress, mtu uint32) *harnessLink {
	return &harnessLink{linkAddr: linkAddr, mtu: mtu}
}

var _ stack.LinkEndpoint = (*harnessLink)(nil)

// --- NetworkLinkEndpoint (14 methods) ---

func (e *harnessLink) MTU() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mtu
}

func (e *harnessLink) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

// MaxHeaderLength is the ethernet header this endpoint prepends in
// AddHeader; there is no lower layer beneath it to add more.
func (e *harnessLink) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

func (e *harnessLink) LinkAddress() tcpip.LinkAddress {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.linkAddr
}

func (e *harnessLink) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

// Capabilities reports CapabilityResolutionRequired so gVisor performs ARP
// address resolution the same way the Swift stack does, rather than
// resolving link addresses through some other mechanism.
func (e *harnessLink) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}

func (e *harnessLink) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

func (e *harnessLink) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}

// Wait, Close, and SetOnCloseAction are no-ops: this harness runs one batch
// of frames to completion and exits: it never shuts down a NIC mid-run.
func (e *harnessLink) Wait() {}

func (e *harnessLink) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader prepends the ethernet header on egress. This mirrors gVisor's
// own link/ethernet.Endpoint.AddHeader.
func (e *harnessLink) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

// ParseHeader consumes the ethernet header on ingress and reports false on a
// runt frame that is too short to carry one.
func (e *harnessLink) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (e *harnessLink) Close() {}

func (e *harnessLink) SetOnCloseAction(func()) {}

// --- LinkWriter (1 method) ---

// WritePackets captures each frame's on-the-wire bytes — link header
// included, since AddHeader has already run by the time the stack calls
// this — instead of transmitting them anywhere.
func (e *harnessLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		buf := pkt.ToBuffer()
		frame := append([]byte(nil), buf.Flatten()...)
		buf.Release()

		e.mu.Lock()
		e.emitted = append(e.emitted, frame)
		e.mu.Unlock()
		n++
	}
	return n, nil
}

// --- Driver interface (not part of stack.LinkEndpoint) ---

// Inject delivers an inbound ethernet frame to the stack, as if it had just
// arrived on the wire. It parses and strips the frame's own ethernet header
// (the same work ParseHeader does for the outbound raw-packet path) and
// reports false — without dispatching anything — for a frame with no
// attached dispatcher or too short to carry an ethernet header.
func (e *harnessLink) Inject(frame []byte) bool {
	e.mu.Lock()
	dispatcher := e.dispatcher
	e.mu.Unlock()
	if dispatcher == nil {
		return false
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), frame...)),
	})
	defer pkt.DecRef()

	if !e.ParseHeader(pkt) {
		return false
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	dispatcher.DeliverNetworkPacket(eth.Type(), pkt)
	return true
}

// TakeEmitted drains and returns every frame WritePackets has captured since
// the last call, in the order the stack wrote them.
func (e *harnessLink) TakeEmitted() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.emitted
	e.emitted = nil
	return out
}
