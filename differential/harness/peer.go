package main

// Peer mode: gVisor as the GUEST, answering a connection a test opens to the
// Swift gateway, and reporting what its application is told.
//
// The batch mode in main.go plays the gateway against scripted guest frames,
// which is the wrong way round for a question about what a reset does to the
// side that receives it. Here the roles are swapped and the conversation is
// live, one JSON command per line in and one JSON reply per line out, because
// the frames the Swift side produces depend on the ones this side did (every
// acknowledgement number is the other's sequence number).
//
//	{"op":"connect"}                  start the active open to 192.168.127.1:8080
//	{"op":"inject","frame":"<b64>"}   a frame from the wire arrives
//	{"op":"advance","ms":n}           the clock moves on
//	{"op":"write","bytes":n}          the application writes n bytes
//	{"op":"read"}                     the application reads; reports bytes and error
//
// Every reply carries the frames this stack put on the wire since the last
// command. Nothing here sleeps: each command ends with Pause/Resume, which
// blocks until gVisor's processor goroutines have nothing left to do.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// The port the peer dials from. VectorFrames and the Swift fixtures fix the
// guest's port at 50000 and the gateway's at 8080.
const peerPort = 50000

type peerCommand struct {
	Op    string `json:"op"`
	Frame string `json:"frame,omitempty"`
	Ms    int64  `json:"ms,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
}

type peerRead struct {
	Bytes int `json:"bytes"`
	// Errno is the Linux errno gVisor's syscall layer gives the application for
	// this read, 0 for none. ECONNRESET is 104.
	Errno int `json:"errno"`
	// Error is netstack's name for it, so a failure reads without a table.
	Error string `json:"error,omitempty"`
}

type peerReply struct {
	Frames []string  `json:"frames"`
	Read   *peerRead `json:"read,omitempty"`
	State  string    `json:"state,omitempty"`
	Error  string    `json:"error,omitempty"`
}

// linuxErrno is the errno for the read errors a TCP peer can see. gVisor's own
// translation (pkg/syserr) cannot be imported here: it drags in safecopy, which
// panics at init on Darwin. The values are Linux's, which is what gVisor reports.
func linuxErrno(err tcpip.Error) int {
	switch err.(type) {
	case *tcpip.ErrConnectionReset:
		return 104 // ECONNRESET
	case *tcpip.ErrConnectionAborted:
		return 103 // ECONNABORTED
	case *tcpip.ErrTimeout:
		return 110 // ETIMEDOUT
	case *tcpip.ErrConnectionRefused:
		return 111 // ECONNREFUSED
	case *tcpip.ErrNotConnected:
		return 107 // ENOTCONN
	case *tcpip.ErrClosedForReceive:
		return 0 // end of stream: read returns 0 bytes, no error
	}
	return -1
}

func runPeer(in io.Reader, out io.Writer) error {
	clock := faketime.NewManualClock()
	link := newHarnessLink(tcpip.LinkAddress(guestMAC), linkMTU)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		Clock:              clock,
	})
	defer s.Close()

	if err := s.CreateNIC(nicID, link); err != nil {
		return fmt.Errorf("create NIC: %s", err)
	}
	guestAddr := net.ParseIP(guestIP).To4()
	gatewayAddr := net.ParseIP(gatewayIP).To4()
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(guestAddr).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add protocol address: %s", err)
	}
	_, guestSubnet, err := net.ParseCIDR(guestSubnetCIDR)
	if err != nil {
		return err
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(guestSubnet.IP), tcpip.MaskFromBytes(guestSubnet.Mask))
	if err != nil {
		return err
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})
	// Static, for the reason main.go gives: a learned entry expires at a random
	// point under a manual clock and the stack then answers with ARP.
	if err := s.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFrom4Slice(gatewayAddr), tcpip.LinkAddress(gatewayMAC)); err != nil {
		return fmt.Errorf("add static neighbor: %s", err)
	}

	settle := func() {
		s.Pause()
		s.Resume()
	}

	var queue waiter.Queue
	var endpoint tcpip.Endpoint
	defer func() {
		if endpoint != nil {
			endpoint.Close()
		}
	}()

	reply := peerReply{}
	frames := func() []string {
		emitted := link.TakeEmitted()
		encoded := make([]string, len(emitted))
		for i, frame := range emitted {
			encoded[i] = base64.StdEncoding.EncodeToString(frame)
		}
		return encoded
	}

	encoder := json.NewEncoder(out)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for scanner.Scan() {
		var command peerCommand
		reply = peerReply{}
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			return fmt.Errorf("decode command: %w", err)
		}

		switch command.Op {
		case "connect":
			ep, tcpErr := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
			if tcpErr != nil {
				reply.Error = fmt.Sprintf("new endpoint: %s", tcpErr)
				break
			}
			endpoint = ep
			if tcpErr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4Slice(guestAddr), Port: peerPort}); tcpErr != nil {
				reply.Error = fmt.Sprintf("bind: %s", tcpErr)
				break
			}
			// ErrConnectStarted is the success of a non-blocking connect.
			if tcpErr := ep.Connect(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4Slice(gatewayAddr), Port: listenPort}); tcpErr != nil {
				if _, started := tcpErr.(*tcpip.ErrConnectStarted); !started {
					reply.Error = fmt.Sprintf("connect: %s", tcpErr)
				}
			}
		case "inject":
			frame, err := base64.StdEncoding.DecodeString(command.Frame)
			if err != nil {
				return fmt.Errorf("decode frame: %w", err)
			}
			link.Inject(frame)
		case "advance":
			clock.Advance(time.Duration(command.Ms) * time.Millisecond)
		case "write":
			if endpoint == nil {
				reply.Error = "write before connect"
				break
			}
			payload := bytes.NewReader(make([]byte, command.Bytes))
			written, tcpErr := endpoint.Write(readerPayloader{payload}, tcpip.WriteOptions{})
			if tcpErr != nil {
				reply.Error = fmt.Sprintf("write: %s", tcpErr)
			} else if written != int64(command.Bytes) {
				reply.Error = fmt.Sprintf("write: %d of %d accepted", written, command.Bytes)
			}
		case "read":
			if endpoint == nil {
				reply.Error = "read before connect"
				break
			}
			settle()
			var sink bytes.Buffer
			result := peerRead{}
			for {
				n, tcpErr := endpoint.Read(&sink, tcpip.ReadOptions{})
				result.Bytes += n.Count
				if tcpErr == nil {
					continue
				}
				// Would-block is "nothing more yet", not a failure: the loop
				// exists to drain what arrived before the error, so a reset
				// that follows buffered data is still reported.
				if _, wouldBlock := tcpErr.(*tcpip.ErrWouldBlock); !wouldBlock {
					result.Error = tcpErr.String()
					result.Errno = linuxErrno(tcpErr)
				}
				break
			}
			reply.Read = &result
		case "state":
			if endpoint != nil {
				reply.State = tcp.EndpointState(endpoint.State()).String()
			}
		default:
			return fmt.Errorf("unknown op %q", command.Op)
		}

		settle()
		reply.Frames = frames()
		if err := encoder.Encode(&reply); err != nil {
			return fmt.Errorf("encode reply: %w", err)
		}
	}
	return scanner.Err()
}

func peerMain() {
	if err := runPeer(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "harness peer:", err)
		os.Exit(1)
	}
}
