package main

// TLS mode: a real TLS client in a real guest TCP stack, through the Swift
// gateway, to a real TLS server on loopback.
//
// Every other mode here drives gVisor frame by frame under a manual clock. This
// one is live, because what it checks is not a frame. The question is whether a
// TLS client that splits its ClientHello across two records is refused for a
// denied name, and whether the server behind the gateway ever sees that hello.
// Those are answered by crypto/tls on both ends. Swift test code that produced
// the hello bytes itself would only be checking that the gateway agrees with
// that same Swift code.
//
//	harness tls <name>...    certificate names the upstream serves
//
// It prints {"port":n}, the loopback port of the upstream TLS server, so the
// test can build a gateway that inspects that port. Then it reads one case, as
// one JSON line, runs it, and prints one result line:
//
//	{"wire":p, "local":p, "destination":ip, "name":s, "split":n, "plain":s}
//
// wire is the path the gateway listens on (Gateway.start(listeningOnDatagramSocketAt:))
// and local is the path this side binds to send from. name is the server name
// the client asks for; "" sends no SNI at all. split > 0 cuts the client's
// first record after that many handshake bytes and sends it as two records,
// as sandbox patch 0013's test does; 38 ends the first record after the
// random, before anything that names a host. plain, if set, is sent as-is
// instead of a TLS handshake.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Long enough for a loaded CI runner, short enough that a hang ends the test
// with a result rather than a timeout with none.
const tlsCaseTimeout = 10 * time.Second

type tlsCase struct {
	Wire        string `json:"wire"`
	Local       string `json:"local"`
	Destination string `json:"destination"`
	Name        string `json:"name"`
	Split       int    `json:"split"`
	Plain       string `json:"plain"`
}

type tlsResult struct {
	// ClientError is what the guest's application was told; "" once its
	// handshake completed, or once a plain request got its reply.
	ClientError string `json:"clientError"`
	// Reply is what a plain request read back before EOF.
	Reply string `json:"reply"`
	// Connections is how many connections the upstream accepted: the gateway
	// dials before it answers the guest's SYN, so a refusal on the name still
	// shows as one.
	Connections int `json:"connections"`
	// UpstreamName is the server name the upstream's handshake was asked for,
	// "" if no hello reached it.
	UpstreamName string `json:"upstreamName"`
	// UpstreamError is the upstream's handshake error, "" once it completed.
	UpstreamError string `json:"upstreamError"`
	// UpstreamBytes counts every byte the upstream received.
	UpstreamBytes int `json:"upstreamBytes"`
	// UpstreamReceived is what a plain request delivered to the upstream.
	UpstreamReceived string `json:"upstreamReceived"`
}

func tlsMain(names []string) {
	if err := runTLS(os.Stdin, os.Stdout, names); err != nil {
		fmt.Fprintln(os.Stderr, "harness tls:", err)
		os.Exit(1)
	}
}

func runTLS(in io.Reader, out io.Writer, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("usage: harness tls <certificate name>...")
	}
	upstream, err := newTLSUpstream(names)
	if err != nil {
		return err
	}
	defer upstream.listener.Close()
	encoder := json.NewEncoder(out)
	port := upstream.listener.Addr().(*net.TCPAddr).Port
	if err := encoder.Encode(map[string]int{"port": port}); err != nil {
		return err
	}

	reader := bufio.NewReader(in)
	var c tlsCase
	if err := json.NewDecoder(reader).Decode(&c); err != nil {
		return fmt.Errorf("decode case: %w", err)
	}
	result, cleanup, err := runTLSCase(c, uint16(port), upstream)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := encoder.Encode(result); err != nil {
		return err
	}
	// The guest stays on the wire until the test has closed its gateway, so
	// the gateway's last frames find a socket rather than logging a failed
	// send for each one.
	io.Copy(io.Discard, reader)
	return nil
}

// tlsUpstream is a crypto/tls server that records what arrives at it.
type tlsUpstream struct {
	listener net.Listener
	pool     *x509.CertPool
	cert     tls.Certificate

	mu          sync.Mutex
	connections int
	done        chan tlsResult
}

func newTLSUpstream(names []string) (*tlsUpstream, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &tlsUpstream{
		listener: listener,
		pool:     pool,
		cert:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		done:     make(chan tlsResult, 1),
	}, nil
}

// countingConn counts, and for a plain case keeps, what the upstream reads.
type countingConn struct {
	net.Conn
	mu       sync.Mutex
	count    int
	received []byte
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.count += n
	if len(c.received) < 4096 {
		c.received = append(c.received, b[:n]...)
	}
	c.mu.Unlock()
	return n, err
}

// serve answers the first connection and reports what it saw. A plain case is
// read to EOF and answered with "ok"; a TLS case gets a handshake.
func (u *tlsUpstream) serve(plain bool) {
	conn, err := u.listener.Accept()
	if err != nil {
		u.done <- tlsResult{UpstreamError: err.Error()}
		return
	}
	u.mu.Lock()
	u.connections++
	u.mu.Unlock()
	// Anything after the first connection is counted, not served: one is all
	// a case opens.
	go func() {
		for {
			extra, err := u.listener.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.connections++
			u.mu.Unlock()
			extra.Close()
		}
	}()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(tlsCaseTimeout))
	counted := &countingConn{Conn: conn}

	var result tlsResult
	if plain {
		_, err := io.ReadAll(counted)
		if err != nil {
			result.UpstreamError = err.Error()
		}
		conn.Write([]byte("ok"))
	} else {
		server := tls.Server(counted, &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				result.UpstreamName = hello.ServerName
				return &u.cert, nil
			},
		})
		if err := server.Handshake(); err != nil {
			result.UpstreamError = err.Error()
		} else {
			// Held until the client hangs up, so the client's handshake is
			// not cut short by this side closing first.
			io.Copy(io.Discard, server)
		}
	}
	counted.mu.Lock()
	result.UpstreamBytes = counted.count
	result.UpstreamReceived = string(counted.received)
	counted.mu.Unlock()
	u.done <- result
}

// runTLSCase returns with the guest still on the wire; cleanup takes it off.
func runTLSCase(c tlsCase, port uint16, upstream *tlsUpstream) (tlsResult, func(), error) {
	go upstream.serve(c.Plain != "")

	s, closeWire, err := guestOnWire(c.Wire, c.Local)
	if err != nil {
		return tlsResult{}, nil, err
	}
	cleanup := func() {
		s.Close()
		closeWire()
	}

	ctx, cancel := context.WithTimeout(context.Background(), tlsCaseTimeout)
	defer cancel()
	destination := tcpip.AddrFrom4Slice(net.ParseIP(c.Destination).To4())
	var clientErr error
	var reply []byte
	conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: nicID, Addr: destination, Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		clientErr = err
	} else {
		conn.SetDeadline(time.Now().Add(tlsCaseTimeout))
		if c.Plain != "" {
			_, clientErr = conn.Write([]byte(c.Plain))
			if clientErr == nil {
				clientErr = conn.CloseWrite()
			}
			if clientErr == nil {
				reply, clientErr = io.ReadAll(conn)
			}
		} else {
			var wire net.Conn = conn
			if c.Split > 0 {
				wire = &splitFirstRecord{Conn: conn, cut: c.Split}
			}
			client := tls.Client(wire, &tls.Config{
				ServerName: c.Name,
				RootCAs:    upstream.pool,
				// Go sends no SNI when ServerName is empty, and without a
				// name there is nothing to verify the certificate against.
				InsecureSkipVerify: c.Name == "",
			})
			clientErr = client.Handshake()
		}
		conn.Close()
	}

	var result tlsResult
	select {
	case result = <-upstream.done:
	case <-time.After(tlsCaseTimeout):
		result.UpstreamError = "the upstream never finished with its connection"
	}
	if clientErr != nil {
		result.ClientError = clientErr.Error()
	}
	result.Reply = string(reply)
	upstream.mu.Lock()
	result.Connections = upstream.connections
	upstream.mu.Unlock()
	return result, cleanup, nil
}

// guestOnWire builds a gVisor stack as the guest at guestIP, on a unix datagram
// socket bound at local that sends its frames to the gateway listening at wire.
func guestOnWire(wire, local string) (*stack.Stack, func(), error) {
	gatewayWire, err := net.ResolveUnixAddr("unixgram", wire)
	if err != nil {
		return nil, nil, err
	}
	os.Remove(local)
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"})
	if err != nil {
		return nil, nil, err
	}
	closeWire := func() {
		socket.Close()
		os.Remove(local)
	}

	link := newHarnessLink(tcpip.LinkAddress(guestMAC), linkMTU)
	link.onEmit = func(frame []byte) {
		socket.WriteToUnix(frame, gatewayWire)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := s.CreateNIC(nicID, link); err != nil {
		closeWire()
		return nil, nil, fmt.Errorf("create NIC: %s", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(net.ParseIP(guestIP).To4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		closeWire()
		return nil, nil, fmt.Errorf("add protocol address: %s", err)
	}
	// Everything through the gateway, the way a guest with a default route
	// sends it. ARP still runs: the gateway is resolved like any neighbour.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header4Any(),
		Gateway:     tcpip.AddrFrom4Slice(net.ParseIP(gatewayIP).To4()),
		NIC:         nicID,
	}})

	go func() {
		frame := make([]byte, 65536)
		for {
			n, _, err := socket.ReadFromUnix(frame)
			if err != nil {
				return
			}
			link.Inject(frame[:n])
		}
	}()
	return s, closeWire, nil
}

func header4Any() tcpip.Subnet {
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	return subnet
}

// splitFirstRecord re-frames the first TLS record written through it into
// two, the first carrying cut bytes of the handshake, and passes everything
// after it through untouched. The same wrapper as sandbox patch 0013's test.
type splitFirstRecord struct {
	net.Conn
	cut     int
	pending []byte
	done    bool
}

func (c *splitFirstRecord) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.pending = append(c.pending, b...)
	if len(c.pending) < 5 {
		return len(b), nil
	}
	end := 5 + (int(c.pending[3])<<8 | int(c.pending[4]))
	if len(c.pending) < end {
		return len(b), nil
	}
	c.done = true

	header, body := c.pending[:3], c.pending[5:end]
	cut := min(c.cut, len(body)-1)
	var out []byte
	for _, part := range [][]byte{body[:cut], body[cut:]} {
		out = append(out, header...)
		out = append(out, byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
	}
	out = append(out, c.pending[end:]...)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}
