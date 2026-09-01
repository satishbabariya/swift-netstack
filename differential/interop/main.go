// Drives a swift-netstack gateway using gvisor-tap-vsock's OWN client library.
//
// Every request below is upstream's code, not a re-implementation of it. That
// is the point: the Swift side was written from reading upstream, and reading
// is what got the `--listen` flag, the `/services/dhcp/leases` path and Go's
// case-insensitive field matching wrong.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

func main() {
	socket := os.Args[1]
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	c := client.New(httpClient, "http://netstack")

	fail := func(what string, err error) {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}

	forwards, err := c.List()
	if err != nil {
		fail("List", err)
	}
	fmt.Printf("OK   List -> %d forward(s)\n", len(forwards))

	if err := c.Expose(&types.ExposeRequest{
		Local: ":0", Remote: "192.168.127.2:80", Protocol: types.TCP,
	}); err != nil {
		fail("Expose", err)
	}
	fmt.Println("OK   Expose")

	after, err := c.List()
	if err != nil {
		fail("List after expose", err)
	}
	if len(after) != len(forwards)+1 {
		fail("List after expose", fmt.Errorf("expected %d forwards, got %d", len(forwards)+1, len(after)))
	}
	// The line below claims the gateway names the protocol, and until this was
	// added it printed whatever came back without reading it -- an empty or
	// absent field would have been reported as a success naming nothing.
	protocol := after[len(after)-1].Protocol
	if protocol != types.TCP {
		fail("List after expose", fmt.Errorf("expected protocol %q, got %q", types.TCP, protocol))
	}
	fmt.Printf("OK   List -> %d forward(s), and it names the protocol: %q\n", len(after), protocol)

	zones, err := c.ListDNS()
	if err != nil {
		fail("ListDNS", err)
	}
	// `Protected` is on upstream's main branch and not in v0.8.9, which is the
	// newest release. This port implements it because it was read from main;
	// the field is simply ignored by an older client, which is what a JSON
	// decoder does with a field it has no home for.
	fmt.Printf("OK   ListDNS -> %d zone(s), first %q\n", len(zones), zones[0].Name)

	if err := c.AddDNS(&types.Zone{
		Name:    "interop.test.",
		Records: []types.Record{{Name: "api", IP: net.ParseIP("10.11.12.13")}},
	}); err != nil {
		fail("AddDNS", err)
	}
	fmt.Println("OK   AddDNS")

	zonesAfter, err := c.ListDNS()
	if err != nil {
		fail("ListDNS after add", err)
	}
	found := false
	for _, z := range zonesAfter {
		if z.Name == "interop.test" || z.Name == "interop.test." {
			found = true
		}
	}
	if !found {
		fail("ListDNS after add", fmt.Errorf("the zone just added is not listed"))
	}
	fmt.Println("OK   ListDNS sees the new zone")

	leases, err := c.ListDHCPLeases()
	if err != nil {
		fail("ListDHCPLeases", err)
	}
	fmt.Printf("OK   ListDHCPLeases -> %d lease(s)\n", len(leases))

	local := after[len(after)-1].Local
	if err := c.Unexpose(&types.UnexposeRequest{Local: local, Protocol: types.TCP}); err != nil {
		fail("Unexpose", err)
	}

	// That the call did not error is not that the forward is gone, and this
	// half asserted only the first. Made to answer 200 and remove nothing, the
	// gateway drove this whole driver to its closing line with the port still
	// bound and still listed. The udp half below has always checked; the tcp
	// half is the one that shipped without a check, which is the asymmetry the
	// comment further down complains about in the opposite direction.
	afterUnexpose, err := c.List()
	if err != nil {
		fail("List after unexpose", err)
	}
	for _, forward := range afterUnexpose {
		if forward.Local == local {
			fail("Unexpose", fmt.Errorf("the forward is still listed: %v", forward))
		}
	}
	fmt.Println("OK   Unexpose, and it is gone from the list")

	// UDP, which nothing exercised until this was written -- not a test, not a
	// script, not this driver. A forward is two halves and only the TCP half of
	// each was ever driven; the UDP expose and unexpose reached the gateway
	// through no path at all.
	//
	// Through upstream's client rather than by hand, because the protocol field
	// has to survive its types as well as this gateway's parsing: "udp" is what
	// upstream sends, and a gateway that only recognised "tcp" would answer this
	// with a 400 nobody had ever seen.
	if err := c.Expose(&types.ExposeRequest{
		Local: ":0", Remote: "192.168.127.2:9999", Protocol: types.UDP,
	}); err != nil {
		fail("Expose udp", err)
	}
	fmt.Println("OK   Expose udp")

	withUDP, err := c.List()
	if err != nil {
		fail("List after exposing udp", err)
	}
	var udpLocal string
	for _, forward := range withUDP {
		if forward.Protocol == types.UDP {
			udpLocal = forward.Local
		}
	}
	if udpLocal == "" {
		fail("List after exposing udp", fmt.Errorf("no udp forward in %v", withUDP))
	}
	fmt.Printf("OK   the udp forward is listed as %s\n", udpLocal)

	if err := c.Unexpose(&types.UnexposeRequest{Local: udpLocal, Protocol: types.UDP}); err != nil {
		fail("Unexpose udp", err)
	}
	fmt.Println("OK   Unexpose udp")

	afterUDP, err := c.List()
	if err != nil {
		fail("List after unexposing udp", err)
	}
	for _, forward := range afterUDP {
		if forward.Protocol == types.UDP {
			fail("Unexpose udp", fmt.Errorf("the forward is still listed: %v", forward))
		}
	}
	fmt.Println("OK   and it is gone from the list")

	fmt.Println("\nupstream's client library drove this gateway end to end")
}
