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
	fmt.Printf("OK   List -> %d forward(s), and it names the protocol: %q\n", len(after), after[len(after)-1].Protocol)

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
	fmt.Println("OK   Unexpose")

	fmt.Println("\nupstream's client library drove this gateway end to end")
}
