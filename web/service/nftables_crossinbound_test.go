package service

import (
	"strings"
	"testing"
)

// countRule reports how many times an exact "saddr X daddr Y <verdict>" prerouting
// rule appears in the generated nft script.
func countRule(script, saddr, daddr, verdict string) int {
	rule := "add rule ip vpn prerouting ip saddr " + saddr + " ip daddr " + daddr + " " + verdict + "\n"
	return strings.Count(script, rule)
}

// TestCrossInboundRules pins the inter-inbound reachability enforcement: traffic
// between two DIFFERENT inbounds is accepted only when BOTH opted into Cross
// Inbound (which the UI gates behind Client to Client), and dropped otherwise.
//
// The drop is the regression this guards: it must be emitted for non-opted pairs
// so the traffic can't fall through to TPROXY and get bridged through Xray, which
// is what made the toggle a silent no-op.
func TestCrossInboundRules(t *testing.T) {
	a := "10.0.2.0/24" // inbound A
	c := "10.1.7.0/24" // inbound C

	both := func(c2c, cross bool) vpnNet { return vpnNet{c2c: c2c, cross: cross} }

	t.Run("both opted in -> accept both directions, no drop", func(t *testing.T) {
		na, nc := both(true, true), both(true, true)
		na.subnets, nc.subnets = []string{a}, []string{c}
		var b strings.Builder
		writeCrossInboundRules(&b, []vpnNet{na, nc})
		s := b.String()
		if countRule(s, a, c, "accept") != 1 || countRule(s, c, a, "accept") != 1 {
			t.Fatalf("expected accept in both directions, got:\n%s", s)
		}
		if strings.Contains(s, "drop") {
			t.Fatalf("opted-in pair must not be dropped, got:\n%s", s)
		}
	})

	t.Run("cross off on one side -> drop both directions", func(t *testing.T) {
		na, nc := both(true, true), both(true, false) // C has Client-to-Client but not Cross Inbound
		na.subnets, nc.subnets = []string{a}, []string{c}
		var b strings.Builder
		writeCrossInboundRules(&b, []vpnNet{na, nc})
		s := b.String()
		if countRule(s, a, c, "drop") != 1 || countRule(s, c, a, "drop") != 1 {
			t.Fatalf("non-mutual pair must be dropped both ways, got:\n%s", s)
		}
		if strings.Contains(s, "accept") {
			t.Fatalf("non-mutual pair must not be accepted, got:\n%s", s)
		}
	})

	t.Run("default (both off) -> drop", func(t *testing.T) {
		na, nc := both(false, false), both(false, false)
		na.subnets, nc.subnets = []string{a}, []string{c}
		var b strings.Builder
		writeCrossInboundRules(&b, []vpnNet{na, nc})
		s := b.String()
		if countRule(s, a, c, "drop") != 1 || countRule(s, c, a, "drop") != 1 {
			t.Fatalf("default pair must be dropped both ways, got:\n%s", s)
		}
	})

	t.Run("single inbound -> no inter-inbound rules", func(t *testing.T) {
		na := both(true, true)
		na.subnets = []string{a}
		var b strings.Builder
		writeCrossInboundRules(&b, []vpnNet{na})
		if s := b.String(); s != "" {
			t.Fatalf("single inbound must emit no cross rules, got:\n%s", s)
		}
	})

	t.Run("multi-subnet inbound (OpenVPN udp+tcp) covers every block pair", func(t *testing.T) {
		udp, tcp := "10.2.3.0/24", "10.3.3.0/24"
		ovpn := both(true, true)
		ovpn.subnets = []string{udp, tcp} // one inbound, two blocks
		other := both(true, true)
		other.subnets = []string{a}
		var b strings.Builder
		writeCrossInboundRules(&b, []vpnNet{ovpn, other})
		s := b.String()
		// Both of the OpenVPN inbound's blocks must reach the other inbound and back.
		for _, pair := range [][2]string{{udp, a}, {tcp, a}, {a, udp}, {a, tcp}} {
			if countRule(s, pair[0], pair[1], "accept") != 1 {
				t.Fatalf("missing accept %s -> %s, got:\n%s", pair[0], pair[1], s)
			}
		}
		// The two blocks belong to the SAME inbound, so no rule between them here.
		if strings.Contains(s, "saddr "+udp+" ip daddr "+tcp) || strings.Contains(s, "saddr "+tcp+" ip daddr "+udp) {
			t.Fatalf("same-inbound blocks must not get cross-inbound rules, got:\n%s", s)
		}
	})
}
