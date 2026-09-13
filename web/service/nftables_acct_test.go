package service

import (
	"strings"
	"testing"
)

// Real `nft -a list chain` shapes from a live server, with two single-device WireGuard
// accounts connected. Uplink and downlink live in separate chains because a combined chain
// has to be jumped from both the prerouting and postrouting hooks, which bills a FORWARDED
// packet twice (see ApplyNftRules).
//
// Note how nft echoes the address: the rule reads `ip saddr 10.7.1.2`, with the /32
// stripped, even though AddClientAccounting was called with "10.7.1.2/32". That mismatch is
// the bug this file guards. The duplicate rules below are genuine: the old add path could
// never recognise its own work, so it re-appended on every sweep, and each extra copy
// counted the same packet again (an accounting chain has no verdict, so traversal continues).
const wgcAcctInListing = `table ip vpn {
	chain wgc_acct_in { # handle 7
		ip saddr 10.7.1.3 counter name "wg-c_up_10_7_1_3m32" # handle 52
		ip saddr 10.7.1.3 counter name "wg-c_up_10_7_1_3m32" # handle 54
		ip saddr 10.7.1.2 counter name "wg-c_up_10_7_1_2m32" # handle 58
		ip saddr 10.7.1.2 counter name "wg-c_up_10_7_1_2m32" # handle 60
	}
}`

const wgcAcctOutListing = `table ip vpn {
	chain wgc_acct_out { # handle 8
		ip daddr 10.7.1.3 counter name "wg-c_down_10_7_1_3m32" # handle 53
		ip daddr 10.7.1.2 counter name "wg-c_down_10_7_1_2m32" # handle 59
	}
}`

// The formatting mismatch that defeated the previous `strings.Contains(out, "addr "+ip+" ")`
// guard. Pinned as its own test because it is the non-obvious fact: a reader checking the
// add path would reasonably assume the key round-trips through nft unchanged. It does not.
func TestNftStripsHostPrefixFromListedAddress(t *testing.T) {
	const key = "10.7.1.2/32"
	if strings.Contains(wgcAcctInListing, "addr "+key+" ") {
		t.Fatalf("fixture no longer reflects nft's normalisation: expected %q to be echoed without its /32", key)
	}
	if !strings.Contains(wgcAcctInListing, "ip saddr 10.7.1.2 counter") {
		t.Fatal("fixture should contain the bare, prefix-stripped address")
	}
}

func TestAcctRuleHandlesFindsEveryDuplicate(t *testing.T) {
	assertHandles(t, wgcAcctInListing, "wg-c_up_10_7_1_2m32", []string{"58", "60"})
}

// A counter name embeds both the direction and the full key, so lookups must not bleed
// across directions or between accounts whose addresses share a prefix.
func TestAcctRuleHandlesDoesNotMatchOtherCountersOrAccounts(t *testing.T) {
	assertHandles(t, wgcAcctInListing, "wg-c_up_10_7_1_3m32", []string{"52", "54"})
	assertHandles(t, wgcAcctOutListing, "wg-c_down_10_7_1_2m32", []string{"59"})
	assertHandles(t, wgcAcctOutListing, "wg-c_down_10_7_1_3m32", []string{"53"})
	// An uplink counter never appears in the downlink chain, and vice versa.
	assertHandles(t, wgcAcctOutListing, "wg-c_up_10_7_1_2m32", nil)
	assertHandles(t, wgcAcctInListing, "wg-c_down_10_7_1_2m32", nil)
	assertHandles(t, wgcAcctInListing, "wg-c_up_10_7_1_9m32", nil)
}

func assertHandles(t *testing.T, listing, counter string, want []string) {
	t.Helper()
	got := acctRuleHandlesFrom(listing, counter)
	if len(got) != len(want) {
		t.Fatalf("%s: handles = %v, want %v", counter, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: handles = %v, want %v", counter, got, want)
		}
	}
}

// Uplink and downlink must resolve to DIFFERENT chains, and the hyphen in a slug like
// "wg-c" has to be stripped or the rules target a chain ApplyNftRules never created.
func TestNftAcctChainNamesByDirection(t *testing.T) {
	for _, tc := range []struct{ proto, dir, want string }{
		{"wg-c", "in", "wgc_acct_in"},
		{"wg-c", "out", "wgc_acct_out"},
		{"l2tp", "in", "l2tp_acct_in"},
		{"openconnect", "out", "openconnect_acct_out"},
	} {
		if got := nftAcctChain(tc.proto, tc.dir); got != tc.want {
			t.Errorf("nftAcctChain(%q, %q) = %q, want %q", tc.proto, tc.dir, got, tc.want)
		}
	}
	if nftAcctChain("wg-c", "in") == nftAcctChain("wg-c", "out") {
		t.Fatal("uplink and downlink must not share a chain: one chain forces both hooks to jump it")
	}
}

// Every slug a client can be accounted under must have had its chains created by
// ApplyNftRules, or its rules land nowhere and the account silently bills zero.
func TestAcctProtocolsCoverEveryAccountedSlug(t *testing.T) {
	created := make(map[string]bool, len(acctProtocols)*2)
	for _, p := range acctProtocols {
		created[p+"_acct_in"] = true
		created[p+"_acct_out"] = true
	}
	// The slugs CollectAndResetTraffic maps back via byProto (see xray_traffic_job.go).
	for _, slug := range []string{
		"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wg-c", "awg",
	} {
		for _, dir := range []string{"in", "out"} {
			if chain := nftAcctChain(slug, dir); !created[chain] {
				t.Errorf("protocol %q needs chain %q, which ApplyNftRules never creates", slug, chain)
			}
		}
	}
}

// counterKey has to survive the round trip that CollectAndResetTraffic reverses, for both
// the bare-IP protocols and WireGuard's block CIDR.
func TestCounterKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ in, key string }{
		{"10.0.2.10", "10_0_2_10"},
		{"10.7.1.2/32", "10_7_1_2m32"},
		{"10.7.8.8/29", "10_7_8_8m29"},
	} {
		if got := counterKey(tc.in); got != tc.key {
			t.Fatalf("counterKey(%q) = %q, want %q", tc.in, got, tc.key)
		}
		back := strings.ReplaceAll(strings.ReplaceAll(tc.key, "_", "."), "m", "/")
		if back != tc.in {
			t.Fatalf("reverse of %q = %q, want %q", tc.key, back, tc.in)
		}
	}
}
