package service

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// pinOpenWrt makes isOpenWrt answer `on` for the duration of a test.
func pinOpenWrt(t *testing.T, on bool) {
	t.Helper()
	prev := isOpenWrt
	isOpenWrt = func() bool { return on }
	t.Cleanup(func() { isOpenWrt = prev })
}

func TestOpenwrtFirewallRules(t *testing.T) {
	if got := openwrtFirewallRules(false); got != "" {
		t.Fatalf("no IPsec inbound must render no rules (the include file is removed), got %q", got)
	}
	got := openwrtFirewallRules(true)
	for _, want := range []string{
		"udp dport { 500, 4500 }",
		"meta l4proto esp",
		// Decrypted client traffic is TPROXYed to a local socket, so it crosses fw4's
		// input chain; the accept must be pinned to IPsec AND to the VPN space.
		"ip saddr " + vpnAddrSpace + " meta secpath exists",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rules missing %q:\n%s", want, got)
		}
	}
	// fw4 includes are bare rule statements inside a chain block.
	for _, ln := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(ln, "add ") || strings.HasPrefix(ln, "table ") || strings.HasPrefix(ln, "chain ") {
			t.Errorf("fw4 chain include must hold bare rules, got %q", ln)
		}
	}
}

func TestOpenwrtForeignMarkRule(t *testing.T) {
	pinOpenWrt(t, false)
	if got := openwrtForeignMarkRule(); got != "" {
		t.Fatalf("off OpenWrt the ruleset must be unchanged, got %q", got)
	}

	pinOpenWrt(t, true)
	got := openwrtForeignMarkRule()
	for _, want := range []string{
		"add rule ip vpn prerouting",
		"ip saddr " + vpnAddrSpace,
		// Xray's own mark is what stops a TPROXY loop; clearing it would break that.
		"meta mark != 0xff",
		"meta mark set 0x0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rule missing %q: %q", want, got)
		}
	}
}

func TestOpenwrtFilterCores(t *testing.T) {
	all := []string{"l2tp", "pptp", "ikev2", "wgc", "gre"}

	pinOpenWrt(t, false)
	if got := openwrtFilterCores(all); !slices.Equal(got, all) {
		t.Fatalf("off OpenWrt the selection must pass through, got %v", got)
	}
	pinOpenWrt(t, true)
	if got := openwrtFilterCores(all); !slices.Equal(got, []string{"ikev2"}) {
		t.Fatalf("on OpenWrt only IKEv2 is installable, got %v", got)
	}
	if got := installableCores(); !slices.Equal(got, []string{"ikev2"}) {
		t.Fatalf("installableCores on OpenWrt = %v, want [ikev2]", got)
	}
}

func TestOpenwrtFilterStatus(t *testing.T) {
	cards := func() []CoreStatus {
		var out []CoreStatus
		for _, n := range []string{"xray", "l2tp", "ipsec", "ikev2", "wgc", "mtproto", "ssh", "radius"} {
			out = append(out, CoreStatus{Name: n})
		}
		return out
	}
	names := func(cs []CoreStatus) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Name)
		}
		return out
	}

	pinOpenWrt(t, false)
	if got := names(openwrtFilterStatus(cards())); len(got) != 8 {
		t.Fatalf("off OpenWrt every card stays, got %v", got)
	}
	pinOpenWrt(t, true)
	if got := names(openwrtFilterStatus(cards())); !slices.Equal(got, []string{"xray", "ikev2", "ssh", "radius"}) {
		t.Fatalf("OpenWrt cards = %v, want [xray ikev2 ssh radius]", got)
	}
}

// The package's DEPENDS is what installs IKEv2's stack with the panel, and
// openwrtIkev2Packages is what provisioning checks and repairs. If they drift, a fresh
// install is either never auto-provisioned or reports IKEv2 ready without a package.
func TestOpenwrtIkev2PackagesMatchMakefile(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/openwrt/ovpn-ui/Makefile")
	if err != nil {
		t.Skip("packaging Makefile not found:", err)
	}
	m := regexp.MustCompile(`(?s)DEPENDS:=(.*?)\n\s*PKGARCH`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("no DEPENDS in the package Makefile")
	}
	var deps []string
	for _, f := range strings.Fields(strings.ReplaceAll(string(m[1]), "\\", " ")) {
		if name := strings.TrimPrefix(f, "+"); name != "ca-bundle" {
			deps = append(deps, name)
		}
	}
	want := append(slices.Clone(openwrtIkev2Packages), openwrtPanelPackages...)
	sort.Strings(deps)
	sort.Strings(want)
	if !slices.Equal(deps, want) {
		t.Fatalf("Makefile DEPENDS %v\ndiffers from openwrtIkev2Packages %v", deps, want)
	}
}

func TestPlatform(t *testing.T) {
	pinOpenWrt(t, false)
	p := Platform()
	if p.OpenWrt || len(p.InboundProtocols) != 0 || !p.PanelUpdate || !p.WarpCli || p.HideUnavailableTunnels {
		t.Fatalf("a server build must offer everything, got %+v", p)
	}
	if !PlatformAllowsInbound("l2tp") {
		t.Fatal("a server build must allow l2tp")
	}

	pinOpenWrt(t, true)
	p = Platform()
	if !p.OpenWrt || p.PanelUpdate || p.WarpCli || !p.HideUnavailableTunnels {
		t.Fatalf("OpenWrt platform = %+v", p)
	}
	for _, proto := range []string{"vless", "vmess", "trojan", "shadowsocks", "wireguard", "ikev2", "ssh"} {
		if !PlatformAllowsInbound(proto) {
			t.Errorf("OpenWrt must offer %s", proto)
		}
	}
	for _, proto := range []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "wg-c", "awg", "gre", "mtproto"} {
		if PlatformAllowsInbound(proto) {
			t.Errorf("OpenWrt has no backend for %s and must not offer it", proto)
		}
	}
}

// Every protocol named for OpenWrt has to be one the frontend knows: the picker filters
// Protocols by this list, so a misspelt entry would silently offer nothing.
func TestOpenwrtInboundProtocolsAreKnown(t *testing.T) {
	raw, err := os.ReadFile("../assets/js/model/inbound.js")
	if err != nil {
		t.Skip("inbound.js not found:", err)
	}
	block := regexp.MustCompile(`(?s)const Protocols = \{(.*?)\};`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("no Protocols object in inbound.js")
	}
	known := map[string]bool{}
	for _, m := range regexp.MustCompile(`:\s*'([^']+)'`).FindAllSubmatch(block[1], -1) {
		known[string(m[1])] = true
	}
	for _, p := range openwrtInboundProtocols {
		if !known[p] {
			t.Errorf("openwrtInboundProtocols names %q, which inbound.js Protocols does not define", p)
		}
	}
}
