package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The OpenVPN gap-lease is what stops two devices of one account from being handed the
// same address, and what the disconnect hook uses to free a slot immediately. It is keyed
// by the SESSION for a reason: every device on an inbound is pushed a block address, so
// openvpn keeps offering the same first pool address to all of them, and a pool-keyed
// lease matched the wrong device on disconnect.

func TestOvpnSessionKeyIdentifiesTheSession(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"real address and port", map[string]string{
			"trusted_ip": "203.0.113.7", "trusted_port": "51820",
			"ifconfig_pool_remote_ip": "10.2.0.2"}, "203.0.113.7:51820"},
		{"address only", map[string]string{
			"trusted_ip": "203.0.113.7", "ifconfig_pool_remote_ip": "10.2.0.2"},
			"203.0.113.7"},
		{"ipv6 client", map[string]string{
			"trusted_ip6": "2001:db8::5", "trusted_port": "1194"}, "2001:db8::5:1194"},
		{"no real address falls back to the pool address", map[string]string{
			"ifconfig_pool_remote_ip": "10.2.0.2"}, "10.2.0.2"},
		{"nothing at all", map[string]string{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"trusted_ip", "trusted_ip6", "trusted_port",
				"ifconfig_pool_remote_ip"} {
				os.Unsetenv(k)
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := ovpnSessionKey(); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// Two devices of one account, each with its own lease. Disconnecting one must free that
// one and leave the other alone. Before the leases were keyed by session, both files held
// the same pool address, so this removed whichever came first in directory order: the
// departing device kept its slot (and could not redial) while a live device lost its own.
func TestOvpnRemoveLeaseBySessionFreesOnlyThatDevice(t *testing.T) {
	dir := t.TempDir()
	write := func(blockIP, key string) {
		if err := os.WriteFile(filepath.Join(dir, blockIP), []byte(key), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("10.2.0.2", "203.0.113.7:1111") // device 1
	write("10.2.0.3", "203.0.113.7:2222") // device 2, same client host, different port

	if got := ovpnRemoveLeaseBySession(dir, "203.0.113.7:2222"); got != "10.2.0.3" {
		t.Fatalf("freed %q, want the leased block IP 10.2.0.3", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "10.2.0.2")); err != nil {
		t.Fatalf("the other device's lease was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "10.2.0.3")); !os.IsNotExist(err) {
		t.Fatalf("the departing device's lease survived: %v", err)
	}

	// An unknown session frees nothing, and an empty key must never match a lease (an
	// empty key means "no session identity", which would otherwise sweep a live lease).
	if got := ovpnRemoveLeaseBySession(dir, "198.51.100.1:9999"); got != "" {
		t.Fatalf("unknown session freed %q", got)
	}
	write("10.2.0.4", "")
	if got := ovpnRemoveLeaseBySession(dir, ""); got != "" {
		t.Fatalf("empty session key matched lease %q", got)
	}
}

// The release marker is how the connect hook learns an address is free before openvpn's
// status file (rewritten every 5s) admits it. Without it a client that dropped and
// redialled inside that window was refused on a "reject" inbound.
func TestOvpnReleaseMarkers(t *testing.T) {
	dir := t.TempDir()
	if got := ovpnReleasedIPs(dir, "udp"); len(got) != 0 {
		t.Fatalf("no markers yet, got %v", got)
	}

	ovpnWriteRelease(dir, "udp", "10.2.0.3")
	if got := ovpnReleasedIPs(dir, "udp"); !got["10.2.0.3"] {
		t.Fatalf("release not reported: %v", got)
	}
	// Per transport: udp's marker must not free tcp's address.
	if got := ovpnReleasedIPs(dir, "tcp"); got["10.2.0.3"] {
		t.Fatal("a udp release leaked into tcp")
	}

	ovpnClearRelease(dir, "udp", "10.2.0.3")
	if got := ovpnReleasedIPs(dir, "udp"); got["10.2.0.3"] {
		t.Fatal("marker survived being handed out again")
	}

	// Past the TTL it is gone, and swept from disk: a marker must never outlive the
	// status-file lag it exists to cover.
	ovpnWriteRelease(dir, "udp", "10.2.0.4")
	old := time.Now().Add(-2 * ovpnReleaseTTL)
	marker := filepath.Join(dir, "released-udp", "10.2.0.4")
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}
	if got := ovpnReleasedIPs(dir, "udp"); got["10.2.0.4"] {
		t.Fatal("expired marker still counted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expired marker not swept: %v", err)
	}

	// An empty address writes nothing (an empty file name would be a directory error).
	ovpnWriteRelease(dir, "udp", "")
	if got := ovpnReleasedIPs(dir, "udp"); len(got) != 0 {
		t.Fatalf("empty release wrote something: %v", got)
	}
}
