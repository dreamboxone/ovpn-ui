package service

import (
	"crypto/ed25519"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testHostKey(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = seed
	}
	pub, _, err := ed25519.GenerateKey(strings.NewReader(string(b) + strings.Repeat("x", 128)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A blank pin must LEARN the first key and then REFUSE a different one. Before
// this it returned nil unconditionally forever, i.e. accept-any-key.
func TestTofuLearnsThenEnforces(t *testing.T) {
	tun := &sshTunnel{cfg: SshOutboundConfig{Tag: "t", AuthType: "password"}, log: &procLog{}}
	cb := tun.clientConfig().HostKeyCallback

	first := testHostKey(t, 1)
	if err := cb("h", &net.TCPAddr{}, first); err != nil {
		t.Fatalf("first connect should be accepted: %v", err)
	}
	if got := tun.learnedKey.Load(); got == nil || *got != ssh.FingerprintSHA256(first) {
		t.Fatal("first key was not recorded, so nothing will ever be compared")
	}
	// Same key again: still fine.
	if err := cb("h", &net.TCPAddr{}, first); err != nil {
		t.Fatalf("reconnect with the same key must succeed: %v", err)
	}
	// Different key: this is the MITM case and must be refused.
	if err := cb("h", &net.TCPAddr{}, testHostKey(t, 2)); err == nil {
		t.Fatal("a CHANGED host key was accepted; TOFU is not enforcing")
	}
}

// An explicit pin still wins and is matched exactly.
func TestExplicitPinStillEnforced(t *testing.T) {
	key := testHostKey(t, 3)
	tun := &sshTunnel{
		cfg: SshOutboundConfig{Tag: "t", AuthType: "password", KnownHost: ssh.FingerprintSHA256(key)},
		log: &procLog{},
	}
	cb := tun.clientConfig().HostKeyCallback
	if err := cb("h", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := cb("h", &net.TCPAddr{}, testHostKey(t, 4)); err == nil {
		t.Fatal("wrong key accepted against an explicit pin")
	}
}
