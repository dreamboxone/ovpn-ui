package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// writeTestCert emits a PEM certificate carrying the given DNS names and IP SANs and
// returns its path. Optionally prepends an unrelated leaf so we also prove certHost
// reads the FIRST cert, not a later one.
func writeTestCert(t *testing.T, dns []string, ips []net.IP) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cn-should-be-ignored.example"},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertHost(t *testing.T) {
	// Domain cert (Let's Encrypt case): the first DNS SAN wins.
	dom := writeTestCert(t, []string{"panel.example.com", "www.example.com"}, nil)
	if got := certHost(dom); got != "panel.example.com" {
		t.Errorf("domain cert: got %q, want panel.example.com", got)
	}

	// IP-only cert (self-signed case): the IP SAN wins.
	ipc := writeTestCert(t, nil, []net.IP{net.ParseIP("203.0.113.7")})
	if got := certHost(ipc); got != "203.0.113.7" {
		t.Errorf("ip cert: got %q, want 203.0.113.7", got)
	}

	// Self-signed panel cert: "localhost" + 127.0.0.1 loopback SANs sit alongside
	// the server's public IP. certHost must skip the loopback identities and return
	// the routable IP, else deploy.sh prints an unreachable https://localhost URL.
	selfsigned := writeTestCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("203.0.113.7")})
	if got := certHost(selfsigned); got != "203.0.113.7" {
		t.Errorf("self-signed cert: got %q, want 203.0.113.7", got)
	}

	// Only loopback SANs (public IP undetected when the cert was generated): nothing
	// routable, so certHost returns "" and panelAccessURL falls back to the detected IP.
	loopback := writeTestCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if got := certHost(loopback); got != "" {
		t.Errorf("loopback-only cert: got %q, want empty", got)
	}

	// No SAN at all: no fallback to the deprecated CN, so empty.
	none := writeTestCert(t, nil, nil)
	if got := certHost(none); got != "" {
		t.Errorf("no-SAN cert: got %q, want empty", got)
	}

	// Missing file: empty, never a panic.
	if got := certHost(filepath.Join(t.TempDir(), "nope.pem")); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
}
