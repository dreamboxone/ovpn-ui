package service

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEffectiveSshK(t *testing.T) {
	one := 1
	zero := 0
	five := 5
	big := 1000
	cases := []struct {
		in   *int
		want int
	}{
		{nil, 1},
		{&one, 1},
		{&zero, 0},
		{&five, 5},
		{&big, 64},
	}
	for _, c := range cases {
		if got := effectiveSshK(c.in); got != c.want {
			t.Errorf("effectiveSshK(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseDirectTCPIP(t *testing.T) {
	var b []byte
	b = appendSSHString(b, "example.com")
	b = binary.BigEndian.AppendUint32(b, 443)
	b = appendSSHString(b, "10.0.0.2")
	b = binary.BigEndian.AppendUint32(b, 51000)

	d, ok := parseDirectTCPIP(b)
	if !ok {
		t.Fatal("parseDirectTCPIP failed on a valid payload")
	}
	if d.destHost != "example.com" || d.destPort != 443 || d.origHost != "10.0.0.2" || d.origPort != 51000 {
		t.Errorf("parsed wrong: %+v", d)
	}
	if _, ok := parseDirectTCPIP([]byte{0, 0, 0, 5, 'a'}); ok {
		t.Error("parseDirectTCPIP accepted a truncated payload")
	}
}

func appendSSHString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func TestSocksEncodeAddr(t *testing.T) {
	atyp, addr := socksEncodeAddr("1.2.3.4")
	if atyp != 0x01 || !bytes.Equal(addr, []byte{1, 2, 3, 4}) {
		t.Errorf("ipv4 encode wrong: %d %v", atyp, addr)
	}
	atyp, addr = socksEncodeAddr("example.com")
	if atyp != 0x03 || addr[0] != byte(len("example.com")) {
		t.Errorf("domain encode wrong: %d %v", atyp, addr)
	}
	atyp, _ = socksEncodeAddr("2001:db8::1")
	if atyp != 0x04 {
		t.Errorf("ipv6 atyp wrong: %d", atyp)
	}
}

func TestSocksUDPRoundTrip(t *testing.T) {
	payload := []byte("hello dns")
	pkt := socksEncodeUDP("8.8.8.8", 53, payload)
	host, port, got, ok := socksDecodeUDP(pkt)
	if !ok {
		t.Fatal("socksDecodeUDP failed")
	}
	if host != "8.8.8.8" || port != 53 || !bytes.Equal(got, payload) {
		t.Errorf("round trip wrong: host=%s port=%d payload=%q", host, port, got)
	}
}

func TestBuildUdpgwReply(t *testing.T) {
	conid := [2]byte{0x34, 0x12}
	reply := buildUdpgwReply(conid, "8.8.8.8", 53, []byte("data"))
	if reply == nil {
		t.Fatal("buildUdpgwReply returned nil")
	}
	// flags(1) + conid(2) + ipv4(4) + port(2) + payload(4) = 13
	if len(reply) != 13 {
		t.Fatalf("reply len = %d, want 13", len(reply))
	}
	if reply[0]&udpgwFlagIPv6 != 0 {
		t.Error("ipv4 reply should not set the IPv6 flag")
	}
	if reply[1] != 0x34 || reply[2] != 0x12 {
		t.Error("conid not echoed verbatim")
	}
	if !bytes.Equal(reply[3:7], []byte{8, 8, 8, 8}) {
		t.Errorf("address wrong: %v", reply[3:7])
	}
	if binary.BigEndian.Uint16(reply[7:9]) != 53 {
		t.Error("port wrong")
	}
}

// newTestSession builds a session for the admit tests (conn is nil; admit never
// touches it).
func newTestSession(email, ip string, since time.Time) *sshSession {
	return &sshSession{email: email, srcIP: ip, since: since}
}

func TestAdmitUnderLimitAndSameDevice(t *testing.T) {
	m := newSshManager()
	t0 := time.Unix(1000, 0)

	// First device admitted under K=2.
	if _, ok := m.admit(newTestSession("a@x", "1.1.1.1", t0), 2, "reject"); !ok {
		t.Fatal("first device should be admitted")
	}
	// A second session from the SAME IP is the same device, always allowed.
	if _, ok := m.admit(newTestSession("a@x", "1.1.1.1", t0.Add(time.Second)), 2, "reject"); !ok {
		t.Fatal("same-device session should be admitted")
	}
	// A second distinct device is admitted while under K=2.
	if _, ok := m.admit(newTestSession("a@x", "2.2.2.2", t0.Add(2*time.Second)), 2, "reject"); !ok {
		t.Fatal("second distinct device should be admitted under K=2")
	}
}

func TestAdmitRejectStrategy(t *testing.T) {
	m := newSshManager()
	t0 := time.Unix(1000, 0)
	if _, ok := m.admit(newTestSession("a@x", "1.1.1.1", t0), 1, "reject"); !ok {
		t.Fatal("first device should be admitted")
	}
	evicted, ok := m.admit(newTestSession("a@x", "2.2.2.2", t0.Add(time.Second)), 1, "reject")
	if ok {
		t.Error("reject strategy should refuse the second distinct device at K=1")
	}
	if len(evicted) != 0 {
		t.Error("reject strategy must not evict anyone")
	}
}

func TestAdmitAcceptEvictsOldest(t *testing.T) {
	m := newSshManager()
	t0 := time.Unix(1000, 0)
	first := newTestSession("a@x", "1.1.1.1", t0)
	if _, ok := m.admit(first, 1, "accept"); !ok {
		t.Fatal("first device should be admitted")
	}
	evicted, ok := m.admit(newTestSession("a@x", "2.2.2.2", t0.Add(time.Second)), 1, "accept")
	if !ok {
		t.Fatal("accept strategy should admit the new device")
	}
	if len(evicted) != 1 || evicted[0] != first {
		t.Errorf("accept strategy should evict the oldest device, got %v", evicted)
	}
}

func TestAdmitUnlimited(t *testing.T) {
	m := newSshManager()
	t0 := time.Unix(1000, 0)
	for i := 0; i < 10; i++ {
		ip := net.IPv4(10, 0, 0, byte(i)).String()
		if _, ok := m.admit(newTestSession("a@x", ip, t0.Add(time.Duration(i)*time.Second)), 0, "reject"); !ok {
			t.Fatalf("unlimited (k=0) should admit device %d", i)
		}
	}
}
