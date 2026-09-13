package service

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// A minimal but RFC-1928/1929-correct SOCKS5 server (CONNECT + UDP ASSOCIATE) used to
// verify the hand-written socks client end-to-end without a live Xray. It mirrors
// exactly what Xray's socks inbound does for the fields the client touches.

func portOf(t *testing.T, addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// startMockSocksConnect serves SOCKS5 CONNECT with user/pass auth, proxying to the
// requested destination. wantUser is the username it requires.
func startMockSocksConnect(t *testing.T, wantUser string) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSocksConnect(c, wantUser)
		}
	}()
	return portOf(t, ln.Addr().String()), func() { ln.Close() }
}

func serveMockSocksConnect(c net.Conn, wantUser string) {
	defer c.Close()
	br := bufio.NewReader(c)
	if !mockSocksAuth(c, br, wantUser) {
		return
	}
	// request: VER CMD RSV ATYP ADDR PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	host, err := socksReadAddr(br, head[3])
	if err != nil {
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	dport := int(binary.BigEndian.Uint16(pb))
	if head[1] != 0x01 { // only CONNECT here
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(dport)), 3*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	go io.Copy(up, br)
	io.Copy(c, up)
}

// mockSocksAuth performs the method negotiation and (if offered) RFC 1929 user/pass
// check. Returns false on any failure. Requires user==pass==wantUser.
func mockSocksAuth(c net.Conn, br *bufio.Reader, wantUser string) bool {
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil || h[0] != 0x05 {
		return false
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return false
	}
	// Require user/pass.
	c.Write([]byte{0x05, 0x02})
	ah := make([]byte, 2)
	if _, err := io.ReadFull(br, ah); err != nil || ah[0] != 0x01 {
		return false
	}
	u := make([]byte, int(ah[1]))
	io.ReadFull(br, u)
	pl := make([]byte, 1)
	io.ReadFull(br, pl)
	p := make([]byte, int(pl[0]))
	io.ReadFull(br, p)
	if string(u) != wantUser || string(p) != wantUser {
		c.Write([]byte{0x01, 0x01})
		return false
	}
	c.Write([]byte{0x01, 0x00})
	return true
}

func TestDialSocksConnectEndToEnd(t *testing.T) {
	// upstream TCP echo
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	socksPort, closeSocks := startMockSocksConnect(t, "alice@x")
	defer closeSocks()

	conn, err := dialSocksConnect(socksPort, "alice@x", "127.0.0.1", portOf(t, echo.Addr().String()))
	if err != nil {
		t.Fatalf("dialSocksConnect: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping-through-socks")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("echo mismatch: got %q", got)
	}
}

func TestDialSocksConnectWrongCreds(t *testing.T) {
	socksPort, closeSocks := startMockSocksConnect(t, "right@x")
	defer closeSocks()
	if _, err := dialSocksConnect(socksPort, "wrong@x", "127.0.0.1", 9999); err == nil {
		t.Error("dialSocksConnect should fail with wrong credentials")
	}
}
