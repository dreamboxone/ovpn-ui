package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// A minimal SOCKS5 client (RFC 1928 + RFC 1929 user/pass auth) used to hand a
// forwarded SSH connection to Xray's loopback socks inbound. The username is the
// account email, which Xray surfaces as the connection's user so per-client routing
// rules resolve. Both CONNECT (TCP) and UDP ASSOCIATE (the UDP bridge) are supported.

const socksDialTimeout = 10 * time.Second

// dialSocksConnect opens a TCP CONNECT through the loopback socks inbound on
// 127.0.0.1:port, authenticating as user (password equals user, matching the
// panel-generated socks accounts), and returns the tunneled connection to
// destHost:destPort. destHost is passed through as a domain when it is not an IP, so
// Xray does the name resolution and can route by domain.
func dialSocksConnect(port int, user, destHost string, destPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), socksDialTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(socksDialTimeout))
	br := bufio.NewReader(conn)
	if err := socksHandshake(conn, br, user); err != nil {
		conn.Close()
		return nil, err
	}

	atyp, addr := socksEncodeAddr(destHost)
	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	req = binary.BigEndian.AppendUint16(req, uint16(destPort))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, err := socksReadReply(br); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// dialSocksUDPAssociate opens a UDP ASSOCIATE on the loopback socks inbound and
// returns the still-open TCP control connection (the association lives only while it
// stays open) and the UDP relay address to send datagrams to.
func dialSocksUDPAssociate(port int, user string) (net.Conn, *net.UDPAddr, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), socksDialTimeout)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(socksDialTimeout))
	br := bufio.NewReader(conn)
	if err := socksHandshake(conn, br, user); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// UDP ASSOCIATE with DST 0.0.0.0:0 (we will send to arbitrary destinations).
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, nil, err
	}
	host, bndPort, err := socksReadReply(br)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	ip := net.ParseIP(host)
	// Xray answers with its own listen address; if it is unspecified use loopback,
	// since the socks inbound is bound to 127.0.0.1.
	if ip == nil || ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, &net.UDPAddr{IP: ip, Port: bndPort}, nil
}

// socksHandshake performs method negotiation and, when required, RFC 1929 user/pass
// auth (password equals user).
func socksHandshake(conn net.Conn, br *bufio.Reader, user string) error {
	// Offer no-auth and user/pass; the panel socks inbound requires user/pass.
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks: bad version %d", head[0])
	}
	switch head[1] {
	case 0x00:
		return nil
	case 0x02:
		u := []byte(user)
		auth := []byte{0x01, byte(len(u))}
		auth = append(auth, u...)
		auth = append(auth, byte(len(u)))
		auth = append(auth, u...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(br, resp); err != nil {
			return err
		}
		if resp[1] != 0x00 {
			return fmt.Errorf("socks: auth rejected")
		}
		return nil
	default:
		return fmt.Errorf("socks: no acceptable auth method (%d)", head[1])
	}
}

// socksReadReply reads a SOCKS5 reply and returns the bound address and port. It
// errors when REP is non-zero.
func socksReadReply(br *bufio.Reader) (string, int, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return "", 0, err
	}
	if head[0] != 0x05 {
		return "", 0, fmt.Errorf("socks: bad reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return "", 0, fmt.Errorf("socks: request failed (rep=%d)", head[1])
	}
	host, err := socksReadAddr(br, head[3])
	if err != nil {
		return "", 0, err
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(pb)), nil
}

// socksReadAddr reads an address of the given ATYP from br and returns it as a string.
func socksReadAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("socks: unknown atyp %d", atyp)
	}
}

// socksEncodeAddr encodes a host as a SOCKS5 (ATYP, address-bytes) pair. A non-IP host
// is sent as a domain so Xray resolves and routes it.
func socksEncodeAddr(host string) (byte, []byte) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return 0x01, v4
		}
		return 0x04, ip.To16()
	}
	if len(host) > 255 {
		host = host[:255]
	}
	return 0x03, append([]byte{byte(len(host))}, host...)
}

// socksEncodeUDP wraps a UDP payload in a SOCKS5 UDP request header addressed to
// destHost:destPort (RFC 1928 section 7). FRAG is always 0 (no fragmentation).
func socksEncodeUDP(destHost string, destPort int, payload []byte) []byte {
	atyp, addr := socksEncodeAddr(destHost)
	out := make([]byte, 0, 4+len(addr)+2+len(payload))
	out = append(out, 0x00, 0x00, 0x00, atyp)
	out = append(out, addr...)
	out = binary.BigEndian.AppendUint16(out, uint16(destPort))
	out = append(out, payload...)
	return out
}

// socksDecodeUDP parses a received SOCKS5 UDP datagram, returning the source address,
// port, and the inner payload.
func socksDecodeUDP(pkt []byte) (host string, port int, payload []byte, ok bool) {
	if len(pkt) < 4 || pkt[2] != 0x00 {
		return "", 0, nil, false
	}
	atyp := pkt[3]
	p := pkt[4:]
	var alen int
	switch atyp {
	case 0x01:
		alen = 4
	case 0x04:
		alen = 16
	case 0x03:
		if len(p) < 1 {
			return "", 0, nil, false
		}
		alen = 1 + int(p[0])
	default:
		return "", 0, nil, false
	}
	if len(p) < alen+2 {
		return "", 0, nil, false
	}
	switch atyp {
	case 0x01:
		host = net.IP(p[:4]).String()
	case 0x04:
		host = net.IP(p[:16]).String()
	case 0x03:
		host = string(p[1:alen])
	}
	port = int(binary.BigEndian.Uint16(p[alen : alen+2]))
	payload = p[alen+2:]
	return host, port, payload, true
}
