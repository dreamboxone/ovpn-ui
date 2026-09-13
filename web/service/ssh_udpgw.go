package service

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The UDP bridge. SSH carries only TCP, so a client tunnels UDP with badvpn-udpgw:
// its tun2socks opens a direct-tcpip channel to the loopback udpgw port THROUGH the
// SOCKS proxy and speaks the udpgw protocol over it. This server terminates that
// protocol in-process and relays each datagram through Xray's socks inbound via SOCKS5
// UDP ASSOCIATE, so UDP is routed and accounted per client exactly like TCP (no
// bundled badvpn daemon, and unlike a direct-egress udpgw it stays inside Xray).
//
// Wire format (badvpn packetproto + udpgw):
//   - Framing: each message is prefixed with a 2-byte little-endian length.
//   - Message: flags(1) + conid(2, opaque, echoed back) + address + payload.
//   - Address: IPv4 = 4-byte IP + 2-byte port (network order); IPv6 = 16 + 2. The
//     IPV6 flag selects which.
const (
	udpgwFlagKeepalive = 0x01
	udpgwFlagRebind    = 0x02
	udpgwFlagDNS       = 0x04 // a transparent-DNS hint; treated as ordinary UDP
	udpgwFlagIPv6      = 0x08

	udpgwMaxPacket = 64 * 1024
	udpgwFlowIdle  = 60 * time.Second
	udpgwMaxFlows  = 256
)

// udpFlow is one conid's UDP association: a SOCKS5 UDP ASSOCIATE control connection
// (the association lives while it is open) plus the local socket that talks to the
// relay. One per conid keeps reply demultiplexing unambiguous.
type udpFlow struct {
	conid   [2]byte
	ctrl    net.Conn
	uconn   *net.UDPConn
	lastUse time.Time
}

func (f *udpFlow) close() {
	if f.uconn != nil {
		f.uconn.Close()
	}
	if f.ctrl != nil {
		f.ctrl.Close()
	}
}

// handleUdpgw runs the udpgw termination + SOCKS5-UDP relay for one channel.
func (m *sshManager) handleUdpgw(srv *sshServer, sess *sshSession, ch ssh.Channel) {
	defer ch.Close()

	var writeMu sync.Mutex
	writeFrame := func(pkt []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(len(pkt)))
		if _, err := ch.Write(hdr[:]); err != nil {
			return err
		}
		_, err := ch.Write(pkt)
		return err
	}

	flows := map[uint16]*udpFlow{}
	var flowsMu sync.Mutex
	defer func() {
		flowsMu.Lock()
		for _, f := range flows {
			f.close()
		}
		flowsMu.Unlock()
	}()

	// Reap idle flows so a long-lived channel cannot accumulate associations.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				flowsMu.Lock()
				for k, f := range flows {
					if time.Since(f.lastUse) > udpgwFlowIdle {
						f.close()
						delete(flows, k)
					}
				}
				flowsMu.Unlock()
			}
		}
	}()

	lenBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(ch, lenBuf); err != nil {
			return
		}
		plen := int(binary.LittleEndian.Uint16(lenBuf))
		if plen == 0 || plen > udpgwMaxPacket {
			return
		}
		pkt := make([]byte, plen)
		if _, err := io.ReadFull(ch, pkt); err != nil {
			return
		}
		m.forwardUdpgw(srv, sess, pkt, flows, &flowsMu, writeFrame)
	}
}

// forwardUdpgw parses one client udpgw message and relays its payload to the
// destination through Xray's socks UDP inbound, creating the conid's association on
// first use.
func (m *sshManager) forwardUdpgw(srv *sshServer, sess *sshSession, pkt []byte, flows map[uint16]*udpFlow, flowsMu *sync.Mutex, writeFrame func([]byte) error) {
	if len(pkt) < 3 {
		return
	}
	flags := pkt[0]
	var conid [2]byte
	copy(conid[:], pkt[1:3])
	rest := pkt[3:]

	// A keepalive carries no datagram; it only keeps the TCP channel warm.
	if flags&udpgwFlagKeepalive != 0 {
		return
	}

	var destIP net.IP
	var destPort int
	if flags&udpgwFlagIPv6 != 0 {
		if len(rest) < 18 {
			return
		}
		destIP = net.IP(append([]byte(nil), rest[:16]...))
		destPort = int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
	} else {
		if len(rest) < 6 {
			return
		}
		destIP = net.IP(append([]byte(nil), rest[:4]...))
		destPort = int(binary.BigEndian.Uint16(rest[4:6]))
		rest = rest[6:]
	}
	payload := rest

	key := binary.LittleEndian.Uint16(conid[:])
	flowsMu.Lock()
	f := flows[key]
	if f != nil && flags&udpgwFlagRebind != 0 {
		f.close()
		delete(flows, key)
		f = nil
	}
	if f == nil {
		if len(flows) >= udpgwMaxFlows {
			flowsMu.Unlock()
			return
		}
		nf, err := m.newUdpFlow(srv, sess, conid, writeFrame)
		if err != nil {
			flowsMu.Unlock()
			return
		}
		flows[key] = nf
		f = nf
	}
	f.lastUse = time.Now()
	uconn := f.uconn
	flowsMu.Unlock()

	if _, err := uconn.Write(socksEncodeUDP(destIP.String(), destPort, payload)); err == nil {
		sess.acct.up.Add(int64(len(payload)))
	}
}

// newUdpFlow opens a SOCKS5 UDP association for one conid and starts its reply reader.
func (m *sshManager) newUdpFlow(srv *sshServer, sess *sshSession, conid [2]byte, writeFrame func([]byte) error) (*udpFlow, error) {
	ctrl, relay, err := dialSocksUDPAssociate(srv.socksPort, sess.email)
	if err != nil {
		return nil, err
	}
	uconn, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	f := &udpFlow{conid: conid, ctrl: ctrl, uconn: uconn, lastUse: time.Now()}
	go f.readReplies(sess, writeFrame)
	return f, nil
}

// readReplies pumps datagrams coming back from the relay to the client, wrapping each
// in a udpgw reply with this flow's conid and the datagram's source address.
func (f *udpFlow) readReplies(sess *sshSession, writeFrame func([]byte) error) {
	buf := make([]byte, udpgwMaxPacket)
	for {
		n, err := f.uconn.Read(buf)
		if err != nil {
			return
		}
		srcHost, srcPort, payload, ok := socksDecodeUDP(buf[:n])
		if !ok {
			continue
		}
		reply := buildUdpgwReply(f.conid, srcHost, srcPort, payload)
		if reply == nil {
			continue
		}
		if err := writeFrame(reply); err != nil {
			return
		}
		sess.acct.down.Add(int64(len(payload)))
	}
}

// buildUdpgwReply frames a server->client udpgw message: flags + conid + source
// address + payload.
func buildUdpgwReply(conid [2]byte, srcHost string, srcPort int, payload []byte) []byte {
	ip := net.ParseIP(srcHost)
	if ip == nil {
		return nil
	}
	var flags byte
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		addr = v4
	} else {
		flags |= udpgwFlagIPv6
		addr = ip.To16()
	}
	out := make([]byte, 0, 3+len(addr)+2+len(payload))
	out = append(out, flags, conid[0], conid[1])
	out = append(out, addr...)
	out = binary.BigEndian.AppendUint16(out, uint16(srcPort))
	out = append(out, payload...)
	return out
}
