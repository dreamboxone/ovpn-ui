package service

import (
	"testing"
	"time"
)

func TestNormUserLimitStrategy(t *testing.T) {
	cases := map[string]string{
		"accept": "accept",
		"reject": "reject",
		"":       "accept", // unset/legacy defaults to accept (evict oldest); see normUserLimitStrategy
		"bogus":  "accept",
	}
	for in, want := range cases {
		if got := normUserLimitStrategy(in); got != want {
			t.Errorf("normUserLimitStrategy(%q) = %q want %q", in, got, want)
		}
	}
}

// TestAllocateBlockIPFreeAndReject covers the two I/O-free allocator paths at the
// User Limit cap. K=6 (even, non-power-of-two) confirms block-size agnosticism.
// The accept-eviction path is covered by TestOldestBlockSession (its selection)
// plus the E2E harness (its disconnect side effects).
func TestAllocateBlockIPFreeAndReject(t *testing.T) {
	subs := []string{"10.0.5"}
	const k = 6 // account 0 -> hosts .6 .. .11

	// free slot: hand out the lowest device IP, no deny.
	s := &RadiusService{sessions: map[string]*radiusSession{}}
	blockIPs := vpnAccountDeviceIPs(subs, 0, k)
	ip, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", "", 0, "")
	if deny || ip == nil || ip.String() != "10.0.5.6" {
		t.Fatalf("free slot: got ip=%v deny=%v want 10.0.5.6/false", ip, deny)
	}

	// full + reject: deny the dial.
	full := map[string]*radiusSession{}
	for d := 0; d < k; d++ {
		full["sess-"+itoa(d)] = &radiusSession{ip: "10.0.5." + itoa(6+d), protocol: "l2tp", started: time.Now()}
	}
	s = &RadiusService{sessions: full}
	if ip, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", "", 0, ""); ip != nil || !deny {
		t.Fatalf("full+reject: got ip=%v deny=%v want nil/true", ip, deny)
	}
}

// TestAllocateBlockIPPerDevice verifies the User Limit cap counts distinct DEVICES,
// not distinct public IPs. Two devices on ONE account behind the SAME NAT share a
// Calling-Station-Id and are told apart only by NAS-Port (the pppd unit). The cap
// must still bind, a genuine redial (same station+port) must stay idempotent, and a
// device past the cap must be rejected.
func TestAllocateBlockIPPerDevice(t *testing.T) {
	subs := []string{"10.0.5"}
	const k = 2                   // account 0 -> .6, .7
	const station = "203.0.113.9" // one NAT / public IP shared by every device

	s := &RadiusService{sessions: map[string]*radiusSession{}}
	blockIPs := vpnAccountDeviceIPs(subs, 0, k)

	// device A (NAS-Port 0) takes the first slot.
	ipA, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", station, 0, "")
	if deny || ipA == nil {
		t.Fatalf("device A: got ip=%v deny=%v", ipA, deny)
	}

	// device B — SAME station, different NAS-Port — must get a DISTINCT slot, not
	// collapse onto A's IP (that collapse was the bug that made K unenforced behind a NAT).
	ipB, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", station, 1, "")
	if deny || ipB == nil {
		t.Fatalf("device B: got ip=%v deny=%v", ipB, deny)
	}
	if ipB.String() == ipA.String() {
		t.Fatalf("device B collapsed onto device A's IP %s — cap bypassed", ipA)
	}

	// redial of device A (same station+port) is idempotent: same IP, no new slot consumed.
	ipA2, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", station, 0, "")
	if deny || ipA2 == nil || ipA2.String() != ipA.String() {
		t.Fatalf("device A redial: got ip=%v deny=%v want %s", ipA2, deny, ipA)
	}

	// device C — a third distinct device at the K=2 cap — must be rejected.
	if ip, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", station, 2, ""); ip != nil || !deny {
		t.Fatalf("device C at cap: got ip=%v deny=%v want nil/true", ip, deny)
	}
}

// TestAllocateBlockIPCapOne verifies User Limit K==1 enforces a SINGLE device: the
// account's one IP goes to the first device, that device's redial stays idempotent,
// and a second distinct device is rejected (strategy=reject) rather than silently
// sharing the IP. Guards the fix that made K==1 enforce instead of being a no-op.
func TestAllocateBlockIPCapOne(t *testing.T) {
	blockIPs := []string{"10.0.5.7"} // K==1: a single-IP block (the account's legacy IP)
	s := &RadiusService{sessions: map[string]*radiusSession{}}

	ip1, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", "198.51.100.5", 0, "")
	if deny || ip1 == nil || ip1.String() != "10.0.5.7" {
		t.Fatalf("device 1: got ip=%v deny=%v want 10.0.5.7/false", ip1, deny)
	}
	if ip, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", "198.51.100.5", 0, ""); deny || ip == nil || ip.String() != "10.0.5.7" {
		t.Fatalf("device 1 redial: got ip=%v deny=%v want 10.0.5.7/false", ip, deny)
	}
	if ip, deny := s.allocateBlockIP(0, 0, blockIPs, "l2tp", "reject", "198.51.100.5", 1, ""); ip != nil || !deny {
		t.Fatalf("device 2 at K=1 cap: got ip=%v deny=%v want nil/true", ip, deny)
	}
}

// TestOldestBlockSession verifies the accept-strategy victim selection picks the
// longest-connected device inside the account's block and ignores other accounts.
func TestOldestBlockSession(t *testing.T) {
	base := time.Now()
	block := map[string]bool{"10.0.5.6": true, "10.0.5.7": true, "10.0.5.8": true}
	sessions := map[string]*radiusSession{
		"a": {ip: "10.0.5.7", started: base.Add(-10 * time.Minute)},
		"b": {ip: "10.0.5.6", started: base.Add(-30 * time.Minute)}, // oldest in block
		"c": {ip: "10.0.5.8", started: base.Add(-5 * time.Minute)},
		"d": {ip: "10.0.9.6", started: base.Add(-99 * time.Minute)}, // older, but other account
	}
	sid, ip := oldestBlockSession(sessions, block)
	if sid != "b" || ip != "10.0.5.6" {
		t.Fatalf("oldestBlockSession = (%q,%q) want (b,10.0.5.6)", sid, ip)
	}

	// No block member connected -> no victim.
	if sid, ip := oldestBlockSession(map[string]*radiusSession{
		"x": {ip: "10.0.9.9", started: base},
	}, block); sid != "" || ip != "" {
		t.Fatalf("no member: got (%q,%q) want empty", sid, ip)
	}
}

// TestAllocateBlockIPOpenconnectRecordsSession verifies the OpenConnect-specific
// behavior added for the strategy-accept fix: because ocserv's accounting carries no
// Framed-IP/NAS-Port, the per-device session must be recorded at AUTH (in
// allocateBlockIP) rather than at Acct-Start. A successful openconnect allocation must
// therefore land in s.sessions keyed by IP, carry the account email, and NOT leave a
// transient pending lease (which would let the ghost-reclaim path steal a live IP).
func TestAllocateBlockIPOpenconnectRecordsSession(t *testing.T) {
	blockIPs := []string{"10.4.1.2", "10.4.1.3"} // K=2 openconnect account block
	s := &RadiusService{sessions: map[string]*radiusSession{}, pending: map[string]time.Time{}, ocActiveFn: func(string) bool { return true }}

	ip, deny := s.allocateBlockIP(0, 0, blockIPs, "openconnect", "accept", "203.0.113.1", 0, "alice@t")
	if deny || ip == nil || ip.String() != "10.4.1.2" {
		t.Fatalf("oc device 1: got ip=%v deny=%v want 10.4.1.2/false", ip, deny)
	}
	sess, ok := s.sessions[ocSessionKey("10.4.1.2")]
	if !ok {
		t.Fatalf("openconnect session not recorded at auth (key %q missing)", ocSessionKey("10.4.1.2"))
	}
	if sess.email != "alice@t" || sess.protocol != "openconnect" || sess.ip != "10.4.1.2" {
		t.Fatalf("recorded session = %+v want email=alice@t proto=openconnect ip=10.4.1.2", sess)
	}
	if _, pendingLeft := s.pending["10.4.1.2"]; pendingLeft {
		t.Fatalf("openconnect auth left a pending lease on 10.4.1.2 — ghost-reclaim could steal a live device's IP")
	}
}

// TestAllocateBlockIPOpenconnectAcceptEvict verifies accept-strategy eviction over the
// auth-recorded openconnect sessions (the E2E strategy-accept regression). At the K=2
// cap, a third device must evict the account's OLDEST device: its session is replaced
// by the newcomer at the same IP, and the block stays at K live sessions.
func TestAllocateBlockIPOpenconnectAcceptEvict(t *testing.T) {
	base := time.Now()
	// Two live devices on one account (auth-recorded sessions), device1 the oldest.
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			ocSessionKey("10.4.1.2"): {email: "alice@t", ip: "10.4.1.2", protocol: "openconnect", started: base.Add(-30 * time.Minute)},
			ocSessionKey("10.4.1.3"): {email: "bob@t", ip: "10.4.1.3", protocol: "openconnect", started: base.Add(-10 * time.Minute)},
		},
		pending: map[string]time.Time{},
		// Both devices are genuinely connected — stub the ocserv liveness probe so the
		// stale-session reconcile doesn't reclaim them (no real ocserv routes in tests).
		ocActiveFn: func(string) bool { return true },
	}
	blockIPs := []string{"10.4.1.2", "10.4.1.3"}

	// Third device on the same account, new station, strategy=accept -> evict oldest (.2).
	ip, deny := s.allocateBlockIP(0, 0, blockIPs, "openconnect", "accept", "203.0.113.9", 0, "carol@t")
	if deny || ip == nil || ip.String() != "10.4.1.2" {
		t.Fatalf("oc device 3 (accept): got ip=%v deny=%v want 10.4.1.2/false (reuse evicted oldest)", ip, deny)
	}
	if len(s.sessions) != 2 {
		t.Fatalf("after evict: %d sessions want 2 (oldest replaced, not added)", len(s.sessions))
	}
	if got := s.sessions[ocSessionKey("10.4.1.2")]; got == nil || got.email != "carol@t" {
		t.Fatalf("evicted IP 10.4.1.2 should now belong to carol@t, got %+v", got)
	}
	if got := s.sessions[ocSessionKey("10.4.1.3")]; got == nil || got.email != "bob@t" {
		t.Fatalf("device 2 (bob@t) on 10.4.1.3 must be untouched, got %+v", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
