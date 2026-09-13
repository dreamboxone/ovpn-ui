package service

import "testing"

const testNow = int64(1_000_000_000_000)

func clientMap(expiry, total int64, enable bool) map[string]any {
	// Numbers arrive as float64 from JSON decoding; mirror that here.
	return map[string]any{
		"email":      "u@t",
		"expiryTime": float64(expiry),
		"totalGB":    float64(total),
		"enable":     enable,
	}
}

func int64Of(v any) int64 { return bulkNumToInt64(v) }

// TestApplyBulkClientOp covers only the MUTATION logic of each op (and its op-level
// no-ops). Skip-toggle filtering is no longer done here — it lives in
// bulkClientSkipped (see TestBulkClientSkipped for the operation x toggle matrix).
func TestApplyBulkClientOp(t *testing.T) {
	const day = bulkMsPerDay
	tests := []struct {
		name       string
		expiry     int64
		total      int64
		enable     bool
		req        BulkClientUpdateRequest
		wantApply  bool
		wantExpiry int64 // checked only when the op is a day op
		wantTotal  int64 // checked only when the op is a traffic op
		wantEnable bool  // checked only when the op is enable/disable
	}{
		// addDays across the three expiryTime regimes.
		{"addDays absolute", 5000, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, 5000 + 2*day, 0, false},
		{"addDays delayed grows", -3 * day, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, -5 * day, 0, false},
		{"addDays no-expiry anchors now", 0, 0, true, BulkClientUpdateRequest{Op: "addDays", Days: 2}, true, testNow + 2*day, 0, false},

		// subDays.
		{"subDays absolute", 10 * day, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, true, 7 * day, 0, false},
		{"subDays delayed clamps at 0", -1 * day, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, true, 0, 0, false},
		{"subDays no-expiry is no-op", 0, 0, true, BulkClientUpdateRequest{Op: "subDays", Days: 3}, false, 0, 0, false},

		// Traffic ops (amount in bytes).
		{"addTraffic limited", 0, 1000, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 500}, true, 0, 1500, false},
		{"addTraffic converts unlimited", 0, 0, true, BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 500}, true, 0, 500, false},
		{"subTraffic limited", 0, 1000, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 300}, true, 0, 700, false},
		{"subTraffic floors at 1 not 0", 0, 1000, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 5000}, true, 0, 1, false},
		{"subTraffic unlimited is no-op", 0, 0, true, BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 5000}, false, 0, 0, false},

		// enable / disable.
		{"enable disabled", 0, 0, false, BulkClientUpdateRequest{Op: "enable"}, true, 0, 0, true},
		{"enable already-enabled no-op", 0, 0, true, BulkClientUpdateRequest{Op: "enable"}, false, 0, 0, true},
		{"disable enabled", 0, 0, true, BulkClientUpdateRequest{Op: "disable"}, true, 0, 0, false},
		{"disable already-disabled no-op", 0, 0, false, BulkClientUpdateRequest{Op: "disable"}, false, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := clientMap(tt.expiry, tt.total, tt.enable)
			got := applyBulkClientOp(cm, tt.req, testNow)
			if got != tt.wantApply {
				t.Fatalf("apply = %v, want %v", got, tt.wantApply)
			}
			if !got {
				return // no-op: nothing should have changed
			}
			switch tt.req.Op {
			case "addDays", "subDays":
				if e := int64Of(cm["expiryTime"]); e != tt.wantExpiry {
					t.Errorf("expiryTime = %d, want %d", e, tt.wantExpiry)
				}
			case "addTraffic", "subTraffic":
				if v := int64Of(cm["totalGB"]); v != tt.wantTotal {
					t.Errorf("totalGB = %d, want %d", v, tt.wantTotal)
				}
			case "enable", "disable":
				if b, _ := cm["enable"].(bool); b != tt.wantEnable {
					t.Errorf("enable = %v, want %v", b, tt.wantEnable)
				}
			}
		})
	}
}

func TestBulkUnknownOpRejected(t *testing.T) {
	s := &InboundService{}
	_, _, err := s.BulkUpdateClients(BulkClientUpdateRequest{Op: "nuke"})
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
}

// TestBulkFreezeUnfreeze covers the freeze/unfreeze ops: freeze disables + parks the
// expiry (locking the remaining time), unfreeze re-enables + resumes from now.
func TestBulkFreezeUnfreeze(t *testing.T) {
	const day = bulkMsPerDay
	cm := clientMap(testNow+10*day, 1000, true) // 10 days remaining, in use
	if !applyBulkClientOp(cm, BulkClientUpdateRequest{Op: "freeze"}, testNow) {
		t.Fatal("freeze should apply")
	}
	if en, _ := cm["enable"].(bool); en {
		t.Error("freeze should disable")
	}
	// remaining time is locked as a negative (non-ticking) value.
	if got := int64Of(cm["expiryTime"]); got != -10*day {
		t.Errorf("freeze expiry = %d, want %d (negative remaining)", got, -10*day)
	}
	if applyBulkClientOp(cm, BulkClientUpdateRequest{Op: "freeze"}, testNow) {
		t.Error("re-freeze of an already-off, non-counting account should be a no-op")
	}
	// unfreeze 3 days later -> re-enabled, expiry = later + 10 days (resume from now).
	later := testNow + 3*day
	if !applyBulkClientOp(cm, BulkClientUpdateRequest{Op: "unfreeze"}, later) {
		t.Fatal("unfreeze should apply")
	}
	if en, _ := cm["enable"].(bool); !en {
		t.Error("unfreeze should enable")
	}
	if got := int64Of(cm["expiryTime"]); got != later+10*day {
		t.Errorf("unfreeze expiry = %d, want %d", got, later+10*day)
	}
	if applyBulkClientOp(cm, BulkClientUpdateRequest{Op: "unfreeze"}, later) {
		t.Error("unfreeze of an active account should be a no-op")
	}
	// freeze a no-expiry account: disabled AND marked frozen via the -1 sentinel, so
	// it reads as frozen (enable=false && expiryTime<0) rather than a plain disable —
	// the whole point, so the cross icon + "Frozen" badge show and it can be unfrozen.
	cm2 := clientMap(0, 0, true)
	if !applyBulkClientOp(cm2, BulkClientUpdateRequest{Op: "freeze"}, testNow) {
		t.Fatal("freeze of a no-expiry account should apply (disable + mark frozen)")
	}
	if en, _ := cm2["enable"].(bool); en {
		t.Error("freeze no-expiry: should be disabled")
	}
	if got := int64Of(cm2["expiryTime"]); got != -1 {
		t.Errorf("freeze no-expiry expiry = %d, want -1 (frozen sentinel)", got)
	}
	if applyBulkClientOp(cm2, BulkClientUpdateRequest{Op: "freeze"}, testNow) {
		t.Error("re-freeze of an already-frozen no-expiry account should be a no-op")
	}
	// unfreeze restores it to unlimited (expiry 0), re-enabled.
	if !applyBulkClientOp(cm2, BulkClientUpdateRequest{Op: "unfreeze"}, testNow) {
		t.Fatal("unfreeze of a frozen no-expiry account should apply")
	}
	if en, _ := cm2["enable"].(bool); !en {
		t.Error("unfreeze no-expiry: should be re-enabled")
	}
	if got := int64Of(cm2["expiryTime"]); got != 0 {
		t.Errorf("unfreeze no-expiry expiry = %d, want 0 (restored to unlimited)", got)
	}
}

// TestBulkClientSkipped is the full operation x toggle matrix: EVERY bulk op must
// honour EVERY skip toggle uniformly. This is the regression guard for the bug where
// freeze/unfreeze silently ignored the toggles.
func TestBulkClientSkipped(t *testing.T) {
	const day = bulkMsPerDay
	allOps := []string{"addDays", "subDays", "addTraffic", "subTraffic", "enable", "disable", "freeze", "unfreeze", "delete"}
	dayOps := map[string]bool{"addDays": true, "subDays": true}

	// (a) With no toggles set, no op ever skips — even a delayed-start, unlimited,
	// disabled account (which would trip every toggle if they were on).
	for _, op := range allOps {
		t.Run("noToggles/"+op, func(t *testing.T) {
			if bulkClientSkipped(clientMap(-2*day, 0, false), BulkClientUpdateRequest{Op: op}) {
				t.Fatalf("%s: no toggles must never skip", op)
			}
		})
	}

	// (b) skipDisabled skips a disabled client and keeps an enabled one — for EVERY op
	// (freeze/unfreeze included: this is the core regression guard).
	for _, op := range allOps {
		t.Run("skipDisabled/"+op, func(t *testing.T) {
			req := BulkClientUpdateRequest{Op: op, SkipDisabled: true}
			if !bulkClientSkipped(clientMap(5000, 100, false), req) {
				t.Errorf("%s + skipDisabled must skip a disabled client", op)
			}
			if bulkClientSkipped(clientMap(5000, 100, true), req) {
				t.Errorf("%s + skipDisabled must keep an enabled client", op)
			}
		})
	}

	// (c) skipFirstUse skips a delayed-start (expiryTime<0) client and keeps an active
	// one — for EVERY op.
	for _, op := range allOps {
		t.Run("skipFirstUse/"+op, func(t *testing.T) {
			req := BulkClientUpdateRequest{Op: op, SkipFirstUse: true}
			if !bulkClientSkipped(clientMap(-1*day, 100, true), req) {
				t.Errorf("%s + skipFirstUse must skip a delayed-start client", op)
			}
			if bulkClientSkipped(clientMap(5000, 100, true), req) {
				t.Errorf("%s + skipFirstUse must keep an active client", op)
			}
		})
	}

	// (d) skipUnlimited is dimension-aware: day ops (addDays/subDays) treat "unlimited"
	// as no-expiry (expiryTime==0); every other op treats it as unlimited traffic
	// (totalGB==0). Each branch also proves it keys on the RIGHT dimension by keeping a
	// client that is unlimited only in the other dimension.
	for _, op := range allOps {
		req := BulkClientUpdateRequest{Op: op, SkipUnlimited: true}
		if dayOps[op] {
			t.Run("skipUnlimited/"+op, func(t *testing.T) {
				if !bulkClientSkipped(clientMap(0, 500, true), req) {
					t.Errorf("%s + skipUnlimited must skip a no-expiry client", op)
				}
				if bulkClientSkipped(clientMap(5000, 0, true), req) {
					t.Errorf("%s + skipUnlimited must key on expiry, not traffic (keep no-traffic timed client)", op)
				}
			})
		} else {
			t.Run("skipUnlimited/"+op, func(t *testing.T) {
				if !bulkClientSkipped(clientMap(5000, 0, true), req) {
					t.Errorf("%s + skipUnlimited must skip an unlimited-traffic client", op)
				}
				if bulkClientSkipped(clientMap(0, 100, true), req) {
					t.Errorf("%s + skipUnlimited must key on traffic, not expiry (keep no-expiry limited client)", op)
				}
			})
		}
	}

	// (e) Combinations ("...and toggles"): the three checks are independent, so a
	// client is skipped if it trips ANY enabled toggle and kept only if it trips none.
	// Verified with all three toggles on at once, for every op.
	allOn := func(op string) BulkClientUpdateRequest {
		return BulkClientUpdateRequest{Op: op, SkipFirstUse: true, SkipDisabled: true, SkipUnlimited: true}
	}
	for _, op := range allOps {
		t.Run("allToggles/"+op, func(t *testing.T) {
			// trips none (enabled, timed, limited traffic): kept.
			if bulkClientSkipped(clientMap(5000, 100, true), allOn(op)) {
				t.Errorf("%s + all toggles must keep a client that trips none", op)
			}
			// disabled -> tripped by skipDisabled: skipped.
			if !bulkClientSkipped(clientMap(5000, 100, false), allOn(op)) {
				t.Errorf("%s + all toggles must skip a disabled client", op)
			}
			// delayed start -> tripped by skipFirstUse: skipped.
			if !bulkClientSkipped(clientMap(-1*day, 100, true), allOn(op)) {
				t.Errorf("%s + all toggles must skip a delayed-start client", op)
			}
		})
	}
}
