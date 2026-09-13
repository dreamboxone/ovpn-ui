package job

import (
	"reflect"
	"testing"
)

func TestMergeClientIps_EvictsStaleOldEntries(t *testing.T) {
	// The cutoff is what stops the list from being an append-only history: an
	// address the access log stopped mentioning has to drop off in bounded
	// time, or a client that has been used from a dozen cafes lists all of
	// them forever. It has no bearing on the limit (the core refcounts live
	// connections), but the panel shows this as the client's current IPs.
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 100},  // stale — client disconnected long ago
		{IP: "2.2.2.2", Timestamp: 1900}, // fresh — still connecting
	}
	new := []IPWithTimestamp{
		{IP: "2.2.2.2", Timestamp: 2000}, // same IP, newer log line
	}

	got := mergeClientIps(old, new, 1000)

	want := map[string]int64{"2.2.2.2": 2000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale 1.1.1.1 should have been dropped\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_KeepsFreshOldEntriesUnchanged(t *testing.T) {
	// Entries that aren't stale are carried forward, so the list survives the
	// hourly access-log rotation instead of emptying itself every hour.
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 1500},
	}
	got := mergeClientIps(old, nil, 1000)

	want := map[string]int64{"1.1.1.1": 1500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh old IP should have been retained\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_PrefersLaterTimestampForSameIp(t *testing.T) {
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1500}}
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1700}}

	got := mergeClientIps(old, new, 1000)

	if got["1.1.1.1"] != 1700 {
		t.Fatalf("expected latest timestamp 1700, got %d", got["1.1.1.1"])
	}
}

func TestMergeClientIps_DropsStaleNewEntries(t *testing.T) {
	// A log line with a clock-skewed old timestamp must not resurrect a
	// stale IP past the cutoff.
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 500}}
	got := mergeClientIps(nil, new, 1000)

	if len(got) != 0 {
		t.Fatalf("stale new IP should have been dropped, got %v", got)
	}
}

func TestMergeClientIps_NoStaleCutoffStillWorks(t *testing.T) {
	// Defensive: a zero cutoff (e.g. during very first run on a fresh
	// install) must not over-evict.
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 100}}
	new := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 200}}

	got := mergeClientIps(old, new, 0)

	want := map[string]int64{"1.1.1.1": 100, "2.2.2.2": 200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zero cutoff should keep everything\ngot:  %v\nwant: %v", got, want)
	}
}
