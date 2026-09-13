package service

import (
	"testing"
	"time"
)

// The debounce IS the window in which a newly added mtproto/ssh client cannot use the
// proxy: those relays authenticate to Xray's socks inbound as the account's email, and
// that account list is fixed at config time, so only a restart applies it. Too slow and
// a fresh client looks broken (the reported "the proxy won't work until I disable and
// re-enable it"); no debounce at all and every edit in a burst drops live connections.
func TestIsRestartDueAndSetFalse(t *testing.T) {
	var s XrayService

	reset := func() {
		isNeedXrayRestart.Store(false)
		xrayRestartReqAt.Store(0)
		xrayRestartFirstAt.Store(0)
	}
	// Rewind both timestamps by d, standing in for elapsed time.
	rewind := func(d time.Duration) {
		xrayRestartReqAt.Store(xrayRestartReqAt.Load() - int64(d))
		xrayRestartFirstAt.Store(xrayRestartFirstAt.Load() - int64(d))
	}

	t.Run("no request means nothing to do", func(t *testing.T) {
		reset()
		if s.IsRestartDueAndSetFalse() {
			t.Fatal("restart fired with no request pending")
		}
	})

	t.Run("a fresh request waits for the burst to settle", func(t *testing.T) {
		reset()
		s.SetToNeedRestart()
		if s.IsRestartDueAndSetFalse() {
			t.Fatal("restarted immediately: a burst of edits would restart Xray once per edit")
		}
		if !isNeedXrayRestart.Load() {
			t.Fatal("the pending flag was cleared without restarting: the request is lost")
		}
	})

	t.Run("fires once settled, then clears", func(t *testing.T) {
		reset()
		s.SetToNeedRestart()
		rewind(xrayRestartDebounce)
		if !s.IsRestartDueAndSetFalse() {
			t.Fatal("did not restart after the debounce elapsed: a new client stays unusable")
		}
		if s.IsRestartDueAndSetFalse() {
			t.Fatal("fired twice for one request: the flag was not cleared")
		}
	})

	t.Run("a burst collapses into one restart", func(t *testing.T) {
		reset()
		for i := 0; i < 5; i++ {
			s.SetToNeedRestart()
			rewind(xrayRestartDebounce / 2) // each edit lands inside the window
			if s.IsRestartDueAndSetFalse() {
				t.Fatalf("restarted mid-burst (edit %d): edits are not being coalesced", i)
			}
		}
		rewind(xrayRestartDebounce)
		if !s.IsRestartDueAndSetFalse() {
			t.Fatal("burst never restarted after going quiet")
		}
	})

	t.Run("an unending stream still restarts by maxWait", func(t *testing.T) {
		reset()
		s.SetToNeedRestart()
		xrayRestartFirstAt.Store(xrayRestartFirstAt.Load() - int64(xrayRestartMaxWait))
		// The stream is still live, so the debounce alone would keep deferring forever.
		s.SetToNeedRestart()
		if !s.IsRestartDueAndSetFalse() {
			t.Fatal("maxWait did not force a restart: a steady stream of edits starves it")
		}
	})
}
