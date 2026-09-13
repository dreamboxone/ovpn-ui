package service

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

func TestListenLoopbackPicksStableBand(t *testing.T) {
	ln, err := listenLoopback(0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := ln.Addr().(*net.TCPAddr).Port
	if p < sshOutPortFirst || p > sshOutPortLast {
		t.Fatalf("port %d outside stable band %d-%d (ephemeral range starts 32768)", p, sshOutPortFirst, sshOutPortLast)
	}
	// Listener must be LIVE (no probe-then-close TOCTOU window).
	if _, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
		t.Fatal("port was not actually held: rebind succeeded")
	}
}

func TestListenLoopbackNoCollisionUnderRace(t *testing.T) {
	const n = 40
	var wg sync.WaitGroup
	ports := make([]int, n)
	lns := make([]net.Listener, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ln, err := listenLoopback(0, false)
			if err != nil {
				t.Error(err)
				return
			}
			lns[i] = ln
			ports[i] = ln.Addr().(*net.TCPAddr).Port
		}(i)
	}
	wg.Wait()
	seen := map[int]bool{}
	for i, p := range ports {
		if lns[i] != nil {
			defer lns[i].Close()
		}
		if p == 0 {
			continue
		}
		if seen[p] {
			t.Fatalf("duplicate port %d handed out concurrently", p)
		}
		seen[p] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct ports, want %d", len(seen), n)
	}
}

func TestListenLoopbackPrefersStoredPort(t *testing.T) {
	first, err := listenLoopback(0, false)
	if err != nil {
		t.Fatal(err)
	}
	want := first.Addr().(*net.TCPAddr).Port
	first.Close() // as stop() does on restart; a listening socket has no TIME_WAIT

	again, err := listenLoopback(want, false)
	if err != nil {
		t.Fatalf("re-binding the stored port failed: %v", err)
	}
	defer again.Close()
	if got := again.Addr().(*net.TCPAddr).Port; got != want {
		t.Fatalf("stored port not honoured: got %d want %d", got, want)
	}
}

func TestListenLoopbackTakenStoredPortFailsLoud(t *testing.T) {
	held, err := listenLoopback(0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	taken := held.Addr().(*net.TCPAddr).Port
	// A stored port that is occupied must ERROR, not silently move: the saved
	// Xray outbound names it by number.
	if ln, err := listenLoopback(taken, false); err == nil {
		ln.Close()
		t.Fatal("taken stored port silently relocated instead of failing")
	}
}

// A SAVE may move a taken port, because Save returns the resolved one and the
// caller rewrites the outbound to match. Boot may not, which the test above pins.
func TestListenLoopbackRepicksWhenAllowed(t *testing.T) {
	held, err := listenLoopback(0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	taken := held.Addr().(*net.TCPAddr).Port

	moved, err := listenLoopback(taken, true)
	if err != nil {
		t.Fatalf("save-path allocation refused to move off a taken port: %v", err)
	}
	defer moved.Close()
	got := moved.Addr().(*net.TCPAddr).Port
	if got == taken {
		t.Fatal("returned the taken port")
	}
	if got < sshOutPortFirst || got > sshOutPortLast {
		t.Fatalf("re-picked port %d outside the stable band", got)
	}
}
