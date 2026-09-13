package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The exit probe decorates results the operator already has: the panel's
// identity tile and a finished outbound test. Every failure mode must therefore
// degrade to "no information", never to an error that hides a working feature.

const sampleTrace = "fl=123abc\nh=cloudflare.com\nip=203.0.113.7\nts=1700000000\nvisit_scheme=https\nloc=US\ntls=TLSv1.3\n"

func TestCfTraceParsesIPAndCountry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleTrace))
	}))
	defer srv.Close()

	ip, loc := cfTrace(srv.Client(), srv.URL)
	if ip != "203.0.113.7" {
		t.Errorf("ip = %q, want 203.0.113.7", ip)
	}
	if loc != "US" {
		t.Errorf("loc = %q, want US", loc)
	}
}

func TestCfTraceTreatsBadResponsesAsUnknown(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"403": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) },
		// A captive portal or ISP hijack answers 200 with something that is not
		// a trace at all; it must not be mistaken for an answer.
		"html":  func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>blocked</html>")) },
		"empty": func(w http.ResponseWriter, r *http.Request) {},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			if ip, loc := cfTrace(srv.Client(), srv.URL); ip != "" || loc != "" {
				t.Errorf("got ip=%q loc=%q, want both empty", ip, loc)
			}
		})
	}
}

// errTransport fails every request, standing in for a host that cannot reach
// Cloudflare at all (censored, offline, or no route).
type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network unreachable")
}

func TestLookupExitIsEmptyWhenEverythingFails(t *testing.T) {
	got := LookupExit(&http.Client{Transport: errTransport{}})
	if !got.Empty() {
		t.Errorf("a fully unreachable host must yield no exit info, got %+v", got)
	}
}

// The domain is tried before the IP literal: a network that blocks the 1.1.1.1
// anycast address while still routing to cloudflare.com is common enough that
// the order is load-bearing, not cosmetic.
func TestTraceEndpointOrderPrefersTheDomain(t *testing.T) {
	if len(cfTraceEndpoints) < 2 {
		t.Fatalf("expected a fallback chain, got %v", cfTraceEndpoints)
	}
	if cfTraceEndpoints[0] != "https://cloudflare.com/cdn-cgi/trace" {
		t.Errorf("first endpoint = %q, want the cloudflare.com domain", cfTraceEndpoints[0])
	}
	if cfTraceEndpoints[1] != "https://1.1.1.1/cdn-cgi/trace" {
		t.Errorf("second endpoint = %q, want the 1.1.1.1 literal", cfTraceEndpoints[1])
	}
}

// A dead first endpoint must not stop the chain: the whole point of the
// fallback is the host where the domain resolves but the literal is filtered,
// or the reverse.
func TestLookupExitFallsBackPastADeadEndpoint(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer dead.Close()
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleTrace))
	}))
	defer live.Close()

	restore := cfTraceEndpoints
	cfTraceEndpoints = []string{dead.URL, live.URL}
	defer func() { cfTraceEndpoints = restore }()

	got := LookupExit(live.Client())
	if got.IPv4 != "203.0.113.7" || got.CountryCode != "US" {
		t.Errorf("fallback did not reach the second endpoint, got %+v", got)
	}
}

func TestExitOrNilDropsAnEmptyProbe(t *testing.T) {
	if exitOrNil(ExitInfo{}) != nil {
		t.Error("an empty probe must be dropped so `exit` is absent from the response")
	}
	got := exitOrNil(ExitInfo{IPv4: "203.0.113.7", CountryCode: "US"})
	if got == nil || got.IPv4 != "203.0.113.7" {
		t.Errorf("a populated probe must survive, got %+v", got)
	}
}
