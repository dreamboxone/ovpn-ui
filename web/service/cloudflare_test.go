package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Cloudflare lookups exist to fail EARLY and in words: a token that is
// mistyped, expired or missing Zone:Zone:Read must be rejected while the operator
// is still standing at the prompt, not several minutes later inside acme.sh where
// the same mistake surfaces as a DNS timeout.

// serveCloudflare points the package's API base at a local server for the duration
// of a test and restores it afterwards.
func serveCloudflare(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	restore := cloudflareAPI
	cloudflareAPI = srv.URL
	t.Cleanup(func() {
		cloudflareAPI = restore
		srv.Close()
	})
}

func TestVerifyCloudflareTokenSendsBearerAndReadsStatus(t *testing.T) {
	var gotAuth, gotPath string
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"abc","status":"active"}}`))
	})

	status, err := VerifyCloudflareToken("secret-token")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if status != "active" {
		t.Errorf("status = %q, want active", status)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want a Bearer token", gotAuth)
	}
	if gotPath != "/user/tokens/verify" {
		t.Errorf("path = %q, want /user/tokens/verify", gotPath)
	}
}

// Cloudflare's own wording ("Invalid API Token") is the whole value of verifying,
// so it has to reach the operator rather than being flattened into "HTTP 400".
func TestVerifyCloudflareTokenSurfacesTheApiError(t *testing.T) {
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"result":null}`))
	})

	if _, err := VerifyCloudflareToken("bad"); err == nil {
		t.Fatal("a rejected token must be an error")
	} else if !strings.Contains(err.Error(), "Invalid API Token") {
		t.Errorf("error = %q, want Cloudflare's own message", err)
	}
}

// success=false with HTTP 200 is a real Cloudflare answer, so the status code
// alone cannot be the verdict.
func TestVerifyCloudflareTokenRejectsSuccessFalseOn200(t *testing.T) {
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`))
	})

	if _, err := VerifyCloudflareToken("bad"); err == nil {
		t.Fatal("success=false must be an error even on HTTP 200")
	}
}

func TestListCloudflareZonesPaginatesAndSorts(t *testing.T) {
	var pages []string
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		// A full first page forces the second request; the short second page ends it.
		if page == "1" {
			var zones []string
			for i := 0; i < cloudflareZonesPerPage; i++ {
				zones = append(zones, fmt.Sprintf(`{"id":"z%d","name":"zz%02d.example","status":"active"}`, i, i))
			}
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":[%s],"result_info":{"page":1,"total_pages":2}}`,
				strings.Join(zones, ","))
			return
		}
		w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"z99","name":"aaa.example","status":"pending"}],` +
			`"result_info":{"page":2,"total_pages":2}}`))
	})

	zones, err := ListCloudflareZones("token")
	if err != nil {
		t.Fatalf("zones: %v", err)
	}
	if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
		t.Errorf("requested pages = %v, want 1 then 2", pages)
	}
	if len(zones) != cloudflareZonesPerPage+1 {
		t.Fatalf("got %d zones, want %d", len(zones), cloudflareZonesPerPage+1)
	}
	// Sorted by name, so the picker's numbering is stable between runs.
	if zones[0].Name != "aaa.example" || zones[0].Status != "pending" {
		t.Errorf("first zone = %+v, want the alphabetically first one with its status", zones[0])
	}
}

// A token scoped to nothing is not an error at this layer: the caller says so in
// words. What matters is that it costs ONE request, not cloudflareMaxZonePages.
func TestListCloudflareZonesStopsOnAnEmptyPage(t *testing.T) {
	calls := 0
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":0}}`))
	})

	zones, err := ListCloudflareZones("token")
	if err != nil {
		t.Fatalf("zones: %v", err)
	}
	if len(zones) != 0 {
		t.Errorf("got %d zones, want none", len(zones))
	}
	if calls != 1 {
		t.Errorf("made %d requests for an empty account, want 1", calls)
	}
}

// The permission mistake this flow exists to catch: a token with DNS:Edit but no
// Zone:Read lists nothing and must not be mistaken for an account with no zones.
func TestListCloudflareZonesSurfacesAPermissionError(t *testing.T) {
	serveCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":` +
			`"Actor is not authorized to perform this action"}],"result":null}`))
	})

	if _, err := ListCloudflareZones("token"); err == nil {
		t.Fatal("a token without Zone:Read must be an error, not an empty list")
	} else if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("error = %q, want Cloudflare's own message", err)
	}
}

func TestCloudflareCallsRejectAnEmptyToken(t *testing.T) {
	if _, err := VerifyCloudflareToken("  "); err == nil {
		t.Error("an empty token must not be sent to Cloudflare")
	}
	if _, err := ListCloudflareZones(""); err == nil {
		t.Error("an empty token must not be sent to Cloudflare")
	}
}
