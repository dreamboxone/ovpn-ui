package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Cloudflare API helpers backing the DNS-01 path of obtain_letsencrypt_cert in
// vpn-ui.sh (`vpn-ui cf verify` / `vpn-ui cf zones`).
//
// The menu asks the binary rather than curling the API itself for the same reason
// it reads `vpn-ui info --get`: no jq on a minimal box, and no shell parsing of
// JSON. It also keeps the token out of a command line, since /proc/<pid>/cmdline is
// world-readable while the environment the binary reads it from is not.
//
// Nothing here ever prints, logs or returns the token: an error message that echoed
// it would land in a deploy transcript the operator pastes into a bug report.

// Fixed host: these requests carry the operator's API token in an Authorization
// header, so the destination must never be caller-controlled. A var only so the
// tests can aim it at a local server.
var cloudflareAPI = "https://api.cloudflare.com/client/v4"

var cloudflareHTTPClient = &http.Client{Timeout: 20 * time.Second}

// Cloudflare pages /zones at 50 per request. The cap is a guard against a
// pathological total_pages, not a real limit: 40 pages is 2000 zones.
const (
	cloudflareZonesPerPage = 50
	cloudflareMaxZonePages = 40
)

// CloudflareZone is one DNS zone the token can see. Status matters to the caller:
// a zone that is not "active" has not finished delegating its nameservers to
// Cloudflare, so a DNS-01 challenge on it would never validate.
type CloudflareZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// cloudflareEnvelope is the wrapper every v4 response carries. `success` is the
// real verdict: Cloudflare answers 200 with success=false often enough that the
// HTTP status alone cannot be trusted.
type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// firstError renders the API's own complaint, which is far more useful than a
// status code ("Invalid API Token", "Actor is not authorized to perform this
// action"). Falls back to the HTTP status when Cloudflare sent no error body.
func (e *cloudflareEnvelope) firstError(status string) string {
	for _, apiErr := range e.Errors {
		if msg := strings.TrimSpace(apiErr.Message); msg != "" {
			return msg
		}
	}
	return "HTTP " + status
}

// cloudflareGet performs an authenticated GET against path (relative to the API
// root) and returns the decoded envelope. A non-2xx response is still decoded
// first: the error body is the only place the reason is written down.
func cloudflareGet(token, path string) (*cloudflareEnvelope, error) {
	req, err := http.NewRequest(http.MethodGet, cloudflareAPI+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the Cloudflare API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading the Cloudflare API response: %w", err)
	}

	var env cloudflareEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("Cloudflare API returned HTTP %s with an unreadable body", resp.Status)
	}
	if !env.Success {
		return &env, fmt.Errorf("%s", env.firstError(resp.Status))
	}
	return &env, nil
}

// VerifyCloudflareToken checks an API token against Cloudflare's own verify
// endpoint and returns its status ("active"). An expired, revoked or mistyped
// token fails here rather than several minutes later inside acme.sh, where the
// failure reads as a DNS problem.
func VerifyCloudflareToken(token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("no API token given")
	}
	env, err := cloudflareGet(token, "/user/tokens/verify")
	if err != nil {
		return "", err
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(env.Result, &result); err != nil {
		return "", fmt.Errorf("unexpected verify response from Cloudflare: %w", err)
	}
	if result.Status != "" && result.Status != "active" {
		return result.Status, fmt.Errorf("the token is %s", result.Status)
	}
	return result.Status, nil
}

// ListCloudflareZones returns every zone the token can read, sorted by name.
//
// An empty list is NOT an error here: it is the normal answer for a token scoped
// to nothing (or to a different account), and the caller says so in words. A token
// with Zone:DNS:Edit but no Zone:Zone:Read fails outright instead, which is the
// permission mistake this whole flow exists to catch early.
func ListCloudflareZones(token string) ([]CloudflareZone, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("no API token given")
	}

	var zones []CloudflareZone
	for page := 1; page <= cloudflareMaxZonePages; page++ {
		env, err := cloudflareGet(token, fmt.Sprintf("/zones?page=%d&per_page=%d", page, cloudflareZonesPerPage))
		if err != nil {
			return nil, err
		}
		var batch []CloudflareZone
		if err := json.Unmarshal(env.Result, &batch); err != nil {
			return nil, fmt.Errorf("unexpected zone list from Cloudflare: %w", err)
		}
		zones = append(zones, batch...)

		// Stop on the last page, and on a short/empty page: total_pages is absent
		// from some error-free responses, and without this an account with no zones
		// would be requested 40 times.
		if len(batch) < cloudflareZonesPerPage || page >= env.ResultInfo.TotalPages {
			break
		}
	}

	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, nil
}
