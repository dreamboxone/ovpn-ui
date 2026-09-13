package service

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// Exit-address discovery, used by two features that ask the same question from
// different vantage points: "what address does the world see, and where is it?"
//
//   - the overview's Panel Location row, asked over the host's own network;
//   - the outbound test, asked THROUGH the proxy under test, so the answer
//     describes the outbound's exit rather than the panel's.
//
// Both go to Cloudflare's trace endpoint, which answers with the observed
// client IP and its country in one round trip. That matters here: an IP-only
// service would need a second, separate geo lookup, and the two could disagree
// (or the geo provider could rate-limit independently). It is also addressed by
// IP literal rather than hostname, so the probe needs no working DNS on a host
// whose resolver may itself be part of what is being tested.
//
// The URLs are compile-time constants on purpose. The outbound test deliberately
// takes its test URL from settings rather than the request to avoid SSRF, and
// these probes must not reopen that hole.
// cfTraceEndpoints are tried in order, first answer wins.
//
// The DOMAIN comes first on purpose. Plenty of hosts can reach cloudflare.com
// while 1.1.1.1 itself is blocked or blackholed: the resolver-facing anycast
// address is a common thing for a network to filter, and some ISPs hijack it
// outright. The IP literals stay as the fallback for the opposite case, a host
// with working routing but broken or censored DNS.
var cfTraceEndpoints = []string{
	"https://cloudflare.com/cdn-cgi/trace",
	"https://1.1.1.1/cdn-cgi/trace",
}

// cfTraceV6 forces the v6 path, so a dual-stack host reports both families
// rather than only whichever one the primary lookup happened to use.
const cfTraceV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"

// ExitInfo is where traffic leaves from, as observed from outside.
type ExitInfo struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	// CountryCode is the ISO 3166-1 alpha-2 code Cloudflare reports, e.g. "US".
	// The UI turns it into a display name and a flag; keeping it a code here
	// means no country-name table has to be carried or translated in Go.
	CountryCode string `json:"countryCode,omitempty"`
}

// Empty reports whether nothing at all was learned.
func (e ExitInfo) Empty() bool {
	return e.IPv4 == "" && e.IPv6 == "" && e.CountryCode == ""
}

// cfTrace fetches one trace endpoint and returns its ip= and loc= fields.
// Every failure is a silent "" : this is decoration on top of a result the
// caller already has, and it must never turn a working feature into an error.
func cfTrace(client *http.Client, url string) (ip, loc string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	// The response is a few hundred bytes of key=value lines; cap it anyway so a
	// misbehaving endpoint cannot stream unbounded data into the panel.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			ip = v
		case "loc":
			loc = strings.ToUpper(v)
		}
	}
	return ip, loc
}

// LookupExit discovers the exit address and country reachable through client.
// The v6 probe is best-effort and additive: a v4-only host (or outbound) simply
// reports no IPv6 rather than failing.
//
// The country comes from whichever probe answered first, since both describe the
// same egress.
func LookupExit(client *http.Client) ExitInfo {
	var out ExitInfo
	for _, endpoint := range cfTraceEndpoints {
		ip, loc := cfTrace(client, endpoint)
		if ip == "" {
			continue // blocked, unreachable or censored: try the next one
		}
		// cloudflare.com resolves to both families, so the answer says which one
		// this host actually used to get there.
		if strings.Contains(ip, ":") {
			out.IPv6 = ip
		} else {
			out.IPv4 = ip
		}
		out.CountryCode = loc
		break
	}
	if ip, loc := cfTrace(client, cfTraceV6); ip != "" && strings.Contains(ip, ":") {
		out.IPv6 = ip
		if out.CountryCode == "" {
			out.CountryCode = loc
		}
	}
	return out
}

// LookupPanelExit discovers where the PANEL itself egresses, over the host's own
// network. Short timeouts throughout: this runs on the dashboard status path, so
// an unreachable Cloudflare must not stall the poll.
func LookupPanelExit() ExitInfo {
	return LookupExit(&http.Client{Timeout: 4 * time.Second})
}
