package controller

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// donateLine matches one README donate row: 🔹USDT-TRC20: ```TXEh…```
var donateLine = regexp.MustCompile("^\\s*🔹\\s*([^:]+):\\s*`{1,3}([^`]+)`{1,3}\\s*$")

// readmeDonateAddresses parses the "## Donate" section of the repo README, up to
// the next heading. Returns nil if the section is missing, which the test treats
// as a failure rather than an empty match.
func readmeDonateAddresses(t *testing.T) []DonateEntry {
	t.Helper()
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	var out []DonateEntry
	inSection := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			// Enter on "## Donate", leave on the next heading of any level.
			inSection = strings.EqualFold(strings.TrimSpace(strings.TrimLeft(trimmed, "# ")), "Donate")
			continue
		}
		if !inSection {
			continue
		}
		if m := donateLine.FindStringSubmatch(trimmed); m != nil {
			out = append(out, DonateEntry{
				Chain:   strings.TrimSpace(m[1]),
				Address: strings.TrimSpace(m[2]),
			})
		}
	}
	return out
}

// TestDonateAddressesMatchReadme pins the list the donate dialog renders to the
// README's Donate section. These are addresses money is sent to, so a silent
// drift between the two is the one failure mode worth a test of its own: edit
// one and this names the mismatch instead of the panel quietly showing a stale
// address.
func TestDonateAddressesMatchReadme(t *testing.T) {
	want := readmeDonateAddresses(t)
	if len(want) == 0 {
		t.Fatal("no donate entries parsed from README.md — has the '## Donate' section moved or changed shape?")
	}
	if len(want) != len(donateAddresses) {
		t.Fatalf("README has %d donate entries, donateAddresses has %d\nREADME: %+v\ncode:   %+v",
			len(want), len(donateAddresses), want, donateAddresses)
	}
	for i := range want {
		if want[i] != donateAddresses[i] {
			t.Errorf("entry %d differs:\n  README: %s = %s\n  code:   %s = %s",
				i, want[i].Chain, want[i].Address,
				donateAddresses[i].Chain, donateAddresses[i].Address)
		}
	}
}

// TestDonateAddressesAreWellFormed guards the copy path: a blank or whitespace
// -carrying address would be copied verbatim into a wallet.
func TestDonateAddressesAreWellFormed(t *testing.T) {
	for _, e := range donateAddresses {
		if e.Chain == "" || e.Address == "" {
			t.Errorf("empty field in entry %+v", e)
		}
		if strings.ContainsAny(e.Address, " \t\n`") {
			t.Errorf("address for %s carries whitespace or a backtick: %q", e.Chain, e.Address)
		}
	}
}
