package service

import (
	"strings"
	"testing"
)

func TestDistroSupportedBy(t *testing.T) {
	cases := []struct {
		id, version string
		want        bool
	}{
		// tested families + versions
		{"ubuntu", "24.04", true},
		{"ubuntu", "26.04", true},
		{"Ubuntu", "24.04", true}, // ID is case-insensitive
		{"debian", "12", true},
		{"debian", "13", true},
		{"fedora", "43", true},
		{"fedora", "44", true},
		{"almalinux", "9.4", true},  // point release -> major 9
		{"almalinux", "10.0", true}, // point release -> major 10
		{"rocky", "9.5", true},
		{"centos", "9", true},      // CentOS Stream 9
		{"centos", "10", true},     // CentOS Stream 10
		{"arch", "", true},         // rolling: no VERSION_ID
		{"arch", "20260101", true}, // rolling: any VERSION_ID

		// untested versions of a tested family
		{"ubuntu", "20.04", false},
		{"ubuntu", "22.04", false}, // dropped from the tested matrix
		{"debian", "11", false},
		{"fedora", "40", false},
		{"rocky", "7.9", false},
		{"almalinux", "7", false},

		// EL8 dropped in v1.4: bundled strongSwan (IKEv2) setup fails there.
		{"almalinux", "8.10", false},
		{"rocky", "8.10", false},
		{"centos", "8", false},

		// distros not on the list at all
		{"linuxmint", "21", false}, // ubuntu-derived, still not tested
		{"opensuse", "15", false},
		{"", "", false}, // missing os-release
	}
	for _, c := range cases {
		got, reason := distroSupportedBy(c.id, c.version)
		if got != c.want {
			t.Errorf("distroSupportedBy(%q, %q) = %v (reason %q); want %v",
				c.id, c.version, got, reason, c.want)
		}
	}
}

func TestSupportedDistroSummary(t *testing.T) {
	s := SupportedDistroSummary()
	for _, want := range []string{"Ubuntu 24/26", "Debian 12/13", "Fedora 43/44",
		"AlmaLinux 9/10", "Rocky 9/10", "CentOS Stream 9/10", "Arch"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q missing %q", s, want)
		}
	}
}
