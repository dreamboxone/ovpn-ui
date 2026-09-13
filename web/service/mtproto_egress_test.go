package service

import "testing"

// egressConfig decides whether a config change needs a telemt RESTART or can ride the
// inotify hot-reload. Getting it wrong is silent in both directions, and both were hit
// in production:
//   - missing a real egress change leaves telemt on a stale upstream: with a tag ON it
//     dials the socks port the panel just deleted and refuses every client; with the tag
//     OFF it keeps egressing direct, so Xray routing (even a blackhole) never applies.
//   - reporting a change that is not one restarts telemt on ordinary client edits and
//     drops every live connection, which is exactly what hot-reload exists to avoid.
func TestEgressConfigDetectsOnlyNonHotReloadableChanges(t *testing.T) {
	direct := `[general]
use_middle_proxy = true
log_level = "normal"

[[upstreams]]
type = "direct"

[access.users]
"a" = "secret1"

[access.user_enabled]
"a" = true
`
	socks := `[general]
use_middle_proxy = false
log_level = "normal"

[[upstreams]]
type = "socks5"
address = "127.0.0.1:12315"
socks_user_from_account = true
username = "telemt-system"
password = "telemt-system"

[access.users]
"a" = "secret1"

[access.user_enabled]
"a" = true
`
	// The same egress, but hot-reloadable content differs: a client was disabled and a
	// new account added. telemt applies these itself.
	socksHotEdit := `[general]
use_middle_proxy = false
log_level = "normal"

[[upstreams]]
type = "socks5"
address = "127.0.0.1:12315"
socks_user_from_account = true
username = "telemt-system"
password = "telemt-system"

[access.users]
"a" = "secret1"
"b" = "secret2"

[access.user_enabled]
"a" = false
"b" = true
`

	t.Run("tag ON to OFF is a restart", func(t *testing.T) {
		if egressConfig(direct) == egressConfig(socks) {
			t.Fatal("direct and socks5 egress compared equal: turning an ad tag off would " +
				"leave telemt egressing direct and silently bypassing Xray routing")
		}
	})

	t.Run("tag OFF to ON is a restart", func(t *testing.T) {
		if egressConfig(socks) == egressConfig(direct) {
			t.Fatal("socks5 and direct egress compared equal: turning an ad tag on would " +
				"leave telemt dialing a socks port the panel has deleted")
		}
	})

	t.Run("client edits are NOT a restart", func(t *testing.T) {
		if egressConfig(socks) != egressConfig(socksHotEdit) {
			t.Fatal("a client add/disable moved the egress signature: telemt would be " +
				"restarted on ordinary edits, dropping every live connection")
		}
	})

	t.Run("identical config is stable", func(t *testing.T) {
		if egressConfig(direct) != egressConfig(direct) {
			t.Fatal("egressConfig is not deterministic")
		}
	})

	t.Run("captures the fields that actually matter", func(t *testing.T) {
		got := egressConfig(socks)
		for _, want := range []string{"use_middle_proxy = false", "[[upstreams]]",
			`type = "socks5"`, `address = "127.0.0.1:12315"`} {
			if !contains(got, want) {
				t.Fatalf("egress signature is missing %q; got:\n%s", want, got)
			}
		}
		// Hot-reloadable noise must stay out, or every client edit looks like an
		// egress change.
		for _, unwanted := range []string{"access.users", "log_level", "user_enabled"} {
			if contains(got, unwanted) {
				t.Fatalf("egress signature wrongly includes hot-reloadable %q; got:\n%s", unwanted, got)
			}
		}
	})
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
