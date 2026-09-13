package service

import "strings"

// EnsureAcmeDeps best-effort installs the host packages the Let's Encrypt flow
// (obtain_letsencrypt_cert in vpn-ui.sh, driving acme.sh) needs but that minimal
// cloud images frequently ship without:
//
//   - A cron daemon (crontab). acme.sh's `--install` pre-check HARD-FAILS without
//     one ("Pre-check failed, cannot install"), so the client never installs and
//     real SSL silently falls back to plain HTTP. This was the actual cause of
//     "acme.sh not found after install, skipping real SSL" on minimal Fedora, which
//     ships no cronie. With cron present acme.sh also registers its own renew job,
//     so certificates actually renew instead of expiring in 90 days.
//   - A standalone HTTP-01 server. `acme.sh --standalone` needs socat OR python.
//     socat is pulled in ONLY when neither socat nor any python is already present,
//     so hosts that have python3 (almost all of them) are left untouched.
//
// Returns a human-readable log for the caller to print. Best-effort by design:
// every failure is reported and swallowed, because the menu additionally runs
// acme.sh with `--force`, so issuance still proceeds (only auto-renew is degraded)
// when a package cannot be installed. No-ops entirely when the deps already exist.
func EnsureAcmeDeps() string {
	haveCron := commandExists("crontab") || commandExists("fcrontab")
	haveStandalone := commandExists("socat") ||
		commandExists("python3") || commandExists("python2") || commandExists("python")
	if haveCron && haveStandalone {
		return "acme.sh dependencies already present (cron daemon + standalone HTTP-01 server)."
	}

	pm := detectPackageManager()
	if pm == nil {
		return "no supported package manager detected; skipping acme.sh dependency install. " +
			"Certificate issuance may still work, but without a cron daemon it will not auto-renew."
	}

	var log strings.Builder

	if !haveCron {
		// Debian/Ubuntu call it "cron"; every other supported manager ships "cronie".
		pkg := "cronie"
		if pm.name == "apt" {
			pkg = "cron"
		}
		if _, err := pm.installPackage(pkg); err != nil {
			log.WriteString("could not install " + pkg +
				" (certificates will not auto-renew): " + err.Error() + "\n")
		} else {
			log.WriteString("installed " + pkg + " (cron) for certificate auto-renewal.\n")
			// Start the daemon so acme.sh's renew job actually fires. The unit is
			// "cron" on Debian/Ubuntu and "crond" elsewhere; try both, ignore misses.
			// Only touched because WE just installed it, so we own enabling it.
			if commandExists("systemctl") {
				if _, err := systemctl("enable", "--now", "crond"); err != nil {
					_, _ = systemctl("enable", "--now", "cron")
				}
			}
		}
	}

	if !haveStandalone {
		if _, err := pm.installPackage("socat"); err != nil {
			log.WriteString("could not install socat (standalone issuance needs socat or python): " +
				err.Error() + "\n")
		} else {
			log.WriteString("installed socat for standalone HTTP-01 issuance.\n")
		}
	}

	if s := strings.TrimSpace(log.String()); s != "" {
		return s
	}
	return "acme.sh dependencies ensured."
}
