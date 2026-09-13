// Package corebundle bakes the project's pinned Xray core binary and the base
// geo data files (geoip.dat / geosite.dat) into the panel executable via
// go:embed and extracts them at runtime.
//
// The panel ships a SPECIFIC patched Xray-core fork (Sir-MmD/Xray-core, which
// fixes the Shadowsocks per-user `method` fallback). To guarantee that exact
// core is always the one that runs, ExtractXray overwrites the on-disk core
// binary on every startup, and the panel forbids switching/updating the core
// version from the dashboard (see ServerService.UpdateXray).
//
// The embedded assets live under core/ and are gitignored (only a .gitkeep is
// tracked) — they are produced at build time by build/core/build.sh, exactly
// like the daemon bundle in the `backend` package. A checkout without them still
// compiles; extraction simply becomes a no-op and the panel falls back to
// whatever core binary is already on disk.
//
// Layout consumed by the go:embed below:
//
//	core/<goarch>/xray      the pinned core binary for that architecture
//	core/geoip.dat          base geo data (architecture-independent)
//	core/geosite.dat
//	core/geo{ip,site}_{IR,RU}.dat   country geo data, absent under GEO_LEAN=1
package corebundle

import (
	"embed"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// bundleFS holds the pinned core binary + base geo files. The `all:` prefix
// keeps the embed working when only the .gitkeep placeholder is present.
//
//go:embed all:core
var bundleFS embed.FS

// geoFiles are every geo data file that may be embedded and extracted as a
// first-run fallback: the complete set the panel's routing editor can name.
//
// build/core/build.sh fetches all six by default. Under GEO_LEAN=1 it fetches
// only the base pair, and this list is then simply longer than what is embedded:
// ReadFile fails for the absent names and ExtractGeofiles skips them, leaving the
// panel to download a country file the first time a rule needs it
// (web/service/geofile.go).
//
// Updating any of them from the dashboard is allowed, so ExtractGeofiles only
// writes a file when it is missing: it never clobbers a dashboard-updated copy.
var geoFiles = []string{
	"geoip.dat", "geosite.dat",
	"geoip_IR.dat", "geosite_IR.dat",
	"geoip_RU.dat", "geosite_RU.dat",
}

// HasGeofile reports whether this build actually carries the named geo file, so
// the dashboard can distinguish "shipped with the panel" from "downloaded here"
// instead of assuming a fixed pair. Under GEO_LEAN=1 the country files are
// absent and this answers false for them.
func HasGeofile(name string) bool {
	f, err := bundleFS.Open("core/" + name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// XrayBinaryName is the on-disk core binary name the panel launches. It matches
// the name xray/process.go builds ("xray-<goos>-<goarch>").
func XrayBinaryName() string {
	return "xray-" + runtime.GOOS + "-" + runtime.GOARCH
}

// archXrayPath is the embedded path of the core binary for this architecture.
func archXrayPath() string { return "core/" + runtime.GOARCH + "/xray" }

// HasXray reports whether a core binary is embedded for this architecture.
func HasXray() bool {
	f, err := bundleFS.Open(archXrayPath())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ExtractXray writes the bundled core binary into binDir as XrayBinaryName(),
// overwriting any existing file so the pinned fork is always the core that runs.
// It is a no-op (returns "", nil) when no core is embedded for this arch.
// Returns the written path.
func ExtractXray(binDir string) (string, error) {
	if !HasXray() {
		return "", nil
	}
	data, err := bundleFS.ReadFile(archXrayPath())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, XrayBinaryName())
	if err := writeAtomically(dest, data, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

// ExtractGeofiles writes each bundled base geo file into binDir ONLY IF it is
// missing, so dashboard updates to geoip.dat/geosite.dat survive a restart.
// Files not embedded in this build are silently skipped. Returns the paths
// actually written.
func ExtractGeofiles(binDir string) ([]string, error) {
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}
	stamps := geoStamps()
	var written []string
	for _, name := range geoFiles {
		data, err := bundleFS.ReadFile("core/" + name)
		if err != nil {
			continue // not bundled in this build
		}
		dest := filepath.Join(binDir, name)
		if _, err := os.Stat(dest); err == nil {
			continue // already present, keep the existing (possibly updated) copy
		}
		if err := writeAtomically(dest, data, 0o644); err != nil {
			return written, err
		}
		// Date the file by its DATA, not by when it was unpacked. The panel's
		// updater asks upstream `If-Modified-Since: <mtime>`, so a file left
		// stamped with the install time claims to be newer than every release
		// published between the build and the install: upstream answers 304, the
		// dashboard reports success, and the stale copy stays. It cannot recover on
		// its own, because a 304 from GitHub carries an ETag but no Last-Modified.
		//
		// Only files written here are stamped. One already on disk belongs to
		// whoever put it there, and its mtime is already the truth about it.
		if when, ok := stamps[name]; ok {
			if err := os.Chtimes(dest, when, when); err != nil {
				// Cosmetic on its own: the file is correct, only its date is not.
				_ = err
			}
		}
		written = append(written, dest)
	}
	return written, nil
}

// geoStamps reads the build-time manifest mapping each embedded geo file to the
// upstream Last-Modified date of its data. Absent on a build that predates the
// manifest, in which case extraction simply skips the dating step.
func geoStamps() map[string]time.Time {
	raw, err := bundleFS.ReadFile("core/geo.stamp")
	if err != nil {
		return nil
	}
	stamps := make(map[string]time.Time)
	for _, line := range strings.Split(string(raw), "\n") {
		name, epoch, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(epoch), 10, 64)
		if err != nil || secs <= 0 {
			continue
		}
		stamps[name] = time.Unix(secs, 0)
	}
	return stamps
}

// writeAtomically writes data to dest via a temp file + rename. The rename swaps
// the directory entry to a fresh inode, which avoids ETXTBSY ("text file busy")
// when overwriting a core binary that is currently mapped by a running process.
func writeAtomically(dest string, data []byte, mode os.FileMode) error {
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
