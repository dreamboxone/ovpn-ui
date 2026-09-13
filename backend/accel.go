package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// The accel-ppp relocatable bundle backs the SSTP protocol. accel-pppd loads its
// feature modules (sstp, radius, auth_mschap_v2, ippool, …) and their shared-lib
// dependencies via dlopen, so — exactly like pppd — it can't be a single static
// binary. It ships as a musl-linked tree (the daemon + /usr/lib/accel-ppp/*.so
// modules + the RADIUS dictionaries + every ldd dependency + the musl loader)
// whose entry points sbin/accel-pppd and bin/accel-cmd are loader-wrapper
// launchers, rooted at a FIXED path that the build (build/backend/accel-ppp-bundle.sh)
// must match. The tree is tarred to backend/bin/<arch>/accel-ppp-bundle.tgz and
// rides the same //go:embed all:bin as the flat daemons (Extract skips *.tgz).
const (
	AccelBundleRoot = "/usr/libexec/vpn-ui-accel" // must equal the bundle build PREFIX
	AccelPppdBin    = AccelBundleRoot + "/sbin/accel-pppd"
	AccelCmdBin     = AccelBundleRoot + "/bin/accel-cmd"

	// AccelShareDir / AccelDictPath: the bundled accel-ppp RADIUS dictionary tree.
	// accel-ppp uses its OWN dictionary format (distinct from radcli's), so the
	// generated accel-ppp.conf points its [radius] dictionary= at this bundled file
	// which must carry the MS-CHAP / MS-MPPE attributes MSCHAPv2 needs. The bundle
	// keeps the dictionary self-contained here (relative $INCLUDEs to siblings).
	AccelShareDir = AccelBundleRoot + "/share/accel-ppp"
	// accel-ppp installs its RADIUS dictionary under the radius/ subdir
	// (/usr/share/accel-ppp/radius/dictionary), and the bundle preserves that tree
	// so the dictionary's relative $INCLUDEs (dictionary.microsoft, …) resolve.
	AccelDictPath = AccelShareDir + "/radius/dictionary"

	// AccelModuleDir is accel-pppd's compiled-in module search directory (Alpine
	// layout). LinkAccelModuleDir points it at the bundle's module tree so bare
	// [modules] names (sstp, radius, …) dlopen the bundled .so files.
	AccelModuleDir = "/usr/lib/accel-ppp"
)

func accelBundleName() string { return archDir() + "/accel-ppp-bundle.tgz" }

// HasAccelBundle reports whether a relocatable accel-ppp bundle is embedded for
// this architecture.
func HasAccelBundle() bool {
	f, err := bundleFS.Open(accelBundleName())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ExtractAccelBundle untars the embedded accel-ppp bundle to the filesystem root
// (its entries are rooted at usr/libexec/vpn-ui-accel). Idempotent; no-op if the
// bundle is absent. Mirrors ExtractPppdBundle.
func ExtractAccelBundle() error {
	if !HasAccelBundle() {
		return nil
	}
	data, err := bundleFS.ReadFile(accelBundleName())
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join("/", filepath.Clean("/"+hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := extractRegularFile(target, tr, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		}
	}
	return nil
}

// LinkAccelModuleDir points /usr/lib/accel-ppp (accel-pppd's compiled-in module
// search path) at the bundle's module tree when the host has no accel-ppp of its
// own, so bare [modules] names dlopen the bundled .so's. No-op if the host already
// has that directory (host accel-ppp installed, or our prior link) or there's no
// bundle. The analogue of LinkPluginDir for pppd.
func LinkAccelModuleDir() error {
	if !HasAccelBundle() {
		return nil
	}
	if _, err := os.Lstat(AccelModuleDir); err == nil {
		return nil // host accel-ppp's module dir (or our prior link) already present
	}
	src := AccelBundleRoot + "/lib/accel-ppp"
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(AccelModuleDir), 0o755)
	return os.Symlink(src, AccelModuleDir)
}

// AccelBinPath resolves a bundled accel-ppp launcher (accel-pppd / accel-cmd) to
// its extracted wrapper path, or "" when not bundled/extracted. daemonBin consults
// this so the panel finds accel-pppd/accel-cmd even though the bundle is a tree
// (not a flat BinDir binary that backend.DaemonPath would resolve). The wrapper is
// a shell launcher that invokes the real binary through the bundled musl loader,
// so the path stays valid regardless of the host libc.
func AccelBinPath(name string) string {
	if !HasAccelBundle() {
		return ""
	}
	var p string
	switch name {
	case "accel-pppd":
		p = AccelPppdBin
	case "accel-cmd":
		p = AccelCmdBin
	default:
		return ""
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}
