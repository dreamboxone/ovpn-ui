package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// The strongSwan relocatable bundle backs the IKEv2/IPsec protocol. charon loads
// its features (eap-radius, eap-mschapv2, eap-tls, kernel-netlink, openssl, vici,
// x509, …) via dlopen from a compiled-in plugin dir, so — exactly like accel-ppp /
// pppd — it can't be a single static binary. It ships as a musl-linked tree (charon
// + swanctl + pki + libstrongswan/libcharon + every /usr/lib/ipsec/plugins/*.so +
// every ldd dependency + the musl loader) whose entry points sbin/charon,
// sbin/swanctl and bin/pki are loader-wrapper launchers, rooted at a FIXED path that
// build/backend/strongswan-bundle.sh must match. The tree is tarred to
// backend/bin/<arch>/strongswan-bundle.tgz and rides the same //go:embed all:bin as
// the flat daemons (Extract skips *.tgz).
const (
	// StrongswanBundleRoot is where the tree unpacks. Its own subdir under the shared
	// /usr/libexec prefix so it never collides with the pppd/accel/libreswan bundles.
	StrongswanBundleRoot = "/usr/libexec/vpn-ui-strongswan" // must equal the bundle build PREFIX

	// CharonBundled is the charon daemon launcher (procmgr runs this directly).
	CharonBundled = StrongswanBundleRoot + "/sbin/charon"
	// SwanctlBundled controls charon over vici: load connections, list/terminate SAs.
	SwanctlBundled = StrongswanBundleRoot + "/sbin/swanctl"
	// PkiBundled is strongSwan's X.509 tool. The panel generates certs in Go, so this
	// is insurance/debug only, but it ships for parity with the host `pki`.
	PkiBundled = StrongswanBundleRoot + "/bin/pki"

	// StrongswanBundleIpsecLib mirrors /usr/lib/ipsec inside the tree: libstrongswan.so.0,
	// libcharon.so.0, and plugins/. charon has /usr/lib/ipsec compiled in as BOTH its
	// shared-lib dir and its plugin dir, and it dlopens each plugin by that ABSOLUTE
	// path — which the launcher's --library-path cannot redirect. So
	// LinkStrongswanIpsecDir symlinks the compiled path at StrongswanIpsecDir to here.
	StrongswanBundleIpsecLib = StrongswanBundleRoot + "/lib/ipsec"
	// StrongswanIpsecDir is charon's compiled-in lib+plugin dir (Alpine layout).
	StrongswanIpsecDir = "/usr/lib/ipsec"

	// StrongswanShareDir holds the harvested stock strongswan.conf + strongswan.d/
	// plugin defaults, so the runtime-generated strongswan.conf can `include` them for
	// a sane default plugin set/order.
	StrongswanShareDir       = StrongswanBundleRoot + "/share/strongswan"
	StrongswanDefaultConfDir = StrongswanShareDir + "/strongswan.d"
)

// hostStrongswanDirs are where distro packages put charon, which is not on PATH: it
// is a libexec helper everywhere. /usr/lib/ipsec is OpenWrt (and Alpine), the
// others are Debian/Fedora. swanctl and pki are ordinary sbin/bin tools.
var hostStrongswanDirs = map[string][]string{
	"charon":  {"/usr/lib/ipsec", "/usr/libexec/ipsec", "/usr/lib/strongswan", "/usr/libexec/strongswan"},
	"swanctl": {"/usr/sbin", "/usr/bin", "/sbin"},
	"pki":     {"/usr/bin", "/usr/sbin"},
}

// HostStrongswanBin returns a host-installed (package manager) strongSwan binary, or
// "" when there is none. It is deliberately separate from StrongswanBinPath: that one
// answers "the BUNDLED launcher", which callers use to decide what is safe to pkill,
// and a host daemon must never be mistaken for ours there.
func HostStrongswanBin(name string) string {
	for _, dir := range hostStrongswanDirs[name] {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// hostStrongswanPluginConfDir is where strongSwan's own packages install the per-plugin
// `load = yes` defaults.
const hostStrongswanPluginConfDir = "/etc/strongswan.d/charon"

// StrongswanPluginConfDir is the directory whose *.conf files the generated
// strongswan.conf includes for the plugin set: the bundle's copy when a bundle is
// embedded, otherwise the host package's. With load_modular = yes charon loads ONLY
// the plugins those files enable, so pointing at a directory that does not exist
// starts a charon with no vici, no kernel interface and no EAP.
func StrongswanPluginConfDir() string {
	if !HasStrongswanBundle() {
		if st, err := os.Stat(hostStrongswanPluginConfDir); err == nil && st.IsDir() {
			return hostStrongswanPluginConfDir
		}
	}
	return StrongswanDefaultConfDir + "/charon"
}

func strongswanBundleName() string { return archDir() + "/strongswan-bundle.tgz" }

// HasStrongswanBundle reports whether a relocatable strongSwan bundle is embedded
// for this architecture.
func HasStrongswanBundle() bool {
	f, err := bundleFS.Open(strongswanBundleName())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// StrongswanBundleReady reports whether the bundle is embedded AND already extracted
// (the charon launcher exists on disk).
func StrongswanBundleReady() bool {
	if !HasStrongswanBundle() {
		return false
	}
	st, err := os.Stat(CharonBundled)
	return err == nil && !st.IsDir()
}

// ExtractStrongswanBundle untars the embedded strongSwan bundle to the filesystem
// root (its entries are rooted at usr/libexec/vpn-ui-strongswan). Idempotent; no-op
// if the bundle is absent. Mirrors ExtractAccelBundle.
func ExtractStrongswanBundle() error {
	if !HasStrongswanBundle() {
		return nil
	}
	data, err := bundleFS.ReadFile(strongswanBundleName())
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

// LinkStrongswanIpsecDir points /usr/lib/ipsec (charon's compiled-in lib+plugin dir)
// at the bundle's mirror tree when the host has no strongSwan of its own, so charon's
// absolute-path plugin dlopens (/usr/lib/ipsec/plugins/libstrongswan-*.so) resolve to
// the bundled plugins. No-op if that directory already exists (host strongSwan, or a
// prior link) or there's no bundle. The analogue of accel.go's LinkAccelModuleDir.
func LinkStrongswanIpsecDir() error {
	if !HasStrongswanBundle() {
		return nil
	}
	if _, err := os.Lstat(StrongswanIpsecDir); err == nil {
		return nil // host strongSwan's dir (or our prior link) already present
	}
	if _, err := os.Stat(StrongswanBundleIpsecLib); err != nil {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(StrongswanIpsecDir), 0o755)
	return os.Symlink(StrongswanBundleIpsecLib, StrongswanIpsecDir)
}

// StrongswanBinPath resolves a bundled strongSwan launcher (charon / swanctl / pki)
// to its extracted wrapper path, or "" when not bundled/extracted. daemonBin consults
// this so the panel finds charon/swanctl even though the bundle is a tree (not a flat
// BinDir binary that backend.DaemonPath would resolve).
func StrongswanBinPath(name string) string {
	if !HasStrongswanBundle() {
		return ""
	}
	var p string
	switch name {
	case "charon":
		p = CharonBundled
	case "swanctl":
		p = SwanctlBundled
	case "pki":
		p = PkiBundled
	default:
		return ""
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}
