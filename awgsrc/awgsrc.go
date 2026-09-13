// Package awgsrc embeds the vendored AmneziaWG Linux kernel-module source tree so the
// panel can DKMS-build the out-of-tree `amneziawg` module on the target host at provision
// time. This is the project's only on-host compile: unlike the bundled static daemons, a
// kernel module must match the running kernel, so it cannot be prebuilt. The source under
// src/ is a pinned copy of github.com/amnezia-vpn/amneziawg-linux-kernel-module (AWG 1.0).
package awgsrc

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed all:src
var srcFS embed.FS

// Version is the vendored module version (matches src/dkms.conf PACKAGE_VERSION).
const Version = "1.0.0"

// Extract writes the embedded module source tree into destDir (destDir gets Makefile,
// Kbuild, dkms.conf, the .c/.h files, and the compat/ + crypto/ subdirs directly). The
// caller then runs `make -C destDir dkms-install` + dkms add/build/install.
func Extract(destDir string) error {
	sub, err := fs.Sub(srcFS, "src")
	if err != nil {
		return err
	}
	return fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}
