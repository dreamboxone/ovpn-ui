#!/usr/bin/env bash
#
# packaging/openwrt/make-apk.sh — turn the static binaries into OpenWrt 25.12 .apk
# packages, one per OpenWrt package architecture.
#
#   packaging/openwrt/make-apk.sh <sdk-dir> [goarch...]      # default: arm arm64 amd64
#
# <sdk-dir> is an unpacked OpenWrt 25.12 SDK (any target, x86-64 is the smallest). The
# package does not compile anything, so a single SDK can stamp every architecture:
# each Go binary is packaged once for every OpenWrt arch string that CPU family uses.
#
# Input:  build/out/openwrt/ovpn-ui-<goarch>   (packaging/openwrt/build-binary.sh)
# Output: build/out/openwrt/dist/ovpn-ui-<pkgarch>.apk + sha256sums. The names carry no
#         version, so releases/latest/download/ovpn-ui-<pkgarch>.apk always resolves.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SDK="${1:?usage: $0 <openwrt-sdk-dir> [goarch...]}"
shift
GOARCHES=("${@:-arm arm64 amd64}")
# shellcheck disable=SC2206
GOARCHES=(${GOARCHES[*]})

SDK="$(cd "$SDK" && pwd)"
[[ -f "$SDK/rules.mk" && -d "$SDK/staging_dir" ]] || { echo "$SDK is not an OpenWrt SDK" >&2; exit 1; }

VERSION="${OVPNUI_VERSION:-$(tr -d '[:space:]' < "$REPO_ROOT/config/version")}"
OUT="$REPO_ROOT/build/out/openwrt"
DIST="$OUT/dist"
mkdir -p "$DIST"

# Every OpenWrt package architecture a binary is known to run on. The arm build is
# ARMv7 hard-float VFPv3-D16 and statically linked, so it does not care which float
# ABI the rest of the firmware was built with.
pkgarches_for() {
    case "$1" in
        arm)   echo "arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a9_vfpv3-d16 arm_cortex-a9_neon arm_cortex-a15_neon-vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a5_vfpv4" ;;
        arm64) echo "aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic" ;;
        amd64) echo "x86_64" ;;
        *) echo "unknown goarch $1" >&2; return 1 ;;
    esac
}

rm -rf "$SDK/package/ovpn-ui"
cp -r "$REPO_ROOT/packaging/openwrt/ovpn-ui" "$SDK/package/ovpn-ui"
cp "$REPO_ROOT/LICENSE" "$SDK/package/ovpn-ui/LICENSE"

cd "$SDK"
[[ -f .config ]] || make defconfig >/dev/null

for goarch in "${GOARCHES[@]}"; do
    bin="$OUT/ovpn-ui-$goarch"
    [[ -f "$bin" ]] || { echo "missing $bin, run build-binary.sh $goarch first" >&2; exit 1; }
    # OVPNUI_PKGARCHES narrows the set (CI packages one architecture per job: the SDK
    # takes several minutes per package because it re-packs the kmod dependencies).
    for pkgarch in ${OVPNUI_PKGARCHES:-$(pkgarches_for "$goarch")}; do
        echo "==> ovpn-ui $VERSION for $pkgarch ($goarch)"
        rm -rf bin/packages/*/base/ovpn-ui-*.apk
        make package/ovpn-ui/clean >/dev/null
        printf 'OVPNUI_BINARY:=%s\nOVPNUI_PKGARCH:=%s\nOVPNUI_VERSION:=%s\n' \
            "$bin" "$pkgarch" "$VERSION" > package/ovpn-ui/build.mk
        make package/ovpn-ui/compile V="${V:-}" -j1
        apk_file="$(ls bin/packages/*/base/ovpn-ui-*.apk 2>/dev/null | head -1)"
        [[ -n "$apk_file" ]] || { echo "the SDK produced no package for $pkgarch" >&2; exit 1; }
        cp "$apk_file" "$DIST/ovpn-ui-${pkgarch}.apk"
    done
done

cd "$DIST"
sha256sum ovpn-ui-*.apk > sha256sums
ls -lh "$DIST"
