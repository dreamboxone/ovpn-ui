#!/usr/bin/env bash
#
# packaging/openwrt/build-binary.sh — build a fully STATIC ovpn-ui binary that runs on
# OpenWrt (musl libc, no glibc, no systemd).
#
#   packaging/openwrt/build-binary.sh arm      # ARMv7 hard-float (ipq40xx, ipq806x, mvebu...)
#   packaging/openwrt/build-binary.sh arm64    # aarch64 (filogic, rockchip, bcm27xx...)
#   packaging/openwrt/build-binary.sh amd64    # x86_64
#
# The regular build.sh links sqlite against the host glibc, which does not exist on a
# router. Here cgo goes through `zig cc` targeting musl and the result is linked
# statically, so the one file runs on any OpenWrt kernel for that CPU family.
#
# What is embedded: the panel, the pinned patched Xray core and the base geo pair
# (GEO_LEAN). NOT embedded: the static VPN daemon bundle (OpenVPN, L2TP, SSTP...),
# which is built for x86 servers and needs kernel modules OpenWrt does not ship.
#
# Output: build/out/openwrt/ovpn-ui-<goarch>
#
# Needs: go (the version in go.mod), zig 0.13+, curl, git.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GOARCH_T="${1:-}"
case "$GOARCH_T" in
    arm)   ZIG_TARGET="arm-linux-musleabihf"; ZIG_CPU="-mcpu=generic+v7a+vfp3d16"; export GOARM=7 ;;
    arm64) ZIG_TARGET="aarch64-linux-musl";   ZIG_CPU="" ;;
    amd64) ZIG_TARGET="x86_64-linux-musl";    ZIG_CPU="" ;;
    *) echo "usage: $0 <arm|arm64|amd64>" >&2; exit 2 ;;
esac

command -v go  >/dev/null || { echo "go is required" >&2; exit 1; }
command -v zig >/dev/null || { echo "zig is required (https://ziglang.org/download/)" >&2; exit 1; }

if [[ ! -f third_party/Xray-core/go.mod ]]; then
    git submodule update --init --recursive
fi

# corebundle embeds every core/<goarch>/ it finds, so a core cached for another
# architecture would ride along (+30 MB each). Park those for the build, then put
# them back so a regular build.sh run keeps its cache.
STASH="$REPO_ROOT/build/out/openwrt/.core-stash"
restore_cores() {
    if [[ -d "$STASH" ]]; then
        for d in "$STASH"/*/; do [[ -d "$d" ]] && mv "$d" corebundle/core/; done
        rmdir "$STASH" 2>/dev/null || true
    fi
}
trap restore_cores EXIT
mkdir -p "$STASH"
for d in corebundle/core/*/; do
    [[ -d "$d" && "$(basename "$d")" != "$GOARCH_T" ]] && mv "$d" "$STASH/"
done

# 1. The pinned Xray core (CGO_ENABLED=0, already static) + the base geo pair.
#    GOARM is exported above, so the arm core is ARMv7 like the panel.
GEO_LEAN=1 bash build/core/build.sh "$GOARCH_T"

# 2. The panel. The daemon bundle directory stays empty on purpose: backend.Available()
#    then reports false and the panel never tries to extract x86 daemons onto a router.
mkdir -p "backend/bin/$GOARCH_T"
OUT_DIR="$REPO_ROOT/build/out/openwrt"
mkdir -p "$OUT_DIR"

# zig wants its caches somewhere writable; CI runners and sandboxes may not have $HOME.
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$REPO_ROOT/build/out/.zig-cache}"
export ZIG_LOCAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR"

CGO_ENABLED=1 GOOS=linux GOARCH="$GOARCH_T" \
CC="zig cc -target $ZIG_TARGET $ZIG_CPU" \
CXX="zig c++ -target $ZIG_TARGET $ZIG_CPU" \
    go build -trimpath -buildvcs=false \
        -tags "netgo,osusergo,sqlite_omit_load_extension" \
        -ldflags "-s -w -buildid= -linkmode external '-extldflags=-static -Wl,--strip-all'" \
        -o "$OUT_DIR/ovpn-ui-$GOARCH_T" main.go

file "$OUT_DIR/ovpn-ui-$GOARCH_T" 2>/dev/null || true
ls -lh "$OUT_DIR/ovpn-ui-$GOARCH_T"
