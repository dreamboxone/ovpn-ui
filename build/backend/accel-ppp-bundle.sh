#!/bin/sh
#
# build/backend/accel-ppp-bundle.sh — assemble the relocatable accel-ppp bundle
# (the SSTP server daemon).
#
# Runs INSIDE an Alpine (musl) container. accel-ppp CANNOT be a single static
# binary: accel-pppd dlopens its features as modules (libsstp.so, libradius.so,
# libauth_mschap_v2.so, libippool.so, …) through libtriton's loader, so a flat
# static ELF is impossible. So — exactly like build/backend/pppd-bundle.sh — we
# HARVEST Alpine's musl-built accel-ppp package: copy the daemon + accel-cmd +
# every /usr/lib/accel-ppp/*.so module + the RADIUS dictionaries + every
# shared-lib dependency + the musl loader into a tree rooted at a FIXED path
# (backend.AccelBundleRoot). Instead of patchelf'ing the ELF interpreter (which
# corrupts musl binaries — verified in pppd-bundle.sh), the entry points
# sbin/accel-pppd + bin/accel-cmd are tiny wrappers that invoke the bundled musl
# loader with --library-path, so the whole thing runs on ANY host libc (glibc
# included).
#
# The tree is tarred to /out/accel-ppp-bundle.tgz, consumed by backend/accel.go.
# The fixed path MUST match backend/accel.go's AccelBundleRoot
# (/usr/libexec/vpn-ui-accel).
#
# MODULE SEARCH PATH  (coordination with G1 — service/sstp.go + backend/accel.go):
#   accel-ppp's triton loader (accel-pppd/triton/loader.c) resolves each [modules]
#   entry as "<path>/lib<name>.so", where <path> = the "path=" directive in the
#   [modules] section if present, else the compile-time MODULE_PATH
#   (/usr/lib/accel-ppp on Alpine). We keep the modules at $PREFIX/lib/accel-ppp/
#   inside the tree, so G1's generated accel-ppp.conf MUST set, as the first line
#   of the [modules] section:
#       path=/usr/libexec/vpn-ui-accel/lib/accel-ppp
#   (source-confirmed loader option; no host symlink then needed). Fallback if G1
#   omits path=: symlink /usr/lib/accel-ppp -> $PREFIX/lib/accel-ppp at provision
#   time, exactly like backend/pppd.go's LinkPluginDir does for /usr/lib/pppd.
set -eu

PREFIX=/usr/libexec/vpn-ui-accel   # must equal backend.AccelBundleRoot
ARCH="${ARCH:-x86_64}"             # musl loader arch (amd64 => x86_64)
LOADER="ld-musl-${ARCH}.so.1"
ROOT=/tmp/accelroot
DEST="$ROOT$PREFIX"
MODDIR="$DEST/lib/accel-ppp"       # bundled module dir (mirrors /usr/lib/accel-ppp)

# accel-ppp lives in the Alpine community repo (enabled by default in the image).
apk update >/dev/null
apk add --no-cache accel-ppp >/dev/null

# LOAD-BEARING CHECK: the entire SSTP feature depends on Alpine's accel-ppp
# shipping the SSTP module. If libsstp.so is absent the bundle is useless — fail
# loudly and immediately (before doing any work) so the build stops here.
if [ ! -f /usr/lib/accel-ppp/libsstp.so ]; then
    echo "FATAL: /usr/lib/accel-ppp/libsstp.so is missing — Alpine's accel-ppp has no SSTP module; cannot bundle SSTP" >&2
    exit 1
fi

# OpenSSL legacy provider (MD4/DES) — added AFTER the load-bearing check. It is
# dlopen'd on demand for any MS-CHAP path, so ldd never sees it; copied defensively
# below, mirroring pppd-bundle.sh. Harmless if unused (our SSTP auth is RADIUS +
# mppe=deny).
apk add --no-cache openssl >/dev/null

ACCEL_VER="$(apk info accel-ppp 2>/dev/null | head -1)"
echo "== accel-ppp-bundle: arch=$ARCH pkg=${ACCEL_VER:-accel-ppp} =="

mkdir -p "$DEST/sbin" "$DEST/bin" "$DEST/lib" "$MODDIR" \
         "$DEST/lib/ossl-modules" "$DEST/share/accel-ppp"

# --- daemon + cli + modules + dictionaries -------------------------------------
cp /usr/sbin/accel-pppd "$DEST/sbin/accel-pppd.bin"
cp /usr/bin/accel-cmd   "$DEST/bin/accel-cmd.bin"

# Every accel-ppp module (libsstp / libradius / libauth_mschap_v* / libippool /
# liblog_file / … + the libtriton framework lib). Keep them in the bundled module
# dir; G1's config points [modules] path= here (see header).
cp /usr/lib/accel-ppp/*.so "$MODDIR/"

# RADIUS + L2TP dictionaries. The SSTP RADIUS dict must carry the MS-CHAP/MS-MPPE
# attributes (/usr/share/accel-ppp/radius/dictionary.microsoft, pulled in by the
# main radius/dictionary via $INCLUDE). Copy the whole tree so the relative
# $INCLUDEs resolve. G1 points [radius] dictionary= at
# $PREFIX/share/accel-ppp/radius/dictionary.
cp -a /usr/share/accel-ppp/. "$DEST/share/accel-ppp/"

# Assert the RADIUS dictionary landed where backend/accel.go's AccelDictPath expects
# ($PREFIX/share/accel-ppp/radius/dictionary). If Alpine ever relocates it, fail the
# build loudly rather than ship a bundle whose accel-ppp.conf dictionary= is broken.
if [ ! -f "$DEST/share/accel-ppp/radius/dictionary" ]; then
    echo "FATAL: RADIUS dictionary not at share/accel-ppp/radius/dictionary — accel.go AccelDictPath would be wrong" >&2
    find "$DEST/share/accel-ppp" -name 'dictionary*' -maxdepth 2 >&2 || true
    exit 1
fi

# OpenSSL legacy provider (default provider is built into libcrypto, not a module).
# Guarded: a layout change must not break the build (it is only insurance).
if [ -f /usr/lib/ossl-modules/legacy.so ]; then
    cp /usr/lib/ossl-modules/legacy.so "$DEST/lib/ossl-modules/legacy.so"
fi

# The musl loader (a real file; libc.musl-* is just a symlink to it).
cp "/lib/$LOADER" "$DEST/lib/$LOADER"
ln -sf "$LOADER" "$DEST/lib/libc.musl-${ARCH}.so.1"

# Recursively copy every shared-lib dependency into the bundle's lib/, so nothing
# resolves to a host path: libssl/libcrypto (SSTP TLS), libtriton (the framework,
# a NEEDED dep of accel-pppd + of every module), libnl-3/libnl-genl, pcre/pcre2,
# zlib, libcrypt, etc.
collect() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        ldd "$f" 2>/dev/null | awk '/=>/ {print $3}' | while read -r lib; do
            [ -f "$lib" ] || continue
            base=$(basename "$lib")
            [ -e "$DEST/lib/$base" ] && continue
            cp -L "$lib" "$DEST/lib/$base"
        done
    done
}
collect "$DEST/sbin/accel-pppd.bin" "$DEST/bin/accel-cmd.bin" \
        "$MODDIR"/*.so "$DEST/lib/ossl-modules/legacy.so"
collect "$DEST"/lib/*.so*      # deps-of-deps (libssl -> libcrypto, etc.)

# Entry-point wrappers: run the real accel-pppd / accel-cmd through the bundled
# musl loader so their ELF interpreter and NEEDED libs (incl. libtriton from the
# module dir) resolve from the bundle regardless of host libc. Same no-patchelf
# technique as pppd-bundle.sh. procMgr.Start invokes daemonBin("accel-pppd") ->
# $PREFIX/sbin/accel-pppd; eviction calls daemonBin("accel-cmd") -> $PREFIX/bin/accel-cmd.
# --library-path carries BOTH lib/ (deps) and lib/accel-ppp/ (libtriton), so the
# dlopen'd modules' framework dependency resolves too.
cat > "$DEST/sbin/accel-pppd" <<EOF
#!/bin/sh
# vpn-ui bundled accel-pppd launcher — do not edit (generated by accel-ppp-bundle.sh).
B=$PREFIX
export OPENSSL_MODULES="\${OPENSSL_MODULES:-\$B/lib/ossl-modules}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib:\$B/lib/accel-ppp" "\$B/sbin/accel-pppd.bin" "\$@"
EOF
chmod 0755 "$DEST/sbin/accel-pppd"

cat > "$DEST/bin/accel-cmd" <<EOF
#!/bin/sh
# vpn-ui bundled accel-cmd launcher — do not edit (generated by accel-ppp-bundle.sh).
B=$PREFIX
exec "\$B/lib/$LOADER" --library-path "\$B/lib:\$B/lib/accel-ppp" "\$B/bin/accel-cmd.bin" "\$@"
EOF
chmod 0755 "$DEST/bin/accel-cmd"

mkdir -p /out
tar czf /out/accel-ppp-bundle.tgz -C "$ROOT" usr

echo "== accel-ppp-bundle.tgz built (${ACCEL_VER:-accel-ppp}, wrapper launcher, no patchelf) =="
echo "== sstp module bundled: $MODDIR/libsstp.so =="
tar tzf /out/accel-ppp-bundle.tgz | sed "s#^#  #"
ls -lh /out/accel-ppp-bundle.tgz | awk '{print "== size: "$5}'
