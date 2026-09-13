#!/bin/sh
#
# build/backend/strongswan-bundle.sh — assemble the relocatable strongSwan bundle
# (the IKEv2/IPsec server daemon: charon + swanctl + pki).
#
# Runs INSIDE an Alpine (musl) container. charon dlopens its features as plugins
# (libstrongswan-eap-radius.so, -eap-mschapv2, -eap-tls, -kernel-netlink, -openssl,
# -vici, -x509, …) from its compiled-in plugin dir /usr/lib/ipsec/plugins, so it
# can't be one static binary. Exactly like build/backend/accel-ppp-bundle.sh we
# HARVEST Alpine's musl strongSwan package into a relocatable tree: charon + swanctl
# + pki + libstrongswan/libcharon + every /usr/lib/ipsec/plugins/*.so + ldd deps +
# the musl loader, rooted at a FIXED path (backend.StrongswanBundleRoot). The entry
# points are loader-wrapper launchers (no patchelf), so the whole thing runs on ANY
# host libc (glibc included).
#
# The tree is tarred to /out/strongswan-bundle.tgz, consumed by backend/strongswan.go.
# The fixed PREFIX here MUST match backend/strongswan.go's StrongswanBundleRoot.
#
# PLUGIN/LIB DIR (coordination with backend/strongswan.go): charon has /usr/lib/ipsec
# compiled in as BOTH its shared-lib dir (libstrongswan.so.0, libcharon.so.0) AND its
# plugin dir (plugins/*.so), and it dlopens plugins by that ABSOLUTE path — which
# --library-path cannot redirect. So backend/strongswan.go symlinks /usr/lib/ipsec ->
# $PREFIX/lib/ipsec at provision time (guarded, like accel.go's LinkAccelModuleDir),
# and the launcher ALSO exports LD_LIBRARY_PATH so plugin dependency resolution hits
# the bundle on a glibc host.
set -eu

PREFIX=/usr/libexec/vpn-ui-strongswan   # must equal backend.StrongswanBundleRoot
ARCH="${ARCH:-x86_64}"                   # musl loader arch (amd64 => x86_64)
LOADER="ld-musl-${ARCH}.so.1"
# Assemble the tree at its REAL deploy path inside the (disposable) build container,
# not under a staging root: the launcher wrappers hard-code $PREFIX, so the build-time
# relocation self-check (charon --version via the wrapper) only resolves when the tree
# actually lives there. Safe — this always runs inside Alpine/Docker. Same approach as
# build/backend/libreswan-bundle.sh.
DEST="$PREFIX"
IPSECLIB="$DEST/lib/ipsec"               # mirrors /usr/lib/ipsec (libs + plugins/)

apk update >/dev/null
apk add --no-cache strongswan >/dev/null

# LOAD-BEARING CHECK: the whole IKEv2 feature needs charon + the eap-radius plugin
# (username/password forwarded to our in-binary RADIUS). Fail loudly and immediately
# if either is missing, before doing any work.
[ -f /usr/lib/strongswan/charon ] || { echo "FATAL: /usr/lib/strongswan/charon missing — Alpine strongswan has no charon daemon" >&2; exit 1; }
[ -f /usr/lib/ipsec/plugins/libstrongswan-eap-radius.so ] || { echo "FATAL: eap-radius plugin missing — cannot do IKEv2 user/pass via RADIUS" >&2; exit 1; }

# openssl legacy provider (MD4/DES for the NT-hash / MSCHAPv2 path) — dlopen'd on
# demand so ldd never lists it; copied defensively like the other bundles.
apk add --no-cache openssl >/dev/null

SWAN_VER="$(apk info strongswan 2>/dev/null | head -1)"
echo "== strongswan-bundle: arch=$ARCH pkg=${SWAN_VER:-strongswan} =="

# GUARDRAIL: strongSwan 6.x REMOVED IKEv1 support, which our L2TP/IPsec (IKEv1 transport
# PSK, one charon shared with IKEv2) and legacy Windows MODP1024 clients depend on. If a
# future Alpine base ships 6.x, fail loudly here instead of silently shipping a charon
# that can only speak IKEv2 and would break L2TP on the next rebuild.
case "$SWAN_VER" in
    strongswan-5.*) : ;;
    *) echo "FATAL: bundled strongswan is not 5.x ('$SWAN_VER') — 6.x dropped IKEv1, which L2TP/IPsec + Windows MODP1024 require" >&2; exit 1 ;;
esac

rm -rf "$DEST"
mkdir -p "$DEST/sbin" "$DEST/bin" "$DEST/libexec/ipsec" "$DEST/lib" \
         "$IPSECLIB" "$DEST/lib/ossl-modules" "$DEST/share/strongswan"

# --- daemon + tools ------------------------------------------------------------
cp /usr/lib/strongswan/charon "$DEST/libexec/ipsec/charon.bin"
cp /usr/sbin/swanctl          "$DEST/sbin/swanctl.bin"
cp /usr/bin/pki               "$DEST/bin/pki.bin"

# --- libstrongswan/libcharon + ALL plugins (mirror /usr/lib/ipsec) -------------
cp -a /usr/lib/ipsec/. "$IPSECLIB/"

# --- default config tree (harvested for reference / runtime include) -----------
# The panel generates its own strongswan.conf + swanctl.conf at runtime and points
# STRONGSWAN_CONF at it, but the stock strongswan.d/ plugin defaults are kept so the
# generated config can `include` them for a sane default plugin set/order.
cp -a /etc/strongswan.conf "$DEST/share/strongswan/strongswan.conf" 2>/dev/null || true
cp -a /etc/strongswan.d    "$DEST/share/strongswan/strongswan.d"    2>/dev/null || true

# openssl legacy provider (default provider is built into libcrypto, not a module).
[ -f /usr/lib/ossl-modules/legacy.so ] && cp /usr/lib/ossl-modules/legacy.so "$DEST/lib/ossl-modules/legacy.so" || true

# --- musl loader ---------------------------------------------------------------
cp "/lib/$LOADER" "$DEST/lib/$LOADER"
ln -sf "$LOADER" "$DEST/lib/libc.musl-${ARCH}.so.1"

# --- recursively collect every NEEDED shared lib into lib/ ----------------------
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
collect "$DEST/libexec/ipsec/charon.bin" "$DEST/sbin/swanctl.bin" "$DEST/bin/pki.bin" \
        "$IPSECLIB"/*.so* "$IPSECLIB"/plugins/*.so "$DEST/lib/ossl-modules/legacy.so"
collect "$DEST"/lib/*.so*      # deps-of-deps (libcharon -> libstrongswan -> libssl, etc.)

# --- entry-point loader wrappers (no patchelf) ---------------------------------
# --library-path fixes each ELF's own NEEDED libs; LD_LIBRARY_PATH additionally
# covers the dlopen'd plugins' dependency resolution (libstrongswan/libcharon in
# lib/ipsec, libssl/libcrypto/gmp in lib). /usr/lib/ipsec is symlinked to lib/ipsec
# by backend/strongswan.go so charon's absolute plugin-dir dlopens resolve too.
cat > "$DEST/sbin/charon" <<EOF
#!/bin/sh
# vpn-ui bundled charon launcher — do not edit (generated by strongswan-bundle.sh).
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\$B/lib/ipsec:\${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="\${OPENSSL_MODULES:-\$B/lib/ossl-modules}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib:\$B/lib/ipsec" "\$B/libexec/ipsec/charon.bin" "\$@"
EOF
chmod 0755 "$DEST/sbin/charon"

cat > "$DEST/sbin/swanctl" <<EOF
#!/bin/sh
# vpn-ui bundled swanctl launcher — do not edit (generated by strongswan-bundle.sh).
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\$B/lib/ipsec:\${LD_LIBRARY_PATH:-}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib:\$B/lib/ipsec" "\$B/sbin/swanctl.bin" "\$@"
EOF
chmod 0755 "$DEST/sbin/swanctl"

cat > "$DEST/bin/pki" <<EOF
#!/bin/sh
# vpn-ui bundled pki launcher — do not edit (generated by strongswan-bundle.sh).
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\$B/lib/ipsec:\${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="\${OPENSSL_MODULES:-\$B/lib/ossl-modules}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib:\$B/lib/ipsec" "\$B/bin/pki.bin" "\$@"
EOF
chmod 0755 "$DEST/bin/pki"

# --- self-check: the bundle must actually relocate + carry the load-bearing plugins
echo "== verifying bundled strongSwan relocates and carries eap-radius =="
[ -f "$IPSECLIB/plugins/libstrongswan-eap-radius.so" ]   || { echo "FATAL: eap-radius plugin not in bundle" >&2; exit 1; }
[ -f "$IPSECLIB/plugins/libstrongswan-eap-identity.so" ] || { echo "FATAL: eap-identity plugin not in bundle" >&2; exit 1; }
[ -f "$IPSECLIB/plugins/libstrongswan-kernel-netlink.so" ] || { echo "FATAL: kernel-netlink plugin not in bundle" >&2; exit 1; }
[ -f "$IPSECLIB/plugins/libstrongswan-vici.so" ]         || { echo "FATAL: vici plugin not in bundle" >&2; exit 1; }
[ -f "$IPSECLIB/plugins/libstrongswan-eap-tls.so" ]      || echo "WARN: eap-tls plugin absent — mutual-cert/EAP-TLS mode unavailable" >&2
# Relocation smoke test: run each tool through the musl-loader wrapper and confirm it
# prints its version banner. --library-path makes the loader prefer the BUNDLED
# libstrongswan/libcharon, so this exercises the relocated libs even inside the build
# container. Grep the banner instead of trusting exit status: `pki`/`swanctl` exit
# non-zero on a bare --version (pki rejects the flag; swanctl also probes the vici
# socket) yet still print "strongSwan X.Y.Z", and `charon --version` is the cleanest.
chout="$("$DEST/sbin/charon" --version 2>&1)" || true
echo "$chout" | grep -q "strongSwan" || { echo "FATAL: bundled charon failed to run via the musl-loader wrapper: $chout" >&2; exit 1; }
swout="$("$DEST/sbin/swanctl" --version 2>&1)" || true
echo "$swout" | grep -q "strongSwan" || { echo "FATAL: bundled swanctl failed to run via the musl-loader wrapper: $swout" >&2; exit 1; }
echo "== OK: charon + swanctl relocate ($chout); eap-radius/eap-identity/kernel-netlink/vici bundled =="

# --- package -------------------------------------------------------------------
# Tar the tree at its real path so ExtractStrongswanBundle (untar to /) recreates
# /usr/libexec/vpn-ui-strongswan exactly.
mkdir -p /out
tar czf /out/strongswan-bundle.tgz -C / "${PREFIX#/}"
echo "== strongswan-bundle.tgz built (${SWAN_VER:-strongswan}, wrapper launcher, no patchelf) =="
tar tzf /out/strongswan-bundle.tgz | wc -l | awk '{print "== entries: "$1}'
ls -lh /out/strongswan-bundle.tgz | awk '{print "== size: "$5}'
