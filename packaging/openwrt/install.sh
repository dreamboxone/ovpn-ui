#!/bin/sh
#
# One-command installer for ovpn-ui on OpenWrt 25.12 or newer.
#
#   wget -qO- https://raw.githubusercontent.com/dreamboxone/ovpn-ui/main/packaging/openwrt/install.sh | sh
#
# or, with a package you copied to the router yourself:
#
#   sh install.sh /tmp/ovpn-ui-arm_cortex-a7_neon-vfpv4.apk
#
# It picks the package for this router's architecture, checks its sha256 against the
# release, installs it and prints the panel login. Nothing else on the router is
# changed: no firewall rule is added, so the panel is reachable from the LAN only.
#
set -eu

REPO="${OVPNUI_REPO:-dreamboxone/ovpn-ui}"
TAG="${OVPNUI_TAG:-latest}"
NEED_KB=$((230 * 1024))

die() { echo "ovpn-ui: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root"
[ -f /etc/openwrt_release ] || die "this is not OpenWrt"
command -v apk >/dev/null 2>&1 || die "OpenWrt 25.12 or newer is required (this firmware has no apk)"

. /etc/openwrt_release
major="${DISTRIB_RELEASE%%.*}"
case "$major" in
	''|*[!0-9]*) echo "ovpn-ui: firmware release '$DISTRIB_RELEASE', assuming a snapshot" ;;
	*) [ "$major" -ge 25 ] || die "OpenWrt 25.12 or newer is required (found $DISTRIB_RELEASE)" ;;
esac

# The OpenWrt package architecture (arm_cortex-a7_neon-vfpv4, aarch64_cortex-a53...),
# which is what the packages are named and stamped with. NOT `apk --print-arch`: that
# prints apk's own generic build arch ("armv7", "aarch64") on every target except x86_64.
arch="${DISTRIB_ARCH:-}"
[ -n "$arch" ] || arch="$(head -n1 /etc/apk/arch 2>/dev/null)"
[ -n "$arch" ] || die "could not determine the package architecture (no DISTRIB_ARCH, no /etc/apk/arch)"
echo "ovpn-ui: OpenWrt $DISTRIB_RELEASE, $arch"

free_kb="$(df -k / | awk 'NR==2 {print $4}')"
[ "${free_kb:-0}" -ge "$NEED_KB" ] || die "not enough flash: $((free_kb / 1024)) MB free on /, about $((NEED_KB / 1024)) MB needed"

mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
[ "${mem_kb:-0}" -ge $((230 * 1024)) ] || echo "ovpn-ui: warning: only $((mem_kb / 1024)) MB RAM, the panel is tight below 256 MB"

pkg="${1:-}"
if [ -z "$pkg" ]; then
	if [ "$TAG" = latest ]; then
		base="https://github.com/$REPO/releases/latest/download"
	else
		base="https://github.com/$REPO/releases/download/$TAG"
	fi
	pkg="/tmp/ovpn-ui-$arch.apk"
	echo "ovpn-ui: downloading ovpn-ui-$arch.apk"
	wget -qO "$pkg" "$base/ovpn-ui-$arch.apk" \
		|| die "no package for $arch in $REPO ($TAG). Supported: arm_cortex-a*/aarch64_*/x86_64"
	wget -qO /tmp/ovpn-ui.sha256sums "$base/sha256sums" || die "could not download sha256sums"
	want="$(awk -v f="ovpn-ui-$arch.apk" '$2 == f || $2 == "*"f {print $1}' /tmp/ovpn-ui.sha256sums)"
	have="$(sha256sum "$pkg" | awk '{print $1}')"
	[ -n "$want" ] && [ "$want" = "$have" ] || { rm -f "$pkg"; die "checksum mismatch for ovpn-ui-$arch.apk"; }
	rm -f /tmp/ovpn-ui.sha256sums
fi
[ -f "$pkg" ] || die "$pkg does not exist"

# The package is not signed with the OpenWrt release key, hence --allow-untrusted.
# Its dependencies (strongSwan, IPsec kmods) come from the feeds, whose index lives
# in RAM and is empty after a reboot.
apk update >/dev/null || die "apk update failed: is the router online?"
apk add --allow-untrusted "$pkg"
[ "${1:-}" ] || rm -f "$pkg"

# default_postinst already enabled and started it; make sure it is really up.
sleep 3
/etc/init.d/ovpn-ui running >/dev/null 2>&1 || /etc/init.d/ovpn-ui restart

echo
echo "ovpn-ui is installed and running."
if [ -s /etc/ovpn-ui/initial-credentials ]; then
	sed -n 's/^url=/  Panel:    /p; s/^username=/  Username: /p; s/^password=/  Password: /p' /etc/ovpn-ui/initial-credentials
fi
echo
echo "  Logs:     logread -e ovpn-ui"
echo "  Service:  /etc/init.d/ovpn-ui {start|stop|restart}"
echo "  Remove:   apk del ovpn-ui"
