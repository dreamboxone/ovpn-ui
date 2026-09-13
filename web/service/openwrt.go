package service

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// OpenWrt support (packaging/openwrt).
//
// On OpenWrt the panel runs on the router itself, next to firewall4 and, often, an
// Xray-based proxy app such as Passwall 2. The daemon bundle is not embedded there
// (it is built for x86 servers), so the kernel VPN cores cannot come from the
// binary. IKEv2 is the exception this file makes work: its whole stack is in
// OpenWrt's own feeds (strongSwan packages plus the IPsec and TPROXY kmods for the
// stock kernel), so the panel installs those with apk and drives them exactly like
// the bundled charon everywhere else.
//
// Three things differ from a server and are handled here:
//
//   - Packages come from apk, and charon lives at /usr/lib/ipsec/charon with its
//     plugin defaults in /etc/strongswan.d (backend.HostStrongswanBin and
//     backend.StrongswanPluginConfDir).
//   - firewall4's input chain rejects everything from the WAN that no rule allows.
//     IKE, ESP and the decrypted client traffic TPROXY delivers to Xray all arrive
//     there, and an accept in the panel's own `ip vpn` table cannot override a
//     reject in fw4's table. The rules go into fw4 through its include directory.
//   - Passwall 2 marks packets in a prerouting chain that runs just before the
//     panel's (mangle - 1). See openwrtForeignMarkRule.

// openwrtReleaseFile exists on every OpenWrt system and on nothing else.
const openwrtReleaseFile = "/etc/openwrt_release"

// isOpenWrt reports whether the panel runs on OpenWrt. A variable so tests can pin it.
var isOpenWrt = sync.OnceValue(func() bool {
	_, err := os.Stat(openwrtReleaseFile)
	return err == nil
})

// openwrtCores are the installable cores OpenWrt can serve. Everything else in the
// catalog needs a daemon bundle or a DKMS build that does not exist for a router.
var openwrtCores = []string{"ikev2"}

// openwrtIkev2Packages is IKEv2's complete dependency set from the official feeds.
// The strongSwan plugins are the ones the generated configs use: vici for swanctl,
// kernel-netlink for XFRM, openssl/x509/pem/pkcs1 for certificates, attr for the DNS
// attribute, and one EAP plugin per auth mode (eap-radius hands MSCHAPv2 to the
// panel's RADIUS server). The kmods are the stock kernel's ESP/XFRM stack, the AEAD
// ciphers modern clients propose, and TPROXY for steering client traffic into Xray.
// ip-full provides the `ip rule`/`ip route get` forms busybox's ip lacks.
var openwrtIkev2Packages = []string{
	"strongswan-charon",
	"strongswan-swanctl",
	"strongswan-mod-vici",
	"strongswan-mod-kernel-netlink",
	"strongswan-mod-socket-default",
	"strongswan-mod-openssl",
	"strongswan-mod-random",
	"strongswan-mod-x509",
	"strongswan-mod-pem",
	"strongswan-mod-pkcs1",
	"strongswan-mod-attr",
	"strongswan-mod-eap-identity",
	"strongswan-mod-eap-mschapv2",
	"strongswan-mod-eap-radius",
	"strongswan-mod-eap-tls",
	"kmod-ipsec4",
	"kmod-crypto-gcm",
	"kmod-crypto-sha256",
	"kmod-nft-tproxy",
	"ip-full",
}

// openwrtPanelPackages are what the rest of the panel needs from the feeds: kmod-tun for
// Xray's TUN inbound, and curl, openssl and socat for the bundled acme.sh behind the
// SSL certificate manager (key and CSR generation, the ACME calls, and the standalone
// HTTP-01 server). The package depends on these too; they are not a provisioning step.
var openwrtPanelPackages = []string{"kmod-tun", "curl", "openssl-util", "socat"}

// openwrtStrongswanServices are OpenWrt's own strongSwan init scripts. Either one
// starts a second charon from UCI, which takes UDP 500/4500 before the panel's does.
var openwrtStrongswanServices = []string{"/etc/init.d/swanctl", "/etc/init.d/ipsec"}

// openwrtInboundProtocols are the inbound protocols a router can actually serve: every
// protocol the embedded Xray core speaks, IKEv2 (openwrtIkev2Packages), and SSH, which
// is an in-process Go server with no daemon or kernel module behind it. Everything
// else needs a daemon bundle or a kernel module OpenWrt does not have.
var openwrtInboundProtocols = []string{
	"vmess", "vless", "trojan", "shadowsocks", "wireguard", "hysteria",
	"anytls", "tuic", "naive", "mixed", "http", "tunnel", "tun",
	"ikev2", "ssh",
}

// PlatformInfo tells the frontend what this host can actually run, so the panel never
// offers a protocol or a feature whose backend is not there. It is rendered into every
// page (page/body_scripts) as the global PanelPlatform, before any page script runs.
type PlatformInfo struct {
	OpenWrt bool `json:"openwrt"`
	// InboundProtocols is the inbound protocol picker's whole list. Empty means every
	// protocol the panel knows, which is the server build.
	InboundProtocols []string `json:"inboundProtocols,omitempty"`
	// HideUnavailableTunnels drops the VPN tunnel outbounds this host cannot raise from
	// the Add Outbound picker, instead of listing them disabled with a reason.
	HideUnavailableTunnels bool `json:"hideUnavailableTunnels"`
	// PanelUpdate is the in-panel updater. It installs the upstream x86 server release,
	// so on OpenWrt updates come from the package instead.
	PanelUpdate bool `json:"panelUpdate"`
	// WarpCli is the official warp-cli SOCKS method, installed through apt/dnf. The
	// WireGuard WARP method is plain HTTP plus an Xray outbound and works everywhere.
	WarpCli bool `json:"warpCli"`
}

// Platform describes this host for the frontend and for the API guards.
func Platform() PlatformInfo {
	if !isOpenWrt() {
		return PlatformInfo{PanelUpdate: true, WarpCli: true}
	}
	return PlatformInfo{
		OpenWrt:                true,
		InboundProtocols:       slices.Clone(openwrtInboundProtocols),
		HideUnavailableTunnels: true,
	}
}

// PlatformJS renders Platform as a JavaScript literal for the page templates' global
// PanelPlatform. Registered as the "platformJSON" template function by both the panel
// and the subscription server, which share html/common/page.html.
func PlatformJS() template.JS {
	raw, err := json.Marshal(Platform())
	if err != nil {
		return template.JS("{}")
	}
	return template.JS(raw)
}

// PlatformAllowsInbound reports whether an inbound of this protocol can be served here.
func PlatformAllowsInbound(protocol string) bool {
	p := Platform()
	return len(p.InboundProtocols) == 0 || slices.Contains(p.InboundProtocols, protocol)
}

// openwrtFilterCores narrows a core selection to what OpenWrt can serve. A no-op
// anywhere else.
func openwrtFilterCores(names []string) []string {
	if !isOpenWrt() {
		return names
	}
	var out []string
	for _, n := range names {
		if slices.Contains(openwrtCores, n) {
			out = append(out, n)
		}
	}
	return out
}

// openwrtFilterStatus drops the status cards of cores OpenWrt cannot run, so a
// router's Core Settings page lists what it can actually serve instead of a column
// of permanent "not installed". Built-in cores (xray, ssh) and radius stay. "ipsec"
// is the L2TP/IPsec card: IKEv2's charon is reported on its own card.
func openwrtFilterStatus(all []CoreStatus) []CoreStatus {
	if !isOpenWrt() {
		return all
	}
	out := all[:0]
	for _, c := range all {
		spec := coreSpecFor(c.Name)
		hidden := c.Name == "ipsec" || (spec != nil && !spec.builtin && !slices.Contains(openwrtCores, c.Name))
		if !hidden {
			out = append(out, c)
		}
	}
	return out
}

// openwrtMissingPackages returns the packages in want that apk does not have
// installed. `apk info -e` prints exactly the installed subset of its arguments.
func openwrtMissingPackages(want []string) []string {
	out, _ := exec.Command("apk", append([]string{"info", "-e"}, want...)...).Output()
	have := map[string]bool{}
	for _, ln := range strings.Fields(string(out)) {
		have[ln] = true
	}
	var missing []string
	for _, p := range want {
		if !have[p] {
			missing = append(missing, p)
		}
	}
	return missing
}

// openwrtEnsurePackages installs whatever of pkgs is missing. `apk update` only runs
// when an install is actually needed: the package lists live in RAM on OpenWrt and
// are gone after every reboot, so a first `apk add` on a fresh boot cannot resolve
// anything without it.
func openwrtEnsurePackages(display string, pkgs []string) ProvisionStep {
	missing := openwrtMissingPackages(pkgs)
	if len(missing) == 0 {
		return ProvisionStep{Name: display, OK: true, Msg: "already installed"}
	}
	var log bytes.Buffer
	upd, _ := exec.Command("apk", "update").CombinedOutput()
	log.Write(upd)
	out, err := exec.Command("apk", append([]string{"add"}, missing...)...).CombinedOutput()
	log.Write(out)
	if err != nil {
		return ProvisionStep{Name: display + " via apk", OK: false,
			Msg: "apk add failed (is the router online?): " + err.Error(), Log: log.String()}
	}
	if still := openwrtMissingPackages(pkgs); len(still) > 0 {
		return ProvisionStep{Name: display + " via apk", OK: false,
			Msg: "still missing: " + strings.Join(still, ", "), Log: log.String()}
	}
	return ProvisionStep{Name: display + " via apk", OK: true,
		Msg: "installed " + strings.Join(missing, ", "), Log: log.String()}
}

// openwrtDisableStrongswanServices stops and disables OpenWrt's own strongSwan
// services so only the panel's charon runs. Returns the ones it changed.
func openwrtDisableStrongswanServices() []string {
	var changed []string
	for _, svc := range openwrtStrongswanServices {
		if _, err := os.Stat(svc); err != nil {
			continue
		}
		enabled := exec.Command(svc, "enabled").Run() == nil
		running := exec.Command(svc, "running").Run() == nil
		if !enabled && !running {
			continue
		}
		_ = exec.Command(svc, "stop").Run()
		_ = exec.Command(svc, "disable").Run()
		changed = append(changed, filepath.Base(svc))
	}
	return changed
}

// runOpenwrtProvision is runProvisionSteps for OpenWrt. It never asks for a reboot:
// every kmod is built for the running kernel and loads immediately.
func (s *CoreService) runOpenwrtProvision(emit func(ProvisionStep), selected, target []string) {
	for _, n := range selected {
		if !slices.Contains(openwrtCores, n) {
			emit(ProvisionStep{Name: coreDisplayName(n), OK: true, Warn: true,
				Msg: "not available on OpenWrt: only IKEv2 has packages for the router's kernel"})
		}
	}
	if !slices.Contains(target, "ikev2") {
		return
	}

	emit(openwrtEnsurePackages("strongSwan + IPsec/TPROXY kernel modules", openwrtIkev2Packages))

	if changed := openwrtDisableStrongswanServices(); len(changed) > 0 {
		emit(ProvisionStep{Name: "OpenWrt strongSwan service", OK: true,
			Msg: "stopped and disabled " + strings.Join(changed, ", ") + " (the panel runs charon itself)"})
	} else {
		emit(ProvisionStep{Name: "OpenWrt strongSwan service", OK: true, Msg: "not running"})
	}

	for _, m := range []string{"xfrm_user", "esp4", "nft_tproxy"} {
		if moduleLoaded(m) {
			continue
		}
		if out, err := exec.Command("modprobe", m).CombinedOutput(); err != nil {
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Warn: true,
				Msg: "could not load now", Log: strings.TrimSpace(string(out))})
		}
	}

	err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	emit(ProvisionStep{Name: "sysctl net.ipv4.ip_forward=1", OK: err == nil, Msg: msgOrOK(err)})
	ownPrepareHostFile("/etc/sysctl.d/99-vpn-ui.conf", "")
	err = os.WriteFile("/etc/sysctl.d/99-vpn-ui.conf", []byte("net.ipv4.ip_forward=1\n"+
		"net.ipv4.conf.all.rp_filter=2\n"+
		"net.ipv4.conf.default.rp_filter=2\n"), 0644)
	emit(ProvisionStep{Name: "persist /etc/sysctl.d/99-vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})
	ensureVpnHostNetworking()

	emit(ProvisionStep{Name: "firewall4 rules for IKEv2", OK: true,
		Msg: "added when the first IKEv2 inbound is enabled, removed with the last one"})
}

// openwrtFirewallInclude is a fw4 automatic include: its rules are inserted at the
// top of fw4's `input` chain, before any zone's reject. Shipped in /usr/share, which
// fw4 reads on every start and reload, so the rules survive reboots and firewall
// restarts without the panel having to re-add them.
const openwrtFirewallInclude = "/usr/share/nftables.d/chain-pre/input/90-ovpn-ui.nft"

// openwrtFirewallRules renders the include for the current state, or "" when no
// enabled inbound needs IPsec (the file is then removed, closing the ports).
//
// The last rule is the one that is easy to miss. TPROXY hands each decrypted client
// packet to Xray's LOCAL socket while it still carries its original destination, so
// it traverses fw4's input chain as a new connection from the WAN and is rejected
// there. It is scoped to the VPN address space AND to packets that actually came out
// of an IPsec SA, so a spoofed 10.x source on the WAN matches nothing.
func openwrtFirewallRules(ipsecActive bool) string {
	if !ipsecActive {
		return ""
	}
	return "# Managed by ovpn-ui. Present only while an IPsec inbound is enabled.\n" +
		"udp dport { 500, 4500 } counter accept comment \"ovpn-ui: IKE\"\n" +
		"meta l4proto esp counter accept comment \"ovpn-ui: ESP\"\n" +
		"ip saddr " + vpnAddrSpace + " meta secpath exists counter accept comment \"ovpn-ui: IPsec client traffic\"\n"
}

var openwrtFirewallMu sync.Mutex

// syncOpenwrtFirewall writes or removes the fw4 include to match whether charon is
// needed, and reloads fw4 only when the file actually changed: a reload rebuilds the
// whole fw4 table, and ApplyNftRules runs on every inbound save.
func syncOpenwrtFirewall() {
	if !isOpenWrt() {
		return
	}
	openwrtFirewallMu.Lock()
	defer openwrtFirewallMu.Unlock()

	want := openwrtFirewallRules(charonNeeded())
	have, err := os.ReadFile(openwrtFirewallInclude)
	switch {
	case want == "" && os.IsNotExist(err):
		return
	case want != "" && err == nil && string(have) == want:
		return
	}
	if want == "" {
		if err := os.Remove(openwrtFirewallInclude); err != nil && !os.IsNotExist(err) {
			logger.Warning("OpenWrt: remove firewall include:", err)
			return
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(openwrtFirewallInclude), 0755); err != nil {
			logger.Warning("OpenWrt: firewall include dir:", err)
			return
		}
		if err := os.WriteFile(openwrtFirewallInclude, []byte(want), 0644); err != nil {
			logger.Warning("OpenWrt: write firewall include:", err)
			return
		}
	}
	if out, err := exec.Command("fw4", "-q", "reload").CombinedOutput(); err != nil {
		logger.Warning("OpenWrt: fw4 reload:", err, strings.TrimSpace(string(out)))
		return
	}
	if want == "" {
		logger.Info("OpenWrt: removed the IKEv2 firewall4 rules")
	} else {
		logger.Info("OpenWrt: added the IKEv2 firewall4 rules (UDP 500/4500, ESP, IPsec client traffic)")
	}
}

// openwrtForeignMarkRule clears marks another app put on VPN client packets, before
// the panel's TPROXY rules add its own bit. Empty off OpenWrt.
//
// The TPROXY rules set `mark or 0x1` and the policy route matches `fwmark 0x1`
// EXACTLY. Passwall 2's prerouting chain runs at mangle - 1, one step before this
// table's, and with its default "all sources" access control it marks every new
// TCP/UDP flow 0x50535732, including traffic that just came out of an IKEv2 SA. The
// panel's OR then yields 0x50535733, which matches neither Passwall's rule nor ours,
// so the client's packets are routed as ordinary forwarded traffic and never reach
// Xray. Resetting the mark first makes the OR produce exactly 0x1 again; the later
// TPROXY statement also replaces the socket Passwall selected.
//
// 0xff is left alone: it is Xray's own outbound mark, which both apps already skip.
func openwrtForeignMarkRule() string {
	if !isOpenWrt() {
		return ""
	}
	return "add rule ip vpn prerouting ip saddr " + vpnAddrSpace +
		" meta mark != 0x0 meta mark != 0xff meta mark set 0x0 comment \"ovpn-ui: clear foreign marks on VPN client traffic\"\n"
}

// openwrtReapStrayCharon kills a charon left running when the panel was stopped
// (procd signals the panel, not its children). Only called while the panel's own
// charon is down and after OpenWrt's strongSwan services are disabled, so any charon
// still holding UDP 500/4500 at that point is a previous panel's.
func openwrtReapStrayCharon() {
	if !isOpenWrt() {
		return
	}
	bin := backend.HostStrongswanBin("charon")
	if bin == "" {
		return
	}
	for _, svc := range openwrtStrongswanServices {
		if exec.Command(svc, "running").Run() == nil {
			return // OpenWrt's own service owns it; leave it to the operator
		}
	}
	_ = exec.Command("pkill", "-f", bin).Run()
}

// OpenwrtStartup runs once at panel start on OpenWrt.
//
// A fresh install whose package already pulled in the IKEv2 dependencies is recorded
// as provisioned for IKEv2, so an operator can create an IKEv2 inbound straight away
// instead of first running core setup for packages that are already there. Only when
// nothing was ever recorded: once an operator installs or removes cores, their choice
// stands.
func OpenwrtStartup() {
	if !isOpenWrt() {
		return
	}
	var cs CoreService
	var ss SettingService
	if cs.coreInstallStateIsRecorded() {
		if cs.provisionedProtocolSet()["ikev2"] {
			// An apk upgrade of strongswan-swanctl re-enables its service; put it back.
			if changed := openwrtDisableStrongswanServices(); len(changed) > 0 {
				logger.Info("OpenWrt: disabled", strings.Join(changed, ", "), "so the panel's charon keeps UDP 500/4500")
			}
		}
		return
	}
	if len(openwrtMissingPackages(openwrtIkev2Packages)) > 0 {
		return
	}
	openwrtDisableStrongswanServices()
	if err := ss.SetVpnProvisioned(true); err != nil {
		logger.Warning("OpenWrt: record provisioned:", err)
		return
	}
	if err := ss.SetProvisionedProtocols([]string{"ikev2"}); err != nil {
		logger.Warning("OpenWrt: record IKEv2 core:", err)
		return
	}
	logger.Info("OpenWrt: IKEv2 dependencies are installed; IKEv2 is ready to use")
}
