package service

import (
	"os"
	"os/exec"
	"strings"

	"github.com/shirou/gopsutil/v4/host"
)

// VirtInfo reports whether this host is a guest (VM or container) and, when it
// is, what runs it. The overview's identity tile renders it as "Yes (KVM)" /
// "No", so System is a display-ready label, not the raw detector id.
type VirtInfo struct {
	Virtualized bool `json:"virtualized"`
	// System is the hypervisor/container engine, e.g. "KVM", "VMware", "LXC".
	// Empty when the detector could only prove *that* the host is a guest, and
	// on bare metal.
	System string `json:"system"`
	// Kind is "vm", "container" or "" (bare metal). The tile doesn't show it,
	// but it distinguishes "a VM you can reboot into a new kernel" from "a
	// container that shares the host kernel", which matters for the setup
	// flow's kernel-module steps.
	Kind string `json:"kind"`
}

// virtLabels maps the ids systemd-detect-virt and gopsutil report to the names
// operators actually use. An id that isn't listed falls back to its raw form,
// so a hypervisor newer than this table still shows something useful.
var virtLabels = map[string]string{
	"kvm":             "KVM",
	"qemu":            "QEMU",
	"vmware":          "VMware",
	"microsoft":       "Hyper-V",
	"hyperv":          "Hyper-V",
	"oracle":          "VirtualBox",
	"virtualbox":      "VirtualBox",
	"xen":             "Xen",
	"bochs":           "Bochs",
	"uml":             "UML",
	"parallels":       "Parallels",
	"bhyve":           "bhyve",
	"qnx":             "QNX",
	"acrn":            "ACRN",
	"powervm":         "PowerVM",
	"zvm":             "z/VM",
	"apple-paravirt":  "Apple Paravirt",
	"amazon":          "AWS Nitro",
	"google":          "Google Compute Engine",
	"proxmox":         "Proxmox",
	"openstack":       "OpenStack",
	"lxc":             "LXC",
	"lxc-libvirt":     "LXC (libvirt)",
	"systemd-nspawn":  "systemd-nspawn",
	"docker":          "Docker",
	"podman":          "Podman",
	"rkt":             "rkt",
	"wsl":             "WSL",
	"proot":           "PRoot",
	"pouch":           "PouchContainer",
	"openvz":          "OpenVZ",
	"container-other": "Container",
}

// virtLabel renders a detector id for the UI.
func virtLabel(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return ""
	}
	if l, ok := virtLabels[id]; ok {
		return l
	}
	return id
}

// DetectVirtualization reports whether this host runs on a hypervisor or inside
// a container.
//
// systemd-detect-virt is asked first and trusted outright: it is the same probe
// the rest of the distro uses (ConditionVirtualization= in units), it reads the
// CPUID hypervisor leaf, DMI and the container markers together, and it names
// the platform rather than just flagging one. It is present on every systemd
// distro the panel targets. gopsutil is the fallback for the systemd-less case
// and the DMI read is the last resort, since a host can be a guest without any
// container marker or /proc/xen.
//
// Callers should treat this as fixed for the process lifetime: a machine does
// not stop being a VM while the panel runs, and ServerService caches it beside
// the other read-once host identity fields.
func DetectVirtualization() VirtInfo {
	if v, ok := detectVirtSystemd(); ok {
		return v
	}
	if v, ok := detectVirtGopsutil(); ok {
		return v
	}
	return detectVirtDMI()
}

// detectVirtSystemd runs systemd-detect-virt. ok is false when the tool isn't
// installed, so the caller can fall through to another detector; a tool that
// ran and said "none" is an authoritative bare-metal answer, not a miss.
//
// The plain invocation reports the container id when inside one and the VM id
// otherwise, so `-c` is asked separately to tell the two apart.
func detectVirtSystemd() (VirtInfo, bool) {
	if !commandExists("systemd-detect-virt") {
		return VirtInfo{}, false
	}
	// Exit status 1 means "not virtualized" and is expected, so the error is
	// ignored and the printed id is what decides.
	out, _ := exec.Command("systemd-detect-virt").Output()
	id := strings.ToLower(strings.TrimSpace(string(out)))
	if id == "" || id == "none" {
		return VirtInfo{}, true
	}

	kind := "vm"
	cout, _ := exec.Command("systemd-detect-virt", "-c").Output()
	if c := strings.ToLower(strings.TrimSpace(string(cout))); c != "" && c != "none" {
		kind = "container"
	}
	return VirtInfo{Virtualized: true, System: virtLabel(id), Kind: kind}, true
}

// detectVirtGopsutil uses the library's own probe (/proc/xen, /proc/cpuinfo,
// the cgroup and container-marker files). ok is false when it neither proves
// nor disproves virtualization, so the DMI fallback still gets a turn.
func detectVirtGopsutil() (VirtInfo, bool) {
	system, role, err := host.Virtualization()
	if err != nil {
		return VirtInfo{}, false
	}
	system = strings.ToLower(strings.TrimSpace(system))
	if system == "" || role != "guest" {
		return VirtInfo{}, false
	}
	kind := "vm"
	switch system {
	case "lxc", "docker", "podman", "rkt", "openvz", "systemd-nspawn", "container-other", "pouch":
		kind = "container"
	}
	return VirtInfo{Virtualized: true, System: virtLabel(system), Kind: kind}, true
}

// detectVirtDMI is the last resort: the firmware's own idea of the machine.
// Cloud VMs and every desktop hypervisor stamp a recognisable vendor here, so
// this catches the systemd-less bare-VM case the two probes above can miss.
// A machine that matches nothing is reported as bare metal, the honest answer
// when no evidence of a hypervisor exists.
func detectVirtDMI() VirtInfo {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(string(b)))
	}
	hay := read("/sys/class/dmi/id/sys_vendor") + " " +
		read("/sys/class/dmi/id/product_name") + " " +
		read("/sys/class/dmi/id/board_vendor")

	// Ordered longest/most-specific first so "qemu" doesn't shadow a KVM board
	// that also names QEMU, and so the Amazon/Google entries win over "xen".
	for _, m := range []struct{ needle, label string }{
		{"amazon ec2", "AWS Nitro"},
		{"google compute engine", "Google Compute Engine"},
		{"microsoft corporation virtual machine", "Hyper-V"},
		{"innotek", "VirtualBox"},
		{"virtualbox", "VirtualBox"},
		{"vmware", "VMware"},
		{"parallels", "Parallels"},
		{"bochs", "Bochs"},
		{"kvm", "KVM"},
		{"qemu", "QEMU"},
		{"xen", "Xen"},
		{"alibaba cloud", "Alibaba Cloud"},
		{"openstack", "OpenStack"},
		{"digitalocean", "DigitalOcean"},
		{"hetzner", "Hetzner"},
		{"oracle", "VirtualBox"},
	} {
		if strings.Contains(hay, m.needle) {
			return VirtInfo{Virtualized: true, System: m.label, Kind: "vm"}
		}
	}
	return VirtInfo{}
}
