package service

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// MemHardware is the physical memory FITTED to this machine, as the firmware
// describes it: capacity, DDR generation and clock. Distinct from the live
// used/total the overview graphs, which comes from MemTotal and is smaller
// (the kernel excludes firmware-reserved regions), and which changes while we
// run. This does not, so it is read once and cached beside the other host
// identity facts in ServerService.
//
// Every field degrades to its zero value independently. A VM typically reports
// a size and nothing else, because QEMU stamps one "DIMM 0" of type Other with
// an unknown speed, so Type and SpeedMTs must be treated as optional rather
// than as "the read failed".
type MemHardware struct {
	// TotalBytes is the sum of every POPULATED module. Zero when the firmware
	// told us nothing, in which case the caller should fall back to MemTotal.
	TotalBytes uint64 `json:"totalBytes"`
	// Type is the DDR generation, e.g. "DDR4". Empty when the firmware reports
	// Other/Unknown (the usual answer on a hypervisor) or when modules disagree.
	Type string `json:"type"`
	// SpeedMTs is the transfer rate in MT/s. This is the CONFIGURED rate where
	// the firmware reports one (what the memory actually runs at), not the
	// module's rated maximum, so a 3200 kit running at 2133 says 2133. Zero when
	// unknown.
	SpeedMTs int `json:"speedMTs"`
}

// dmiEntriesDir holds one directory per SMBIOS structure. Root-only (0400), and
// the panel runs as root; a non-root run simply reports nothing.
const dmiEntriesDir = "/sys/firmware/dmi/entries"

// SMBIOS 7.18, Memory Device (type 17). Offsets into the formatted area.
const (
	memDevSize      = 0x0C // WORD.  0=empty slot, 0x7FFF=see extended, bit15: 0=MB 1=KB
	memDevType      = 0x12 // BYTE.  the enum below
	memDevSpeed     = 0x15 // WORD.  rated MT/s, 0xFFFF=see extended
	memDevExtSize   = 0x1C // DWORD. MB
	memDevConfSpeed = 0x20 // WORD.  configured MT/s, 0xFFFF=see extended
	memDevExtSpeed  = 0x54 // DWORD. MT/s
	memDevExtConf   = 0x58 // DWORD. MT/s
)

// memTypes is the Memory Type enum. Only the generations worth printing are
// listed: everything absent here (Other, Unknown, plain RAM, ROM, flash) is a
// firmware that does not know, which reads better as no answer than as a wrong
// one.
var memTypes = map[byte]string{
	0x0F: "SDRAM",
	0x12: "DDR",
	0x13: "DDR2",
	0x14: "DDR2 FB-DIMM",
	0x18: "DDR3",
	0x1A: "DDR4",
	0x1B: "LPDDR",
	0x1C: "LPDDR2",
	0x1D: "LPDDR3",
	0x1E: "LPDDR4",
	0x20: "HBM",
	0x21: "HBM2",
	0x22: "DDR5",
	0x23: "LPDDR5",
	0x24: "HBM3",
}

// DetectMemHardware reads the fitted memory out of SMBIOS.
//
// Callers should treat the result as fixed for the process lifetime, and should
// NOT call it inside a container: SMBIOS describes the host's DIMMs, while a
// container's memory is a cgroup limit that has nothing to do with them.
func DetectMemHardware() MemHardware {
	if hw, ok := readMemHardware(); ok {
		return hw
	}
	// /sys/firmware/dmi/entries only exists with CONFIG_DMI_SYSFS, which Debian
	// and Ubuntu build as a module and do not autoload. One modprobe is the whole
	// difference between "DDR4 at 3200" and a bare capacity on the distros this
	// panel is most often installed on, so it is worth the exec. Failure is fine:
	// the retry below just finds nothing again.
	if !dmiEntriesPresent() {
		_ = exec.Command("modprobe", "dmi-sysfs").Run()
	}
	hw, _ := readMemHardware()
	return hw
}

func dmiEntriesPresent() bool {
	st, err := os.Stat(dmiEntriesDir)
	return err == nil && st.IsDir()
}

// readMemHardware aggregates every type-17 structure. ok is false when not one
// populated module could be read, so the caller can decide whether to retry.
func readMemHardware() (MemHardware, bool) {
	dirs, err := filepath.Glob(filepath.Join(dmiEntriesDir, "17-*"))
	if err != nil || len(dirs) == 0 {
		return MemHardware{}, false
	}
	sort.Strings(dirs)

	raws := make([][]byte, 0, len(dirs))
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(d, "raw"))
		if err != nil {
			continue
		}
		raws = append(raws, raw)
	}
	hw := aggregateMemDevices(raws)
	return hw, hw.TotalBytes > 0
}

// aggregateMemDevices folds every type-17 structure into one answer.
//
// Types and speeds are collected rather than taken from the first module: a
// machine with mismatched sticks has no single honest answer, and printing the
// first one would be a guess dressed as a fact. Capacity still sums, because
// that one is true regardless of what is mixed.
func aggregateMemDevices(raws [][]byte) MemHardware {
	var hw MemHardware
	types := map[string]struct{}{}
	speeds := map[int]struct{}{}

	for _, raw := range raws {
		size, ok := memDevBytes(raw)
		if !ok || size == 0 {
			continue // empty slot, or a size the firmware would not name
		}
		hw.TotalBytes += size
		if t, ok := memTypes[dmiByte(raw, memDevType)]; ok {
			types[t] = struct{}{}
		}
		if sp := memDevSpeedMTs(raw); sp > 0 {
			speeds[sp] = struct{}{}
		}
	}
	if len(types) == 1 {
		for t := range types {
			hw.Type = t
		}
	}
	if len(speeds) == 1 {
		for s := range speeds {
			hw.SpeedMTs = s
		}
	}
	return hw
}

// dmiFits reports whether a field of width bytes at off is inside BOTH the
// structure's declared formatted area (raw[1]) and the bytes we actually read.
// Both bounds matter: the sysfs blob carries the trailing string table too, so
// its length alone would happily read a field a short structure never had.
func dmiFits(raw []byte, off, width int) bool {
	if len(raw) < 2 || off+width > len(raw) {
		return false
	}
	return int(raw[1]) >= off+width
}

func dmiByte(raw []byte, off int) byte {
	if !dmiFits(raw, off, 1) {
		return 0
	}
	return raw[off]
}

func dmiWord(raw []byte, off int) (uint16, bool) {
	if !dmiFits(raw, off, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(raw[off:]), true
}

func dmiDword(raw []byte, off int) (uint32, bool) {
	if !dmiFits(raw, off, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw[off:]), true
}

// memDevBytes decodes one module's size. ok is false when the structure is too
// short to carry one; a populated slot of unknown size and an empty slot both
// return 0, which the caller skips either way.
func memDevBytes(raw []byte) (uint64, bool) {
	size, ok := dmiWord(raw, memDevSize)
	if !ok {
		return 0, false
	}
	switch size {
	case 0, 0xFFFF: // empty slot / unknown
		return 0, true
	case 0x7FFF: // too big for the word: the real value is the extended field, in MB
		ext, ok := dmiDword(raw, memDevExtSize)
		if !ok {
			return 0, true
		}
		return uint64(ext&0x7FFFFFFF) * 1024 * 1024, true
	}
	if size&0x8000 != 0 { // bit 15 set: the value is in KB
		return uint64(size&0x7FFF) * 1024, true
	}
	return uint64(size) * 1024 * 1024, true
}

// memDevSpeedMTs returns the rate this module runs at, preferring the
// configured speed over the rated one. Zero when the firmware knows neither,
// which is the normal answer on a hypervisor.
func memDevSpeedMTs(raw []byte) int {
	read := func(word, ext int) int {
		v, ok := dmiWord(raw, word)
		if !ok || v == 0 {
			return 0
		}
		if v == 0xFFFF {
			e, ok := dmiDword(raw, ext)
			if !ok {
				return 0
			}
			return int(e)
		}
		return int(v)
	}
	if sp := read(memDevConfSpeed, memDevExtConf); sp > 0 {
		return sp
	}
	return read(memDevSpeed, memDevExtSpeed)
}
