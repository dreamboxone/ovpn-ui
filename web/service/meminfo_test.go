package service

import (
	"encoding/binary"
	"testing"
)

// memDev builds one SMBIOS type-17 structure. length is the DECLARED formatted
// area, which is what decides whether a field exists; the returned blob is
// padded past it with the two zero bytes that terminate a structure's string
// table, exactly as /sys/firmware/dmi/entries/17-N/raw presents it. The two
// lengths differ on purpose: a short structure followed by strings must not
// look like a long one.
func memDev(length int, fields map[int]any) []byte {
	raw := make([]byte, length+2)
	raw[0] = 17
	raw[1] = byte(length)
	for off, v := range fields {
		switch t := v.(type) {
		case byte:
			raw[off] = t
		case uint16:
			binary.LittleEndian.PutUint16(raw[off:], t)
		case uint32:
			binary.LittleEndian.PutUint32(raw[off:], t)
		default:
			panic("memDev: unsupported field type")
		}
	}
	return raw
}

const gib = 1024 * 1024 * 1024

// A pair of matched DDR4 sticks: the everyday bare-metal case.
func TestAggregateMemDevicesMatchedPair(t *testing.T) {
	stick := memDev(0x54, map[int]any{
		memDevSize:      uint16(8192), // MB
		memDevType:      byte(0x1A),   // DDR4
		memDevSpeed:     uint16(3200),
		memDevConfSpeed: uint16(3200),
	})
	hw := aggregateMemDevices([][]byte{stick, stick})

	if hw.TotalBytes != 16*gib {
		t.Errorf("total = %d; want %d", hw.TotalBytes, uint64(16*gib))
	}
	if hw.Type != "DDR4" {
		t.Errorf("type = %q; want DDR4", hw.Type)
	}
	if hw.SpeedMTs != 3200 {
		t.Errorf("speed = %d; want 3200", hw.SpeedMTs)
	}
}

// Empty slots are structures too. They must contribute nothing at all, not a
// zero-sized module that drags the type or speed consensus with it.
func TestAggregateMemDevicesSkipsEmptySlots(t *testing.T) {
	populated := memDev(0x54, map[int]any{
		memDevSize:      uint16(16384),
		memDevType:      byte(0x22), // DDR5
		memDevConfSpeed: uint16(5600),
	})
	// An empty slot carries size 0 and, on most firmwares, type Unknown.
	empty := memDev(0x54, map[int]any{
		memDevSize: uint16(0),
		memDevType: byte(0x02),
	})
	hw := aggregateMemDevices([][]byte{populated, empty, empty, empty})

	if hw.TotalBytes != 16*gib {
		t.Errorf("total = %d; want %d", hw.TotalBytes, uint64(16*gib))
	}
	if hw.Type != "DDR5" {
		t.Errorf("type = %q; want DDR5 (an empty slot must not break the consensus)", hw.Type)
	}
	if hw.SpeedMTs != 5600 {
		t.Errorf("speed = %d; want 5600", hw.SpeedMTs)
	}
}

// The configured rate is what the memory actually runs at. A 3200 kit left at
// its JEDEC default must report 2133, not the sticker on the box.
func TestMemDevSpeedPrefersConfigured(t *testing.T) {
	raw := memDev(0x54, map[int]any{
		memDevSpeed:     uint16(3200),
		memDevConfSpeed: uint16(2133),
	})
	if got := memDevSpeedMTs(raw); got != 2133 {
		t.Errorf("speed = %d; want 2133", got)
	}
}

// Firmware that reports no configured speed must still yield the rated one
// rather than falling through to "unknown".
func TestMemDevSpeedFallsBackToRated(t *testing.T) {
	raw := memDev(0x54, map[int]any{
		memDevSpeed:     uint16(2666),
		memDevConfSpeed: uint16(0),
	})
	if got := memDevSpeedMTs(raw); got != 2666 {
		t.Errorf("speed = %d; want 2666", got)
	}
}

// 0xFFFF in either speed word means "read the extended DWORD instead".
func TestMemDevSpeedExtended(t *testing.T) {
	raw := memDev(0x60, map[int]any{
		memDevSpeed:     uint16(0xFFFF),
		memDevConfSpeed: uint16(0xFFFF),
		memDevExtSpeed:  uint32(9000),
		memDevExtConf:   uint32(8000),
	})
	if got := memDevSpeedMTs(raw); got != 8000 {
		t.Errorf("speed = %d; want 8000 (extended configured)", got)
	}
}

// 0x7FFF in the size word means the module is too big for it; the real value is
// the extended DWORD, in MB, with bit 31 reserved.
func TestMemDevBytesExtendedSize(t *testing.T) {
	raw := memDev(0x54, map[int]any{
		memDevSize:    uint16(0x7FFF),
		memDevExtSize: uint32(65536), // 64 GB
	})
	got, ok := memDevBytes(raw)
	if !ok {
		t.Fatal("memDevBytes reported the structure too short")
	}
	if got != 64*gib {
		t.Errorf("size = %d; want %d", got, uint64(64*gib))
	}
}

// Bit 15 set flips the size unit from MB to KB.
func TestMemDevBytesKilobyteUnit(t *testing.T) {
	raw := memDev(0x54, map[int]any{
		memDevSize: uint16(0x8000 | 512), // 512 KB
	})
	got, _ := memDevBytes(raw)
	if got != 512*1024 {
		t.Errorf("size = %d; want %d", got, 512*1024)
	}
}

// The everyday hypervisor answer: one whole-RAM "DIMM 0" of an unnamed type at
// an unknown speed. Capacity must survive; type and speed must come back empty
// rather than as a guess.
func TestAggregateMemDevicesHypervisor(t *testing.T) {
	// SMBIOS 2.3-era structure: 0x15 long, so it carries no speed field at all.
	raw := memDev(0x15, map[int]any{
		memDevSize: uint16(4096),
		memDevType: byte(0x07), // "RAM", i.e. the firmware declining to say
	})
	hw := aggregateMemDevices([][]byte{raw})

	if hw.TotalBytes != 4*gib {
		t.Errorf("total = %d; want %d", hw.TotalBytes, uint64(4*gib))
	}
	if hw.Type != "" {
		t.Errorf("type = %q; want empty (0x07 is not a DDR generation)", hw.Type)
	}
	if hw.SpeedMTs != 0 {
		t.Errorf("speed = %d; want 0 (the structure is too short to hold one)", hw.SpeedMTs)
	}
}

// Mismatched sticks have no single honest type or speed. Capacity still sums.
func TestAggregateMemDevicesMismatched(t *testing.T) {
	ddr4 := memDev(0x54, map[int]any{
		memDevSize: uint16(8192), memDevType: byte(0x1A), memDevConfSpeed: uint16(3200),
	})
	ddr3 := memDev(0x54, map[int]any{
		memDevSize: uint16(4096), memDevType: byte(0x18), memDevConfSpeed: uint16(1600),
	})
	hw := aggregateMemDevices([][]byte{ddr4, ddr3})

	if hw.TotalBytes != 12*gib {
		t.Errorf("total = %d; want %d", hw.TotalBytes, uint64(12*gib))
	}
	if hw.Type != "" || hw.SpeedMTs != 0 {
		t.Errorf("type/speed = %q/%d; want empty/0 for mismatched modules", hw.Type, hw.SpeedMTs)
	}
}

// A field beyond the DECLARED formatted area must never be read, even though
// the blob is long enough to contain those bytes: past raw[1] they are the
// string table, and decoding them as a speed would invent one.
func TestDmiFitsRespectsDeclaredLength(t *testing.T) {
	raw := make([]byte, 0x60)
	raw[0] = 17
	raw[1] = 0x15 // declares a short structure...
	binary.LittleEndian.PutUint16(raw[memDevSpeed:], 3200)

	if dmiFits(raw, memDevSpeed, 2) {
		t.Error("dmiFits allowed a read past the declared formatted area")
	}
	if got := memDevSpeedMTs(raw); got != 0 {
		t.Errorf("speed = %d; want 0 (the bytes are string table, not a speed)", got)
	}
}

// A truncated read must not panic or produce a number.
func TestMemDevBytesShortStructure(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {17}, {17, 0x54, 0x00}} {
		if _, ok := memDevBytes(raw); ok {
			t.Errorf("memDevBytes(%v) reported ok on a truncated structure", raw)
		}
	}
	if hw := aggregateMemDevices([][]byte{nil, {17}}); hw.TotalBytes != 0 {
		t.Errorf("total = %d; want 0", hw.TotalBytes)
	}
}
