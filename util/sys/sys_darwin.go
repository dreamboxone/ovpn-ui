//go:build darwin
// +build darwin

package sys

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/unix"
)

var SIGUSR1 = syscall.SIGUSR1

func GetTCPCount() (int, error) {
	stats, err := net.Connections("tcp")
	if err != nil {
		return 0, err
	}
	return len(stats), nil
}

func GetUDPCount() (int, error) {
	stats, err := net.Connections("udp")
	if err != nil {
		return 0, err
	}
	return len(stats), nil
}

// --- CPU Utilization (macOS native) ---

// sysctl kern.cp_time returns an array of 5 longs: user, nice, sys, idle, intr.

// CPUTimesRaw returns the cumulative idle and total CPU ticks. Utilization is the
// ratio of their DELTAS between two reads; see the Linux twin for why the deltas
// belong to the caller and not to a package-level baseline.
func CPUTimesRaw() (idleAll, total uint64, err error) {
	raw, err := unix.SysctlRaw("kern.cp_time")
	if err != nil {
		return 0, 0, err
	}
	// Expect either 5*8 bytes (uint64) or 5*4 bytes (uint32)
	var out [5]uint64
	switch len(raw) {
	case 5 * 8:
		for i := range 5 {
			out[i] = binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
		}
	case 5 * 4:
		for i := range 5 {
			out[i] = uint64(binary.LittleEndian.Uint32(raw[i*4 : (i+1)*4]))
		}
	default:
		return 0, 0, fmt.Errorf("unexpected kern.cp_time size: %d", len(raw))
	}

	// user, nice, sys, idle, intr
	idleAll = out[3]
	return idleAll, out[0] + out[1] + out[2] + out[3] + out[4], nil
}
