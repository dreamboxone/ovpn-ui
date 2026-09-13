//go:build linux
// +build linux

package sys

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

var SIGUSR1 = syscall.SIGUSR1

func getLinesNum(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	sum := 0
	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)

		var buffPosition int
		for {
			i := bytes.IndexByte(buf[buffPosition:n], '\n')
			if i < 0 {
				break
			}
			buffPosition += i + 1
			sum++
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return 0, err
		}
	}
	return sum, nil
}

// GetTCPCount returns the number of active TCP connections by reading
// /proc/net/tcp and /proc/net/tcp6 when available.
func GetTCPCount() (int, error) {
	root := HostProc()

	tcp4, err := safeGetLinesNum(fmt.Sprintf("%v/net/tcp", root))
	if err != nil {
		return 0, err
	}
	tcp6, err := safeGetLinesNum(fmt.Sprintf("%v/net/tcp6", root))
	if err != nil {
		return 0, err
	}

	return tcp4 + tcp6, nil
}

func GetUDPCount() (int, error) {
	root := HostProc()

	udp4, err := safeGetLinesNum(fmt.Sprintf("%v/net/udp", root))
	if err != nil {
		return 0, err
	}
	udp6, err := safeGetLinesNum(fmt.Sprintf("%v/net/udp6", root))
	if err != nil {
		return 0, err
	}

	return udp4 + udp6, nil
}

// safeGetLinesNum returns 0 if the file does not exist, otherwise forwards
// to getLinesNum to count the number of lines.
func safeGetLinesNum(path string) (int, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return getLinesNum(path)
}

// --- CPU Utilization (Linux native) ---

// CPUTimesRaw returns the cumulative-since-boot idle and total CPU jiffies from
// /proc/stat. Utilization is the ratio of their DELTAS between two reads, and the
// deltas are deliberately left to the caller: these counters used to be turned into
// a percentage here against a package-level baseline, which made the reading depend
// on who called last. The dashboard polls every 2s and the Telegram bot's usage
// report calls the same path on its own schedule, so each was silently consuming the
// other's interval and reporting a percentage measured over a window it did not own.
// Per-caller state cannot have that problem.
func CPUTimesRaw() (idleAll, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return 0, 0, err
	}
	// Expect line like: cpu  user nice system idle iowait irq softirq steal guest guest_nice
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("unexpected /proc/stat format")
	}

	var nums []uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			break
		}
		nums = append(nums, v)
	}
	if len(nums) < 4 { // need at least user,nice,system,idle
		return 0, 0, fmt.Errorf("insufficient cpu fields")
	}

	// Conform with standard Linux CPU accounting
	var user, nice, system, idle, iowait, irq, softirq, steal uint64
	user = nums[0]
	if len(nums) > 1 {
		nice = nums[1]
	}
	if len(nums) > 2 {
		system = nums[2]
	}
	if len(nums) > 3 {
		idle = nums[3]
	}
	if len(nums) > 4 {
		iowait = nums[4]
	}
	if len(nums) > 5 {
		irq = nums[5]
	}
	if len(nums) > 6 {
		softirq = nums[6]
	}
	if len(nums) > 7 {
		steal = nums[7]
	}

	idleAll = idle + iowait
	nonIdle := user + nice + system + irq + softirq + steal
	return idleAll, idleAll + nonIdle, nil
}
