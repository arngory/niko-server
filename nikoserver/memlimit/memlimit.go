// Package memlimit reads the memory a process may have: the limits of its
// cgroup and of the cgroup's ancestors, and the host's MemTotal
// (raycontrol docs/spec/memory-v1.md §3). systemd sets a unit's limits as
// shares of the host's memory (MemoryMax, MemoryHigh) and recomputes them
// when the host's size changes; a process reads what they came to at its
// start, and sizes its Go memory limit (GoLimit) and its budgets by it.
package memlimit

import (
	"bufio"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Paths are where Read looks: /proc/self/cgroup, the cgroup mount, and
// /proc/meminfo (System); the tests give their own.
type Paths struct {
	Cgroup  string // the process's cgroups, /proc/self/cgroup's format
	Root    string // cgroup v2's mount; v1's memory hierarchy is Root/memory
	Meminfo string
}

// System are the paths of the running process.
var System = Paths{Cgroup: "/proc/self/cgroup", Root: "/sys/fs/cgroup", Meminfo: "/proc/meminfo"}

// Limits are the memory of a process: each 0 when none is known.
type Limits struct {
	// Max is the least memory.max (v2) or memory.limit_in_bytes (v1) of
	// the process's cgroup and its ancestors: past it the kernel reclaims
	// and then kills.
	Max int64
	// High is the least memory.high (v2) of the same: past it the kernel
	// throttles the cgroup and reclaims hard. v1 has none.
	High int64
	// MemTotal is the host's memory (/proc/meminfo).
	MemTotal int64
}

// Read reads the limits at p. "max", a value that does not parse and one
// of 0 or less are no limit; a file missing is none. A cgroup's path
// from p.Cgroup that is not under the mount (a container's own cgroup
// mounted as the root) is read from the mount's root up: each directory
// from the path's own to the root that has the file counts.
func Read(p Paths) Limits {
	var l Limits
	least := func(at *int64, n int64) {
		if n > 0 && (*at == 0 || n < *at) {
			*at = n
		}
	}
	limits := func(dir, mount, file string, at *int64) {
		for dir = path.Clean("/" + dir); ; dir = path.Dir(dir) {
			if b, err := os.ReadFile(path.Join(mount, dir, file)); err == nil {
				n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64) // "max", garbage: 0
				least(at, n)
			}
			if dir == "/" {
				return
			}
		}
	}
	if b, err := os.ReadFile(p.Cgroup); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.SplitN(line, ":", 3)
			switch {
			case len(f) < 3:
			case f[0] == "0" && f[1] == "":
				limits(f[2], p.Root, "memory.max", &l.Max)
				limits(f[2], p.Root, "memory.high", &l.High)
			case slices.Contains(strings.Split(f[1], ","), "memory"):
				limits(f[2], path.Join(p.Root, "memory"), "memory.limit_in_bytes", &l.Max)
			}
		}
	}
	if f, err := os.Open(p.Meminfo); err == nil {
		defer f.Close()
		for s := bufio.NewScanner(f); s.Scan(); {
			if v, ok := strings.CutPrefix(s.Text(), "MemTotal:"); ok {
				kb, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
				if kb > 0 && kb < 1<<42 {
					l.MemTotal = kb << 10
				}
			}
		}
	}
	return l
}

// below is n when it is a limit below the host: under MemTotal (when that
// is known) and under 2^62 (v1's "unlimited" is 2^63 less a page); else 0.
func (l Limits) below(n int64) int64 {
	if n <= 0 || n >= 1<<62 || l.MemTotal > 0 && n >= l.MemTotal {
		return 0
	}
	return n
}

// Limit is the cgroup's limit, the less of High and Max, when it is below
// the host; else 0: a limit at or above MemTotal limits nothing.
func (l Limits) Limit() int64 {
	h, m := l.below(l.High), l.below(l.Max)
	if h == 0 || m > 0 && m < h {
		return m
	}
	return h
}

// Memory is what the process may have: its cgroup's Limit, else MemTotal;
// 0 when neither is known.
func (l Limits) Memory() int64 {
	if n := l.Limit(); n > 0 {
		return n
	}
	return l.MemTotal
}

// GoLimitFloor is the least Go memory limit GoLimit gives.
const GoLimitFloor = 64 << 20

// GoLimit is the Go runtime's memory limit for a process under the
// limits: num/den of the less of High and 15/16 of Max (Max's last
// sixteenth for what Go does not count: the kernel's buffers charged to
// the cgroup, the binary's pages), GoLimitFloor at least; 0 without a
// limit below the host, where a limit from the host's memory would do
// nothing.
func (l Limits) GoLimit(num, den int64) int64 {
	base := l.below(l.High)
	if m := l.below(l.Max) / 16 * 15; m > 0 && (base == 0 || m < base) {
		base = m
	}
	if base == 0 || num <= 0 || den <= 0 {
		return 0
	}
	return max(base/den*num, GoLimitFloor)
}

// SetGoLimit gives the runtime GoLimit(num, den) through set (the
// runtime's debug.SetMemoryLimit) unless the environment (getenv) has
// GOMEMLIMIT: the runtime took that one at its start, and a unit that
// sets it means it. It returns the limit set, 0 when none was.
func SetGoLimit(l Limits, num, den int64, getenv func(string) string, set func(int64) int64) int64 {
	if getenv("GOMEMLIMIT") != "" {
		return 0
	}
	n := l.GoLimit(num, den)
	if n > 0 {
		set(n)
	}
	return n
}
