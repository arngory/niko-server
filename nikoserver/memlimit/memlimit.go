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

// Paths are where Read looks: /proc/self/cgroup, the process's mounts,
// the cgroup mount, and /proc/meminfo (System); the tests give their own.
type Paths struct {
	Cgroup string // the process's cgroups, /proc/self/cgroup's format
	// Mountinfo is the process's mounts, /proc/self/mountinfo's format:
	// where cgroup v2 and v1's memory controller (co-mounted with others or
	// not, cpu,memory) are mounted, and which of their cgroups each mount
	// is. Without it, or without either there, Root's.
	Mountinfo string
	Root      string // cgroup v2's mount; v1's memory hierarchy is Root/memory
	Meminfo   string
}

// System are the paths of the running process.
var System = Paths{Cgroup: "/proc/self/cgroup", Mountinfo: "/proc/self/mountinfo", Root: "/sys/fs/cgroup", Meminfo: "/proc/meminfo"}

// mount is a cgroup hierarchy's mount: where (point), and which of its
// cgroups is mounted there (root, "/" for the hierarchy's own root).
type mount struct{ point, root string }

// mounts reads where cgroup v2 and v1's memory controller are mounted,
// from mountinfo; the first of each.
func mounts(mountinfo string) (v2, v1 *mount) {
	b, err := os.ReadFile(mountinfo)
	if err != nil {
		return nil, nil
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		// id parent major:minor root point options [optional...] - type source super
		left, right, ok := strings.Cut(line, " - ")
		f, r := strings.Fields(left), strings.Fields(right)
		if !ok || len(f) < 5 || len(r) < 1 {
			continue
		}
		m := &mount{point: unescape(f[4]), root: path.Clean("/" + unescape(f[3]))}
		switch {
		case r[0] == "cgroup2" && v2 == nil:
			v2 = m
		case r[0] == "cgroup" && v1 == nil && len(r) >= 3 && slices.Contains(strings.Split(r[2], ","), "memory"):
			v1 = m
		}
	}
	return v2, v1
}

// unescape undoes mountinfo's octal escapes (\040 a space).
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// under is the cgroup dir as a path under a mount of the cgroup root:
// dir less root when it is under it, else dir (not under the mount: read
// from the mount's root up).
func under(dir, root string) string {
	dir = path.Clean("/" + dir)
	if root == "/" {
		return dir
	}
	if rel, ok := strings.CutPrefix(dir, root); ok && (rel == "" || rel[0] == '/') {
		return path.Clean("/" + rel)
	}
	return dir
}

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
// of 0 or less are no limit; a file missing is none. A cgroup's path from
// p.Cgroup is taken under the mount of its hierarchy (Mountinfo, less the
// cgroup mounted there); one not under the mount (a container's own
// cgroup mounted as the root, unknown to mountinfo) is read from the
// mount's root up: each directory from the path's own to the root that
// has the file counts.
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
	v2, v1 := mounts(p.Mountinfo)
	if v2 == nil {
		v2 = &mount{point: p.Root, root: "/"}
	}
	if v1 == nil {
		v1 = &mount{point: path.Join(p.Root, "memory"), root: "/"}
	}
	if b, err := os.ReadFile(p.Cgroup); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.SplitN(line, ":", 3)
			switch {
			case len(f) < 3:
			case f[0] == "0" && f[1] == "":
				limits(under(f[2], v2.root), v2.point, "memory.max", &l.Max)
				limits(under(f[2], v2.root), v2.point, "memory.high", &l.High)
			case slices.Contains(strings.Split(f[1], ","), "memory"):
				limits(under(f[2], v1.root), v1.point, "memory.limit_in_bytes", &l.Max)
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

// below is n when it is a limit: at or under MemTotal (when that is known)
// and under 2^62 (v1's "unlimited" is 2^63 less a page); else 0. At
// MemTotal counts: under lxcfs (LXC, Incus, Proxmox) /proc/meminfo is the
// container's memory.max, and systemd's MemoryMax=100% is the host's
// memory, a limit either way.
func (l Limits) below(n int64) int64 {
	if n <= 0 || n >= 1<<62 || l.MemTotal > 0 && n > l.MemTotal {
		return 0
	}
	return n
}

// Limit is the cgroup's limit, the less of High and Max, when it is not
// above the host; else 0: a limit above MemTotal limits nothing.
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
