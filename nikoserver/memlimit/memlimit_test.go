package memlimit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mib = 1 << 20

// tree is a fake /proc/self/cgroup, cgroup mount and /proc/meminfo.
type tree struct {
	t   *testing.T
	dir string
}

func newTree(t *testing.T, cgroup string) (*tree, Paths) {
	tr := &tree{t: t, dir: t.TempDir()}
	tr.write("cgroup", cgroup)
	tr.write("meminfo", "MemTotal:        4194304 kB\nMemFree:  1 kB\n") // 4 GiB
	return tr, Paths{Cgroup: tr.path("cgroup"), Root: tr.path("fs"), Meminfo: tr.path("meminfo")}
}

func (tr *tree) path(name string) string { return filepath.Join(tr.dir, name) }

func (tr *tree) write(name, s string) {
	tr.t.Helper()
	p := tr.path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		tr.t.Fatal(err)
	}
}

func check(t *testing.T, what string, p Paths, want Limits) Limits {
	t.Helper()
	got := Read(p)
	if got != want {
		t.Fatalf("%s: %+v, want %+v", what, got, want)
	}
	return got
}

// cgroup v2: the least memory.max and memory.high of the cgroup and its
// ancestors, each apart, "max" none; a unit's limit below the slice's.
func TestReadV2(t *testing.T) {
	tr, p := newTree(t, "0::/raycontrol.slice/raycontrol-data.slice/niko-hy2.service\n")
	check(t, "no files", p, Limits{MemTotal: 4 << 30})
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/niko-hy2.service/memory.max", "max\n")
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/niko-hy2.service/memory.high", "max\n")
	check(t, "max", p, Limits{MemTotal: 4 << 30})
	// The slice's lower than the unit's (an ancestor lower), its high
	// lower than its max.
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/memory.max", "1073741824\n")
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/memory.high", "939524096\n")
	l := check(t, "the slice's", p, Limits{Max: 1 << 30, High: 896 * mib, MemTotal: 4 << 30})
	if l.Limit() != 896*mib || l.Memory() != 896*mib {
		t.Fatalf("limit %d, memory %d", l.Limit(), l.Memory())
	}
	// The unit's own, lower still: its max under the slice's high.
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/niko-hy2.service/memory.max", "536870912\n")
	l = check(t, "the unit's", p, Limits{Max: 512 * mib, High: 896 * mib, MemTotal: 4 << 30})
	if l.Limit() != 512*mib {
		t.Fatalf("limit %d", l.Limit())
	}
	// Higher up, the root slice's, the lowest high.
	tr.write("fs/raycontrol.slice/memory.high", "268435456")
	check(t, "the root slice's", p, Limits{Max: 512 * mib, High: 256 * mib, MemTotal: 4 << 30})
	// Garbage and nonsense are no limit; the others stand.
	tr.write("fs/raycontrol.slice/memory.high", "lots\n")
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/memory.high", "-5\n")
	tr.write("fs/raycontrol.slice/raycontrol-data.slice/niko-hy2.service/memory.high", "0\n")
	check(t, "garbage", p, Limits{Max: 512 * mib, MemTotal: 4 << 30})
}

// A container's own cgroup mounted as the root: its path from
// /proc/self/cgroup is not under the mount, the root's file is read.
func TestReadContainerRoot(t *testing.T) {
	tr, p := newTree(t, "0::/docker/abc\n")
	tr.write("fs/memory.max", "268435456\n")
	tr.write("fs/memory.high", "max\n")
	check(t, "v2 root", p, Limits{Max: 256 * mib, MemTotal: 4 << 30})
}

// cgroup v1: the memory hierarchy's memory.limit_in_bytes, "unlimited"
// (2^63 less a page) no limit below the host; a hybrid's empty v2 line
// adds nothing.
func TestReadV1(t *testing.T) {
	tr, p := newTree(t, "4:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n0::/\n")
	tr.write("fs/memory/memory.limit_in_bytes", "9223372036854771712\n")
	l := check(t, "unlimited", p, Limits{Max: 9223372036854771712, MemTotal: 4 << 30})
	if l.Limit() != 0 || l.Memory() != 4<<30 || l.GoLimit(7, 8) != 0 {
		t.Fatalf("unlimited: limit %d, memory %d, Go %d", l.Limit(), l.Memory(), l.GoLimit(7, 8))
	}
	tr.write("fs/memory/memory.limit_in_bytes", "1073741824\n")
	check(t, "the container's root", p, Limits{Max: 1 << 30, MemTotal: 4 << 30})
	tr.write("fs/memory/docker/abc/memory.limit_in_bytes", "268435456\n")
	l = check(t, "its own", p, Limits{Max: 256 * mib, MemTotal: 4 << 30})
	if l.Limit() != 256*mib {
		t.Fatalf("limit %d", l.Limit())
	}
	// Combined controllers, as some v1 mounts have them.
	tr2, p2 := newTree(t, "5:memory,hugetlb:/a\n")
	tr2.write("fs/memory/a/memory.limit_in_bytes", "134217728\n")
	check(t, "combined", p2, Limits{Max: 128 * mib, MemTotal: 4 << 30})
}

// lxcfs: /proc/meminfo is the container's own, its MemTotal its
// memory.max; the limit stands.
func TestReadLxcfs(t *testing.T) {
	tr, p := newTree(t, "0::/\n")
	tr.write("meminfo", "MemTotal:        1048576 kB\n")
	tr.write("fs/memory.max", "1073741824\n")
	l := check(t, "lxcfs", p, Limits{Max: 1 << 30, MemTotal: 1 << 30})
	if l.Limit() != 1<<30 || l.GoLimit(7, 8) != 840*mib {
		t.Fatalf("limit %d, Go %d", l.Limit(), l.GoLimit(7, 8))
	}
}

// The mounts from mountinfo: v1's memory controller co-mounted with cpu
// (cpu,memory), not at Root/memory; v2 at another point, a container's
// cgroup mounted there (its root field), the path from /proc/self/cgroup
// taken under it.
func TestReadMountinfo(t *testing.T) {
	tr, p := newTree(t, "5:cpu,memory:/lxc/c1/app\n0::/lxc/c1/app\n")
	v1, v2 := tr.path("v1 mounts/cpu,memory"), tr.path("v2")
	tr.write("mountinfo", "36 23 0:28 / "+tr.path("fs")+" rw,relatime - tmpfs tmpfs rw,mode=755\n"+
		"37 36 0:29 / "+strings.ReplaceAll(v1, " ", "\\040")+" rw,relatime shared:9 - cgroup cgroup rw,cpu,memory\n"+
		"38 36 0:30 /lxc/c1 "+v2+" rw,relatime - cgroup2 cgroup2 rw,nsdelegate\n")
	p.Mountinfo = tr.path("mountinfo")
	tr.write("v1 mounts/cpu,memory/lxc/c1/memory.limit_in_bytes", "268435456\n")
	tr.write("v2/app/memory.high", "201326592\n")
	tr.write("v2/memory.max", "536870912\n")
	tr.write("fs/memory/lxc/c1/memory.limit_in_bytes", "1\n") // not the mount: unread
	tr.write("fs/lxc/c1/app/memory.max", "1\n")
	check(t, "mountinfo", p, Limits{Max: 256 * mib, High: 192 * mib, MemTotal: 4 << 30})
	// Several mounts of v2: the one whose root is the longest prefix of
	// the cgroup's path; one outside the namespace ("..") skipped.
	other := tr.path("v2 other")
	tr.write("mountinfo", "37 36 0:29 / "+strings.ReplaceAll(v1, " ", "\\040")+" rw - cgroup cgroup rw,cpu,memory\n"+
		"38 36 0:30 / "+strings.ReplaceAll(other, " ", "\\040")+" rw - cgroup2 cgroup2 rw\n"+
		"39 36 0:30 /../.. "+tr.path("v2 outside")+" rw - cgroup2 cgroup2 rw\n"+
		"40 36 0:30 /lxc/c1 "+v2+" rw - cgroup2 cgroup2 rw\n"+
		"41 36 0:30 /lxc/c2 "+tr.path("v2 c2")+" rw - cgroup2 cgroup2 rw\n")
	tr.write("v2 other/memory.max", "1\n")
	tr.write("v2 outside/memory.max", "2\n")
	tr.write("v2 c2/memory.max", "3\n")
	check(t, "longest prefix", p, Limits{Max: 256 * mib, High: 192 * mib, MemTotal: 4 << 30}) // not 1, 2 or 3
	// Without mountinfo, Root's and Root/memory.
	p.Mountinfo = tr.path("none")
	check(t, "no mountinfo", p, Limits{Max: 1, MemTotal: 4 << 30})
}

// Nothing known: no files, or files of garbage.
func TestReadNone(t *testing.T) {
	dir := t.TempDir()
	none := filepath.Join(dir, "none")
	if l := Read(Paths{Cgroup: none, Root: none, Meminfo: none}); l != (Limits{}) || l.Memory() != 0 || l.GoLimit(7, 8) != 0 {
		t.Fatalf("nothing: %+v", l)
	}
	tr, p := newTree(t, "garbage\n::\n1:\n")
	tr.write("meminfo", "MemTotal: many kB\n")
	tr.write("fs/memory.max", "1\n")
	check(t, "garbage", p, Limits{})
}

// A limit above MemTotal limits nothing; at or under it, the less of High
// and Max is the limit: under lxcfs MemTotal is the container's
// memory.max, and MemoryMax=100% the host's memory.
func TestLimit(t *testing.T) {
	const host = 4 << 30
	for _, c := range []struct {
		l             Limits
		limit, memory int64
	}{
		{Limits{MemTotal: host}, 0, host},
		{Limits{Max: host, MemTotal: host}, host, host},     // lxcfs, MemoryMax=100%
		{Limits{Max: host + 4096, MemTotal: host}, 0, host}, // above it
		{Limits{Max: host, High: host / 8 * 7, MemTotal: host}, host / 8 * 7, host / 8 * 7},
		{Limits{Max: 8 << 30, High: 8 << 30, MemTotal: host}, 0, host},
		{Limits{Max: 1 << 30, MemTotal: host}, 1 << 30, 1 << 30},
		{Limits{High: 1 << 30, MemTotal: host}, 1 << 30, 1 << 30},
		{Limits{Max: 1 << 30, High: 896 * mib, MemTotal: host}, 896 * mib, 896 * mib},
		{Limits{Max: 512 * mib, High: 896 * mib, MemTotal: host}, 512 * mib, 512 * mib},
		{Limits{Max: 8 << 30, High: 1 << 30, MemTotal: host}, 1 << 30, 1 << 30},
		{Limits{Max: 1 << 30}, 1 << 30, 1 << 30}, // MemTotal unknown
	} {
		if got := c.l.Limit(); got != c.limit {
			t.Errorf("%+v: limit %d, want %d", c.l, got, c.limit)
		}
		if got := c.l.Memory(); got != c.memory {
			t.Errorf("%+v: memory %d, want %d", c.l, got, c.memory)
		}
	}
}

// The Go limit: num/den of the less of High and 15/16 of Max, 64 MiB at
// least, none without a limit below the host.
func TestGoLimit(t *testing.T) {
	const host = 16 << 30
	for _, c := range []struct {
		l           Limits
		back, front int64
	}{
		{Limits{MemTotal: host}, 0, 0},
		{Limits{Max: 32 << 30, MemTotal: host}, 0, 0},
		{Limits{Max: 1 << 30, MemTotal: host}, 1 << 30 / 16 * 15 / 8 * 7, 1 << 30 / 16 * 15 / 4 * 3}, // 840, 720 MiB
		{Limits{Max: 1 << 30, High: 896 * mib, MemTotal: host}, 784 * mib, 672 * mib},
		{Limits{Max: 512 * mib, High: 1 << 30, MemTotal: host}, 420 * mib, 360 * mib},
		{Limits{High: 512 * mib, MemTotal: host}, 448 * mib, 384 * mib},
		{Limits{Max: 64 * mib, MemTotal: host}, 64 * mib, 64 * mib}, // the floor
	} {
		if got := c.l.GoLimit(7, 8); got != c.back {
			t.Errorf("%+v: backend %d MiB, want %d MiB", c.l, got/mib, c.back/mib)
		}
		if got := c.l.GoLimit(3, 4); got != c.front {
			t.Errorf("%+v: front %d MiB, want %d MiB", c.l, got/mib, c.front/mib)
		}
	}
}

// SetGoLimit sets the limit when GOMEMLIMIT is unset and a cgroup's limit
// is below the host; else nothing.
func TestSetGoLimit(t *testing.T) {
	limited := Limits{Max: 1 << 30, High: 896 * mib, MemTotal: 16 << 30}
	for _, c := range []struct {
		name string
		env  string
		l    Limits
		want int64
	}{
		{"unset", "", limited, 784 * mib},
		{"set", "300MiB", limited, 0},
		{"off", "off", limited, 0},
		{"no cgroup limit", "", Limits{MemTotal: 16 << 30}, 0},
		{"nothing known", "", Limits{}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var set []int64
			getenv := func(k string) string {
				if k == "GOMEMLIMIT" {
					return c.env
				}
				return ""
			}
			got := SetGoLimit(c.l, 7, 8, getenv, func(n int64) int64 { set = append(set, n); return 0 })
			if got != c.want {
				t.Fatalf("returned %d, want %d", got, c.want)
			}
			if c.want == 0 && len(set) != 0 || c.want != 0 && (len(set) != 1 || set[0] != c.want) {
				t.Fatalf("set %v, want %d", set, c.want)
			}
		})
	}
}
