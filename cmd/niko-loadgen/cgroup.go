//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// newCgroup makes a memory cgroup of its own, name, with a limit of limit
// bytes and no swap, for a process to start in (startIn): the process
// then reads the limit at its start, as a unit's does (raycontrol
// memory-v1). self is /proc/self/cgroup's content, root the cgroup mount.
// Under systemd the loadgen asks it instead (systemdScope); this is for
// the hosts and containers without.
//
// cgroup v2 where the hierarchy at root has the memory controller: a
// sibling of the loadgen's own cgroup (a cgroup with processes may not
// have children with controllers), memory.max and memory.swap.max, the
// controller enabled in the parent's cgroup.subtree_control when it is not
// yet. Its own cgroup the root ("0::/", a cgroup namespace's: a container)
// is an error: there is no sibling, and a child would take the controller
// from a root that has processes. Else cgroup v1's memory hierarchy (a
// hybrid's v2 at root/unified has no memory controller): a child of the
// loadgen's own, memory.limit_in_bytes and memory.memsw.limit_in_bytes.
func newCgroup(self, root, name string, limit int64) (dir string, v2 bool, err error) {
	var p2, p1 string
	found2, found1 := false, false
	for line := range strings.SplitSeq(self, "\n") {
		f := strings.SplitN(line, ":", 3)
		switch {
		case len(f) < 3:
		case f[0] == "0" && f[1] == "":
			p2, found2 = path.Clean("/"+f[2]), true
		case slices.Contains(strings.Split(f[1], ","), "memory"):
			p1, found1 = path.Clean("/"+f[2]), true
		}
	}
	n := strconv.FormatInt(limit, 10)
	if b, err := os.ReadFile(filepath.Join(root, "cgroup.controllers")); err == nil && found2 && slices.Contains(strings.Fields(string(b)), "memory") {
		if p2 == "/" {
			return "", true, errors.New("cgroup v2: the loadgen's own cgroup is the root of its namespace (a container's): start it in a cgroup of its own below the root, or under systemd-run")
		}
		parent := filepath.Join(root, path.Dir(p2))
		if b, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers")); err != nil || !slices.Contains(strings.Fields(string(b)), "memory") {
			return "", true, fmt.Errorf("cgroup v2: no memory controller in %s", parent)
		}
		if b, _ := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control")); !slices.Contains(strings.Fields(string(b)), "memory") {
			if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+memory"), 0o644); err != nil {
				return "", true, fmt.Errorf("cgroup v2: enabling memory in %s: %v", parent, err)
			}
		}
		dir = filepath.Join(parent, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", true, err
		}
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(n), 0o644); err != nil {
			os.Remove(dir)
			return "", true, err
		}
		os.WriteFile(filepath.Join(dir, "memory.swap.max"), []byte("0"), 0o644) // none without swap accounting
		return dir, true, nil
	}
	if !found1 {
		return "", false, errors.New("no memory cgroup: neither v2 with the memory controller nor v1's memory hierarchy")
	}
	dir = filepath.Join(root, "memory", p1, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"), []byte(n), 0o644); err != nil {
		os.Remove(dir)
		return "", false, err
	}
	os.WriteFile(filepath.Join(dir, "memory.memsw.limit_in_bytes"), []byte(n), 0o644) // none without swap accounting
	return dir, false, nil
}

// startIn is the command that runs args in the cgroup dir from their
// start: a shell that moves itself there and execs them, the same pid.
func startIn(dir string, args ...string) []string {
	return append([]string{"sh", "-c", `echo $$ >"$1/cgroup.procs" && shift && exec "$@"`, "sh", dir}, args...)
}

// systemdScope is the command that runs args in a transient scope of
// systemd's, name, with MemoryMax limit and no swap, when systemd runs the
// host (PID 1, /run/systemd/system) and systemd-run is there; else nil.
// systemd-run execs args in the scope (the same pid), and the scope goes
// when they end.
func systemdScope(name string, limit int64, args ...string) []string {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return nil
	}
	return append([]string{"systemd-run", "--scope", "--quiet", "--collect", "--unit", name,
		"-p", "MemoryMax=" + strconv.FormatInt(limit, 10), "-p", "MemorySwapMax=0", "--"}, args...)
}

// cgroupOf is the memory cgroup of pid, as /proc/<pid>/cgroup says, under
// the mount at root: v2's when it has the memory controller, else v1's.
func cgroupOf(pid int, root string) (dir string, v2 bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", false
	}
	ctl, _ := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.SplitN(line, ":", 3)
		switch {
		case len(f) < 3:
		case f[0] == "0" && f[1] == "" && slices.Contains(strings.Fields(string(ctl)), "memory"):
			return filepath.Join(root, f[2]), true
		case slices.Contains(strings.Split(f[1], ","), "memory"):
			dir = filepath.Join(root, "memory", f[2])
		}
	}
	return dir, false
}

// atExit and cleanup: what the loadgen undoes however it ends, at its
// end, at must's failure or at SIGINT and SIGTERM (os.Exit runs no
// defers): the servers stopped, the cgroups removed. Last first, once.
var exits struct {
	sync.Mutex
	fs   []func()
	done bool
}

func atExit(f func()) {
	exits.Lock()
	defer exits.Unlock()
	exits.fs = append(exits.fs, f)
}

func cleanup() {
	exits.Lock()
	fs := exits.fs
	if exits.done {
		fs = nil
	}
	exits.done = true
	exits.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
}

// oomKills is the cgroup's count of processes the OOM killer killed in
// it: oom_kill of memory.events (v2) or of memory.oom_control (v1, Linux
// 4.13 and later); -1 when unknown.
func oomKills(dir string, v2 bool) int64 {
	file := "memory.oom_control"
	if v2 {
		file = "memory.events"
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return -1
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return n
			}
		}
	}
	return -1
}
