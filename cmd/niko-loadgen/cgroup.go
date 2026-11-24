//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// newCgroup makes a memory cgroup of its own, name, with a limit of limit
// bytes and no swap, for a process to start in (startIn): the process
// then reads the limit at its start, as a unit's does (raycontrol
// memory-v1). self is /proc/self/cgroup's content, root the cgroup mount.
//
// cgroup v2 where the hierarchy at root has the memory controller: a
// sibling of the loadgen's own cgroup (a cgroup with processes may not
// have children with controllers), memory.max and memory.swap.max, the
// controller enabled in the parent's cgroup.subtree_control when it is not
// yet. Else cgroup v1's memory hierarchy (a hybrid's v2 at root/unified
// has no memory controller): a child of the loadgen's own,
// memory.limit_in_bytes and memory.memsw.limit_in_bytes.
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
