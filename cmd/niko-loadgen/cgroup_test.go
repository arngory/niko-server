//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cgroup v2: a sibling of the loadgen's own cgroup, the memory controller
// enabled in the parent when it is not, memory.max and no swap.
func TestNewCgroupV2(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cgroup.controllers"), "cpuset cpu io memory pids\n")
	writeFile(t, filepath.Join(root, "user.slice/cgroup.controllers"), "cpu memory pids\n")
	writeFile(t, filepath.Join(root, "user.slice/cgroup.subtree_control"), "cpu\n")
	dir, v2, err := newCgroup("0::/user.slice/session-1.scope\n", root, "niko-load-1", 256<<20)
	if err != nil || !v2 || dir != filepath.Join(root, "user.slice/niko-load-1") {
		t.Fatalf("%s, v2 %v, %v", dir, v2, err)
	}
	if got := readFile(t, filepath.Join(dir, "memory.max")); got != "268435456" {
		t.Fatalf("memory.max %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "memory.swap.max")); got != "0" {
		t.Fatalf("memory.swap.max %q", got)
	}
	if got := readFile(t, filepath.Join(root, "user.slice/cgroup.subtree_control")); got != "+memory" {
		t.Fatalf("subtree_control written %q", got)
	}
	// Enabled already: left alone. The root's own: a child of the root.
	writeFile(t, filepath.Join(root, "cgroup.subtree_control"), "cpu memory\n")
	dir, _, err = newCgroup("0::/\n", root, "niko-load-2", 128<<20)
	if err != nil || dir != filepath.Join(root, "niko-load-2") {
		t.Fatalf("%s, %v", dir, err)
	}
	if got := readFile(t, filepath.Join(root, "cgroup.subtree_control")); got != "cpu memory\n" {
		t.Fatalf("subtree_control rewritten: %q", got)
	}
	// No memory controller in the parent: an error, nothing made.
	writeFile(t, filepath.Join(root, "system.slice/cgroup.controllers"), "cpu pids\n")
	if _, _, err := newCgroup("0::/system.slice/x.service\n", root, "niko-load-3", 128<<20); err == nil || !strings.Contains(err.Error(), "no memory controller") {
		t.Fatalf("%v", err)
	}
	// The kills, from memory.events.
	writeFile(t, filepath.Join(dir, "memory.events"), "low 0\nhigh 3\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n")
	if n := oomKills(dir, true); n != 1 {
		t.Fatalf("oom_kill %d", n)
	}
}

// cgroup v1 (a hybrid host's, its v2 at unified without the memory
// controller): a child of the loadgen's own in the memory hierarchy.
func TestNewCgroupV1(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "unified/cgroup.controllers"), "")
	self := "9:name=systemd:/\n4:memory:/process_api/abc\n1:cpu:/\n0::/\n"
	dir, v2, err := newCgroup(self, root, "niko-load-1", 256<<20)
	if err != nil || v2 || dir != filepath.Join(root, "memory/process_api/abc/niko-load-1") {
		t.Fatalf("%s, v2 %v, %v", dir, v2, err)
	}
	for _, f := range []string{"memory.limit_in_bytes", "memory.memsw.limit_in_bytes"} {
		if got := readFile(t, filepath.Join(dir, f)); got != "268435456" {
			t.Fatalf("%s %q", f, got)
		}
	}
	writeFile(t, filepath.Join(dir, "memory.oom_control"), "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n")
	if n := oomKills(dir, false); n != 2 {
		t.Fatalf("oom_kill %d", n)
	}
	if n := oomKills(filepath.Join(root, "none"), false); n != -1 {
		t.Fatalf("oom_kill unknown: %d", n)
	}
	// Neither: an error.
	if _, _, err := newCgroup("0::/\n", root, "niko-load-2", 256<<20); err == nil {
		t.Fatal("a cgroup made without the memory controller")
	}
}

// The command starts in the cgroup, and runs what it was given with its
// arguments, the same process.
func TestStartIn(t *testing.T) {
	dir := t.TempDir()
	args := startIn(dir, "sh", "-c", `echo "$$ $1" >"$0"`, filepath.Join(dir, "out"), "a b")
	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	procs := strings.TrimSpace(readFile(t, filepath.Join(dir, "cgroup.procs")))
	out := strings.TrimSpace(readFile(t, filepath.Join(dir, "out")))
	if out != procs+" a b" {
		t.Fatalf("cgroup.procs %q, the command wrote %q", procs, out)
	}
}
