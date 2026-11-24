package nikoserver

import (
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/arngory/niko-server/nikoserver/memlimit"
)

// procMemory is the process's memory as its start found it: its cgroup's
// limits and the host's MemTotal (raycontrol docs/spec/memory-v1.md). The
// budgets of Hysteria2 (hyMemBudget) and of Yggdrasil's exits
// (yggExitBudget, yggExitsBound) come from it, as the Go memory limit
// does (SetMemoryLimit).
var procMemory = sync.OnceValue(func() memlimit.Limits { return memlimit.Read(memlimit.System) })

// The Go memory limit's share of the cgroup's limit (memlimit.GoLimit):
// 7/8 for a backend, 3/4 for the front, whose sockets' queues (those of
// unix sockets to the backends are charged nowhere, TCP's and UDP's to the
// cgroup) the runtime does not see.
const (
	goLimitBackendNum, goLimitBackendDen = 7, 8
	goLimitFrontNum, goLimitFrontDen     = 3, 4
)

// SetMemoryLimit gives the Go runtime a memory limit from the process's
// cgroup at its start, the front's or a backend's share of it, when
// GOMEMLIMIT is not set and the cgroup has a limit below the host's
// memory; one line in the log says so, with the figures. Without such a
// limit it does nothing: a soft limit at the host's memory would do
// nothing either. Go (1.27) reads cpu.max of its cgroup, not memory.max.
func SetMemoryLimit(log *Logger, front bool) {
	setMemoryLimit(log, front, procMemory(), os.Getenv, debug.SetMemoryLimit)
}

func setMemoryLimit(log *Logger, front bool, l memlimit.Limits, getenv func(string) string, set func(int64) int64) int64 {
	num, den, role := int64(goLimitBackendNum), int64(goLimitBackendDen), "backend"
	if front {
		num, den, role = goLimitFrontNum, goLimitFrontDen, "front"
	}
	n := memlimit.SetGoLimit(l, num, den, getenv, set)
	if n > 0 && log != nil {
		log.Infof("memory: cgroup's memory.max %s, memory.high %s, host %d MiB: Go memory limit %d MiB (the %s's %d/%d of the less of high and 15/16 of max, 64 MiB at least)",
			mibOrNone(l.Max, l), mibOrNone(l.High, l), l.MemTotal>>20, n>>20, role, num, den)
	}
	return n
}

// mibOrNone is n in MiB, or "none" when it limits nothing below the host.
func mibOrNone(n int64, l memlimit.Limits) string {
	if (memlimit.Limits{Max: n, MemTotal: l.MemTotal}).Limit() == 0 {
		return "none"
	}
	return strconv.FormatInt(n>>20, 10) + " MiB"
}
