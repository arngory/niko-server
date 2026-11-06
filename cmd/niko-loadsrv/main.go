//go:build linux

// niko-loadsrv is niko-server front|backend for load tests only (not
// shipped): the same nikoserver.RunFront/RunBackend, plus, with
// NIKO_PPROF=host:port, net/http/pprof and /stats (MemStats, goroutines,
// KCP SNMP, VmRSS/VmHWM, rusage) for the load generator.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/arngory/niko-server/nikoserver"
	"github.com/xtaci/kcp-go/v5"
)

func main() {
	if len(os.Args) != 4 || os.Args[2] != "-c" {
		fmt.Fprintln(os.Stderr, "usage: niko-loadsrv front|backend -c FILE")
		os.Exit(1)
	}
	config, errs, err := nikoserver.Load(os.Args[3])
	if err != nil || len(errs) > 0 {
		fmt.Fprintln(os.Stderr, "config:", err, errs)
		os.Exit(1)
	}
	if addr := os.Getenv("NIKO_PPROF"); addr != "" {
		http.HandleFunc("/stats", stats)
		http.HandleFunc("/gc", func(w http.ResponseWriter, _ *http.Request) {
			runtime.GC()
			debug.FreeOSMemory()
			fmt.Fprintln(w, "ok")
		})
		go func() { fmt.Fprintln(os.Stderr, http.ListenAndServe(addr, nil)) }()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch c := config.(type) {
	case *nikoserver.FrontConfig:
		err = nikoserver.RunFront(ctx, c, nikoserver.NewLogger(c.Log.Level, nil))
	case *nikoserver.BackendConfig:
		err = nikoserver.RunBackend(ctx, c, nikoserver.NewLogger(c.Log.Level, nil))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "niko-loadsrv:", err)
		os.Exit(2)
	}
}

type Stats struct {
	HeapAlloc, HeapInuse, HeapSys, HeapIdle, HeapReleased uint64
	StackInuse, Sys, TotalAlloc, Mallocs, Frees           uint64
	NumGC                                                 uint32
	PauseTotalNs                                          uint64
	Goroutines                                            int
	VmRSS, VmHWM                                          uint64 // bytes
	UtimeNs, StimeNs                                      int64
	KCPCurrEstab, KCPPassiveOpens, KCPInPkts, KCPOutPkts  uint64
	KCPInErrs, KCPRetransSegs, KCPLostSegs                uint64
}

func stats(w http.ResponseWriter, _ *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := Stats{HeapAlloc: m.HeapAlloc, HeapInuse: m.HeapInuse, HeapSys: m.HeapSys, HeapIdle: m.HeapIdle,
		HeapReleased: m.HeapReleased, StackInuse: m.StackInuse, Sys: m.Sys, TotalAlloc: m.TotalAlloc,
		Mallocs: m.Mallocs, Frees: m.Frees, NumGC: m.NumGC, PauseTotalNs: m.PauseTotalNs,
		Goroutines: runtime.NumGoroutine()}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseUint(f[1], 10, 64)
				switch f[0] {
				case "VmRSS:":
					s.VmRSS = v << 10
				case "VmHWM:":
					s.VmHWM = v << 10
				}
			}
		}
	}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		s.UtimeNs = ru.Utime.Nano()
		s.StimeNs = ru.Stime.Nano()
	}
	snmp := kcp.DefaultSnmp.Copy()
	s.KCPCurrEstab, s.KCPPassiveOpens, s.KCPInPkts, s.KCPOutPkts = snmp.CurrEstab, snmp.PassiveOpens, snmp.InPkts, snmp.OutPkts
	s.KCPInErrs, s.KCPRetransSegs, s.KCPLostSegs = snmp.InErrs, snmp.RetransSegs, snmp.LostSegs
	json.NewEncoder(w).Encode(s)
}
