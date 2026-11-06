//go:build linux

// niko-loadgen load-tests the DNS path of niko-server (not shipped): it
// writes a front and a dnstt backend config with everything on, runs both
// as separate processes (niko-loadsrv, the same RunFront/RunBackend) pinned
// to some CPUs with a GOMAXPROCS, drives one scenario at them and samples
// their CPU, RSS and Go heap.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"www.bamsoftware.com/git/dnstt.git/noise"
)

var (
	flagDir      = flag.String("dir", "", "work directory (configs, logs, profiles)")
	flagSrv      = flag.String("srv", "", "niko-loadsrv binary")
	flagAuth     = flag.String("auth", "required", "dnstt auth: off|optional|required")
	flagDevices  = flag.Int("devices", 100, "devices in the auth keys file")
	flagSeal     = flag.String("seal", "required", "dnstt seal: off|optional|required")
	flagSealKeys = flag.Int("sealkeys", 4, "seal keys in the file (1..4)")
	flagProbe    = flag.Bool("probe", true, "front answers dnsprobe-v1")
	flagApex     = flag.Bool("apex", true, "front answers the apex (ns)")
	flagProcs    = flag.Int("procs", 1, "GOMAXPROCS of the server processes")
	flagCPUs     = flag.String("cpus", "0", "taskset CPU list of the server processes")
	flagMemLimit = flag.String("memlimit", "", "GOMEMLIMIT of the server processes")
	flagCgroup   = flag.Int64("cgroup", 0, "memory cgroup limit (bytes) for the backend process; 0: none")
	flagScenario = flag.String("scenario", "legit", "legit|flood|garbage|probe|apex|refused|idle")
	flagDur      = flag.Duration("d", 30*time.Second, "load duration")
	flagAfter    = flag.Duration("after", 0, "keep sampling this long after the load")
	flagRate     = flag.Float64("rate", 0, "queries per second (0: as fast as the senders go)")
	flagSenders  = flag.Int("senders", 4, "sender goroutines (floods)")
	flagN        = flag.Int("n", 100, "legit: sessions")
	flagVariant  = flag.String("variant", "ack", "flood: poll|ack|push64k|pushbad")
	flagIDs      = flag.Int("ids", 0, "flood: stop after this many distinct ClientIDs (0: no limit)")
	flagSealed   = flag.Bool("sealed", false, "garbage: sealed with the zone key (an attacker with a link)")
	flagLarge    = flag.Bool("large", true, "probe: large probes")
	flagValid    = flag.Bool("valid", true, "probe: valid MAC")
	flagQType    = flag.Int("qtype", 6, "apex: query type")
	flagEDNS     = flag.Int("edns", 1232, "EDNS size of the queries (0: none)")
	flagRetry    = flag.Duration("retry", 0, "legit: the resolver asks again after this (0: never)")
	flagOut      = flag.String("out", "run", "label for output files")
	flagCPUProf  = flag.Int("cpuprof", 0, "seconds of CPU profile of the backend during the load")
	flagHeap     = flag.Bool("heap", true, "save heap profiles at the end of the load and of after")
	flagSample   = flag.Duration("sample", 500*time.Millisecond, "sampling period")
	flagStopRSS  = flag.Int64("stoprss", 3<<30, "stop the load when a server's RSS passes this")
)

const zone = "t.example.com"

type node struct {
	dir                   string
	dnsAddr               string
	sealKey               []byte
	probeKey              []byte
	devices               [][32]byte
	privkey               []byte
	inner                 string
	front, backend        *proc
	frontPprof, backPprof string
}

type proc struct {
	role  string
	cmd   *exec.Cmd
	pprof string
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "niko-loadgen:", err)
		os.Exit(1)
	}
}

func randKey() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func freePort(network string) string {
	if network == "udp" {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		must(err)
		defer c.Close()
		return c.LocalAddr().String()
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().String()
}

func writeJSON(path string, v any) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	must(os.WriteFile(path, raw, 0o600))
}

// setup writes keys and configs, starts the inner server, the backend and the front.
func setup() *node {
	n := &node{dir: *flagDir}
	must(os.MkdirAll(filepath.Join(n.dir, "dns"), 0o710))
	uid := os.Getuid()
	n.privkey, _ = noise.GeneratePrivkey()
	keyFile := filepath.Join(n.dir, "noise.key")
	must(os.WriteFile(keyFile, []byte(hex.EncodeToString(n.privkey)+"\n"), 0o600))
	var authKeys strings.Builder
	for i := range *flagDevices {
		var k [32]byte
		copy(k[:], randKey())
		n.devices = append(n.devices, k)
		fmt.Fprintf(&authKeys, "dev%04d %s\n", i, hex.EncodeToString(k[:]))
	}
	authFile := filepath.Join(n.dir, "auth.keys")
	must(os.WriteFile(authFile, []byte(authKeys.String()), 0o600))
	var sealKeys strings.Builder
	for i := range *flagSealKeys {
		k := randKey()
		if i == 0 {
			n.sealKey = k
		}
		sealKeys.WriteString(hex.EncodeToString(k) + "\n")
	}
	sealFile := filepath.Join(n.dir, "seal.keys")
	must(os.WriteFile(sealFile, []byte(sealKeys.String()), 0o600))
	n.probeKey = randKey()
	probeFile := filepath.Join(n.dir, "dnsprobe.key")
	must(os.WriteFile(probeFile, []byte(hex.EncodeToString(n.probeKey)+"\n"), 0o600))

	n.inner = filepath.Join(n.dir, "i.sock")
	os.Remove(n.inner)
	startInner(n.inner)

	socket := filepath.Join(n.dir, "dns", "p.sock")
	n.dnsAddr = freePort("udp")
	n.frontPprof, n.backPprof = freePort("tcp"), freePort("tcp")
	options := map[string]any{"zone": zone, "private_key_file": keyFile}
	if *flagAuth != "off" {
		options["auth"], options["auth_keys_file"] = *flagAuth, authFile
	}
	if *flagSeal != "off" {
		options["seal"], options["seal_key_file"] = *flagSeal, sealFile
	}
	backendPath := filepath.Join(n.dir, "backend.json")
	writeJSON(backendPath, map[string]any{
		"schema": 1, "role": "backend", "kind": "dnstt", "log": map[string]string{"level": "warn"},
		"socket": socket, "front_uid": uid, "options": options, "inner": n.inner,
	})
	z := map[string]any{"zone": zone, "backend": "dns"}
	frontDNS := map[string]any{"listen": []string{n.dnsAddr}}
	if *flagProbe {
		z["probe"] = true
		frontDNS["probe_key_file"] = probeFile
		if *flagSeal != "off" {
			z["seal_pad"] = true
		}
	}
	if *flagApex {
		z["ns"] = []string{"ns1.example.com", "ns2.example.com"}
	}
	frontDNS["zones"] = []any{z}
	frontPath := filepath.Join(n.dir, "front.json")
	writeJSON(frontPath, map[string]any{
		"schema": 1, "role": "front", "log": map[string]string{"level": "warn"},
		"backends": map[string]any{"dns": map[string]any{"socket": socket, "mode": "packet", "uid": uid}},
		"dns":      frontDNS,
	})
	n.backend = start("backend", backendPath, n.backPprof)
	if *flagCgroup > 0 {
		cgroupLimit(n.backend.cmd.Process.Pid, *flagCgroup)
	}
	time.Sleep(300 * time.Millisecond)
	n.front = start("front", frontPath, n.frontPprof)
	time.Sleep(500 * time.Millisecond)
	return n
}

func start(role, config, pprof string) *proc {
	cmd := exec.Command("taskset", "-c", *flagCPUs, *flagSrv, role, "-c", config)
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(*flagProcs), "NIKO_PPROF="+pprof)
	if *flagMemLimit != "" {
		cmd.Env = append(cmd.Env, "GOMEMLIMIT="+*flagMemLimit)
	}
	logf, err := os.Create(filepath.Join(*flagDir, *flagOut+"."+role+".log"))
	must(err)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	must(cmd.Start())
	return &proc{role: role, cmd: cmd, pprof: pprof}
}

// cgroupLimit puts pid in a memory cgroup (v1) of its own with a limit.
func cgroupLimit(pid int, limit int64) {
	self, _ := os.ReadFile("/proc/self/cgroup")
	base := "/sys/fs/cgroup/memory"
	for _, line := range strings.Split(string(self), "\n") {
		if f := strings.SplitN(line, ":", 3); len(f) == 3 && f[1] == "memory" {
			base = filepath.Join(base, f[2])
		}
	}
	dir := filepath.Join(base, "niko-load-"+strconv.Itoa(pid))
	must(os.MkdirAll(dir, 0o755))
	must(os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"), []byte(strconv.FormatInt(limit, 10)), 0o644))
	os.WriteFile(filepath.Join(dir, "memory.memsw.limit_in_bytes"), []byte(strconv.FormatInt(limit, 10)), 0o644)
	must(os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644))
	fmt.Printf("backend pid %d in %s, limit %d MiB\n", pid, dir, limit>>20)
}

func (p *proc) stop() {
	if p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { p.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			p.cmd.Process.Kill()
		}
	}
}

func (p *proc) alive() bool {
	if p.cmd.Process == nil {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.cmd.Process.Pid))
	if err != nil {
		return false
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return len(f) > 0 && f[0] != "Z" && f[0] != "X"
}

// Stats is niko-loadsrv's /stats.
type Stats struct {
	HeapAlloc, HeapInuse, HeapSys, HeapIdle, HeapReleased uint64
	StackInuse, Sys, TotalAlloc, Mallocs, Frees           uint64
	NumGC                                                 uint32
	PauseTotalNs                                          uint64
	Goroutines                                            int
	VmRSS, VmHWM                                          uint64
	UtimeNs, StimeNs                                      int64
	KCPCurrEstab, KCPPassiveOpens, KCPInPkts, KCPOutPkts  uint64
	KCPInErrs, KCPRetransSegs, KCPLostSegs                uint64
}

func (s Stats) cpu() float64 { return float64(s.UtimeNs+s.StimeNs) / 1e9 }

var httpc = &http.Client{Timeout: 5 * time.Second}

func (p *proc) stats() (Stats, error) {
	var s Stats
	r, err := httpc.Get("http://" + p.pprof + "/stats")
	if err != nil {
		return s, err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&s)
	return s, err
}

func (p *proc) gc() {
	if r, err := httpc.Get("http://" + p.pprof + "/gc"); err == nil {
		r.Body.Close()
	}
}

func (p *proc) save(path, what string) {
	c := &http.Client{Timeout: 120 * time.Second}
	r, err := c.Get("http://" + p.pprof + "/debug/pprof/" + what)
	if err != nil {
		fmt.Println("profile:", err)
		return
	}
	defer r.Body.Close()
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	io.Copy(f, r.Body)
}

// sampler keeps the series and the peaks of both processes.
type sampler struct {
	mu    sync.Mutex
	csv   *os.File
	start time.Time
	peak  map[string]*Stats
	last  map[string]Stats
	first map[string]Stats
}

func newSampler(path string) *sampler {
	f, err := os.Create(path)
	must(err)
	fmt.Fprintln(f, "t,role,rss_mib,hwm_mib,heapinuse_mib,heapsys_mib,stack_mib,goroutines,cpu_s,kcp_estab,kcp_opens,mallocs,totalalloc_mib,numgc,sent,answered")
	return &sampler{csv: f, start: time.Now(), peak: map[string]*Stats{}, last: map[string]Stats{}, first: map[string]Stats{}}
}

var sent, answered atomic.Uint64
var processed uint64 // queries the front read, for the per-query costs

func (s *sampler) sample(ps ...*proc) {
	for _, p := range ps {
		st, err := p.stats()
		if err != nil {
			continue
		}
		s.mu.Lock()
		if _, ok := s.first[p.role]; !ok {
			s.first[p.role] = st
		}
		s.last[p.role] = st
		pk := s.peak[p.role]
		if pk == nil {
			pk = &Stats{}
			s.peak[p.role] = pk
		}
		pk.VmRSS = max(pk.VmRSS, st.VmRSS)
		pk.VmHWM = max(pk.VmHWM, st.VmHWM)
		pk.HeapInuse = max(pk.HeapInuse, st.HeapInuse)
		pk.HeapSys = max(pk.HeapSys, st.HeapSys)
		pk.StackInuse = max(pk.StackInuse, st.StackInuse)
		pk.Goroutines = max(pk.Goroutines, st.Goroutines)
		pk.KCPCurrEstab = max(pk.KCPCurrEstab, st.KCPCurrEstab)
		fmt.Fprintf(s.csv, "%.1f,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%d,%.2f,%d,%d,%d,%.1f,%d,%d,%d\n",
			time.Since(s.start).Seconds(), p.role, mib(st.VmRSS), mib(st.VmHWM), mib(st.HeapInuse), mib(st.HeapSys),
			mib(st.StackInuse), st.Goroutines, st.cpu(), st.KCPCurrEstab, st.KCPPassiveOpens, st.Mallocs, mib(st.TotalAlloc), st.NumGC,
			sent.Load(), answered.Load())
		s.mu.Unlock()
	}
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }

func (s *sampler) run(stop <-chan struct{}, ps ...*proc) {
	t := time.NewTicker(*flagSample)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.sample(ps...)
		}
	}
}

func (s *sampler) snapshot(role string) Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last[role]
}

func (s *sampler) peakOf(role string) Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.peak[role]; p != nil {
		return *p
	}
	return Stats{}
}

func report(phase string, d time.Duration, before, after map[string]Stats, peaks map[string]Stats, q0, a0, q1, a1 uint64) {
	queries, answers := q1-q0, a1-a0
	fmt.Printf("== %s: %s, sent %d (%.0f/s), answered %d (%.0f/s, %.1f%%)\n", phase, d.Round(time.Second),
		queries, float64(queries)/d.Seconds(), answers, float64(answers)/d.Seconds(), 100*float64(answers)/max(1, float64(queries)))
	var totalCPU float64
	for _, role := range []string{"front", "backend"} {
		b, a, pk := before[role], after[role], peaks[role]
		cpu := a.cpu() - b.cpu()
		totalCPU += cpu
		perQ := 0.0
		if processed > 0 {
			perQ = cpu / float64(processed) * 1e6
		}
		fmt.Printf("   %-7s cpu %.2fs (%.0f%% of a core, %.2f us/query read by the front); RSS now %.1f MiB, peak %.1f MiB (VmHWM %.1f); heap inuse now %.1f, peak %.1f MiB; stack %.1f MiB; goroutines now %d peak %d; KCP sessions now %d peak %d (opened %d); allocs %.1f/query, %.0f B/query; GCs %d\n",
			role, cpu, 100*cpu/d.Seconds(), perQ, mib(a.VmRSS), mib(pk.VmRSS), mib(a.VmHWM), mib(a.HeapInuse), mib(pk.HeapInuse), mib(a.StackInuse),
			a.Goroutines, pk.Goroutines, a.KCPCurrEstab, pk.KCPCurrEstab, a.KCPPassiveOpens-b.KCPPassiveOpens,
			float64(a.Mallocs-b.Mallocs)/max(1, float64(processed)), float64(a.TotalAlloc-b.TotalAlloc)/max(1, float64(processed)), a.NumGC-b.NumGC)
	}
	if processed > 0 {
		fmt.Printf("   total server cpu %.2fs (%.0f%% of a core), %.2f us per query read by the front\n", totalCPU, 100*totalCPU/d.Seconds(), totalCPU/float64(processed)*1e6)
	}
}

func main() {
	flag.Parse()
	if *flagDir == "" || *flagSrv == "" {
		must(fmt.Errorf("-dir and -srv"))
	}
	os.RemoveAll(*flagDir)
	n := setup()
	defer n.front.stop()
	defer n.backend.stop()
	smp := newSampler(filepath.Join(*flagDir, *flagOut+".csv"))
	stopSampling := make(chan struct{})
	smp.sample(n.front, n.backend)
	go smp.run(stopSampling, n.front, n.backend)
	fmt.Printf("scenario %s: auth=%s (%d devices) seal=%s (%d keys) probe=%v apex=%v GOMAXPROCS=%d cpus=%s GOMEMLIMIT=%q\n",
		*flagScenario, *flagAuth, *flagDevices, *flagSeal, *flagSealKeys, *flagProbe, *flagApex, *flagProcs, *flagCPUs, *flagMemLimit)

	before := map[string]Stats{}
	for _, p := range []*proc{n.front, n.backend} {
		st, err := p.stats()
		must(err)
		before[p.role] = st
	}
	if *flagCPUProf > 0 {
		go n.backend.save(filepath.Join(*flagDir, *flagOut+".backend.cpu.pprof"), "profile?seconds="+strconv.Itoa(*flagCPUProf))
		go n.front.save(filepath.Join(*flagDir, *flagOut+".front.cpu.pprof"), "profile?seconds="+strconv.Itoa(*flagCPUProf))
	}
	q0, a0 := sent.Load(), answered.Load()
	drops0 := udpDrops(n.dnsAddr)
	t0 := time.Now()
	stopLoad := make(chan struct{})
	go func() { // the RSS guard
		for {
			select {
			case <-stopLoad:
				return
			case <-time.After(200 * time.Millisecond):
			}
			for _, role := range []string{"front", "backend"} {
				if s := smp.snapshot(role); int64(s.VmRSS) > *flagStopRSS {
					fmt.Printf("!! %s RSS %.0f MiB over -stoprss: load stopped at %s\n", role, mib(s.VmRSS), time.Since(t0).Round(time.Second))
					close(stopLoad)
					return
				}
			}
			if !n.backend.alive() {
				fmt.Printf("!! backend died at %s\n", time.Since(t0).Round(time.Second))
				close(stopLoad)
				return
			}
		}
	}()
	runScenario(n, stopLoad)
	d := time.Since(t0)
	smp.sample(n.front, n.backend)
	after := map[string]Stats{"front": smp.snapshot("front"), "backend": smp.snapshot("backend")}
	peaks := map[string]Stats{"front": smp.peakOf("front"), "backend": smp.peakOf("backend")}
	drops := udpDrops(n.dnsAddr) - drops0
	fmt.Printf("== front socket: %d queries dropped by the kernel, %d read by the front (%.0f/s)\n", drops, sent.Load()-q0-drops, float64(sent.Load()-q0-drops)/d.Seconds())
	processed = sent.Load() - q0 - drops
	report("load", d, before, after, peaks, q0, a0, sent.Load(), answered.Load())
	if *flagHeap {
		n.backend.save(filepath.Join(*flagDir, *flagOut+".backend.heap.pprof"), "heap")
		n.front.save(filepath.Join(*flagDir, *flagOut+".front.heap.pprof"), "heap")
		n.backend.save(filepath.Join(*flagDir, *flagOut+".backend.goroutine.txt"), "goroutine?debug=1")
	}
	if *flagAfter > 0 {
		b2 := after
		t1 := time.Now()
		time.Sleep(*flagAfter)
		n.front.gc()
		n.backend.gc()
		time.Sleep(time.Second)
		smp.sample(n.front, n.backend)
		a2 := map[string]Stats{"front": smp.snapshot("front"), "backend": smp.snapshot("backend")}
		processed = 0
		report("after (idle, then GC)", time.Since(t1), b2, a2, map[string]Stats{"front": smp.peakOf("front"), "backend": smp.peakOf("backend")}, 0, 0, 0, 0)
		if *flagHeap {
			n.backend.save(filepath.Join(*flagDir, *flagOut+".backend.after.heap.pprof"), "heap")
		}
	}
	close(stopSampling)
	fmt.Println("backend log lines:", countLines(filepath.Join(*flagDir, *flagOut+".backend.log")))
}

// udpDrops is the kernel's drop counter of the UDP socket bound to addr (/proc/net/udp).
func udpDrops(addr string) uint64 {
	host, port, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host).To4()
	p, _ := strconv.Atoi(port)
	want := fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], p)
	b, _ := os.ReadFile("/proc/net/udp")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 12 && f[1] == want {
			v, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return v
		}
	}
	return 0
}

func countLines(path string) int {
	b, _ := os.ReadFile(path)
	return strings.Count(string(b), "\n")
}
