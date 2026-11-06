package dnsttserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ScanKind is the budget a scan of the keys comes from (raycontrol
// docs/spec/dnsauth-masterdns.md §3.2, §3.4): MTU probes, SESSION_INITs,
// and queries to a session the server has no record of.
type ScanKind int

const (
	ScanProbe ScanKind = iota
	ScanInit
	ScanSession
	scanKinds
)

// scanShare is each kind's part of the scan budget. Probes and INITs apart:
// after a restart of the node every client starts with probes at once, and
// a probe left unanswered for the budget reads to the client as a bad
// resolver, but the INITs of those that passed their probes must not wait
// behind them. Sessions gone (a restarted node) the least: an answer there
// only hurries the client to a new session it opens anyway.
var scanShare = [scanKinds]float64{0.4, 0.4, 0.2}

// recentMax is how many devices a scan tries first: those whose tags scans
// found last (a client's probes and INIT come together).
const recentMax = 64

// deviceKeys is one generation of the keys: each key's HMAC for Device,
// under the key's own lock (a session's check waits for no other
// session's, nor for a scan), and one per scan kind, each kind scanning
// alone (review 13).
type deviceKeys struct {
	*authKeys
	device []*keyMAC
	scan   [scanKinds][]hash.Hash
}

type keyMAC struct {
	mu      sync.Mutex
	h       hash.Hash
	scratch tagScratch
}

// scanSlot is a kind's scan: one at a time, and a query that finds it busy
// is refused at once rather than waiting (review 13: masterdns's few
// workers waited behind scans of garbage holding one lock, the live
// sessions' queries behind them). Its budget and scratch go with it.
type scanSlot struct {
	mu      sync.Mutex
	tokens  float64
	last    time.Time
	scratch tagScratch
	recent  []int  // the keys of the recent devices, tried first
	skip    []bool // the same keys marked, for the full pass to skip
}

// DeviceAuth checks the device tags of masterdns queries (raycontrol
// docs/spec/dnsauth-masterdns.md §3): Device for a session's own device,
// within up to 3 HMACs and no budget; Scan for a query no session
// explains, the recent devices first, within a budget of its kind. Tags
// as dnsauth-v1's (Tag): HMAC-SHA256(K, "dnsauth1" || uint32_be(epoch) ||
// msg)[:8], the epoch now and the ones next to it. Safe for concurrent
// use; the keys can be replaced while it runs.
type DeviceAuth struct {
	Now func() time.Time // time.Now when nil
	// ScanHMACs bounds the HMACs a second scans spend, all kinds together
	// (scanShare); as Auth's: zero is 100000, or 20 full scans a second if
	// the devices are more than that allows. Each kind also gets two full
	// scans a second at least: with many devices the floors together can
	// pass ScanHMACs.
	ScanHMACs float64

	keys atomic.Pointer[deviceKeys]
	text atomic.Pointer[[]byte] // the keys file's text in force

	slots [scanKinds]scanSlot

	recentMu sync.Mutex
	recent   []string // device ids, the latest first

	// Counters (the log, every hour): tags found, by Device or a scan;
	// queries no key explained; scans not done, for the budget or a scan of
	// the kind under way.
	Valid, Refused, Throttled atomic.Uint64
}

// SetKeys replaces the keys, as Auth's: lines "<device id> <64 hex
// digits>". A device gone fails Device and Scan from then on: a session
// bound to it gets no answers.
func (a *DeviceAuth) SetKeys(text []byte) error {
	k, err := parseAuthKeys(text)
	if err != nil {
		return err
	}
	dk := &deviceKeys{authKeys: k, device: make([]*keyMAC, len(k.keys))}
	for i := range k.keys {
		dk.device[i] = &keyMAC{h: hmac.New(sha256.New, k.keys[i].key[:])}
	}
	// The keys' own HMACs (parseAuthKeys) are the first kind's: Device
	// and the other kinds get theirs.
	dk.scan[0] = k.macs
	for kind := 1; kind < int(scanKinds); kind++ {
		dk.scan[kind] = make([]hash.Hash, len(k.keys))
		for i := range k.keys {
			dk.scan[kind][i] = hmac.New(sha256.New, k.keys[i].key[:])
		}
	}
	a.keys.Store(dk)
	kept := slices.Clone(text)
	a.text.Store(&kept)
	return nil
}

// Devices is the number of keys in force.
func (a *DeviceAuth) Devices() int {
	if k := a.keys.Load(); k != nil {
		return len(k.keys)
	}
	return 0
}

// LoadKeys reads the keys file.
func (a *DeviceAuth) LoadKeys(file string) error {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
	if err != nil {
		return err
	}
	return a.SetKeys(b)
}

// WatchKeys reads the file again every period until stop, as Auth's.
func (a *DeviceAuth) WatchKeys(file string, every time.Duration, stop <-chan struct{}, logf func(string, ...any)) {
	var said [3]uint64
	watchKeys(file, every, stop, logf, &a.text, a.SetKeys, a.Devices, func() {
		now := [3]uint64{a.Valid.Load(), a.Refused.Load(), a.Throttled.Load()}
		if now != said {
			said = now
			logf("auth: %d valid, %d refused, %d scans not done (budget, or one under way) since the start", now[0], now[1], now[2])
		}
	})
}

func (a *DeviceAuth) clock() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// epochs are the epochs a tag may be in, now's first.
func epochs(now time.Time) [3]uint32 {
	e := EpochOf(now)
	return [3]uint32{e, e - 1, e + 1}
}

// Device reports whether tag is device id's over msg.
func (a *DeviceAuth) Device(id string, tag [AuthTagLen]byte, msg []byte) bool {
	k := a.keys.Load()
	if k == nil {
		a.Refused.Add(1)
		return false
	}
	idx := k.byID[id]
	if len(idx) == 0 {
		a.Refused.Add(1) // revoked, or never there
		return false
	}
	es := epochs(a.clock())
	var t [AuthTagLen]byte
	for _, i := range idx {
		m := k.device[i]
		m.mu.Lock()
		for _, e := range es {
			tagWith(m.h, e, msg, &m.scratch, &t)
			if hmac.Equal(t[:], tag[:]) {
				m.mu.Unlock()
				a.Valid.Add(1)
				return true
			}
		}
		m.mu.Unlock()
	}
	a.Refused.Add(1)
	return false
}

// Scan finds the device whose tag it is: the recent devices first, then
// the others, the current epoch first; within kind's budget, of which only
// the HMACs done are charged. A scan may start while the budget is above
// zero and leave it below. A scan of the kind under way refuses it at once.
func (a *DeviceAuth) Scan(kind ScanKind, tag [AuthTagLen]byte, msg []byte) (string, bool) {
	if kind < 0 || kind >= scanKinds {
		kind = ScanSession
	}
	slot := &a.slots[kind]
	if !slot.mu.TryLock() {
		a.Throttled.Add(1)
		return "", false
	}
	defer slot.mu.Unlock()
	// The keys as they are now: a device revoked is not found.
	k := a.keys.Load()
	if k == nil || len(k.keys) == 0 {
		a.Refused.Add(1)
		return "", false
	}
	if a.refill(slot, kind, a.clock(), len(k.keys)) <= 0 {
		a.Throttled.Add(1)
		return "", false
	}
	es := epochs(a.clock())
	macs := k.scan[kind]
	hmacs := 0
	defer func() { slot.tokens -= float64(hmacs) }()
	var t [AuthTagLen]byte
	match := func(i int, e uint32) bool {
		hmacs++
		tagWith(macs[i], e, msg, &slot.scratch, &t)
		return hmac.Equal(t[:], tag[:])
	}
	// The recent devices' keys, marked for the full pass to skip.
	if cap(slot.skip) < len(k.keys) {
		slot.skip = make([]bool, len(k.keys))
	}
	skip := slot.skip[:len(k.keys)]
	clear(skip)
	recent := slot.recent[:0]
	a.recentMu.Lock()
	for _, id := range a.recent {
		for _, i := range k.byID[id] {
			recent = append(recent, i)
			skip[i] = true
		}
	}
	a.recentMu.Unlock()
	slot.recent = recent
	for _, e := range es {
		for _, i := range recent {
			if match(i, e) {
				id := k.keys[i].id
				a.found(id)
				return id, true
			}
		}
	}
	for _, e := range es {
		for i := range k.keys {
			if skip[i] {
				continue
			}
			if match(i, e) {
				id := k.keys[i].id
				a.found(id)
				return id, true
			}
		}
	}
	a.Refused.Add(1)
	return "", false
}

// found puts a device first among the recent ones; ids no longer in the
// keys drop out.
func (a *DeviceAuth) found(id string) {
	a.Valid.Add(1)
	k := a.keys.Load()
	a.recentMu.Lock()
	defer a.recentMu.Unlock()
	a.recent = slices.DeleteFunc(a.recent, func(r string) bool { return r == id || k == nil || len(k.byID[r]) == 0 })
	a.recent = slices.Insert(a.recent, 0, id)
	if len(a.recent) > recentMax {
		a.recent = a.recent[:recentMax]
	}
}

// refill brings kind's budget up to now and returns it: its share of the
// rate (Auth.refill's), never under two full scans of n devices a second;
// two seconds' worth may go at once.
func (a *DeviceAuth) refill(slot *scanSlot, kind ScanKind, now time.Time, n int) float64 {
	rate := a.ScanHMACs
	if rate <= 0 {
		rate = max(100000, float64(3*n*20))
	}
	rate = max(rate*scanShare[kind], float64(6*n))
	burst := 2 * rate
	if slot.last.IsZero() {
		slot.tokens = burst
	} else if d := now.Sub(slot.last).Seconds(); d > 0 {
		slot.tokens = min(burst, slot.tokens+d*rate)
	}
	slot.last = now
	return slot.tokens
}
