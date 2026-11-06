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

// deviceKeys is one generation of the keys with a second HMAC of each, for
// Device: a session's check never waits for a scan.
type deviceKeys struct {
	*authKeys
	device []hash.Hash
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
	// the devices are more than that allows, and never under two full
	// scans of a kind a second.
	ScanHMACs float64

	keys atomic.Pointer[deviceKeys]
	text atomic.Pointer[[]byte] // the keys file's text in force

	devMu      sync.Mutex // Device's HMACs
	devScratch tagScratch

	scanMu      sync.Mutex // the scans' HMACs, budgets and the recent devices
	scanScratch tagScratch
	tokens      [scanKinds]float64
	last        [scanKinds]time.Time
	recent      []string // device ids, the latest first

	// Counters (the log, every hour): tags found, by Device or a scan;
	// queries no key explained; scans not done or cut short for the budget.
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
	dk := &deviceKeys{authKeys: k, device: make([]hash.Hash, len(k.keys))}
	for i := range k.keys {
		dk.device[i] = hmac.New(sha256.New, k.keys[i].key[:])
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
			logf("auth: %d valid, %d refused, %d scans over the budget since the start", now[0], now[1], now[2])
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
	a.devMu.Lock()
	defer a.devMu.Unlock()
	for _, i := range idx {
		for _, e := range es {
			tagWith(k.device[i], e, msg, &a.devScratch, &t)
			if hmac.Equal(t[:], tag[:]) {
				a.Valid.Add(1)
				return true
			}
		}
	}
	a.Refused.Add(1)
	return false
}

// Scan finds the device whose tag it is: the recent devices first, then
// the others, the current epoch first; within kind's budget, of which only
// the HMACs done are charged. A scan may start while the budget is above
// zero and leave it below.
func (a *DeviceAuth) Scan(kind ScanKind, tag [AuthTagLen]byte, msg []byte) (string, bool) {
	if kind < 0 || kind >= scanKinds {
		kind = ScanSession
	}
	k := a.keys.Load()
	if k == nil || len(k.keys) == 0 {
		a.Refused.Add(1)
		return "", false
	}
	es := epochs(a.clock())
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	if a.refill(kind, a.clock(), len(k.keys)) <= 0 {
		a.Throttled.Add(1)
		return "", false
	}
	hmacs := 0
	defer func() { a.tokens[kind] -= float64(hmacs) }()
	var t [AuthTagLen]byte
	match := func(i int, e uint32) bool {
		hmacs++
		tagWith(k.macs[i], e, msg, &a.scanScratch, &t)
		return hmac.Equal(t[:], tag[:])
	}
	for _, id := range a.recent {
		for _, i := range k.byID[id] {
			for _, e := range es {
				if match(i, e) {
					a.found(id)
					return id, true
				}
			}
		}
	}
	for _, e := range es {
		for i := range k.keys {
			id := k.keys[i].id
			if slices.Contains(a.recent, id) {
				continue
			}
			if match(i, e) {
				a.found(id)
				return id, true
			}
		}
	}
	a.Refused.Add(1)
	return "", false
}

// found puts a device first among the recent ones.
func (a *DeviceAuth) found(id string) {
	a.Valid.Add(1)
	if i := slices.Index(a.recent, id); i >= 0 {
		a.recent = slices.Delete(a.recent, i, i+1)
	}
	a.recent = slices.Insert(a.recent, 0, id)
	if len(a.recent) > recentMax {
		a.recent = a.recent[:recentMax]
	}
}

// refill brings kind's budget up to now and returns it: its share of the
// rate (Auth.refill's), never under two full scans of n devices a second;
// two seconds' worth may go at once.
func (a *DeviceAuth) refill(kind ScanKind, now time.Time, n int) float64 {
	rate := a.ScanHMACs
	if rate <= 0 {
		rate = max(100000, float64(3*n*20))
	}
	rate = max(rate*scanShare[kind], float64(6*n))
	burst := 2 * rate
	if a.last[kind].IsZero() {
		a.tokens[kind] = burst
	} else if d := now.Sub(a.last[kind]).Seconds(); d > 0 {
		a.tokens[kind] = min(burst, a.tokens[kind]+d*rate)
	}
	a.last[kind] = now
	return a.tokens[kind]
}
