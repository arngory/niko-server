package dnsttserver

// dnsauth-v1 (neko; raycontrol docs/spec/dnsauth-v1.md): every query carries
// an 8-byte tag before the ClientID, an HMAC of the rest with a key of the
// device that sent it. Without a valid tag the zone answers as an empty one
// (NXDOMAIN), so a leaked or old link opens no sessions and a probe of the
// zone finds nothing.

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// AuthTagLen is the tag's length in a query's payload.
	AuthTagLen = 8
	// AuthEpoch is the time step of the tag; the node takes the epochs
	// before and after too (resolver caches delay queries).
	AuthEpoch = 600 * time.Second
	authLabel = "dnsauth1"
	// authCacheMax bounds the ClientID -> key cache.
	authCacheMax = 4096
)

// AuthMode is how the tags are checked.
type AuthMode int

const (
	AuthOff      AuthMode = iota // no tags (dnstt as it was)
	AuthOptional                 // tagged queries and untagged ones (clients moving over)
	AuthRequired                 // tagged queries only
)

// ParseAuthMode reads "", "off", "optional" or "required".
func ParseAuthMode(s string) (AuthMode, error) {
	switch s {
	case "", "off":
		return AuthOff, nil
	case "optional":
		return AuthOptional, nil
	case "required":
		return AuthRequired, nil
	}
	return AuthOff, fmt.Errorf("auth %q: off, optional or required", s)
}

type authKey struct {
	id  string
	key [32]byte
}

// authKeys is one generation of the keys: the HMAC of each key made once
// (Reset brings it back to the key, without hmac.New per query), and the
// keys of each device id for the cached sessions (an id may come twice,
// e.g. while a key is replaced).
type authKeys struct {
	keys []authKey
	macs []hash.Hash
	byID map[string][]int
	gen  uint64 // later keys have a larger one (hintIndexes.get)
}

// keysGen numbers the generations of keys as they are read.
var keysGen atomic.Uint64

// Auth checks the tags of queries against the keys of the devices allowed
// on the service. Safe for concurrent use (the checks take turns); the keys
// can be replaced while it runs.
type Auth struct {
	Mode AuthMode
	// Hint takes dnsauth-v2 tags, whose hint names the key: looked up, not
	// scanned, and outside the scan budget (raycontrol dnsauth-v2.md);
	// HintRequired takes no dnsauth-v1 tag and scans nothing.
	Hint HintMode
	Now  func() time.Time // time.Now when nil
	// ScanHMACs bounds the HMACs a second spent on full scans of the keys
	// (a query no cached session explains; up to 3 per device each), so
	// garbage cannot take the tunnel's one reader; two seconds' worth may
	// go at once. Zero: 100000 (a few percent of a core), or 20 full scans
	// a second if the devices are more than that allows.
	ScanHMACs float64

	keys  atomic.Pointer[authKeys]
	text  atomic.Pointer[[]byte] // the keys file's text in force (WatchKeys)
	hints hintIndexes            // dnsauth-v2's, for the keys in force

	mu sync.Mutex // the macs, the caches and the scan budget
	// ClientID -> device id of its last valid tag, in two generations: a
	// full cache becomes the previous one instead of being dropped.
	cache, prev map[turbotunnel.ClientID]string
	// The first 8 bytes of queries no key explained, with when they were
	// first seen: an old client's ClientID, taken as untagged in optional
	// mode and refused in required mode. A tagged query starts with a fresh
	// tag, so it matches one only if someone copied the tag (validLocked).
	unknown, unknownPrev map[turbotunnel.ClientID]time.Time
	tokens               float64
	last                 time.Time
	scratch              tagScratch

	// Counters for the log: queries with a valid tag, untagged ones taken
	// (optional), refused ones, and of those refused without a scan over
	// the budget.
	Valid, Untagged, Refused, Throttled atomic.Uint64
}

// SetKeys replaces the keys: lines "<device id> <64 hex digits>"; empty lines
// and lines starting with # are skipped. Cached sessions stay: a session
// whose device is gone no longer finds its key and is refused.
func (a *Auth) SetKeys(text []byte) error {
	k, err := parseAuthKeys(text)
	if err != nil {
		return err
	}
	a.keys.Store(k)
	kept := bytes.Clone(text)
	a.text.Store(&kept)
	if a.Hint != HintOff {
		a.hints.get(k, EpochOf(a.clock())) // at once: a key gone is not found
	}
	return nil
}

// parseAuthKeys reads a keys file's text (SetKeys).
func parseAuthKeys(text []byte) (*authKeys, error) {
	k := &authKeys{byID: map[string][]int{}, gen: keysGen.Add(1)}
	sc := bufio.NewScanner(bytes.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("auth keys line %d: want \"<device id> <key hex>\"", line)
		}
		b, err := hex.DecodeString(f[1])
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("auth keys line %d: the key is not 32 bytes of hex", line)
		}
		ak := authKey{id: f[0]}
		copy(ak.key[:], b)
		k.byID[ak.id] = append(k.byID[ak.id], len(k.keys))
		k.keys = append(k.keys, ak)
		k.macs = append(k.macs, hmac.New(sha256.New, ak.key[:]))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return k, nil
}

// Devices is the number of keys in force.
func (a *Auth) Devices() int {
	if k := a.keys.Load(); k != nil {
		return len(k.keys)
	}
	return 0
}

// LoadKeys reads the keys file.
func (a *Auth) LoadKeys(file string) error {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
	if err != nil {
		return err
	}
	return a.SetKeys(b)
}

// WatchKeys reads the file again every period, until stop is closed, and
// takes it when its text differs from the keys in force: by content, not
// modification time and size (review 8: a file rewritten before the first
// look, or at the same size within a tick, kept a revoked device's key, as
// the seal's watcher did before). A file that does not parse keeps the keys
// in force. Every hour it logs the counters, when they moved.
func (a *Auth) WatchKeys(file string, every time.Duration, stop <-chan struct{}, logf func(string, ...any)) {
	var said [4]uint64
	watchKeys(file, every, stop, logf, &a.text, a.SetKeys, a.Devices, func() {
		now := [4]uint64{a.Valid.Load(), a.Untagged.Load(), a.Refused.Load(), a.Throttled.Load()}
		if now != said {
			said = now
			logf("auth: %d valid, %d untagged, %d refused (%d over the scan budget) since the start", now[0], now[1], now[2], now[3])
		}
	})
}

// watchKeys is WatchKeys of Auth and DeviceAuth: the file read every period
// until stop, taken by set when it differs from text (the keys in force)
// and from the last one set refused; report runs every hour.
func watchKeys(file string, every time.Duration, stop <-chan struct{}, logf func(string, ...any),
	text *atomic.Pointer[[]byte], set func([]byte) error, devices func() int, report func()) {
	var bad []byte
	var readErr string // the last read error logged, once
	t := time.NewTicker(every)
	defer t.Stop()
	next := time.Now().Add(time.Hour)
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if time.Now().After(next) {
			next = time.Now().Add(time.Hour)
			report()
		}
		b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
		if err != nil {
			// Being replaced, or gone: the keys stay, said once.
			if err.Error() != readErr {
				readErr = err.Error()
				logf("auth keys %s not read, the %d in force stay: %v", file, devices(), err)
			}
			continue
		}
		readErr = ""
		// bad != nil: an empty file is not the bad one (review 9: a file
		// emptied of its last device was never taken).
		if cur := text.Load(); (cur != nil && bytes.Equal(b, *cur)) || (bad != nil && bytes.Equal(b, bad)) {
			continue
		}
		if err := set(b); err != nil {
			bad = b
			logf("auth keys %s not reloaded: %v", file, err)
			continue
		}
		bad = nil
		logf("auth keys reloaded: %d devices", devices())
	}
}

// Tag computes the tag of a payload (ClientID and what follows) for a key and
// an epoch; clients do the same.
func Tag(key *[32]byte, epoch uint32, payload []byte) [AuthTagLen]byte {
	var out [AuthTagLen]byte
	tagWith(hmac.New(sha256.New, key[:]), epoch, payload, new(tagScratch), &out)
	return out
}

// tagScratch holds what a tag is computed in: kept with the Auth, it does
// not move to the heap on every HMAC through the hash.Hash interface.
type tagScratch struct {
	head [16 + 4]byte // the longest label (dnsauth-v2's) and the epoch
	sum  [sha256.Size]byte
}

// tagWith computes a dnsauth-v1 tag with a key's HMAC, which it resets.
func tagWith(m hash.Hash, epoch uint32, payload []byte, sc *tagScratch, out *[AuthTagLen]byte) {
	tagWithLabel(m, authLabel, epoch, payload, sc, out)
}

// tagWithLabel computes HMAC(K, label || uint32_be(epoch) || payload)[:8]
// with a key's HMAC, which it resets.
func tagWithLabel(m hash.Hash, label string, epoch uint32, payload []byte, sc *tagScratch, out *[AuthTagLen]byte) {
	m.Reset()
	n := copy(sc.head[:], label)
	binary.BigEndian.PutUint32(sc.head[n:], epoch)
	m.Write(sc.head[:n+4])
	m.Write(payload)
	copy(out[:], m.Sum(sc.sum[:0]))
}

// EpochOf is the tag epoch of a time.
func EpochOf(t time.Time) uint32 { return uint32(t.Unix() / int64(AuthEpoch/time.Second)) }

// Check takes a query's decoded payload. With a valid tag it returns the
// payload after the tag; without one, the payload as it is when the mode
// takes untagged queries; otherwise ok is false and the query is answered
// as by an empty zone.
func (a *Auth) Check(payload []byte) (rest []byte, ok bool) {
	rest, _, ok = a.CheckDevice(payload)
	return rest, ok
}

// CheckDevice is Check that also names the device whose valid tag the
// payload carries ("" without one).
func (a *Auth) CheckDevice(payload []byte) (rest []byte, device string, ok bool) {
	if a == nil || a.Mode == AuthOff {
		return payload, "", true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	untagged := func() ([]byte, string, bool) {
		if a.Mode == AuthOptional {
			a.Untagged.Add(1)
			return payload, "", true
		}
		a.Refused.Add(1)
		return nil, "", false
	}
	if len(payload) < AuthTagLen+len(turbotunnel.ClientID{}) {
		return untagged() // too short for a tag; nothing to remember
	}
	var head turbotunnel.ClientID
	copy(head[:], payload)
	switch a.validLocked(payload, head) {
	case tagValid:
		a.Valid.Add(1)
		var cid turbotunnel.ClientID
		copy(cid[:], payload[AuthTagLen:])
		return payload[AuthTagLen:], a.cache[cid], true // validLocked cached it
	case tagThrottled:
		// Not looked at: refused even in optional mode, since a tagged
		// query read as untagged would feed the session garbage.
		a.Throttled.Add(1)
		a.Refused.Add(1)
		return nil, "", false
	case tagKnown:
		return untagged() // no key explained this head before
	case tagKnownBusy:
		if a.Mode != AuthOptional {
			a.Throttled.Add(1) // refused for the budget; optional takes it
		}
		return untagged()
	}
	a.remember(head)
	return untagged()
}

type tagResult int

const (
	tagInvalid   tagResult = iota
	tagValid               // a key's tag
	tagThrottled           // not looked at: over the budget
	tagKnown               // the head of a query no key explained before
	tagKnownBusy           // the same, not looked at again: over half the budget
)

// knownRescan is how long a remembered head is looked at again: long enough
// for a copied tag and the genuine query, which come close together; an old
// client's ClientID, which lives for minutes or hours, is then free.
const knownRescan = 30 * time.Second

// validLocked checks a tag: first against the keys of the session its
// ClientID names, if it is cached, so a session's queries, retransmits
// included, pass whatever else came with the same first bytes; then, if
// the head is not one no key explained before, against all the keys within
// the budget. A head remembered less than knownRescan ago is scanned again
// while more than half the budget is left (always with a full one):
// someone who copies a new session's tag into garbage cannot get the
// session's first query refused unless the node is under load.
func (a *Auth) validLocked(payload []byte, head turbotunnel.ClientID) tagResult {
	keys := a.keys.Load()
	if keys == nil || len(keys.keys) == 0 {
		if _, known := a.known(head, a.clock()); known {
			return tagKnown
		}
		return tagInvalid
	}
	var tag [AuthTagLen]byte
	copy(tag[:], payload)
	body := payload[AuthTagLen:]
	var cid turbotunnel.ClientID
	copy(cid[:], body)
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	e := EpochOf(now)
	epochs := [3]uint32{e, e - 1, e + 1}
	var t [AuthTagLen]byte
	hmacs := 0
	match := func(i int, epoch uint32) bool {
		hmacs++
		tagWith(keys.macs[i], epoch, body, &a.scratch, &t)
		return hmac.Equal(t[:], tag[:])
	}
	// The keys this session signed with last.
	id, cached := a.cache[cid]
	if !cached {
		id, cached = a.prev[cid]
	}
	tried := keys.byID[id]
	if !cached {
		tried = nil
	}
	// dnsauth-v2: the session's keys whose hint it is, then the keys the
	// hint names; no scan and nothing from its budget.
	if a.Hint != HintOff {
		x := a.hints.get(keys, e)
		match2Key := func(i int, epoch uint32) bool { return match2(keys.macs[i], epoch, &tag, body, &a.scratch) }
		for _, i := range tried {
			if x.keyMatches(i, &tag, func(epoch uint32) bool { return match2Key(i, epoch) }) {
				a.cacheSession(cid, id)
				return tagValid
			}
		}
		// The session's keys were tried above: not again.
		if i := x.find(&tag, func(i int, epoch uint32) bool { return !slices.Contains(tried, i) && match2Key(i, epoch) }); i >= 0 {
			a.cacheSession(cid, keys.keys[i].id)
			return tagValid
		}
		if a.Hint == HintRequired {
			// No dnsauth-v1 tag is taken: nothing to scan.
			if _, known := a.known(head, now); known {
				return tagKnown
			}
			return tagInvalid
		}
	}
	for _, i := range tried {
		for _, epoch := range epochs {
			if match(i, epoch) {
				a.cacheSession(cid, id)
				return tagValid
			}
		}
	}
	seen, known := a.known(head, now)
	tokens, burst := a.refill(now, len(keys.keys))
	scan := float64(3 * len(keys.keys))
	switch {
	case known && now.Sub(seen) >= knownRescan:
		return tagKnown
	case known && tokens < min(burst, burst/2+scan):
		return tagKnownBusy // a remembered head never takes the lower half
	case tokens <= 0:
		return tagThrottled
	}
	// All the others: the current epoch first, where a client's tag nearly
	// always is. Only the HMACs done are charged.
	defer func() { a.tokens -= float64(hmacs) }()
	for _, epoch := range epochs {
		for i := range keys.keys {
			if slices.Contains(tried, i) {
				continue
			}
			if match(i, epoch) {
				a.cacheSession(cid, keys.keys[i].id)
				return tagValid
			}
		}
	}
	if known {
		return tagKnown
	}
	return tagInvalid
}

// refill brings the budget up to now and returns it with its ceiling. The
// rate is ScanHMACs, or by default 100000 a second and at least 20 full
// scans of n devices, never under two full scans; two seconds' worth may go
// at once. A scan may start
// while the budget is above zero and leave it below.
func (a *Auth) refill(now time.Time, n int) (tokens, burst float64) {
	rate := a.ScanHMACs
	if rate <= 0 {
		rate = max(100000, float64(3*n*20))
	}
	// Two full scans a second at least: one can go to a copied tag and one
	// to the genuine query right behind it.
	rate = max(rate, float64(6*n))
	burst = 2 * rate
	if a.last.IsZero() {
		a.tokens = burst
	} else if d := now.Sub(a.last).Seconds(); d > 0 {
		a.tokens = min(burst, a.tokens+d*rate)
	}
	a.last = now
	return a.tokens, burst
}

// cacheSession remembers the device a session's tag was valid for.
func (a *Auth) cacheSession(cid turbotunnel.ClientID, id string) {
	if old, ok := a.cache[cid]; ok {
		if old != id {
			a.cache[cid] = id
		}
		return
	}
	if a.cache == nil || len(a.cache) >= authCacheMax {
		a.prev, a.cache = a.cache, map[turbotunnel.ClientID]string{}
	}
	a.cache[cid] = id
}

// known reports whether no key explained a query that began with head, and
// since when; a hit in the previous generation moves to the current one, so
// an old client that keeps asking stays.
func (a *Auth) known(head turbotunnel.ClientID, now time.Time) (time.Time, bool) {
	if seen, ok := a.unknown[head]; ok {
		return seen, true
	}
	if seen, ok := a.unknownPrev[head]; ok {
		a.rememberAt(head, seen)
		return seen, true
	}
	return now, false
}

func (a *Auth) remember(head turbotunnel.ClientID) { a.rememberAt(head, a.clock()) }

func (a *Auth) rememberAt(head turbotunnel.ClientID, seen time.Time) {
	if a.unknown == nil || len(a.unknown) >= authCacheMax {
		a.unknownPrev, a.unknown = a.unknown, map[turbotunnel.ClientID]time.Time{}
	}
	a.unknown[head] = seen
}

func (a *Auth) clock() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}
