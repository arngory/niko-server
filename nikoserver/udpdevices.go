//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"golang.org/x/crypto/blake2b"
)

// A route of salamander_passwords_file (v0.19.3, raycontrol
// salamander-device-v1 §4): a salamander password of each device, and the
// front, not the backend, takes salamander off and puts it on. A
// datagram of no flow is tried under the keys, those its source matched
// lately first; the key it opens under pins the flow, and the flow's
// datagrams go to the backend opened, its answers back under that key
// with a salt of their own. A device's password opens its own packets
// only: one device cannot read another's, and a device revoked loses
// its open flows with its key.

const (
	// maxSalamanderPasswords: a route's list at most (§4.2); a file with
	// more is not taken.
	maxSalamanderPasswords = 65536
	// trialRate and trialBurst: the keys tried for the datagrams of no
	// flow of a source (an IPv4 address, an IPv6 /64), a second;
	// trialTotalRate and trialTotalBurst: of all (§4.1). A key is one
	// BLAKE2b of 40 bytes (BenchmarkUDPFrontDeviceTrial: ~0.25 µs), so
	// the front's share, with its own keys' budget (600,000 a second in
	// all), is ~0.15 s of a core a second at most, spent on the socket's
	// own goroutine. The budget makes an exhaustion of the
	// CPU one of these trials: a source's share is a fiftieth of the
	// front's, and only an address past the knock reaches the front, so
	// it takes 50 sources that knocked to keep new flows out (devices'
	// new ports go on: their own keys have a budget apart). With 1000
	// keys a source opens 10 new flows a second, 40 at once (a datagram
	// no key opens costs the whole list); a list longer than a burst is
	// tried once the bucket fills to it (65,536 keys: one a source each
	// 6.5 s, ~16 ms of the socket's goroutine each).
	trialRate, trialBurst           = 10000, 40000
	trialTotalRate, trialTotalBurst = 500000, 500000
	// recentTrialRate and recentTrialBurst: the trials of a source's own
	// keys (the candidate and those it matched lately, 5 a datagram at
	// most), a second, a source; recentTrialTotalRate and
	// recentTrialTotalBurst: of all. A budget apart: whoever spends the
	// rest, a device's new port is still matched at its first key.
	recentTrialRate, recentTrialBurst           = 1000, 4000
	recentTrialTotalRate, recentTrialTotalBurst = 100000, 100000
	// candidatesMax: the 4-tuples of a generation (a minute) whose next
	// datagram tries a candidate first (tryKeys).
	candidatesMax = 16384
	// recentKeysFor: a source's keys are tried first for this long (two
	// generations of it at most): a client whose NAT gave it a new port
	// is matched at the first key. recentKeysMax: the sources of a
	// generation; recentPerSource: the keys a source's (a CGNAT address
	// has a few devices behind it).
	recentKeysFor   = 10 * time.Minute
	recentKeysMax   = 65536
	recentPerSource = 4
	// saltsFor and saltsMax: the salts of the Initials matched, two
	// generations of saltsFor of saltsMax each at most (§7): a copy of a
	// client's Initial sent again gets nothing, where it got the server's
	// handshake, some 3 × 1280 bytes that tell the service is alive.
	// saltsPerKey: a key's Initials a generation at most, past them
	// dropped: one key cannot turn the generations over early and flush
	// the memory, 16 together can (a device opens a few connections in
	// 10 minutes).
	saltsFor    = 10 * time.Minute
	saltsMax    = 65536
	saltsPerKey = 4096
	// devicesEvery: how often a route's file is read again.
	devicesEvery = 5 * time.Second
)

// deviceRoute is a route of salamander_passwords_file.
type deviceRoute struct {
	file  string
	link  *backendLink
	label uint16    // its backend's label, 0 none
	codec *cidCodec // the label's key; nil: no routing by ID
	// keys: one flowRoute a password, swapped whole on a reload; a
	// trial reads it without the front's lock.
	keys atomic.Pointer[[]*flowRoute]
	// text: the file as last taken; problem: the last error said (the
	// watch's only, after the start).
	text    []byte
	problem string
}

// list is the keys in force.
func (r *deviceRoute) list() []*flowRoute {
	if k := r.keys.Load(); k != nil {
		return *k
	}
	return nil
}

// deviceStats are the counters of the device routes, all together:
// numbers only, never a key or an address (§6).
type deviceStats struct {
	pinned, unmatched, overBudget, replayed, keyShare, cut atomic.Uint64
}

// errTooManyPasswords: a file past maxSalamanderPasswords, not taken.
var errTooManyPasswords = fmt.Errorf("more than %d passwords", maxSalamanderPasswords)

// parseSalamanderPasswords reads a passwords file (§4.2): a password a
// line, as its bytes; empty lines and lines starting with # skipped,
// trailing \r and spaces trimmed, a password once. An empty list lets
// nobody in, and is no error. Its errors never say what the file holds.
func parseSalamanderPasswords(b []byte) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		line = bytes.TrimRight(line, " \t\r")
		if len(line) == 0 || line[0] == '#' || seen[string(line)] {
			continue
		}
		if len(out) == maxSalamanderPasswords {
			return nil, errTooManyPasswords
		}
		seen[string(line)] = true
		out = append(out, bytes.Clone(line))
	}
	return out, nil
}

// loadDevices reads a route's file and takes its list; with an error the
// list in force stays.
func (f *udpFront) loadDevices(r *deviceRoute) (changed bool, err error) {
	b, err := os.ReadFile(r.file)
	if err != nil {
		return false, err
	}
	if r.keys.Load() != nil && bytes.Equal(b, r.text) {
		return false, nil
	}
	passwords, err := parseSalamanderPasswords(b)
	if err != nil {
		return false, err
	}
	f.setDevices(r, passwords)
	r.text = b
	return true, nil
}

// setDevices puts a route's list in force. A key kept is the same
// flowRoute, its flows stay; the flows of a key gone are forgotten at
// once (their next datagram is tried and opens under nothing), and a
// trial under way that found one pins nothing (flowRoute.gone).
func (f *udpFront) setDevices(r *deviceRoute, passwords [][]byte) {
	old := map[string]*flowRoute{}
	for _, k := range r.list() {
		old[string(k.password)] = k
	}
	list := make([]*flowRoute, 0, len(passwords))
	for _, pw := range passwords {
		k := old[string(pw)]
		if k == nil {
			k = &flowRoute{password: pw, front: true, device: r}
		}
		delete(old, string(pw))
		list = append(list, k)
	}
	f.access.Lock()
	defer f.access.Unlock()
	r.keys.Store(&list)
	if len(old) == 0 {
		return
	}
	for _, k := range old {
		k.gone = true
	}
	for key, fl := range f.flows {
		if fl.route != nil && fl.route.gone {
			f.unpin(key)
			f.devStats.cut.Add(1)
		}
	}
}

// watchDevices reads a route's file again every period until ctx ends, as
// the DNS front its zones' auth_keys_file: a file that does not read
// leaves the list in force, said once (being replaced, or gone). A file
// of too many passwords leaves it too, and is an error at each read
// while it stays: no device it adds gets in, none it removes is cut.
func (f *udpFront) watchDevices(ctx context.Context, r *deviceRoute, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := f.loadDevices(r)
		switch {
		case errors.Is(err, errTooManyPasswords):
			r.problem = err.Error()
			f.log.Errorf("udp salamander passwords %s not taken, the %d in force stay, revocations too: %v", r.file, len(r.list()), err)
		case err != nil:
			if err.Error() != r.problem {
				r.problem = err.Error()
				f.log.Warnf("udp salamander passwords %s not read, the %d in force stay: %v", r.file, len(r.list()), err)
			}
		case changed:
			r.problem = ""
			f.log.Infof("udp salamander passwords %s: %d", r.file, len(r.list()))
		default:
			r.problem = ""
		}
	}
}

// reportDevices logs the device routes' counters, when they changed.
func (f *udpFront) reportDevices(said *[6]uint64) {
	s := &f.devStats
	now := [6]uint64{s.pinned.Load(), s.unmatched.Load(), s.overBudget.Load(), s.replayed.Load(), s.keyShare.Load(), s.cut.Load()}
	if now == *said {
		return
	}
	*said = now
	f.log.Infof("udp salamander keys: %d flows pinned, %d datagrams opened under none, %d over the trial budget, "+
		"%d Initials sent again, %d Initials past their key's share, %d flows of keys gone cut, since the start",
		now[0], now[1], now[2], now[3], now[4], now[5])
}

// tryKeys finds the key of a device route that a datagram of no flow
// opens under: to a QUIC Initial (v1, v2) of 1200 bytes or more under
// its salt, or to a packet to the label of the route's backend. It
// returns the datagram opened.
//
// The keys of the source go first, each budget of its own: the key a
// label matched on this 4-tuple's last datagram (a candidate), then those
// its source (an IPv4 address, an IPv6 /64) matched in the last minutes.
// A client whose NAT gave it a new port is matched at the first key,
// whatever the others spend. Then all the rest, or none: the trial
// budget holds them all, or the datagram is dropped untried.
//
// A label is 24 bits of the 64 of a connection ID's block: under one of
// K keys, a datagram of garbage reads as a short header with the label at
// about K × 2^-26. So a label the rest matched does not pin: its key is
// the 4-tuple's candidate, and the next datagram, under it, pins (2^-52).
// An Initial (34 bits and its size) and a key of the source's pin at once.
func (f *udpFront) tryKeys(key flowKey, d []byte, now time.Time) (*backendLink, *flowRoute, [][]byte) {
	if len(d) < salamanderSalt+7 {
		return nil, nil, nil
	}
	initial := len(d) >= salamanderSalt+minInitialDatagram
	short := len(d)-salamanderSalt >= minCIDPacket
	total := 0
	for _, r := range f.devices {
		if r.can(initial, short) {
			total += len(r.list())
		}
	}
	if total == 0 {
		return nil, nil, nil
	}
	src := key.client.Addr()
	sk := sourceKey(src)

	var first [recentPerSource + 1]*flowRoute
	n, nAll := 0, 0
	f.access.Lock()
	recent := f.recent.get(sk)
	if c := f.candidates.get(key); c != nil && c.device.can(initial, short) {
		first[n] = c
		n++
	}
	for _, fr := range recent {
		if fr != nil && fr != first[0] && fr.device.can(initial, short) {
			first[n] = fr
			n++
		}
	}
	nAll = n
	if n > 0 && !f.recentGrant(src, n, now) {
		n = 0 // past the source's own: tried with the rest, its keys still
	}
	f.access.Unlock()

	var found *flowRoute
	var k [blake2b.Size256]byte
	kind := matchNone
	for _, fr := range first[:n] {
		if k, kind = fr.device.open(fr, d, initial, short); kind != matchNone {
			found = fr
			break
		}
	}
	firsts := first[:n]
	rest := 0
	if found == nil {
		want := total - n
		f.access.Lock()
		ok := want > 0 && f.trialGrant(src, want, now)
		f.access.Unlock()
		if want > 0 && !ok {
			f.devStats.overBudget.Add(1)
			return nil, nil, nil
		}
	routes:
		for _, r := range f.devices {
			if !r.can(initial, short) {
				continue
			}
			for _, fr := range r.list() {
				if rest == want {
					break routes // the list grew meanwhile
				}
				if isFirst(firsts, fr) {
					continue
				}
				rest++
				if k, kind = r.open(fr, d, initial, short); kind != matchNone {
					found = fr
					break routes
				}
			}
		}
		f.access.Lock()
		f.trialReturn(src, want, want-rest, now)
		f.access.Unlock()
	}
	if found == nil {
		f.devStats.unmatched.Add(1)
		return nil, nil, nil
	}

	// The salt, the key's share and its place among the source's go
	// with the pin (pinFlow): a datagram that pins nothing takes none.
	f.access.Lock()
	ok := !found.gone
	switch {
	case !ok, kind == matchInitial:
	case rest > 0 && !isFirst(first[:nAll], found):
		// A label of the rest: a candidate, not a pin. One of the
		// source's own keys tried with the rest (its own budget spent)
		// pins as it would have first.
		f.candidates.note(key, found, now)
		ok = false
	default:
		ok = f.cidSources.allow(src, now)
	}
	f.access.Unlock()
	if !ok {
		return nil, nil, nil
	}
	out := make([]byte, len(d)-salamanderSalt)
	hysteria2.SalamanderXOR(out, d[salamanderSalt:], &k, 0)
	return found.device.link, found, [][]byte{out}
}

// deviceInitial reports whether d opens under k's key to an Initial of a
// size (tryKeys' matchInitial).
func deviceInitial(k *flowRoute, d []byte) bool {
	if len(d) < salamanderSalt+minInitialDatagram {
		return false
	}
	key := salamanderKey(k.password, d[:salamanderSalt])
	h, n := openHeadKey(&key, d, 7)
	return n == 7 && isQUICInitial(h[:7])
}

// newSalt reports whether an Initial a key opened is new (§7), and
// remembers its salt: not a salt seen in the two generations, nor past
// the key's share of one (saltsPerKey). With f.access.
func (f *udpFront) newSalt(k *flowRoute, d []byte, now time.Time) bool {
	salt := binary.LittleEndian.Uint64(d[:salamanderSalt])
	if f.salts.has(salt) {
		f.devStats.replayed.Add(1)
		return false
	}
	if k.saltGen != f.salts.gen {
		k.saltGen, k.salts = f.salts.gen, 0
	}
	if k.salts >= saltsPerKey {
		f.devStats.keyShare.Add(1)
		return false
	}
	k.salts++
	f.salts.add(salt, now)
	return true
}

func isFirst(first []*flowRoute, fr *flowRoute) bool {
	for _, x := range first {
		if x == fr {
			return true
		}
	}
	return false
}

// candidates are the keys a label of the rest matched, by 4-tuple, for
// its next datagram (tryKeys), in two generations of a minute.
type candidates struct {
	current, older map[flowKey]*flowRoute
	swapped        time.Time
}

// get is a 4-tuple's candidate still in force. With f.access.
func (c *candidates) get(key flowKey) *flowRoute {
	k := c.current[key]
	if k == nil {
		k = c.older[key]
	}
	if k == nil || k.gone {
		return nil
	}
	return k
}

func (c *candidates) note(key flowKey, k *flowRoute, now time.Time) {
	if c.current == nil || len(c.current) >= candidatesMax {
		c.older, c.current, c.swapped = c.current, map[flowKey]*flowRoute{}, now
	}
	c.current[key] = k
}

func (c *candidates) drop(key flowKey) {
	delete(c.current, key)
	delete(c.older, key)
}

func (c *candidates) age(now time.Time) {
	if c.current != nil && now.Sub(c.swapped) > time.Minute {
		c.older, c.current, c.swapped = c.current, map[flowKey]*flowRoute{}, now
	}
}

// What a key opens a datagram to.
const (
	matchNone    = iota
	matchInitial // an Initial of a size
	matchLabel   // a packet to the route's label
)

// can reports whether a datagram of no flow may open on the route: an
// Initial's size, or a short or labelled packet's with a label to read.
func (r *deviceRoute) can(initial, short bool) bool {
	return initial || (short && r.codec != nil)
}

// open opens d's head under fr's key and tells what it is, with the key.
// One BLAKE2b, no allocation.
func (r *deviceRoute) open(fr *flowRoute, d []byte, initial, short bool) ([blake2b.Size256]byte, int) {
	k := salamanderKey(fr.password, d[:salamanderSalt])
	var head [cidHead]byte
	n := min(len(head), len(d)-salamanderSalt)
	for i := range n {
		head[i] = d[salamanderSalt+i] ^ k[i]
	}
	if isQUICInitial(head[:7]) {
		if initial {
			return k, matchInitial
		}
		return k, matchNone
	}
	if short && r.codec != nil {
		if id := clientCID(head[:n], len(d)-salamanderSalt); id != nil {
			if label, ok := r.codec.label(id); ok && label == r.label {
				return k, matchLabel
			}
		}
	}
	return k, matchNone
}

// recentGrant takes n trials of the source's keys from the source's
// budget of them and the front's, or none. With f.access.
func (f *udpFront) recentGrant(src netip.Addr, n int, now time.Time) bool {
	sb := f.recentSources.bucket(src, now)
	if !sb.take(float64(n), recentTrialRate, recentTrialBurst, now) {
		return false
	}
	if !f.allRecent.take(float64(n), recentTrialTotalRate, recentTrialTotalBurst, now) {
		sb.give(n, recentTrialBurst)
		return false
	}
	return true
}

// trialGrant takes want trials from src's budget and the front's, or
// none. A list longer than a burst is tried whole once the bucket has
// filled to it.
func (f *udpFront) trialGrant(src netip.Addr, want int, now time.Time) bool {
	sb := f.trialSources.bucket(src, now)
	if !sb.take(float64(want), trialRate, max(trialBurst, float64(want)), now) {
		return false
	}
	if !f.allTrials.take(float64(want), trialTotalRate, max(trialTotalBurst, float64(want)), now) {
		sb.give(want, max(trialBurst, float64(want)))
		return false
	}
	return true
}

// trialReturn gives back n of the want trials granted, not made. With
// f.access.
func (f *udpFront) trialReturn(src netip.Addr, want, n int, now time.Time) {
	if n > 0 {
		f.trialSources.bucket(src, now).give(n, max(trialBurst, float64(want)))
		f.allTrials.give(n, max(trialTotalBurst, float64(want)))
	}
}

// give puts back n taken.
func (b *tokenBucket) give(n int, burst float64) {
	b.tokens = min(burst, b.tokens+float64(n))
}

// recentKeys are the keys each source (sourceKey) matched lately, the
// last first, in two generations of recentKeysFor.
type recentKeys struct {
	current, older map[uint64]*[recentPerSource]*flowRoute
	swapped        time.Time
}

// get is a source's keys still in force. With f.access.
func (r *recentKeys) get(src uint64) (out [recentPerSource]*flowRoute) {
	keys := r.current[src]
	if keys == nil {
		keys = r.older[src]
	}
	if keys == nil {
		return out
	}
	i := 0
	for _, k := range keys {
		if k != nil && !k.gone {
			out[i] = k
			i++
		}
	}
	return out
}

// note puts a key first among its source's. With f.access.
func (r *recentKeys) note(src uint64, k *flowRoute, now time.Time) {
	if r.current == nil || len(r.current) >= recentKeysMax {
		r.older, r.current, r.swapped = r.current, map[uint64]*[recentPerSource]*flowRoute{}, now
	}
	keys := r.current[src]
	if keys == nil {
		keys = &[recentPerSource]*flowRoute{}
		if o := r.older[src]; o != nil {
			*keys = *o
		}
		r.current[src] = keys
	}
	at := len(keys) - 1
	for i, x := range keys {
		if x == k {
			at = i
			break
		}
	}
	copy(keys[1:at+1], keys[:at])
	keys[0] = k
}

func (r *recentKeys) age(now time.Time) {
	if r.current != nil && now.Sub(r.swapped) > recentKeysFor {
		r.older, r.current, r.swapped = r.current, map[uint64]*[recentPerSource]*flowRoute{}, now
	}
}

// saltMemory is the salts of the Initials a key opened (§7), in two
// generations of saltsFor, saltsMax each at most; gen counts the
// generations, for each key's share of one (flowRoute.salts).
type saltMemory struct {
	current, older map[uint64]struct{}
	swapped        time.Time
	gen            uint64
}

// has reports whether a salt came before. With f.access.
func (s *saltMemory) has(salt uint64) bool {
	_, ok := s.current[salt]
	if !ok {
		_, ok = s.older[salt]
	}
	return ok
}

// add remembers a salt. With f.access.
func (s *saltMemory) add(salt uint64, now time.Time) {
	if s.current == nil || len(s.current) >= saltsMax {
		s.turn(now)
	}
	s.current[salt] = struct{}{}
}

func (s *saltMemory) turn(now time.Time) {
	s.older, s.current, s.swapped = s.current, make(map[uint64]struct{}, 1024), now
	s.gen++
}

func (s *saltMemory) age(now time.Time) {
	if s.current != nil && now.Sub(s.swapped) > saltsFor {
		s.turn(now)
	}
}

// sealBuffers hold the backends' answers under salamander on their way out.
var sealBuffers = sync.Pool{New: func() any {
	b := make([]byte, salamanderSalt+maxDatagram)
	return &b
}}

// salamanderSeal puts a datagram under salamander with password, a fresh
// random salt (as a client's) in front, into buf.
func salamanderSeal(buf, password, d []byte) []byte {
	out := buf[:salamanderSalt+len(d)]
	_, _ = rand.Read(out[:salamanderSalt])
	k := salamanderKey(password, out[:salamanderSalt])
	hysteria2.SalamanderXOR(out[salamanderSalt:], d, &k, 0)
	return out
}
