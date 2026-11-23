//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
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
	// the front's share is about an eighth of a core at most. Only an
	// address past the knock reaches the front: a source pays with its
	// own budget.
	trialRate, trialBurst           = 50000, 200000
	trialTotalRate, trialTotalBurst = 500000, 500000
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
	saltsFor = 10 * time.Minute
	saltsMax = 65536
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
	pinned, unmatched, overBudget, replayed, cut atomic.Uint64
}

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
			return nil, fmt.Errorf("more than %d passwords", maxSalamanderPasswords)
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
// the DNS front its zones' auth_keys_file: a file that does not read, or
// not as a list, leaves the list in force, said once.
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
func (f *udpFront) reportDevices(said *[5]uint64) {
	s := &f.devStats
	now := [5]uint64{s.pinned.Load(), s.unmatched.Load(), s.overBudget.Load(), s.replayed.Load(), s.cut.Load()}
	if now == *said {
		return
	}
	*said = now
	f.log.Infof("udp salamander keys: %d flows pinned, %d datagrams opened under none, %d over the trial budget, "+
		"%d Initials sent again, %d flows of keys gone cut, since the start", now[0], now[1], now[2], now[3], now[4])
}

// tryKeys finds the key of a device route that a datagram of no flow
// opens under: to a QUIC Initial (v1, v2) of 1200 bytes or more under
// its salt, or to a packet to the label of the route's backend. Its
// source's keys of the last minutes go first, then the rest, within the
// trial budget; past it the datagram is dropped. It returns the datagram
// opened.
func (f *udpFront) tryKeys(key flowKey, d []byte, now time.Time) (*backendLink, *flowRoute, [][]byte) {
	if len(d) < salamanderSalt+7 {
		return nil, nil, nil
	}
	initial := len(d) >= salamanderSalt+minInitialDatagram
	short := len(d)-salamanderSalt >= minCIDPacket
	want := 0
	for _, r := range f.devices {
		if r.can(initial, short) {
			want += len(r.list())
		}
	}
	if want == 0 {
		return nil, nil, nil
	}
	src := key.client.Addr()
	sk := sourceKey(src)
	f.access.Lock()
	n := f.trialGrant(src, want, now)
	recent := f.recent.get(sk)
	f.access.Unlock()
	if n == 0 {
		f.devStats.overBudget.Add(1)
		return nil, nil, nil
	}
	tried := 0
	var found *flowRoute
	var k [blake2b.Size256]byte
	var kind int
	for _, fr := range recent {
		if fr == nil || tried == n {
			break
		}
		if !fr.device.can(initial, short) {
			continue
		}
		tried++
		if k, kind = fr.device.open(fr, d, initial, short); kind != matchNone {
			found = fr
			break
		}
	}
routes:
	for _, r := range f.devices {
		if found != nil {
			break
		}
		if !r.can(initial, short) {
			continue
		}
		for _, fr := range r.list() {
			if tried == n {
				break routes
			}
			if isRecent(&recent, fr) {
				continue
			}
			tried++
			if k, kind = r.open(fr, d, initial, short); kind != matchNone {
				found = fr
				break routes
			}
		}
	}
	f.access.Lock()
	f.trialReturn(src, n-tried, now)
	ok := found != nil && !found.gone
	switch {
	case !ok:
	case kind == matchInitial:
		if f.salts.seen(binary.LittleEndian.Uint64(d[:salamanderSalt]), now) {
			f.devStats.replayed.Add(1)
			ok = false
		}
	default:
		ok = f.cidSources.allow(src, now)
	}
	if ok {
		f.recent.note(sk, found, now)
	}
	f.access.Unlock()
	if found == nil && tried == n && n < want {
		f.devStats.overBudget.Add(1)
	} else if found == nil {
		f.devStats.unmatched.Add(1)
	}
	if !ok {
		return nil, nil, nil
	}
	out := make([]byte, len(d)-salamanderSalt)
	hysteria2.SalamanderXOR(out, d[salamanderSalt:], &k, 0)
	return found.device.link, found, [][]byte{out}
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

func isRecent(recent *[recentPerSource]*flowRoute, fr *flowRoute) bool {
	for _, x := range recent {
		if x == fr {
			return true
		}
	}
	return false
}

// trialGrant takes up to want trials from src's budget and the front's,
// as many as both hold. With f.access.
func (f *udpFront) trialGrant(src netip.Addr, want int, now time.Time) int {
	sb := f.trialSources.bucket(src, now)
	n := sb.takeUpTo(want, trialRate, trialBurst, now)
	g := f.allTrials.takeUpTo(n, trialTotalRate, trialTotalBurst, now)
	sb.give(n-g, trialBurst)
	return g
}

// trialReturn gives back the trials granted and not made. With f.access.
func (f *udpFront) trialReturn(src netip.Addr, n int, now time.Time) {
	if n > 0 {
		f.trialSources.bucket(src, now).give(n, trialBurst)
		f.allTrials.give(n, trialTotalBurst)
	}
}

// takeUpTo takes up to n, as many whole ones as the bucket holds, and
// returns how many.
func (b *tokenBucket) takeUpTo(n int, rate, burst float64, now time.Time) int {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
	k := max(min(float64(n), b.tokens), 0)
	k = float64(int(k))
	b.tokens -= k
	return int(k)
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
// generations of saltsFor, saltsMax each at most.
type saltMemory struct {
	current, older map[uint64]struct{}
	swapped        time.Time
}

// seen reports whether a salt came before, and remembers it. With
// f.access.
func (s *saltMemory) seen(salt uint64, now time.Time) bool {
	if _, ok := s.current[salt]; ok {
		return true
	}
	if _, ok := s.older[salt]; ok {
		return true
	}
	if s.current == nil || len(s.current) >= saltsMax {
		s.older, s.current, s.swapped = s.current, make(map[uint64]struct{}, 1024), now
	}
	s.current[salt] = struct{}{}
	return false
}

func (s *saltMemory) age(now time.Time) {
	if s.current != nil && now.Sub(s.swapped) > saltsFor {
		s.older, s.current, s.swapped = s.current, make(map[uint64]struct{}, 1024), now
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
