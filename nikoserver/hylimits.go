//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The per-user connection limits of a Hysteria2 backend (raycontrol
// docs/spec/conn-limit-v1.md §2, §3.2, §5; the model of rayd naive,
// raycontrol v0.24.0): one set per user in the process, by the user's base
// name (u5 for u5 and the names of its credentials, u5-<fingerprint>: a
// rotation does not multiply them). They count what the kernel will hold:
// every TCP attempt, failed dials, UDP pairs even after their session, name
// lookups. A user's tokens outlive their last connection until they have
// refilled: closing gives none back.
//
// Nothing here goes to the log but "too many connections" at debug, without
// a name or a destination; the refusals are counted by base name and kind
// and read on the stats socket (the line traffic).

// hyLimitNumbers are the limits' numbers (§5). They are not configurable
// (§8: neither per user nor numbers); tests make them small.
type hyLimitNumbers struct {
	tcp               int           // TCP at once, dials in flight too
	tcpRate, tcpBurst float64       // attempts: each SYN the node sends for the user
	tcpWait           time.Duration // the wait for an attempt's token; less than the first SYN retry (1 s)
	// Failed dials, paid after the failure, in debt (failDebt bounds it: as
	// many failures as dials in flight).
	failRate, failBurst, failDebt float64
	// UDP sessions at once; a new one past them takes the place of the
	// quietest, one silent both ways for quietAfter.
	udp        int
	quietAfter time.Duration
	// New UDP destinations, all sessions together.
	destRate, destBurst float64
	// Pairs (local port, destination) of UDP, live sessions' and ended
	// ones' until their time runs out.
	pairs int
	// Name lookups (misses of the process's cache), TCP and UDP together.
	lookupRate, lookupBurst float64
}

var hyLimitDefaults = hyLimitNumbers{
	tcp: 1024, tcpRate: 30, tcpBurst: 600, tcpWait: 500 * time.Millisecond,
	failRate: 5, failBurst: 100, failDebt: 1024,
	udp: 256, quietAfter: 10 * time.Second,
	destRate: 100, destBurst: 200,
	pairs:      1024,
	lookupRate: 20, lookupBurst: 100,
}

const (
	// A pair of UDP as conntrack keeps it: 30 s after the last packet sent
	// without an answer, 120 s after the last packet either way with one.
	pairAnswered   = 120 * time.Second
	pairUnanswered = 30 * time.Second
	// ageEvery: a user's pairs are aged this often at most.
	ageEvery = time.Second
	// The process's ceiling of pairs: a quarter of nf_conntrack_max, read
	// again every ceilingEvery; defaultCeiling where it cannot be read.
	ceilingEvery   = time.Minute
	defaultCeiling = 65536 / 4
	// A refused UDP session's number is remembered this long: the client
	// repeats the refusal with every datagram, and it counts once.
	refusedFor = 10 * time.Second
	// refusedKept bounds the numbers remembered for one user; past them a
	// refusal counts each time.
	refusedKept = 1024
)

// The kinds of refusals (§2), counted by base name since the process
// started.
const (
	refusedTCP     = "tcp"     // TCP at once
	refusedRate    = "rate"    // TCP attempts
	refusedFailed  = "failed"  // failed dials in debt
	refusedUDP     = "udp"     // UDP sessions, none quiet to give way
	refusedEvicted = "evicted" // a quiet UDP session gave way
	refusedDest    = "dest"    // new UDP destinations
	refusedLive    = "live"    // UDP pairs
	refusedLookup  = "lookup"  // name lookups
)

var (
	// errTooMany is what a client is told at a limit. Niko compares the
	// text (conn-limit-v1 §4.3): it must not change.
	errTooMany = errors.New("too many connections")
	// errEvicted ends a quiet UDP session for a new one of the same user.
	errEvicted = errors.New("a quiet session gave way to a new one")
)

// procStart is when the process started: the stats socket's uptime, and
// the monotonic clock's zero.
var procStart = time.Now()

// monoAt is t on the monotonic clock: t's monotonic reading where it has
// one (time.Now's), its wall time otherwise (a test's fake clock). The
// pairs' and sessions' times are these: the wall clock may step back, and a
// step back would hold every pair.
func monoAt(t time.Time) int64 { return int64(t.Sub(procStart)) }

// hyLimits are a backend's per-user limits and its cache of names.
type hyLimits struct {
	n hyLimitNumbers

	mu    sync.Mutex
	now   func() time.Time // time.Now when nil (tests: a fake clock)
	sleep func(ctx context.Context, d time.Duration) error
	off   atomic.Bool

	users   map[string]*limUser
	swept   time.Time
	refused map[string]map[string]int64

	// ctMax reads nf_conntrack_max (the file when nil).
	ctMax     func() (uint64, error)
	ceiling   int
	ceilingAt time.Time
	pairs     int // counted pairs of all users
	withPairs int // users with pairs counted: the fair share's divisor
	agedAll   time.Time

	names hyNames
	// resolve looks a name up (the host's resolver when nil).
	resolve func(ctx context.Context, name string) ([]netip.Addr, error)
}

func newHyLimits() *hyLimits { return &hyLimits{n: hyLimitDefaults} }

type limUser struct {
	tcp      int
	sessions int // UDP sessions holding a place
	// slots are the UDP sessions not ended yet: those holding a place, and
	// those that gave way and are ending (their pairs still count).
	slots map[*udpSlot]struct{}
	// attempts, failures (in debt below zero), new UDP destinations,
	// lookups.
	attempts, failed, dests, lookups bucket
	journal                          []int64 // the ends of ended sessions' pairs (monoAt)
	pairs                            int     // counted: live sessions' and the journal's
	aged                             time.Time
	// noQuiet (once noted): no session of the user can have been quiet for
	// quietAfter before this (monoAt), so a refusal until then looks at
	// none of them.
	noQuiet int64
	noted   bool
	// refusedIDs are the session numbers refused and until when (monoAt)
	// each is remembered.
	refusedIDs map[udpID]int64
}

// udpID tells a UDP session of a user: the client's address (its QUIC
// connection) and the session's number in it.
type udpID struct {
	from   netip.AddrPort
	number uint32
}

func (l *hyLimits) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *hyLimits) wait(ctx context.Context, d time.Duration) error {
	if l.sleep != nil {
		return l.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// SetConnLimit turns the limits on or off; what is open stays.
func (l *hyLimits) SetConnLimit(on bool) { l.off.Store(!on) }

// limited reports whether the limits hold for this user now: they are on,
// and there is a user (the outbound driven without one, in tests, is
// limited by nothing).
func (l *hyLimits) limited(user string) bool { return user != "" && !l.off.Load() }

// baseName is whose limits a name takes: u5 for u5 and for the names of its
// credentials (u5-<fingerprint>; u5-n and u5-p before raycontrol v0.23.0).
// Never "", which is nobody's: a name that begins with a dash is its own
// user, and the users without a name are one user, "-".
func baseName(name string) string {
	if b, _, _ := strings.Cut(name, "-"); b != "" {
		return b
	}
	if name == "" {
		return "-"
	}
	return name
}

// userLocked is a user's state, made at first sight with full buckets.
func (l *hyLimits) userLocked(name string, now time.Time) *limUser {
	if now.Sub(l.swept) > 10*time.Second {
		l.sweepLocked(now)
	}
	u := l.users[name]
	if u == nil {
		if l.users == nil {
			l.users = map[string]*limUser{}
		}
		u = &limUser{attempts: bucket{l.n.tcpBurst, now}, failed: bucket{l.n.failBurst, now}, dests: bucket{l.n.destBurst, now},
			lookups: bucket{l.n.lookupBurst, now}}
		l.users[name] = u
	}
	return u
}

// sweepLocked forgets the users with nothing open, nothing owed and full
// buckets, after aging their journals.
func (l *hyLimits) sweepLocked(now time.Time) {
	l.swept = now
	m := monoAt(now)
	for k, u := range l.users {
		l.ageLocked(u, now, true)
		for id, until := range u.refusedIDs {
			if m >= until {
				delete(u.refusedIDs, id)
			}
		}
		if u.tcp == 0 && u.pairs == 0 && len(u.slots) == 0 && len(u.refusedIDs) == 0 &&
			u.attempts.full(now, l.n.tcpRate, l.n.tcpBurst) && u.failed.full(now, l.n.failRate, l.n.failBurst) &&
			u.dests.full(now, l.n.destRate, l.n.destBurst) && u.lookups.full(now, l.n.lookupRate, l.n.lookupBurst) {
			delete(l.users, k)
		}
	}
}

// refuseLocked counts a refusal of the user's.
func (l *hyLimits) refuseLocked(user, kind string) {
	if l.refused == nil {
		l.refused = map[string]map[string]int64{}
	}
	if l.refused[user] == nil {
		l.refused[user] = map[string]int64{}
	}
	l.refused[user][kind]++
}

func (l *hyLimits) refuse(user, kind string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refuseLocked(user, kind)
}

// Refused are the refusals by base name and kind since the process
// started, only names with some. Reading resets nothing.
func (l *hyLimits) Refused() map[string]map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]map[string]int64, len(l.refused))
	for name, kinds := range l.refused {
		k := make(map[string]int64, len(kinds))
		for kind, n := range kinds {
			k[kind] = n
		}
		out[name] = k
	}
	return out
}

// tcpStart takes a place among the user's TCP connections and a token for
// its first attempt, waiting tcpWait at most and no longer than ctx, and
// checks the debt of failed dials. done gives the place back; kind says
// why not ("" with done when admitted). With the limits off, or without a
// user, all pass.
func (l *hyLimits) tcpStart(ctx context.Context, user string) (done func(), kind string) {
	if !l.limited(user) {
		return func() {}, ""
	}
	l.mu.Lock()
	u := l.userLocked(user, l.clock())
	if u.tcp >= l.n.tcp {
		l.refuseLocked(user, refusedTCP)
		l.mu.Unlock()
		return nil, refusedTCP
	}
	u.tcp++
	l.mu.Unlock()
	var once sync.Once
	done = func() {
		once.Do(func() {
			l.mu.Lock()
			u.tcp--
			l.mu.Unlock()
		})
	}
	// Waiting holds the place: a queue of an abuser's would only grow.
	if !l.waitAttempt(ctx, user, u) {
		done()
		return nil, refusedRate
	}
	l.mu.Lock()
	debt := u.failed.level(l.clock(), l.n.failRate, l.n.failBurst) < 0
	if debt {
		l.refuseLocked(user, refusedFailed)
	}
	l.mu.Unlock()
	if debt {
		done()
		return nil, refusedFailed
	}
	return done, ""
}

// waitAttempt takes an attempt token, waiting for one up to tcpWait while
// ctx lasts; a refusal is counted.
func (l *hyLimits) waitAttempt(ctx context.Context, user string, u *limUser) bool {
	start := l.clock()
	for {
		l.mu.Lock()
		now := l.clock()
		if u.attempts.take(now, l.n.tcpRate, l.n.tcpBurst) {
			l.mu.Unlock()
			return true
		}
		// Until the next token comes. A millisecond at least: a float's
		// dust must not spin the loop.
		need := max(time.Millisecond, time.Duration((1-u.attempts.tokens)/l.n.tcpRate*float64(time.Second)))
		if now.Add(need).Sub(start) > l.n.tcpWait || ctx.Err() != nil {
			l.refuseLocked(user, refusedRate)
			l.mu.Unlock()
			return false
		}
		l.mu.Unlock()
		if l.wait(ctx, need) != nil {
			l.refuse(user, refusedRate)
			return false
		}
	}
}

// attempt takes a token for one more attempt of a dial (the next address
// of a name), without waiting.
func (l *hyLimits) attempt(user string) bool {
	if !l.limited(user) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(user, now)
	if !u.attempts.take(now, l.n.tcpRate, l.n.tcpBurst) {
		l.refuseLocked(user, refusedRate)
		return false
	}
	return true
}

// failedDial charges a dial that sent a SYN and got no connection: a
// timeout, ECONNREFUSED, EHOSTUNREACH. ENETUNREACH and EPERM did not send
// one (no route, or raycontrol's guard of the conntrack table refused it),
// nor did a destination that is not public, nor a dial given up: not
// charged.
func (l *hyLimits) failedDial(user string, err error) {
	if err == nil || !l.limited(user) || !chargeable(err) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(user, now)
	u.failed.charge(now, l.n.failRate, l.n.failBurst, l.n.failDebt)
}

// chargeable reports whether a dial's error means a SYN went and nothing
// came of it.
func chargeable(err error) bool {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EPERM), errors.Is(err, context.Canceled),
		errors.Is(err, errNotPublic):
		return false
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH):
		return true
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// lookup takes a token for a name lookup the cache missed.
func (l *hyLimits) lookup(user string) bool {
	if !l.limited(user) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(user, now)
	if !u.lookups.take(now, l.n.lookupRate, l.n.lookupBurst) {
		l.refuseLocked(user, refusedLookup)
		return false
	}
	return true
}

// udpSlot is a UDP session's place and its pairs. A session without a
// user, or with no limits (lim nil), has neither.
type udpSlot struct {
	lim    *hyLimits
	user   string
	cancel context.CancelCauseFunc
	last   atomic.Int64 // monoAt: the last packet either way
	left   bool         // under lim.mu: its place is free (it gave way, or ended)

	mu sync.Mutex
	// peers are where the session sent, and each pair's times: each is a
	// conntrack entry until it ends.
	peers map[netip.AddrPort]pairTimes
	aged  time.Time
}

// pairTimes are a pair's last packet sent, last either way (monoAt), and
// whether an answer came.
type pairTimes struct {
	sent, any int64
	answered  bool
}

// end is when conntrack lets the pair go: 30 s after the last packet sent
// while unanswered, 120 s after the last either way once answered.
func (p pairTimes) end() int64 {
	if p.answered {
		return p.any + int64(pairAnswered)
	}
	return p.sent + int64(pairUnanswered)
}

// udpTake gives a UDP session its place. At the user's limit the quietest
// session, silent both ways for quietAfter, gives way (its context is
// cancelled; the client's next datagram of it makes it anew); with none,
// nil and why. The client repeats a refused session with every datagram:
// the refusal is counted once for its number (first), remembered
// refusedFor, and costs no look at the user's sessions until one of them
// can be quiet. With the limits off every session gets a place, counted
// all the same.
func (l *hyLimits) udpTake(user string, id udpID, cancel context.CancelCauseFunc) (slot *udpSlot, kind string, first bool) {
	if user == "" {
		return &udpSlot{}, "", false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	m := monoAt(now)
	u := l.userLocked(user, now)
	if u.sessions >= l.n.udp && !l.off.Load() {
		var quiet *udpSlot
		if !u.noted || m >= u.noQuiet {
			oldest := m
			for s := range u.slots {
				if s.left {
					continue
				}
				last := s.last.Load()
				oldest = min(oldest, last)
				if time.Duration(m-last) >= l.n.quietAfter && (quiet == nil || last < quiet.last.Load()) {
					quiet = s
				}
			}
			if quiet == nil {
				u.noQuiet, u.noted = oldest+int64(l.n.quietAfter), true
			}
		}
		if quiet == nil {
			if until, ok := u.refusedIDs[id]; !ok || m >= until {
				first = true
				l.refuseLocked(user, refusedUDP)
				l.rememberLocked(u, id, m)
			}
			return nil, refusedUDP, first
		}
		// It stays among the slots until it ends: its pairs count there,
		// then in the journal.
		quiet.left = true
		quiet.cancel(errEvicted)
		u.sessions--
		l.refuseLocked(user, refusedEvicted)
	}
	delete(u.refusedIDs, id)
	s := &udpSlot{lim: l, user: user, cancel: cancel, peers: map[netip.AddrPort]pairTimes{}}
	s.last.Store(m)
	if u.slots == nil {
		u.slots = map[*udpSlot]struct{}{}
	}
	u.slots[s] = struct{}{}
	u.sessions++
	return s, "", false
}

// rememberLocked keeps a refused session's number for refusedFor, within
// refusedKept numbers a user (those whose time ran out go first).
func (l *hyLimits) rememberLocked(u *limUser, id udpID, m int64) {
	if len(u.refusedIDs) >= refusedKept {
		for k, until := range u.refusedIDs {
			if m >= until {
				delete(u.refusedIDs, k)
			}
		}
		if len(u.refusedIDs) >= refusedKept {
			return
		}
	}
	if u.refusedIDs == nil {
		u.refusedIDs = map[udpID]int64{}
	}
	u.refusedIDs[id] = m + int64(refusedFor)
}

// udpPut gives a session's place back (unless it gave way already) and
// moves its pairs to the user's journal, to live out their time there.
func (l *hyLimits) udpPut(s *udpSlot) {
	if s.lim == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(s.user, now)
	if !s.left {
		u.sessions--
	}
	delete(u.slots, s)
	s.left = true
	if ends := s.ends(); !l.off.Load() {
		u.journal = append(u.journal, ends...)
	}
	l.recountLocked(u, now)
}

// touch notes a packet either way: the session is not quiet.
func (s *udpSlot) touch(m int64) { s.last.Store(m) }

// mayReach reports whether the session may send to ap now: a destination
// it has a pair with, or a new one the user's limits let it have
// (newPair). A packet costs the session's own lock and no allocation; the
// limits' lock is taken for a new pair only.
func (s *udpSlot) mayReach(ap netip.AddrPort, m int64) bool {
	l := s.lim
	if l == nil || l.off.Load() {
		return true
	}
	s.mu.Lock()
	t, ok := s.peers[ap]
	if ok {
		t.sent, t.any = m, m
		s.peers[ap] = t
	}
	s.mu.Unlock()
	if ok {
		return true
	}
	// Not under s.mu: the limits age the user's sessions under their lock.
	if !l.newPair(s) {
		return false
	}
	s.mu.Lock()
	s.peers[ap] = pairTimes{sent: m, any: m}
	s.mu.Unlock()
	return true
}

// heard notes an answer from a pair.
func (s *udpSlot) heard(ap netip.AddrPort, m int64) {
	if s.lim == nil {
		return
	}
	s.mu.Lock()
	if t, ok := s.peers[ap]; ok {
		t.any, t.answered = m, true
		s.peers[ap] = t
	}
	s.mu.Unlock()
}

// age drops the pairs whose time ran out, once in ageEvery at most, and
// says how many are left.
func (s *udpSlot) age(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.aged) >= ageEvery {
		s.aged = now
		m := monoAt(now)
		for p, t := range s.peers {
			if m >= t.end() {
				delete(s.peers, p)
			}
		}
	}
	return len(s.peers)
}

// ends are when the session's pairs end, for the user's journal; the
// session keeps none.
func (s *udpSlot) ends() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int64, 0, len(s.peers))
	for _, t := range s.peers {
		out = append(out, t.end())
	}
	clear(s.peers)
	return out
}

// newPair admits a session's new pair (a destination it has no pair with):
// within the user's pairs, the process's ceiling, and a token for a new
// destination. A refusal is counted.
func (l *hyLimits) newPair(s *udpSlot) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(s.user, now)
	l.ageLocked(u, now, false)
	if u.pairs >= l.n.pairs {
		l.refuseLocked(s.user, refusedLive)
		return false
	}
	if c := l.ceilingLocked(now); l.pairs >= c {
		// Every user's pairs aged first: the count may be behind. Once in
		// ageEvery, not at each new pair.
		if now.Sub(l.agedAll) >= ageEvery {
			l.agedAll = now
			for _, x := range l.users {
				l.ageLocked(x, now, true)
			}
		}
		// At the ceiling only those above their fair share are refused.
		if l.pairs >= c && u.pairs > c/max(1, l.withPairs) {
			l.refuseLocked(s.user, refusedLive)
			return false
		}
	}
	if !u.dests.take(now, l.n.destRate, l.n.destBurst) {
		l.refuseLocked(s.user, refusedDest)
		return false
	}
	l.setPairsLocked(u, u.pairs+1)
	return true
}

// setPairsLocked sets a user's count of pairs, and the process's counts:
// its pairs, and how many users have some (the fair share of the ceiling
// is the ceiling over them; counted as it goes, not by walking the users
// at each new pair).
func (l *hyLimits) setPairsLocked(u *limUser, n int) {
	switch {
	case u.pairs == 0 && n > 0:
		l.withPairs++
	case u.pairs > 0 && n == 0:
		l.withPairs--
	}
	l.pairs += n - u.pairs
	u.pairs = n
}

// ceilingLocked is the process's ceiling of pairs: a quarter of the live
// nf_conntrack_max, read again every ceilingEvery.
func (l *hyLimits) ceilingLocked(now time.Time) int {
	if l.ceiling > 0 && now.Sub(l.ceilingAt) < ceilingEvery {
		return l.ceiling
	}
	l.ceilingAt = now
	read := l.ctMax
	if read == nil {
		read = conntrackMax
	}
	if v, err := read(); err == nil && v >= 4 {
		l.ceiling = int(min(v/4, 1<<30))
	} else {
		l.ceiling = defaultCeiling
	}
	return l.ceiling
}

// conntrackMax reads nf_conntrack_max (readable under
// ProtectKernelTunables).
func conntrackMax() (uint64, error) {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// ageLocked ages a user's pairs once in ageEvery (always with force): the
// live sessions' and the journal's, and sets the counts anew.
func (l *hyLimits) ageLocked(u *limUser, now time.Time, force bool) {
	if !force && now.Sub(u.aged) < ageEvery {
		return
	}
	l.recountLocked(u, now)
}

// recountLocked counts a user's pairs from its sessions and the journal.
func (l *hyLimits) recountLocked(u *limUser, now time.Time) {
	u.aged = now
	m := monoAt(now)
	u.journal = slices.DeleteFunc(u.journal, func(end int64) bool { return m >= end })
	n := len(u.journal)
	for s := range u.slots {
		n += s.age(now)
	}
	if l.off.Load() {
		n = 0
	}
	l.setPairsLocked(u, n)
}

// bucket is a token bucket: rate tokens a second, up to burst.
type bucket struct {
	tokens float64
	at     time.Time
}

// level is the tokens now, refilled.
func (b *bucket) level(now time.Time, rate, burst float64) float64 {
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	return b.tokens
}

func (b *bucket) full(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.at).Seconds()*rate >= burst
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.level(now, rate, burst) < 1 {
		return false
	}
	b.tokens--
	return true
}

// charge takes a token in debt: down to -debt.
func (b *bucket) charge(now time.Time, rate, burst, debt float64) {
	b.tokens = max(-debt, b.level(now, rate, burst)-1)
}
