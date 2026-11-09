//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// limClock is a clock that moves only when told, and a sleep that moves it.
type limClock struct{ t time.Time }

func (c *limClock) now() time.Time { return c.t }
func (c *limClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.t = c.t.Add(d)
	return nil
}

// fakeHyLimits are limits with the default numbers, a clock of their own
// (a day after the process started, as a running backend's is: times on
// the monotonic clock are above zero) and a conntrack table far from full.
func fakeHyLimits() (*hyLimits, *limClock) {
	c := &limClock{t: time.Unix(procStart.Unix()+86400, 0)}
	l := newHyLimits()
	l.now, l.sleep = c.now, c.sleep
	l.ctMax = func() (uint64, error) { return 1 << 20, nil }
	return l, c
}

func bg() context.Context { return context.Background() }

// The numbers are the spec's (conn-limit-v1 §5): a change here is a change
// of what a user may do, not a refactoring.
func TestHyLimitDefaults(t *testing.T) {
	want := hyLimitNumbers{tcp: 1024, tcpRate: 30, tcpBurst: 600, tcpWait: 500 * time.Millisecond,
		failRate: 5, failBurst: 100, failDebt: 1024, udp: 256, quietAfter: 10 * time.Second,
		destRate: 100, destBurst: 200, pairs: 1024, lookupRate: 20, lookupBurst: 100}
	if got := newHyLimits().n; got != want {
		t.Fatalf("defaults %+v", got)
	}
	if pairAnswered != 120*time.Second || pairUnanswered != 30*time.Second || refusedFor != 10*time.Second {
		t.Fatal("the pairs' times or the refused numbers' memory")
	}
	if errTooMany.Error() != "too many connections" {
		t.Fatalf("the client compares this text: %q", errTooMany)
	}
}

// TCP at once: 1024 a user, the next refused at once; places come back;
// another user is not touched.
func TestHyLimitsTCPConcurrent(t *testing.T) {
	l, c := fakeHyLimits()
	var dones []func()
	for i := range l.n.tcp {
		done, kind := l.tcpStart(bg(), "u5")
		if kind != "" {
			t.Fatalf("%d: %s", i, kind)
		}
		dones = append(dones, done)
		c.t = c.t.Add(time.Second / 30) // tokens enough
	}
	before := c.t
	if _, kind := l.tcpStart(bg(), "u5"); kind != refusedTCP || c.t != before {
		t.Fatalf("the 1025th: %q, waited %v", kind, c.t.Sub(before))
	}
	if _, kind := l.tcpStart(bg(), "u6"); kind != "" {
		t.Fatalf("another user: %q", kind)
	}
	dones[0]()
	dones[0]() // twice changes nothing
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" {
		t.Fatalf("after one ended: %q", kind)
	} else {
		done()
	}
	if got := l.Refused()["u5"][refusedTCP]; got != 1 {
		t.Fatalf("refused tcp: %d", got)
	}
	for _, d := range dones {
		d()
	}
	if l.users["u5"].tcp != 0 {
		t.Fatalf("places left: %d", l.users["u5"].tcp)
	}
}

// Attempts: the burst, then a wait for the next token (0.5 s at most),
// which a client gone ends at once, giving its place back.
func TestHyLimitsTCPAttempts(t *testing.T) {
	l, c := fakeHyLimits()
	start := c.t
	for i := range 600 {
		done, kind := l.tcpStart(bg(), "u5")
		if kind != "" {
			t.Fatalf("%d of the burst: %s", i, kind)
		}
		done()
	}
	if c.t != start {
		t.Fatal("the burst waited")
	}
	// The next waits for its token: 1/30 s.
	done, kind := l.tcpStart(bg(), "u5")
	if kind != "" || c.t.Sub(start) < time.Second/30-time.Millisecond || c.t.Sub(start) > time.Second/30+time.Millisecond {
		t.Fatalf("after the burst: %q, waited %v", kind, c.t.Sub(start))
	}
	done()
	// Closing gave no token back: the bucket is empty still.
	if got := l.users["u5"].attempts.tokens; got >= 1 {
		t.Fatalf("tokens after the burst's connections closed: %v", got)
	}
	// Time gives them back, up to the burst and no further: after an hour
	// with a stream open, 600 at once and the next one waits.
	held, _ := l.tcpStart(bg(), "u5")
	c.t = c.t.Add(time.Hour)
	hour := c.t
	for i := range 600 {
		done, kind := l.tcpStart(bg(), "u5")
		if kind != "" || c.t != hour {
			t.Fatalf("%d of the burst an hour later: %q, waited %v", i, kind, c.t.Sub(hour))
		}
		done()
	}
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" || c.t == hour {
		t.Fatalf("past the burst an hour later: %q, waited %v", kind, c.t.Sub(hour))
	} else {
		done()
	}
	held()
	// A token further than 0.5 s away: refused without waiting.
	l.users["u5"].attempts = bucket{-20, c.t} // 0.7 s to the next
	before := c.t
	if _, kind := l.tcpStart(bg(), "u5"); kind != refusedRate || c.t != before {
		t.Fatalf("0.7 s away: %q, waited %v", kind, c.t.Sub(before))
	}
	// 0.4 s away: waited.
	l.users["u5"].attempts = bucket{-11, c.t}
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" || c.t.Sub(before) < 390*time.Millisecond || c.t.Sub(before) > 410*time.Millisecond {
		t.Fatalf("0.4 s away: %q, waited %v", kind, c.t.Sub(before))
	} else {
		done()
	}
	// A client gone while it waits: refused, its place back.
	l.users["u5"].attempts = bucket{0, c.t}
	ctx, cancel := context.WithCancel(bg())
	cancel()
	if _, kind := l.tcpStart(ctx, "u5"); kind != refusedRate {
		t.Fatalf("a client gone: %q", kind)
	}
	if l.users["u5"].tcp != 0 {
		t.Fatalf("a client gone kept its place: %d", l.users["u5"].tcp)
	}
	if got := l.Refused()["u5"][refusedRate]; got != 2 {
		t.Fatalf("refused rate: %d", got)
	}
	// Another dial attempt (the next address) takes a token now or none.
	l.users["u5"].attempts = bucket{1, c.t}
	if !l.attempt("u5") || l.attempt("u5") {
		t.Fatal("next attempts")
	}
	// The one waiting holds a place: with the places full of waiters, the
	// next is refused for the place, not queued.
	l.n.tcp = 1
	l.users["u6"] = &limUser{attempts: bucket{0, c.t}, failed: bucket{100, c.t}}
	inWait := make(chan struct{})
	release := make(chan struct{})
	l.sleep = func(context.Context, time.Duration) error { close(inWait); <-release; return errors.New("gone") }
	go l.tcpStart(bg(), "u6")
	<-inWait
	if _, kind := l.tcpStart(bg(), "u6"); kind != refusedTCP {
		t.Fatalf("behind a waiter: %q", kind)
	}
	close(release)
}

// Real waiting: concurrent attempts past the burst wait their tokens, and
// those that would wait more than 0.5 s are refused.
func TestHyLimitsTCPAttemptsWait(t *testing.T) {
	l := newHyLimits()
	for range 600 {
		done, _ := l.tcpStart(bg(), "u5")
		done()
	}
	type res struct {
		kind string
		took time.Duration
	}
	out := make(chan res, 40)
	for range 40 {
		go func() {
			start := time.Now()
			done, kind := l.tcpStart(bg(), "u5")
			if done != nil {
				done()
			}
			out <- res{kind, time.Since(start)}
		}()
	}
	ok, refused := 0, 0
	for range 40 {
		r := <-out
		switch r.kind {
		case "":
			ok++
			if r.took > 700*time.Millisecond {
				t.Errorf("admitted after %v", r.took)
			}
		case refusedRate:
			refused++
		}
	}
	// 30 a second: about 15 in half a second (more when the machine is
	// slow to start them: each waits from its own start).
	if ok < 8 || ok > 26 || refused != 40-ok {
		t.Fatalf("admitted %d, refused %d", ok, refused)
	}
	// A client that leaves ends its wait at once.
	ctx, cancel := context.WithCancel(bg())
	done := make(chan string, 1)
	l.mu.Lock()
	l.users["u5"].attempts = bucket{-10, time.Now()} // a third of a second away
	l.mu.Unlock()
	start := time.Now()
	go func() { _, kind := l.tcpStart(ctx, "u5"); done <- kind }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if kind := <-done; kind != refusedRate || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("a client gone: %q after %v", kind, time.Since(start))
	}
}

// Failed dials: a timeout, ECONNREFUSED and EHOSTUNREACH charge, in debt;
// ENETUNREACH, EPERM, a destination not public and a dial given up do not.
// In debt new ones are refused until it is paid off at 5 a second.
func TestHyLimitsFailedDials(t *testing.T) {
	for _, c := range []struct {
		err    error
		charge bool
	}{
		{syscall.ECONNREFUSED, true},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, true},
		{syscall.EHOSTUNREACH, true},
		{&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, true},
		{context.DeadlineExceeded, true},
		{syscall.ETIMEDOUT, true},
		{syscall.ENETUNREACH, false},
		{syscall.EPERM, false},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EPERM)}, false},
		{context.Canceled, false},
		{&net.OpError{Op: "dial", Err: errNotPublic}, false},
		{errors.New("something else"), false},
	} {
		if got := chargeable(c.err); got != c.charge {
			t.Errorf("%v: charged %v", c.err, got)
		}
	}
	l, c := fakeHyLimits()
	for range 100 {
		l.failedDial("u5", syscall.ECONNREFUSED)
	}
	l.failedDial("u5", syscall.ENETUNREACH) // not charged
	l.failedDial("u5", syscall.EPERM)       // not charged
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" {
		t.Fatalf("at zero, not in debt: %q", kind)
	} else {
		done()
	}
	l.failedDial("u5", syscall.EHOSTUNREACH) // one in debt
	before := c.t
	if _, kind := l.tcpStart(bg(), "u5"); kind != refusedFailed || c.t != before {
		t.Fatalf("in debt: %q, waited %v", kind, c.t.Sub(before))
	}
	if l.users["u5"].tcp != 0 {
		t.Fatal("a refusal for the debt kept its place")
	}
	if _, kind := l.tcpStart(bg(), "u6"); kind != "" {
		t.Fatalf("another user, not in debt: %q", kind)
	}
	c.t = c.t.Add(time.Second) // 5 back: out of debt
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" {
		t.Fatalf("debt paid: %q", kind)
	} else {
		done()
	}
	if got := l.Refused()["u5"][refusedFailed]; got != 1 {
		t.Fatalf("refused failed: %d", got)
	}
	// The debt is bounded.
	for range 10 * 1024 {
		l.failedDial("u7", syscall.ECONNREFUSED)
	}
	if v := l.users["u7"].failed.tokens; v != -1024 {
		t.Fatalf("debt %v", v)
	}
	// Off: nothing charged, nothing refused.
	l.SetConnLimit(false)
	l.failedDial("u8", syscall.ECONNREFUSED)
	if l.users["u8"] != nil {
		t.Fatal("charged while off")
	}
	if done, kind := l.tcpStart(bg(), "u7"); kind != "" {
		t.Fatalf("off: %q", kind)
	} else {
		done()
	}
}

// slotOf gives a user a UDP session.
func slotOf(t *testing.T, l *hyLimits, user string) *udpSlot {
	t.Helper()
	slot, kind, _ := l.udpTake(user, udpID{}, func(error) {})
	if slot == nil {
		t.Fatalf("no slot: %s", kind)
	}
	return slot
}

func destOf(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 443)
}

// refillDest gives the user new-destination tokens enough.
func refillDest(l *hyLimits, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if u := l.users[user]; u != nil {
		u.dests = bucket{l.n.destBurst, l.clock()}
	}
}

func (l *hyLimits) reach(s *udpSlot, ap netip.AddrPort) bool {
	return s.mayReach(ap, monoAt(l.clock()))
}

func (l *hyLimits) pairsOf(user string) (pairs, journal int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.users[user].pairs, len(l.users[user].journal)
}

// The journal of pairs: a pair without an answer counts 30 s after the
// last packet sent, one with an answer 120 s after the last packet either
// way; in a live session and after its end. A long-lived session whose old
// destinations went quiet takes new ones again.
func TestHyLimitsPairJournal(t *testing.T) {
	l, c := fakeHyLimits()
	slot := slotOf(t, l, "u5")
	for i := range 1024 {
		refillDest(l, "u5")
		if !l.reach(slot, destOf(i)) {
			t.Fatalf("pair %d refused", i)
		}
	}
	refillDest(l, "u5")
	if l.reach(slot, destOf(5000)) {
		t.Fatal("pair 1025 admitted")
	}
	if got := l.Refused()["u5"][refusedLive]; got != 1 {
		t.Fatalf("refused live: %d", got)
	}
	// A pair the session has costs nothing new, at the limit too.
	if !l.reach(slot, destOf(3)) {
		t.Fatal("a pair it has refused at the limit")
	}
	// Another session of the user is within the same pairs; another user
	// is not.
	if other := slotOf(t, l, "u5"); l.reach(other, destOf(6000)) {
		t.Fatal("the user's other session got pair 1025")
	}
	if !l.reach(slotOf(t, l, "u6"), destOf(6000)) {
		t.Fatal("another user refused")
	}
	// Half of them answered.
	for i := 0; i < 1024; i += 2 {
		slot.heard(destOf(i), monoAt(c.t))
	}
	// 29 s on: all still held.
	c.t = c.t.Add(29 * time.Second)
	refillDest(l, "u5")
	if l.reach(slot, destOf(5000)) {
		t.Fatal("unanswered pairs gone before 30 s")
	}
	// 31 s on: the unanswered ones are gone, in the live session too.
	c.t = c.t.Add(2 * time.Second)
	refillDest(l, "u5")
	if !l.reach(slot, destOf(5000)) {
		t.Fatal("unanswered pairs still held after 30 s")
	}
	if pairs, _ := l.pairsOf("u5"); pairs != 1024/2+1 {
		t.Fatalf("pairs %d, want %d", pairs, 1024/2+1)
	}
	// A packet either way keeps an answered pair: one sent at 100 s, one
	// heard from at 100 s.
	c.t = c.t.Add(69 * time.Second)
	l.reach(slot, destOf(0))
	slot.heard(destOf(2), monoAt(c.t))
	// The session ends: its pairs live out their time in the journal.
	l.udpPut(slot)
	if pairs, journal := l.pairsOf("u5"); journal != 1024/2 || pairs != 1024/2 {
		// 5000 was unanswered and sent at 31 s: gone at 61 s.
		t.Fatalf("at the session's end: journal %d, pairs %d; want %d", journal, pairs, 1024/2)
	}
	slot2 := slotOf(t, l, "u5")
	c.t = c.t.Add(30 * time.Second) // 130 s: the answered ones of 0 s are gone (120 s), 0 and 2 not (100 s)
	refillDest(l, "u5")
	if !l.reach(slot2, destOf(7000)) {
		t.Fatal("refused with the old pairs gone")
	}
	if pairs, journal := l.pairsOf("u5"); journal != 2 || pairs != 3 {
		t.Fatalf("journal %d, pairs %d; want 2 and 3", journal, pairs)
	}
	c.t = c.t.Add(121 * time.Second)
	l.udpPut(slot2)
	l.mu.Lock()
	l.sweepLocked(c.t.Add(time.Minute))
	left := l.pairs
	l.mu.Unlock()
	if left != 0 {
		t.Fatalf("pairs left in the process: %d", left)
	}
}

// wallStepped is t with its wall clock moved by d and its monotonic reading
// kept, as after an NTP step: time.Time's layout (wall: hasMonotonic, 33
// bits of seconds since 1885, 30 of nanoseconds; ext: the monotonic
// reading), checked below.
func wallStepped(t *testing.T, at time.Time, d time.Duration) time.Time {
	t.Helper()
	type layout struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	if d%time.Second != 0 {
		t.Fatal("whole seconds only")
	}
	out := at
	l := (*layout)(unsafe.Pointer(&out))
	l.wall += uint64(int64(d/time.Second)) << 30
	if out.Unix() != at.Unix()+int64(d/time.Second) || out.Sub(at) != 0 {
		t.Fatalf("time.Time's layout changed: %v, %v", out.Unix()-at.Unix(), out.Sub(at))
	}
	return out
}

// A step back of the wall clock (NTP) holds no pair and no quiet session:
// they age by the monotonic clock, in the live session and in the journal.
func TestHyLimitsWallStep(t *testing.T) {
	l := newHyLimits()
	base := time.Now()
	now := base
	l.now = func() time.Time { return now }
	l.ctMax = func() (uint64, error) { return 1 << 20, nil }
	slot := slotOf(t, l, "u5")
	for i := range 1024 {
		refillDest(l, "u5")
		if !l.reach(slot, destOf(i)) {
			t.Fatalf("pair %d refused", i)
		}
	}
	// 31 s on by the monotonic clock, an hour back by the wall's.
	now = wallStepped(t, base.Add(31*time.Second), -time.Hour)
	refillDest(l, "u5")
	if !l.reach(slot, destOf(5000)) {
		t.Fatal("after a step back of the wall clock, pairs 30 s old still held")
	}
	// The journal too.
	l.udpPut(slot)
	now = wallStepped(t, base.Add(62*time.Second), -2*time.Hour)
	l.mu.Lock()
	l.sweepLocked(now)
	left := l.pairs
	l.mu.Unlock()
	if left != 0 {
		t.Fatalf("pairs left in the journal: %d", left)
	}
	// A session quiet 11 s by the monotonic clock gives way, whatever the
	// wall clock says.
	l.n.udp = 1
	slotOf(t, l, "u7")
	now = wallStepped(t, base.Add(73*time.Second), -3*time.Hour)
	if s, kind, _ := l.udpTake("u7", udpID{number: 2}, func(error) {}); s == nil {
		t.Fatalf("a quiet session held by a step back of the wall clock: %s", kind)
	}
}

// The count of users with pairs (the fair share's divisor at the ceiling)
// is kept as pairs come and go, never by walking the users: it matches the
// users through new pairs, aging, sessions' ends, the journal, the sweep
// and the switch.
func TestHyLimitsWithPairs(t *testing.T) {
	l, c := fakeHyLimits()
	l.ctMax = func() (uint64, error) { return 400, nil } // a ceiling of 100
	check := func(what string) {
		t.Helper()
		l.mu.Lock()
		defer l.mu.Unlock()
		n, pairs := 0, 0
		for _, u := range l.users {
			if u.pairs > 0 {
				n++
			}
			pairs += u.pairs
		}
		if l.withPairs != n || l.pairs != pairs {
			t.Fatalf("%s: with pairs %d, counted %d; pairs %d, counted %d", what, l.withPairs, n, l.pairs, pairs)
		}
	}
	var slots []*udpSlot
	for i := range 30 {
		user := fmt.Sprintf("u%d", i)
		slot := slotOf(t, l, user)
		slots = append(slots, slot)
		for j := range 2 + i%5 { // 120 asked: the ceiling refuses some
			refillDest(l, user)
			l.reach(slot, destOf(i*8+j))
		}
	}
	check("new pairs")
	live := int64(0)
	for _, kinds := range l.Refused() {
		live += kinds[refusedLive]
	}
	if live == 0 {
		t.Fatal("the ceiling refused no one above the share")
	}
	// At the ceiling: refused above the share, admitted below it.
	if !l.reach(slotOf(t, l, "u99"), destOf(4000)) {
		t.Fatal("a user without pairs refused at the ceiling")
	}
	check("at the ceiling")
	for i, slot := range slots {
		if i%2 == 0 {
			l.udpPut(slot)
		}
	}
	check("sessions ended")
	c.t = c.t.Add(31 * time.Second)
	l.mu.Lock()
	l.sweepLocked(c.t)
	l.mu.Unlock()
	check("aged and swept")
	if l.withPairs != 0 {
		t.Fatalf("unanswered pairs 31 s old: %d users with pairs", l.withPairs)
	}
	refillDest(l, "u1")
	l.reach(slotOf(t, l, "u1"), destOf(5000))
	check("one more")
	l.SetConnLimit(false)
	l.mu.Lock()
	l.sweepLocked(c.t)
	l.mu.Unlock()
	check("off")
	if l.pairs != 0 {
		t.Fatalf("off: %d pairs counted", l.pairs)
	}
}

// The process's ceiling, a quarter of nf_conntrack_max: at it, a new pair
// is refused only to those above the fair share; the others get theirs.
func TestHyLimitsCeiling(t *testing.T) {
	l, c := fakeHyLimits()
	ctMax := uint64(400) // a ceiling of 100
	read := 0
	l.ctMax = func() (uint64, error) { read++; return ctMax, nil }
	a, b := slotOf(t, l, "u1"), slotOf(t, l, "u2")
	for i := range 90 {
		refillDest(l, "u1")
		if !l.reach(a, destOf(i)) {
			t.Fatalf("u1 pair %d", i)
		}
	}
	for i := range 10 {
		refillDest(l, "u2")
		if !l.reach(b, destOf(100+i)) {
			t.Fatalf("u2 pair %d", i)
		}
	}
	// 100 pairs: the ceiling. The share is 50.
	refillDest(l, "u1")
	if l.reach(a, destOf(1000)) {
		t.Fatal("u1, above the share, got a pair at the ceiling")
	}
	if got := l.Refused()["u1"][refusedLive]; got != 1 {
		t.Fatalf("refused live: %d", got)
	}
	refillDest(l, "u2")
	if !l.reach(b, destOf(1001)) {
		t.Fatal("u2, below the share, was refused at the ceiling")
	}
	if read != 1 {
		t.Fatalf("nf_conntrack_max read %d times within a minute", read)
	}
	// The ceiling follows nf_conntrack_max, read again each minute.
	ctMax = 4000
	c.t = c.t.Add(time.Minute)
	refillDest(l, "u1")
	if !l.reach(a, destOf(1002)) {
		t.Fatal("refused under a bigger ceiling")
	}
	// Unreadable: a quarter of 65 536.
	l.ctMax = func() (uint64, error) { return 0, errors.New("no file") }
	c.t = c.t.Add(time.Minute)
	l.mu.Lock()
	got := l.ceilingLocked(c.t)
	l.mu.Unlock()
	if got != 16384 {
		t.Fatalf("ceiling without the file: %d", got)
	}
}

// At the ceiling every user's pairs are aged once a second at most, not at
// each new pair: a refused user's packets must not walk the users under
// the limits' lock.
func TestHyLimitsCeilingWalk(t *testing.T) {
	l, c := fakeHyLimits()
	l.ctMax = func() (uint64, error) { return 40, nil } // a ceiling of 10
	a := slotOf(t, l, "u1")
	for i := range 10 {
		l.reach(a, destOf(i))
	}
	l.reach(slotOf(t, l, "u2"), destOf(100)) // at the ceiling, below the share
	for i := range 50 {
		l.reach(a, destOf(200+i)) // refused: above the share
	}
	l.mu.Lock()
	first := l.agedAll
	l.mu.Unlock()
	if first != c.t {
		t.Fatal("the users' pairs were not aged at the ceiling")
	}
	c.t = c.t.Add(500 * time.Millisecond)
	l.reach(a, destOf(300))
	l.mu.Lock()
	again := l.agedAll
	l.mu.Unlock()
	if again != first {
		t.Fatal("every user aged again within a second")
	}
}

// A new session past a user's 256 takes the place of the quietest one,
// silent 10 s both ways; with none quiet it is refused, and the refusal,
// which the client repeats with every datagram, counts once for the
// session's number in 10 s.
func TestHyLimitsEvictQuiet(t *testing.T) {
	l, c := fakeHyLimits()
	var slots []*udpSlot
	ended := map[*udpSlot]error{}
	for i := range 256 {
		var s *udpSlot
		s, _, _ = l.udpTake("u5", udpID{number: uint32(i)}, func(err error) { ended[s] = err })
		if s == nil {
			t.Fatalf("session %d refused", i)
		}
		slots = append(slots, s)
	}
	id := udpID{from: netip.MustParseAddrPort("203.0.113.9:4000"), number: 300}
	if s, kind, first := l.udpTake("u5", id, func(error) {}); s != nil || kind != refusedUDP || !first {
		t.Fatalf("none quiet: %v %q %v", s != nil, kind, first)
	}
	// The client's next datagrams of the session: refused, not counted
	// again; the same number on another connection is another session.
	for range 5 {
		c.t = c.t.Add(time.Second)
		if s, _, first := l.udpTake("u5", id, func(error) {}); s != nil || first {
			t.Fatal("a repeated refusal admitted or counted")
		}
	}
	other := udpID{from: netip.MustParseAddrPort("203.0.113.9:4001"), number: 300}
	if s, _, first := l.udpTake("u5", other, func(error) {}); s != nil || !first {
		t.Fatal("another connection's session of the same number")
	}
	if got := l.Refused()["u5"][refusedUDP]; got != 2 {
		t.Fatalf("refused udp: %d, want 2", got)
	}
	// A number refused, then admitted, is not remembered as refused: its
	// next refusal counts.
	l.udpPut(slots[200])
	if s, _, _ := l.udpTake("u5", other, func(error) {}); s == nil {
		t.Fatal("a free place not taken")
	} else {
		l.udpPut(s)
		slots[200] = slotOf(t, l, "u5")
	}
	if s, _, first := l.udpTake("u5", other, func(error) {}); s != nil || !first {
		t.Fatal("refused again after it was admitted: not counted")
	}
	// 10 s on the number is forgotten: refused still (the sessions are
	// kept loud), counted anew.
	for _, s := range slots {
		s.touch(monoAt(c.t))
	}
	c.t = c.t.Add(5 * time.Second)
	if s, _, first := l.udpTake("u5", id, func(error) {}); s != nil || !first {
		t.Fatal("after 10 s: not counted anew")
	}
	if _, _, first := l.udpTake("u6", id, func(error) {}); first {
		t.Fatal("another user refused")
	}
	// Two go quiet: 11 s and 30 s. The quietest gives way.
	for _, s := range slots {
		s.touch(monoAt(c.t))
	}
	c.t = c.t.Add(30 * time.Second)
	for i, s := range slots {
		switch i {
		case 9: // the quietest: nothing since
		case 7:
			s.touch(monoAt(c.t.Add(-11 * time.Second)))
		case 8:
			s.touch(monoAt(c.t.Add(-9 * time.Second))) // not quiet yet
		default:
			s.touch(monoAt(c.t))
		}
	}
	s, kind, _ := l.udpTake("u5", id, func(error) {})
	if s == nil || kind != "" {
		t.Fatalf("a quiet one did not give way: %q", kind)
	}
	if !errors.Is(ended[slots[9]], errEvicted) || len(ended) != 1 {
		t.Fatalf("ended: %v", ended)
	}
	if l.users["u5"].sessions != 256 {
		t.Fatalf("sessions %d", l.users["u5"].sessions)
	}
	// The next one takes the second quiet one's place; after it none is
	// quiet (9 s is not).
	if s, _, _ := l.udpTake("u5", udpID{number: 301}, func(error) {}); s == nil || !errors.Is(ended[slots[7]], errEvicted) {
		t.Fatal("the second quiet one did not give way")
	}
	if s, _, _ := l.udpTake("u5", udpID{number: 302}, func(error) {}); s != nil || len(ended) != 2 {
		t.Fatal("a session silent 9 s gave way")
	}
	// The one that gave way ends later: its place is given already. Its
	// client's next datagram makes it anew, in place of the next quiet one.
	l.udpPut(slots[9])
	l.udpPut(slots[9])
	if l.users["u5"].sessions != 256 {
		t.Fatalf("an evicted session gave its place twice: %d", l.users["u5"].sessions)
	}
	c.t = c.t.Add(time.Second) // slots[8] is quiet now
	if s, _, _ := l.udpTake("u5", udpID{number: 9}, func(error) {}); s == nil || !errors.Is(ended[slots[8]], errEvicted) {
		t.Fatal("the evicted session's next datagram did not make it anew")
	}
	if got := l.Refused()["u5"]; got[refusedEvicted] != 3 || got[refusedUDP] != 5 {
		t.Fatalf("refused %v", got)
	}
	// One that ends frees its place: the next needs no quiet one.
	l.udpPut(slots[100])
	if s, _, _ := l.udpTake("u5", udpID{number: 400}, func(error) {}); s == nil || len(ended) != 3 {
		t.Fatal("a free place not taken")
	}
	// Off: every session gets a place, none gives way.
	l.SetConnLimit(false)
	if s, _, _ := l.udpTake("u5", udpID{number: 401}, func(error) {}); s == nil || len(ended) != 3 {
		t.Fatal("off: refused, or a session gave way")
	}
}

// A refused session costs no look at the user's sessions until one of them
// can be quiet: the client repeats it with every datagram.
func TestHyLimitsRefusalCheap(t *testing.T) {
	l, c := fakeHyLimits()
	var slots []*udpSlot
	for i := range 256 {
		slots = append(slots, slotOf(t, l, "u5"))
		slots[i].touch(monoAt(c.t.Add(time.Duration(i) * time.Millisecond)))
	}
	l.udpTake("u5", udpID{number: 1000}, func(error) {})
	if want := monoAt(c.t) + int64(10*time.Second); l.users["u5"].noQuiet != want {
		t.Fatalf("no session can be quiet before %v, noted %v", time.Duration(want), time.Duration(l.users["u5"].noQuiet))
	}
	// Until then a refusal reads no session: one made quiet behind the
	// limits' back (never by a packet: times only grow) is not found.
	slots[3].last.Store(monoAt(c.t.Add(-time.Minute)))
	c.t = c.t.Add(9 * time.Second)
	if s, _, _ := l.udpTake("u5", udpID{number: 1001}, func(error) {}); s != nil {
		t.Fatal("the sessions were looked at before one could be quiet")
	}
	c.t = c.t.Add(time.Second)
	s, _, _ := l.udpTake("u5", udpID{number: 1001}, func(error) {})
	if s == nil {
		t.Fatal("not looked at once one can be quiet")
	}
	slots = append(slots, s)
	// The numbers remembered are bounded: past them a refusal counts each
	// time, and nothing grows.
	for _, s := range slots {
		s.touch(monoAt(c.t))
	}
	l.users["u5"].noted = false
	for i := range 3 * refusedKept {
		l.udpTake("u5", udpID{number: uint32(5000 + i)}, func(error) {})
	}
	if n := len(l.users["u5"].refusedIDs); n != refusedKept {
		t.Fatalf("%d numbers remembered", n)
	}
	c.t = c.t.Add(11 * time.Second)
	for _, s := range slots {
		s.touch(monoAt(c.t))
	}
	l.users["u5"].noted = false
	l.udpTake("u5", udpID{number: 1}, func(error) {})
	if n := len(l.users["u5"].refusedIDs); n != 1 {
		t.Fatalf("%d numbers remembered after their time", n)
	}
}

// A packet to a destination the session has a pair with takes neither the
// limits' lock nor memory: only a new pair does.
func TestHyLimitsPacketPath(t *testing.T) {
	l, c := fakeHyLimits()
	slot := slotOf(t, l, "u5")
	if !l.reach(slot, destOf(1)) {
		t.Fatal("refused")
	}
	m := monoAt(c.t)
	l.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		ok := slot.mayReach(destOf(1), m)
		slot.heard(destOf(1), m)
		slot.touch(m)
		done <- ok
	}()
	select {
	case ok := <-done:
		l.mu.Unlock()
		if !ok {
			t.Fatal("refused")
		}
	case <-time.After(2 * time.Second):
		l.mu.Unlock()
		t.Fatal("a packet of a pair the session has took the limits' lock")
	}
	if n := testing.AllocsPerRun(200, func() {
		slot.mayReach(destOf(1), m)
		slot.heard(destOf(1), m)
		slot.touch(m)
	}); n != 0 {
		t.Fatalf("%v allocations a packet", n)
	}
	// An answer from an address the session did not send to makes no pair.
	slot.heard(destOf(77), m)
	if n := slot.age(c.t); n != 1 {
		t.Fatalf("%d pairs", n)
	}
}

// New destinations: 200 at once, then 100 a second; a destination the
// session sent to is not new.
func TestHyLimitsDestinations(t *testing.T) {
	l, c := fakeHyLimits()
	slot := slotOf(t, l, "u5")
	for i := range 200 {
		if !l.reach(slot, destOf(i)) {
			t.Fatalf("destination %d of the burst refused", i)
		}
	}
	if l.reach(slot, destOf(1000)) {
		t.Fatal("destination 201 admitted")
	}
	for i := range 200 {
		if !l.reach(slot, destOf(i)) {
			t.Fatalf("a destination it sent to, %d, refused", i)
		}
	}
	if !l.reach(slotOf(t, l, "u6"), destOf(1000)) {
		t.Fatal("another user refused")
	}
	c.t = c.t.Add(100 * time.Millisecond) // 10 tokens
	ok := 0
	for i := range 20 {
		if l.reach(slot, destOf(2000+i)) {
			ok++
		}
	}
	if ok != 10 {
		t.Fatalf("%d new destinations in 0.1 s, want 10", ok)
	}
	if got := l.Refused()["u5"][refusedDest]; got != 11 {
		t.Fatalf("refused dest: %d", got)
	}
	// A refused destination left no pair behind.
	if pairs, _ := l.pairsOf("u5"); pairs != 210 {
		t.Fatalf("pairs %d", pairs)
	}
}

// Off: nothing is limited, counted or charged, in sessions that began
// under the limits too; on again, the limits are back.
func TestHyLimitsOff(t *testing.T) {
	l, c := fakeHyLimits()
	slot := slotOf(t, l, "u5")
	l.reach(slot, destOf(0))
	l.SetConnLimit(false)
	for i := range 3000 { // past the pairs (1024) and the new destinations (200)
		if !l.reach(slot, destOf(1+i)) {
			t.Fatalf("off: destination %d refused", i)
		}
	}
	for i := range 2000 { // past TCP at once (1024) and the attempts (600)
		if _, kind := l.tcpStart(bg(), "u5"); kind != "" {
			t.Fatalf("off: stream %d: %s", i, kind)
		}
	}
	for i := range 300 { // past the sessions (256)
		if s, kind, _ := l.udpTake("u5", udpID{number: uint32(i)}, func(error) {}); s == nil {
			t.Fatalf("off: session %d: %s", i, kind)
		}
	}
	for range 200 { // past the lookups (100)
		if !l.lookup("u5") {
			t.Fatal("off: a lookup refused")
		}
	}
	if !l.attempt("u5") {
		t.Fatal("off: an attempt refused")
	}
	if got := l.Refused(); len(got) != 0 {
		t.Fatalf("off: refused %v", got)
	}
	l.mu.Lock()
	u := l.users["u5"]
	tokens := []float64{u.attempts.tokens, u.failed.tokens, u.dests.tokens, u.lookups.tokens}
	l.mu.Unlock()
	if tokens[0] != 600 || tokens[1] != 100 || tokens[2] != 199 || tokens[3] != 100 {
		t.Fatalf("off: tokens spent: %v", tokens)
	}
	// On again: the sessions made while off hold places, so the next is
	// refused; TCP begins anew.
	l.SetConnLimit(true)
	if s, kind, _ := l.udpTake("u5", udpID{number: 9999}, func(error) {}); s != nil || kind != refusedUDP {
		t.Fatal("on again: a session past the limit")
	}
	if done, kind := l.tcpStart(bg(), "u5"); kind != "" {
		t.Fatalf("on again: %s", kind)
	} else {
		done()
	}
	// A session that ends while the limits are off leaves no pairs in the
	// journal: switched on again, its user has none.
	u6 := slotOf(t, l, "u6")
	for i := range 3 {
		if !l.reach(u6, destOf(100+i)) {
			t.Fatalf("u6's pair %d refused", i)
		}
		u6.heard(destOf(100+i), monoAt(c.t))
	}
	if pairs, _ := l.pairsOf("u6"); pairs != 3 {
		t.Fatalf("u6's pairs before: %d", pairs)
	}
	l.SetConnLimit(false)
	l.udpPut(u6)
	l.SetConnLimit(true)
	l.mu.Lock()
	l.sweepLocked(c.t) // ages every user: the journal is counted anew
	u6user := l.users["u6"]
	l.mu.Unlock()
	if u6user != nil && (u6user.pairs != 0 || len(u6user.journal) != 0) {
		t.Fatalf("on again after a session ended while off: %d pairs, %d in the journal", u6user.pairs, len(u6user.journal))
	}
}

// Users apart; the names of u5's credentials share u5's limits.
func TestHyLimitsByBaseName(t *testing.T) {
	for name, want := range map[string]string{"u5": "u5", "u5-n": "u5", "u5-p": "u5", "u5-3f2a9c0d1e4b5a67": "u5", "u50": "u50", "alice": "alice",
		// Never "": that is nobody, whom nothing limits.
		"": "-", "-": "-", "-u5": "-u5", "--": "--"} {
		if got := baseName(name); got != want {
			t.Errorf("%q: base %q, want %q", name, got, want)
		}
	}
	l, _ := fakeHyLimits()
	l.n.tcp = 2
	// Streams of three credentials of one user take one user's places.
	for _, name := range []string{"u5-n", "u5-p"} {
		if _, kind := l.tcpStart(bg(), baseName(name)); kind != "" {
			t.Fatalf("%s: %q", name, kind)
		}
	}
	if _, kind := l.tcpStart(bg(), baseName("u5-3f2a9c0d1e4b5a67")); kind != refusedTCP {
		t.Fatalf("the user's third credential: %q", kind)
	}
	if _, kind := l.tcpStart(bg(), baseName("u50-n")); kind != "" {
		t.Fatalf("u50 is not u5: %q", kind)
	}
	if got := l.Refused(); len(got) != 1 || got["u5"][refusedTCP] != 1 {
		t.Fatalf("refused: %v", got)
	}
	// Reading resets nothing, and gives a copy.
	l.Refused()["u5"][refusedTCP] = 100
	if got := l.Refused()["u5"][refusedTCP]; got != 1 {
		t.Fatalf("read again: %d", got)
	}
	// Without a user nothing is limited and nothing kept.
	for range 10 {
		if _, kind := l.tcpStart(bg(), ""); kind != "" {
			t.Fatalf("no user: %q", kind)
		}
	}
	if s, _, _ := l.udpTake("", udpID{}, func(error) {}); s == nil || !s.mayReach(destOf(1), 0) {
		t.Fatal("no user: a session refused")
	} else {
		s.touch(1)
		s.heard(destOf(1), 1)
		l.udpPut(s)
	}
	if _, ok := l.users[""]; ok {
		t.Fatal("no user: state kept")
	}
}

// A user with nothing open, nothing owed and full buckets is forgotten;
// one with anything left is not.
func TestHyLimitsSweep(t *testing.T) {
	l, c := fakeHyLimits()
	done, _ := l.tcpStart(bg(), "open")
	if done, _ := l.tcpStart(bg(), "spent"); done != nil {
		done()
	}
	l.failedDial("debt", syscall.ECONNREFUSED)
	slot := slotOf(t, l, "session")
	paired := slotOf(t, l, "paired")
	l.reach(paired, destOf(1))
	paired.heard(destOf(1), monoAt(c.t))
	l.udpPut(paired)
	l.lookup("lookups")
	for i := range 1000 {
		if d, _ := l.tcpStart(bg(), fmt.Sprintf("u%d", i)); d != nil {
			d()
		}
	}
	// 20 s on: one attempt token is back in 1/30 s, a failure's in 0.2 s,
	// a lookup's in 0.05 s; the pair is held 120 s.
	c.t = c.t.Add(20 * time.Second)
	l.mu.Lock()
	l.sweepLocked(c.t)
	left := map[string]bool{}
	for name := range l.users {
		left[name] = true
	}
	l.mu.Unlock()
	if len(left) != 3 || !left["open"] || !left["session"] || !left["paired"] {
		t.Fatalf("left after the sweep: %v", left)
	}
	done()
	l.udpPut(slot)
	c.t = c.t.Add(101 * time.Second)
	l.tcpStart(bg(), "u1") // any user's coming sweeps, once in 10 s
	l.mu.Lock()
	n := len(l.users)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d users left", n)
	}
}

// The limits hold up under everything at once (the race detector's test).
func TestHyLimitsConcurrent(t *testing.T) {
	l := newHyLimits()
	l.n.udp, l.n.quietAfter = 4, time.Millisecond
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("u%d", g%3)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithCancelCause(bg())
				if done, kind := l.tcpStart(ctx, user); kind == "" {
					l.attempt(user)
					l.failedDial(user, syscall.ECONNREFUSED)
					done()
				}
				if s, _, _ := l.udpTake(user, udpID{number: uint32(g<<16 | i)}, cancel); s != nil {
					m := monoAt(l.clock())
					for j := range 4 {
						if s.mayReach(destOf(g*100+j), m) {
							s.heard(destOf(g*100+j), m)
						}
						s.touch(m)
					}
					if i%3 != 0 {
						l.udpPut(s)
					}
				}
				l.lookup(user)
				if i%50 == 0 {
					l.SetConnLimit(i%100 != 0)
					l.Refused()
				}
				cancel(nil)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	l.SetConnLimit(true)
	l.mu.Lock()
	defer l.mu.Unlock()
	n, pairs := 0, 0
	for _, u := range l.users {
		if u.pairs > 0 {
			n++
		}
		pairs += u.pairs
		if u.tcp != 0 || u.sessions < 0 {
			t.Fatalf("tcp %d, sessions %d left", u.tcp, u.sessions)
		}
	}
	if l.withPairs != n || l.pairs != pairs {
		t.Fatalf("with pairs %d (counted %d), pairs %d (counted %d)", l.withPairs, n, l.pairs, pairs)
	}
}
