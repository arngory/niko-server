//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/niko-server/nikoserver/memlimit"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-quic/hysteria2"
)

const mib = 1 << 20

// unit is a process in a unit of systemd with MemoryMax max and
// MemoryHigh 7/8 of it (raycontrol memory-v1 §4) on a host of 16 GiB.
func unit(max int64) memlimit.Limits {
	return memlimit.Limits{Max: max, High: max / 8 * 7, MemTotal: 16 << 30}
}

// At its start a process takes a Go memory limit from its cgroup's, a
// backend 7/8 and the front 3/4 of the less of high and 15/16 of max,
// unless GOMEMLIMIT is set or the cgroup has no limit below the host; one
// line in the log says so, with the figures and nothing else.
func TestSetMemoryLimit(t *testing.T) {
	for _, c := range []struct {
		name  string
		front bool
		env   string
		l     memlimit.Limits
		want  int64
		line  string
	}{
		{"backend", false, "", unit(1 << 30), 784 * mib,
			"memory: cgroup's memory.max 1024 MiB, memory.high 896 MiB, host 16384 MiB: Go memory limit 784 MiB (the backend's 7/8"},
		{"front", true, "", unit(1 << 30), 672 * mib,
			"memory: cgroup's memory.max 1024 MiB, memory.high 896 MiB, host 16384 MiB: Go memory limit 672 MiB (the front's 3/4"},
		{"max only", false, "", memlimit.Limits{Max: 512 * mib, MemTotal: 16 << 30}, 420 * mib,
			"memory.max 512 MiB, memory.high none, host 16384 MiB: Go memory limit 420 MiB"},
		{"small", true, "", unit(64 * mib), 64 * mib, "Go memory limit 64 MiB"},
		{"GOMEMLIMIT", false, "512MiB", unit(1 << 30), 0, ""},
		{"no limit", false, "", memlimit.Limits{MemTotal: 16 << 30}, 0, ""},
		{"above the host", false, "", unit(32 << 30), 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out syncBuffer
			log := NewLogger("info", &out)
			var set []int64
			getenv := func(k string) string {
				if k == "GOMEMLIMIT" {
					return c.env
				}
				return ""
			}
			got := setMemoryLimit(log, c.front, c.l, getenv, func(n int64) int64 { set = append(set, n); return 0 })
			if got != c.want || c.want > 0 && (len(set) != 1 || set[0] != c.want) || c.want == 0 && len(set) > 0 {
				t.Fatalf("set %v, returned %d, want %d", set, got, c.want)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			switch {
			case c.line == "" && out.String() != "":
				t.Fatalf("logged %q", out.String())
			case c.line != "" && (len(lines) != 1 || !strings.Contains(lines[0], c.line)):
				t.Fatalf("logged %q, want one line with %q", out.String(), c.line)
			}
		})
	}
}

// The budgets from the same limits: Hysteria2's 3/8 of the unit's limit
// (2 GiB at most), Yggdrasil's exits' a third (4 GiB at most) and as many
// exits as a quarter of it has floors for (4096 at most); without a limit
// below the host, an eighth and a quarter of MemTotal as before, the
// exits 4096 at most as many as a quarter of MemTotal has floors for.
func TestMemoryBudgets(t *testing.T) {
	for _, c := range []struct {
		name      string
		l         memlimit.Limits
		hy, exits int64
		n         int
	}{
		// MemoryMax 512 MiB, 1, 2 and 4 GiB, MemoryHigh 7/8 of it: the
		// limit is the high, 448, 896, 1792 and 3584 MiB.
		{"512 MiB", unit(512 * mib), 168 * mib, 448 * mib / 3, 1194},
		{"1 GiB", unit(1 << 30), 336 * mib, 896 * mib / 3, 2389},
		{"2 GiB", unit(2 << 30), 672 * mib, 1792 * mib / 3, 4096},
		{"4 GiB", unit(4 << 30), 1344 * mib, 3584 * mib / 3, 4096},
		{"MemoryMax 512 MiB alone", memlimit.Limits{Max: 512 * mib, MemTotal: 16 << 30}, 192 * mib, 512 * mib / 3, 1365},
		{"8 GiB", unit(8 << 30), 2 << 30, 7168 * mib / 3, 4096},
		{"16 GiB", unit(16 << 30), 2 << 30, 4 << 30, 4096},
		{"host 1 GiB", memlimit.Limits{MemTotal: 1 << 30}, 128 * mib, 256 * mib, 2730},
		{"host 64 GiB", memlimit.Limits{MemTotal: 64 << 30}, 2 << 30, 4 << 30, 4096},
		{"host 128 MiB", memlimit.Limits{MemTotal: 128 * mib}, 32 * mib, 64 * mib, 341},
		{"nothing known", memlimit.Limits{}, 32 * mib, 64 * mib, 4096},
	} {
		if got := hyBudgetFor(c.l); got != c.hy {
			t.Errorf("%s: Hysteria2's budget %d MiB, want %d MiB", c.name, got/mib, c.hy/mib)
		}
		if got := exitBudgetFor(c.l); got != c.exits {
			t.Errorf("%s: the exits' budget %d MiB, want %d MiB", c.name, got/mib, c.exits/mib)
		}
		if got := exitsFor(c.l); got != c.n {
			t.Errorf("%s: %d exits, want %d", c.name, got, c.n)
		}
		// In a unit, the exits' budget and floors fit in 7/12 of its limit.
		if n := c.l.Limit(); n > 0 && exitBudgetFor(c.l)+int64(exitsFor(c.l))*(yggExitSendFloor+yggExitRecvFloor) > n/12*7+12 {
			t.Errorf("%s: the exits' budget and floors past 7/12 of the limit", c.name)
		}
	}
}

// The floors of the authenticated connections are in the budget: taken
// from it when each authenticates, not from its user's share, shortening
// what the others may grow by, and given back when it ends; a budget short
// of one has the others give back first (pressure), and refuses only when
// that did not make room.
func TestHyMemFloors(t *testing.T) {
	var out syncBuffer
	m := newHyMem(2*hyFloor+256<<10, NewLogger("warn", &out)) // two floors and 256 KiB, shares of 480 KiB
	m.floorsIn = true
	ends := make([]chan struct{}, 4)
	for i := range ends {
		ends[i] = make(chan struct{})
	}
	s0 := m.sender(ends[0], "u1", &fakeCC{cwnd: 8 << 20})
	m.sender(ends[1], "u2", &fakeCC{cwnd: 8 << 20})
	if !m.takeFloor(ends[0], nil) || !m.takeFloor(ends[0], nil) || !m.takeFloor(ends[1], nil) {
		t.Fatal("two floors refused in a budget of two and more")
	}
	if m.floors != 2*hyFloor || m.grown != 0 {
		t.Fatalf("floors %d, grown %d: a floor taken twice, or as growth", m.floors, m.grown)
	}
	// What is left past the floors is all a sender grows by, though its
	// share is more.
	for i := 0; i < 8; i++ {
		s0.CanSend(congestion.ByteCount(s0.limit.Load()))
		s0.shortUntil.Store(0)
	}
	if took := s0.limit.Load() - hySendFloor; took != 256<<10 {
		t.Fatalf("past the floors a sender grew by %d KiB, want the 256 KiB left", took>>10)
	}
	// A third connection: the budget is short. s0 sends nothing and holds
	// nothing in flight: it gives back what it grew by, which makes no
	// floor. Refused, warned once.
	s0.lastSent.Store(int64(monotime.Now().Add(-2 * hyMemIdle)))
	s0.inFlight.Store(0)
	m.mu.Lock()
	m.reclaimed = time.Time{} // s0's own sweep, short, was just now
	m.mu.Unlock()
	m.sender(ends[2], "u3", &fakeCC{cwnd: 8 << 20})
	if m.takeFloor(ends[2], nil) {
		t.Fatal("a floor past the budget taken")
	}
	if s0.limit.Load() != hySendFloor {
		t.Fatalf("short of a floor, the others kept %d KiB they did not need", (s0.limit.Load()-hySendFloor)>>10)
	}
	if n := strings.Count(out.String(), "floors and windows at the node's budget"); n != 1 {
		t.Fatalf("%d warnings: %q", n, out.String())
	}
	// One ends: its floor comes back, and a newcomer has it.
	close(ends[1])
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		m.mu.Lock()
		f := m.floors
		m.mu.Unlock()
		if f == hyFloor {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("an ended connection's floor kept: %d", f)
		}
	}
	m.sender(ends[3], "u3", &fakeCC{cwnd: 8 << 20})
	if !m.takeFloor(ends[3], nil) {
		t.Fatal("a floor given back, yet refused")
	}
	// A budget of two floors: the first grown by its share (448 KiB), the
	// budget is short of a second floor by that; the first, idle, gives
	// it back and the floor is taken: pressure before refusal.
	m2 := newHyMem(2*hyFloor, nil)
	m2.floorsIn = true
	e0, e1 := make(chan struct{}), make(chan struct{})
	defer close(e0)
	defer close(e1)
	g := m2.sender(e0, "u1", &fakeCC{cwnd: 8 << 20})
	if !m2.takeFloor(e0, nil) {
		t.Fatal("the first floor refused")
	}
	for i := 0; i < 8; i++ {
		g.CanSend(congestion.ByteCount(g.limit.Load()))
		g.shortUntil.Store(0)
	}
	if g.limit.Load() == hySendFloor {
		t.Fatal("the first never grew")
	}
	g.lastSent.Store(int64(monotime.Now().Add(-2 * hyMemIdle)))
	g.inFlight.Store(0)
	m2.sender(e1, "u2", &fakeCC{cwnd: 8 << 20})
	if !m2.takeFloor(e1, nil) {
		t.Fatal("an idle connection's growth not given back for a floor")
	}
	if g.limit.Load() != hySendFloor {
		t.Fatalf("the idle one kept %d", g.limit.Load()-hySendFloor)
	}
	for _, e := range []chan struct{}{ends[0], ends[2], ends[3]} {
		close(e)
	}
	waitReleased(t, m)
}

// A backend whose budget has one floor and a half takes one connection;
// the next, its password good, is closed before its auth's answer and
// counted as memory; one more once the first ended gets in.
func TestHysteriaFloorsWithinBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	var out syncBuffer
	mem := newHyMem(hyFloor+hyFloor/2, NewLogger("warn", &out))
	mem.floorsIn = true
	node := hy2MasqNode(t, ctx, lim, mem, "u1", "password-one", "u2", "password-two")
	// dial authenticates; refused: the server closes the connection
	// before its auth's answer, and the client gets no 233.
	dial := func(password string, refused bool) *rawHy2 {
		t.Helper()
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		st, err := r.tryAuth(password, 0)
		if refused && err == nil {
			t.Fatalf("refused, yet answered %d", st)
		}
		if !refused && (err != nil || st != 233) {
			t.Fatalf("auth %d, %v", st, err)
		}
		return r
	}
	closed := func(r *rawHy2, within time.Duration) bool {
		select {
		case <-r.conn.Context().Done():
			return true
		case <-time.After(within):
			return false
		}
	}
	first := dial("password-one", false)
	second := dial("password-two", true)
	if !closed(second, 5*time.Second) {
		t.Fatal("a connection past the budget's floors stayed")
	}
	if closed(first, 0) {
		t.Fatal("the first closed")
	}
	if n := node.traffic(t).Limit["u2"]["memory"]; n != 1 {
		t.Fatalf("memory refusals %d, want 1", n)
	}
	first.conn.CloseWithError(0, "")
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		mem.mu.Lock()
		f := mem.floors
		mem.mu.Unlock()
		if f == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first's floor kept")
		}
	}
	third := dial("password-two", false)
	if closed(third, time.Second) {
		t.Fatal("a floor given back, yet the next closed")
	}
	if n := strings.Count(out.String(), "floors and windows at the node's budget"); n != 1 {
		t.Fatalf("%d warnings: %q", n, out.String())
	}
	third.conn.CloseWithError(0, "")
	waitReleased(t, mem)
}

// Yggdrasil's exits at once are as many as a quarter of the limit has
// floors for: in a unit of 512 MiB (its high 448 MiB) 1194; a place frees
// when one ends.
func TestYggExitsBound(t *testing.T) {
	c := newYggExitCount()
	c.max = exitsFor(unit(512 * mib))
	if c.max != 1194 {
		t.Fatalf("bound %d", c.max)
	}
	who := func(i int) yggExitSource {
		return yggExitSource{key: [32]byte{byte(i >> 8), byte(i)}, user: "u" + string(rune('a'+i%26))}
	}
	n := 0
	for i := 0; i < 2*c.max; i++ {
		if c.take(who(i)) {
			c.shook(who(i))
			n++
		}
	}
	if n != c.max {
		t.Fatalf("%d exits taken, the bound %d", n, c.max)
	}
	c.done(who(0), nil)
	if !c.take(who(0)) {
		t.Fatal("a place freed, yet refused")
	}
}

// A user's floors are a quarter of the budget at most, one connection's at
// least; past it a connection of its own is refused, others' are not, and
// one that replaces a connection of its user's takes over that one's
// floor, whatever the budget or the quarter. Without a cgroup limit
// (floorsIn off) the floors stay outside the budget, as before v0.19.3.
func TestHyMemFloorsPerUser(t *testing.T) {
	m := newHyMem(8*hyFloor, nil) // a user's quarter: two floors
	m.floorsIn = true
	var ends []chan struct{}
	conn := func(user string) chan struct{} {
		e := make(chan struct{})
		ends = append(ends, e)
		m.sender(e, user, &fakeCC{cwnd: 8 << 20})
		return e
	}
	a, b, c := conn("u1"), conn("u1"), conn("u1")
	if !m.takeFloor(a, nil) || !m.takeFloor(b, nil) {
		t.Fatal("a user's floors within its quarter refused")
	}
	if m.takeFloor(c, nil) {
		t.Fatal("a user's floors past its quarter taken")
	}
	if !m.takeFloor(conn("u2"), nil) {
		t.Fatal("another user's floor refused")
	}
	// c replaces a: a's floor passes to c.
	if !m.takeFloor(c, a) {
		t.Fatal("a replacement refused")
	}
	m.mu.Lock()
	floors, byU1, aFloor := m.floors, m.floorsBy["u1"], m.conns[a].floor
	m.mu.Unlock()
	if floors != 3*hyFloor || byU1 != 2*hyFloor || aFloor {
		t.Fatalf("after the replacement: floors %d, u1's %d, the replaced one's kept %v", floors/hyFloor, byU1/hyFloor, aFloor)
	}
	// Not another user's: u2 cannot take u1's floor.
	d := conn("u2")
	m.budget = 3 * hyFloor // full
	if m.takeFloor(d, b) {
		t.Fatal("a floor passed between users")
	}
	for _, e := range ends {
		close(e)
	}
	waitReleased(t, m)

	// Without a cgroup limit: no floor taken, whatever the budget.
	off := newHyMemFor(memlimit.Limits{MemTotal: 1 << 30}, nil)
	if off.floorsIn || off.budget != 128*mib {
		t.Fatalf("no limit: floors in %v, budget %d", off.floorsIn, off.budget)
	}
	e := make(chan struct{})
	for range 200 { // 350 MiB of floors past a budget of 128 MiB
		if !off.takeFloor(e, nil) {
			t.Fatal("no limit, yet a floor refused")
		}
	}
	if off.floors != 0 {
		t.Fatalf("no limit, floors %d", off.floors)
	}
	close(e)
	if on := newHyMemFor(unit(1<<30), nil); !on.floorsIn || on.budget != 336*mib {
		t.Fatalf("a limit: floors in %v, budget %d", on.floorsIn, on.budget)
	}
}

// The budget full, a user at its limit of connections reconnects from the
// same device: its new connection takes the old one's place and floor,
// and the old one closes; another user's still finds no room.
func TestHysteriaFloorReplaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.conns = 1
	mem := newHyMem(hyFloor+hyFloor/2, nil)
	mem.floorsIn = true
	node := hy2MasqNode(t, ctx, lim, mem, "u1", "password-one", "u2", "password-two")
	dial := func(password string) (*rawHy2, bool) {
		t.Helper()
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		st, err := r.tryAuth(password, 0)
		return r, err == nil && st == 233
	}
	closed := func(r *rawHy2, within time.Duration) bool {
		select {
		case <-r.conn.Context().Done():
			return true
		case <-time.After(within):
			return false
		}
	}
	old, ok := dial("password-one")
	if !ok {
		t.Fatal("the first refused")
	}
	if _, ok := dial("password-two"); ok {
		t.Fatal("past the budget, another user's admitted")
	}
	next, ok := dial("password-one")
	if !ok {
		t.Fatal("the budget full, a replacement refused")
	}
	if !closed(old, 5*time.Second) {
		t.Fatal("the replaced connection stayed")
	}
	if closed(next, 500*time.Millisecond) {
		t.Fatal("the replacement closed")
	}
	tr := node.traffic(t)
	if tr.Limit["u1"]["conns"] != 1 || tr.Limit["u1"]["memory"] != 0 || tr.Limit["u2"]["memory"] != 1 {
		t.Fatalf("refusals %v", tr.Limit)
	}
	mem.mu.Lock()
	floors := mem.floors
	mem.mu.Unlock()
	if floors != hyFloor {
		t.Fatalf("floors %d after the replacement", floors)
	}
	next.conn.CloseWithError(0, "")
	waitReleased(t, mem)
}

// A connection is admitted only once its hook said yes: another auth
// request of it meanwhile waits, and gets no 233 when the hook refuses;
// a TCP stream sent right after the auth, before the answer, is reset and
// never dials, whatever the hook says. Before, the second request was
// answered at once and the stream dialled while the hook ran.
func TestHysteriaAdmittedOnlyAfterTheHook(t *testing.T) {
	for _, refuse := range []bool{true, false} {
		t.Run(map[bool]string{true: "refused", false: "admitted"}[refuse], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var dialled atomic.Int32
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					dialled.Add(1)
					c.Close()
				}
			}()
			mem := newHyMem(1<<30, nil)
			if refuse {
				mem = newHyMem(hyFloor/2, nil) // no floor fits: every connection refused
			}
			mem.floorsIn = true
			// The service slow between its connDone and the connection's
			// close (where it logs the close): a request that returned
			// there would have http3 answer 200 before the close.
			var slow log.ContextLogger = slowCloseLogger{nopLogger()}
			serviceLogger.Store(&slow)
			defer serviceLogger.Store(nil)
			node := hy2MasqNode(t, ctx, nil, mem, "u1", "password-one")
			admitDelay.Store(int64(400 * time.Millisecond))
			defer admitDelay.Store(0)
			r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			st := make([]int, 2)
			start := time.Now()
			var second time.Duration
			for i := range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if i == 1 {
						time.Sleep(50 * time.Millisecond)
					}
					st[i], _ = r.tryAuth("password-one", 0)
					if i == 1 {
						second = time.Since(start)
					}
				}()
			}
			// A stream while the hook runs: its request at once.
			time.Sleep(100 * time.Millisecond)
			r.stream(t, ln.Addr().String())
			wg.Wait()
			t.Logf("statuses %v, the second after %v", st, second.Round(time.Millisecond))
			time.Sleep(200 * time.Millisecond)
			if n := dialled.Load(); n != 0 {
				t.Errorf("a stream sent before the admission dialled %d times", n)
			}
			if refuse && (st[0] != 0 || st[1] != 0) {
				t.Fatalf("a refused connection answered: %v", st)
			}
			if !refuse && (st[0] != 233 || st[1] != 233 || second < 300*time.Millisecond) {
				t.Fatalf("admitted: statuses %v, the second answered after %v, before the hook", st, second)
			}
			if !refuse {
				// Once admitted, a stream goes through.
				s := r.stream(t, ln.Addr().String())
				defer s.Close()
				for deadline := time.Now().Add(5 * time.Second); dialled.Load() == 0; time.Sleep(10 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatal("after the admission a stream never dialled")
					}
				}
			}
		})
	}
}

// The budget full and the user under its limit of connections (or the
// limits off): a device that reconnects (after a change of network, its
// old connection not yet idled out) takes its old connection's place and
// floor, counted as memory; another user's newcomer is still refused.
func TestHysteriaFloorReconnectUnderLimit(t *testing.T) {
	for _, off := range []bool{false, true} {
		t.Run(map[bool]string{false: "limits on", true: "limits off"}[off], func(t *testing.T) {
			m := newHyMem(2*hyFloor, nil) // two floors in all
			m.floorsIn = true
			u := newHy2Users()
			u.limits, u.mem = newHyLimits(), m // 16 connections a user
			u.limits.SetConnLimit(!off)
			u.set([]string{"u1-a", "u2-a", "u3-a"}, []string{"p1", "p2", "p3"}, func([]*hy2User, []string) {})
			hook := connectionHook(u, &sessions{})
			var ends []chan struct{}
			conn := func(p, name string) (ok bool, closed *atomic.Bool) {
				done := make(chan struct{})
				ends = append(ends, done)
				closed = new(atomic.Bool)
				m.sender(done, baseName(name), &fakeCC{cwnd: 1 << 20})
				ok = hook(&net.UDPAddr{}, u.byPass[p], func() hysteria2.ConnectionStats { return hysteria2.ConnectionStats{} },
					func() { closed.Store(true) }, done)
				return ok, closed
			}
			ok1, old := conn("p1", "u1-a")
			ok2, _ := conn("p2", "u2-a")
			if !ok1 || !ok2 {
				t.Fatal("two floors in a budget of two refused")
			}
			if ok, _ := conn("p3", "u3-a"); ok {
				t.Fatal("a third user's past the budget admitted")
			}
			ok3, _ := conn("p1", "u1-a") // the same device, reconnected
			if !ok3 || !old.Load() {
				t.Fatalf("the device's reconnect admitted %v, its old connection closed %v", ok3, old.Load())
			}
			r := u.limits.Refused()
			if r["u1"]["memory"] != 1 || r["u3"]["memory"] != 1 || r["u1"]["conns"] != 0 {
				t.Fatalf("refusals %v", r)
			}
			m.mu.Lock()
			floors := m.floors
			m.mu.Unlock()
			if floors != 2*hyFloor {
				t.Fatalf("floors %d", floors/hyFloor)
			}
			for _, e := range ends {
				close(e)
			}
			waitReleased(t, m)
		})
	}
}

// slowCloseLogger is a service's logger that takes 100 ms over the line of
// a connection closed by the server.
type slowCloseLogger struct{ log.ContextLogger }

func (l slowCloseLogger) Debug(args ...any) {
	if strings.Contains(fmt.Sprint(args...), "closed by the server") {
		time.Sleep(100 * time.Millisecond)
	}
	l.ContextLogger.Debug(args...)
}
