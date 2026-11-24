//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/arngory/niko-server/nikoserver/memlimit"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
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
