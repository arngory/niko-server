//go:build linux

package nikoserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iwn "github.com/Arceliar/ironwood/network"
	iwt "github.com/Arceliar/ironwood/types"
)

// Links the filter keeps alive (yggLinkFilter.answer). An ironwood peer
// that sends a frame ends the link unless some frame comes back within 3 s
// (iw: peers.go:140-181); a frame the filter dropped got none, and the
// links of idle clients went: when another client looked one up, sprayed
// paths at the node, or, with no one at fault, when the tree's root left
// and stale paths led to another client (review of v0.15.0). Each case
// keeps the isolation: nothing from one client reaches another.

// iwKeys are n keys, the least first.
func iwKeys(n int) []ed25519.PrivateKey {
	var keys []ed25519.PrivateKey
	for range n {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y ed25519.PrivateKey) int { return bytes.Compare(x[32:], y[32:]) })
	return keys
}

// filtered is a client's link to the node N through the filter.
func filtered(n *iwn.PacketConn, client *iwn.PacketConn, dropped *atomic.Uint64, lie func([]byte) []byte) iwClient {
	return iwClient{lie: lie, filter: &yggLinkFilter{
		rule: yggRule{node: [32]byte(iwKey(n)), key: [32]byte(iwKey(client)), groups: noGroup}, dropped: dropped}}
}

// reach has from send to to until it arrives.
func (n *iwNet) reach(from, to *iwn.PacketConn, d time.Duration) bool {
	return waitFor(d, func() bool {
		_, _ = from.WriteTo([]byte("hello"), iwt.Addr(iwKey(to)))
		return n.received(to, from)
	})
}

// stays: the link of each client stays up for d, checked each 50 ms, while
// do runs and until it says done.
func (n *iwNet) stays(d time.Duration, do func() (done bool), clients ...*iwn.PacketConn) {
	n.t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		done := do()
		for i, c := range clients {
			if !n.up(c) {
				n.t.Fatalf("client %d's link went", i)
			}
		}
		if done {
			return
		}
	}
}

// trafficTo rewrites a client's traffic as a client that lies would: to
// dest (when set), on the tree path of a port and with a fresh watermark
// (when path is set and not 0), from the coordinates of a port (when from
// is set and not 0).
func trafficTo(dest *[32]byte, path, from *atomic.Uint64) func([]byte) []byte {
	return func(frame []byte) []byte {
		if frame[0] != yggTraffic {
			return frame
		}
		afterPath, _ := yggSkipPath(frame[1:])
		p := frame[1 : len(frame)-len(afterPath)]
		afterFrom, _ := yggSkipPath(afterPath)
		f := afterPath[:len(afterPath)-len(afterFrom)]
		keys := slices.Clone(afterFrom[:64])
		payload, _ := yggSkipUint(afterFrom[64:])
		watermark := afterFrom[64 : len(afterFrom)-len(payload)]
		if dest != nil {
			copy(keys[32:], dest[:])
		}
		if path != nil && path.Load() != 0 {
			p, watermark = iwPath(nil, path.Load()), binary.AppendUvarint(nil, ^uint64(0))
		}
		if from != nil && from.Load() != 0 {
			f = iwPath(nil, from.Load())
		}
		return slices.Concat([]byte{yggTraffic}, p, f, keys, watermark, payload)
	}
}

// deadLink is B's link to N through the filter, which can die as a TCP
// connection does without a word: B's side gone, N's side open and
// quiet, what N writes to it swallowed. kill does that; gone says whether
// N has ended its side.
func deadLink(N, B *iwn.PacketConn, f *yggLinkFilter) (kill func(), gone func() bool) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	f1, f2 := net.Pipe()
	var dead, ended atomic.Bool
	go func() {
		_ = N.HandleConn(iwKey(B), b1, 0)
		ended.Store(true)
		f1.Close()
		f2.Close()
		f.close()
	}()
	go func() { _ = B.HandleConn(iwKey(N), a1, 0) }()
	f.attach(b2, f2)
	go f.client.run(f.done)
	go func() { _ = f.up(f2) }()
	go func() { _ = f.copy(&f.client, b2, false) }()
	go func() { // B to the filter, until dead
		buf := make([]byte, 1<<16)
		for {
			n, err := a2.Read(buf)
			if err != nil || dead.Load() {
				return
			}
			if _, err := f1.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() { // the filter to B, swallowed once dead
		buf := make([]byte, 1<<16)
		for {
			n, err := f1.Read(buf)
			if err != nil {
				return
			}
			if !dead.Load() {
				_, _ = a2.Write(buf[:n])
			}
		}
	}()
	return func() {
		dead.Store(true)
		a1.Close()
		a2.Close()
	}, ended.Load
}

func TestNekoServerYggFilterLiveness(t *testing.T) {
	// A looks B up (by its key): N passes the lookup to B's link, the filter
	// drops it. B, idle, stays; it gets no lookup with A's key.
	t.Run("a lookup of an idle client", func(t *testing.T) {
		t.Parallel()
		keys := iwKeys(3)
		n := &iwNet{t: t}
		N, A, B := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
		var dA, dB atomic.Uint64
		n.link(A, N, filtered(N, A, &dA, nil))
		n.link(B, N, filtered(N, B, &dB, nil))
		for _, c := range []*iwn.PacketConn{A, B} {
			if !n.reach(c, N, 15*time.Second) {
				t.Fatal("a client never reached N")
			}
		}
		time.Sleep(time.Second)
		n.stays(8*time.Second, func() bool {
			_, _ = A.WriteTo([]byte("x"), iwt.Addr(iwKey(B)))
			return false
		}, A, B)
		if dB.Load() == 0 {
			t.Error("nothing dropped on B's link: no lookup came")
		}
		ka := [32]byte(iwKey(A))
		if n.received(B, A) || n.find(func(s iwSeen) bool {
			return bytes.Equal(s.to, iwKey(B)) && s.typ == yggPathLookup && (s.source == ka || s.dest == ka)
		}) {
			t.Error("B got A's traffic or a lookup with A's key")
		}
	})

	// A sends N traffic for N (the filter passes it) on the tree path of
	// each small port, from the coordinates of each: N takes it itself, its
	// watermark 0 (yggZeroWatermark). Nothing goes to B or C, nothing is
	// dropped, no pathBroken comes back to A to tell it which ports are
	// taken; B and C, idle, stay (review of v0.15.0: their links went, a
	// pathBroken told A of each taken port, one along another's from was
	// dropped twice).
	t.Run("a client steering its traffic to the node", func(t *testing.T) {
		t.Parallel()
		keys := iwKeys(4)
		n := &iwNet{t: t}
		N, A, B, C := n.node(keys[0]), n.node(keys[1]), n.node(keys[2]), n.node(keys[3])
		var path, from atomic.Uint64
		var d [3]atomic.Uint64
		n.link(A, N, filtered(N, A, &d[0], trafficTo(nil, &path, &from)))
		n.link(B, N, filtered(N, B, &d[1], nil))
		n.link(C, N, filtered(N, C, &d[2], nil))
		for _, c := range []*iwn.PacketConn{A, B, C} {
			if !n.reach(c, N, 15*time.Second) {
				t.Fatal("a client never reached N")
			}
		}
		time.Sleep(time.Second)
		ka, kn := [32]byte(iwKey(A)), [32]byte(iwKey(N))
		brokenToA := func() bool {
			return n.find(func(s iwSeen) bool { return bytes.Equal(s.to, ka[:]) && s.typ == yggPathBroken })
		}
		n.stays(6*time.Second, func() bool {
			for p := uint64(1); p <= 5; p++ {
				for q := uint64(0); q <= 5; q++ {
					path.Store(p)
					from.Store(q)
					n.mu.Lock()
					delete(n.got, [2][32]byte{kn, ka})
					n.mu.Unlock()
					_, _ = A.WriteTo([]byte("x"), iwt.Addr(kn[:]))
					if !waitFor(time.Second, func() bool { return n.received(N, A) }) {
						t.Fatalf("A's traffic on the path of port %d, from port %d, did not reach N", p, q)
					}
				}
			}
			return false
		}, A, B, C)
		if d[1].Load() != 0 || d[2].Load() != 0 || brokenToA() {
			t.Errorf("dropped on B %d, on C %d; a pathBroken to A %v", d[1].Load(), d[2].Load(), brokenToA())
		}
		if n.received(B, A) || n.received(C, A) {
			t.Error("A's traffic reached another client")
		}
	})

	// B's connection dies without a word and B comes back on a new one; N
	// goes on sending to B over the old one (the older link of a key wins).
	// N ends the dead link in 3 s: whether nobody looks B up, A does, or A
	// floods N with lookups for B, none of which is answered for B (review
	// of v0.15.0: each dropped lookup, answered to the core, kept the dead
	// link up for good). Then N reaches B on the new one.
	for _, mode := range []string{"nobody looks it up", "a client looks it up", "a client floods lookups for it"} {
		t.Run("a dead link, "+mode, func(t *testing.T) {
			t.Parallel()
			keys := iwKeys(3)
			n := &iwNet{t: t}
			N, A, B := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
			ka, kn, kb := [32]byte(iwKey(A)), [32]byte(iwKey(N)), [32]byte(iwKey(B))
			var dA, dOld, dNew atomic.Uint64
			var flood atomic.Bool
			lie := func(frame []byte) []byte { // A's traffic to N, a lookup for B instead
				if !flood.Load() || frame[0] != yggTraffic {
					return frame
				}
				return iwLookup(ka, kb)
			}
			n.link(A, N, filtered(N, A, &dA, lie))
			kill, gone := deadLink(N, B, &yggLinkFilter{rule: yggRule{node: kn, key: kb, groups: noGroup}, dropped: &dOld})
			if !n.reach(N, B, 15*time.Second) || !n.reach(A, N, 15*time.Second) {
				t.Fatal("no traffic")
			}
			time.Sleep(2 * time.Second)
			kill()
			time.Sleep(500 * time.Millisecond) // B ends its side
			n.link(B, N, filtered(N, B, &dNew, nil))
			n.mu.Lock()
			delete(n.got, [2][32]byte{kb, kn})
			n.mu.Unlock()
			flood.Store(mode == "a client floods lookups for it")
			start := time.Now()
			var took time.Duration
			if !waitFor(20*time.Second, func() bool {
				_, _ = N.WriteTo([]byte("n"), iwt.Addr(kb[:]))
				switch mode {
				case "a client looks it up":
					_, _ = A.WriteTo([]byte("a"), iwt.Addr(kb[:]))
				case "a client floods lookups for it":
					for range 10 {
						_, _ = A.WriteTo([]byte("a"), iwt.Addr(kn[:]))
					}
				}
				if took == 0 && gone() {
					took = time.Since(start)
				}
				return gone() && n.received(B, N)
			}) {
				t.Fatalf("after 20 s: the dead link ended %v, N reached B %v; dropped on it %d", gone(), n.received(B, N), dOld.Load())
			}
			t.Logf("the dead link ended in %v (dropped on it %d), N reached B in %v", took, dOld.Load(), time.Since(start))
			if took > 6*time.Second {
				t.Errorf("the dead link lasted %v", took)
			}
		})
	}

	// No one at fault. Keys C < N < D, B: D comes first (port 1 at N), then
	// C, the least key, the tree's root and N's parent, then B. C goes: N is
	// the root, its coordinates [port] become [], and port 1 is D's, so the
	// paths of B and N to each other lead to D. With the filter they come
	// right as fast as without it (the pathBroken each one gets from D's
	// link), and D stays.
	t.Run("the tree's root leaves", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		gaps := map[bool]time.Duration{}
		t.Run("each", func(t *testing.T) {
			for _, filter := range []bool{false, true} {
				t.Run(map[bool]string{false: "no filter", true: "filter"}[filter], func(t *testing.T) {
					t.Parallel()
					gap := rootLeaves(t, filter)
					mu.Lock()
					gaps[filter] = gap
					mu.Unlock()
				})
			}
		})
		t.Logf("N and B apart after the root left: %v without the filter, %v with it", gaps[false], gaps[true])
		if gaps[true] > gaps[false]+3*time.Second {
			t.Errorf("apart %v with the filter, %v without", gaps[true], gaps[false])
		}
	})

	// B's traffic is all to A (forged in its frames): dropped from B's
	// side, nothing reaches N. B stays: the filter answers it. And while N
	// talks to B, B's dropped frames would have paid B's keepalive to N:
	// the filter pays it.
	for _, nodeTalks := range []bool{false, true} {
		name := map[bool]string{false: "a client's own dropped frames", true: "a client's own dropped frames, the node talking to it"}[nodeTalks]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := iwKeys(3)
			n := &iwNet{t: t}
			N, A, B := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
			ka := [32]byte(iwKey(A))
			var dA, dB atomic.Uint64
			var forge atomic.Bool
			lie := func(frame []byte) []byte {
				if !forge.Load() {
					return frame
				}
				return trafficTo(&ka, nil, nil)(frame)
			}
			n.link(A, N, filtered(N, A, &dA, nil))
			n.link(B, N, filtered(N, B, &dB, lie))
			for _, c := range []*iwn.PacketConn{A, B} {
				if !n.reach(c, N, 15*time.Second) {
					t.Fatal("a client never reached N")
				}
			}
			if nodeTalks && !n.reach(N, B, 15*time.Second) {
				t.Fatal("N never reached B")
			}
			forge.Store(true)
			time.Sleep(time.Second)
			last := time.Now()
			n.stays(8*time.Second, func() bool {
				_, _ = B.WriteTo([]byte("b"), iwt.Addr(iwKey(N)))
				if nodeTalks && time.Since(last) > time.Second {
					_, _ = N.WriteTo([]byte("n"), iwt.Addr(iwKey(B)))
					last = time.Now()
				}
				return false
			}, A, B)
			if dB.Load() == 0 || n.received(A, B) {
				t.Errorf("dropped on B's link %d; A got B's traffic %v", dB.Load(), n.received(A, B))
			}
		})
	}

	// B talks to N, so N owes it keepalives; A looks B up meanwhile, and a
	// lookup N sends B (dropped) pays N's debt: B gets the keepalive from
	// the filter.
	t.Run("a client waiting while the node's answer is dropped", func(t *testing.T) {
		t.Parallel()
		keys := iwKeys(3)
		n := &iwNet{t: t}
		N, A, B := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
		var dA, dB atomic.Uint64
		n.link(A, N, filtered(N, A, &dA, nil))
		n.link(B, N, filtered(N, B, &dB, nil))
		for _, c := range []*iwn.PacketConn{A, B} {
			if !n.reach(c, N, 15*time.Second) {
				t.Fatal("a client never reached N")
			}
		}
		last := time.Now()
		n.stays(10*time.Second, func() bool {
			_, _ = A.WriteTo([]byte("x"), iwt.Addr(iwKey(B)))
			if time.Since(last) > 1500*time.Millisecond {
				_, _ = B.WriteTo([]byte("b"), iwt.Addr(iwKey(N)))
				last = time.Now()
			}
			return false
		}, A, B)
		if dB.Load() == 0 {
			t.Error("nothing dropped on B's link")
		}
	})
}

// rootLeaves: the longest N and B do not reach each other, in rounds of
// 200 ms both ways, after the tree's root leaves (the case above).
func rootLeaves(t *testing.T, filter bool) time.Duration {
	keys := iwKeys(4)
	n := &iwNet{t: t}
	C, N, D, B := n.node(keys[0]), n.node(keys[1]), n.node(keys[2]), n.node(keys[3])
	var d [3]atomic.Uint64
	mk := func(c *iwn.PacketConn, i int) iwClient {
		if !filter {
			return iwClient{}
		}
		return filtered(N, c, &d[i], nil)
	}
	// One at a time, so that their ports at N are 1, 2, 3.
	n.link(D, N, mk(D, 0))
	if !n.reach(D, N, 15*time.Second) {
		t.Fatal("D never reached N")
	}
	cutC := n.link(C, N, mk(C, 1))
	if !n.reach(C, N, 15*time.Second) {
		t.Fatal("C never reached N")
	}
	n.link(B, N, mk(B, 2))
	kb, kn := [32]byte(iwKey(B)), [32]byte(iwKey(N))
	round := func() bool {
		n.mu.Lock()
		delete(n.got, [2][32]byte{kb, kn})
		delete(n.got, [2][32]byte{kn, kb})
		n.mu.Unlock()
		_, _ = B.WriteTo([]byte("b"), iwt.Addr(kn[:]))
		_, _ = N.WriteTo([]byte("n"), iwt.Addr(kb[:]))
		time.Sleep(200 * time.Millisecond)
		return n.received(N, B) && n.received(B, N)
	}
	if !waitFor(15*time.Second, round) {
		t.Fatal("N and B never reached each other")
	}
	waitFor(2*time.Second, func() bool { round(); return false }) // on C's tree
	cutC()
	var gap time.Duration
	var failing time.Time
	n.stays(8*time.Second, func() bool {
		switch ok := round(); {
		case !ok && failing.IsZero():
			failing = time.Now()
		case ok && !failing.IsZero():
			gap, failing = max(gap, time.Since(failing)), time.Time{}
		}
		return false
	}, D, B)
	if !failing.IsZero() {
		t.Fatalf("N and B do not reach each other since %v", time.Since(failing))
	}
	if filter {
		t.Logf("dropped on D's link: %d (the stale paths led there)", d[0].Load())
	}
	return gap
}
