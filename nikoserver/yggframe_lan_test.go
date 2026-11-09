//go:build linux

package nikoserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	iwn "github.com/Arceliar/ironwood/network"
	iwt "github.com/Arceliar/ironwood/types"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// The routes by which two devices of one group moved data through the node
// past their group's bucket (review of v0.16.0), on ironwood's own routers:
// a node N, its clients A and B of one group, each through the filter. A
// lies as only a client of its own making would: its frames rewritten
// before anyone sees them, with what it knows (its group's keys, which one
// user's devices share, and B's port on N, from the tree). At
// lan_relay_mbps 0 nothing of A's may reach B; at 1 Mbit/s no more than the
// bucket lets through.

// lanBig is a frame large enough to carry data: a path of 64 ports of 9
// bytes, the most a frame may have (yggPathMax), is 577 bytes; the frames
// ironwood makes itself here are under 150. lanCapped is more than any
// frame with such a path and a short payload makes.
const (
	lanBig    = 500
	lanCapped = 1000
)

// lanPorts are n ports from first on, past any the node gives, each 9
// bytes: a path that carries 9n bytes of whatever its maker wants.
func lanPorts(first uint64, n int) []uint64 {
	ports := make([]uint64, n)
	for i := range ports {
		ports[i] = 1<<62 + first + uint64(i)
	}
	return ports
}

// lanRoute is N with A and B of the group u5 at mbps.
type lanRoute struct {
	*iwNet
	N, A, B    *iwn.PacketConn
	keys       []ed25519.PrivateKey // N's, A's, B's
	kn, ka, kb [32]byte
	relay      *yggRelay
	g          *yggLAN
	dA, dB     atomic.Uint64 // dropped by the rule on A's and B's link
	portB      uint64        // B's port on N
	attack     atomic.Bool   // A's frames rewritten from now on
	seq        atomic.Uint64 // the seq of A's pathNotify, past any of ironwood's own (iw: pathfinder.go:107-111)
}

// newLANRoute links A and B to N, A's frames through lie once the attack
// starts, B's bloom claiming every key when bLies; and waits until each of
// them and N have reached each other.
func newLANRoute(t *testing.T, mbps int, lie func(r *lanRoute, frame []byte) []byte, bLies bool) *lanRoute {
	keys := iwKeys(3)
	r := &lanRoute{iwNet: &iwNet{t: t}, keys: keys}
	r.N, r.A, r.B = r.node(keys[0]), r.node(keys[1]), r.node(keys[2])
	r.kn, r.ka, r.kb = [32]byte(iwKey(r.N)), [32]byte(iwKey(r.A)), [32]byte(iwKey(r.B))
	r.relay = newYggRelay(mbps)
	r.g = r.relay.group("u5")
	r.seq.Store(uint64(time.Now().Unix()) + 1000)
	groups := func() yggGroups { return yggGroups{r.ka: r.g, r.kb: r.g} }
	lieA := func(frame []byte) []byte {
		if lie == nil || !r.attack.Load() {
			return frame
		}
		return lie(r, frame)
	}
	var lieB func([]byte) []byte
	if bLies {
		lieB = yggAllOnes
	}
	r.link(r.A, r.N, iwClient{lie: lieA, filter: &yggLinkFilter{rule: yggRule{node: r.kn, key: r.ka, groups: groups}, dropped: &r.dA}})
	r.link(r.B, r.N, iwClient{lie: lieB, filter: &yggLinkFilter{rule: yggRule{node: r.kn, key: r.kb, groups: groups}, dropped: &r.dB}})
	if !waitFor(15*time.Second, func() bool {
		for _, p := range [][2]*iwn.PacketConn{{r.A, r.N}, {r.B, r.N}, {r.N, r.A}, {r.N, r.B}} {
			_, _ = p[0].WriteTo([]byte("hello"), iwt.Addr(iwKey(p[1])))
		}
		return r.received(r.N, r.A) && r.received(r.N, r.B) && r.received(r.A, r.N) && r.received(r.B, r.N)
	}) {
		t.Fatal("A, B and N never all reached each other")
	}
	for _, p := range r.N.Debug.GetPeers() {
		if bytes.Equal(p.Key, r.kb[:]) {
			r.portB = p.Port
		}
	}
	if r.portB == 0 {
		t.Fatal("no port of B's on N")
	}
	return r
}

// run attacks for d, do in a loop, and then lets what is on its way
// arrive.
func (r *lanRoute) run(d time.Duration, do func()) time.Duration {
	r.attack.Store(true)
	start := time.Now()
	for time.Since(start) < d {
		do()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	return time.Since(start)
}

// toB counts the frames N's link gave B of type typ from source to dest,
// lanBig or larger, and their bytes.
func (r *lanRoute) toB(typ byte, source, dest [32]byte) (frames, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.frames {
		if bytes.Equal(s.to, r.kb[:]) && s.typ == typ && s.source == source && s.dest == dest && s.size >= lanBig {
			frames++
			size += s.size
		}
	}
	return frames, size
}

// lanBound is what a group's bucket at mbps lets through in d at most: its
// burst and the rate, and two of the largest frames for what was on its way.
func lanBound(mbps int, d time.Duration) int {
	rate := float64(mbps) * 1e6 / 8
	return int(yggBurst(rate)+rate*d.Seconds()) + 2*yggFrameMax
}

// notifyInfo signs a pathNotify's info as ironwood does (iw:
// pathfinder.go:377-386): the seq and the path.
func notifyInfo(key ed25519.PrivateKey, seq uint64, coords []uint64) [64]byte {
	return [64]byte(ed25519.Sign(key, iwPath(binary.AppendUvarint(nil, seq), coords...)))
}

func TestNekoServerYggLANRoutes(t *testing.T) {
	// A's lookups as lookups for N (by key, or by address: N answers both,
	// iw: pathfinder.go:62-64), each with 64 ports in its from, the most it may have; B's bloom
	// claims every key, so that N passes each on to B (pathfinder.go:56-60:
	// N multicasts a lookup it answers, too). One for N is for N: B never
	// gets one, at any rate. One for another, N passes on to B as well:
	// charged where it goes out to B.
	for _, c := range []struct {
		forN, byAddress bool
		mbps            int
	}{{true, false, 0}, {true, false, 1 << 20}, {true, true, 1 << 20}, {false, false, 0}, {false, false, 1}} {
		t.Run(fmt.Sprintf("a lying bloom, lookups for N %v (by address %v), %d Mbit/s", c.forN, c.byAddress, c.mbps), func(t *testing.T) {
			t.Parallel()
			dest := [32]byte{1, 2, 3}
			r := newLANRoute(t, c.mbps, func(r *lanRoute, frame []byte) []byte {
				if frame[0] != yggPathLookup {
					return frame
				}
				return iwLookup(r.ka, dest, lanPorts(0, yggPathMax)...)
			}, true)
			switch {
			case c.byAddress:
				dest = [32]byte(address.AddrForKey(r.kn[:]).GetKey())
			case c.forN:
				dest = r.kn
			}
			took := r.run(2*time.Second, func() {
				var k [32]byte
				_, _ = rand.Read(k[:])
				_, _ = r.A.WriteTo([]byte("x"), iwt.Addr(k[:])) // A looks k up: the lie makes it big
			})
			frames, size := r.toB(yggPathLookup, r.ka, dest)
			t.Logf("B got %d lookups of A's, %d bytes, in %v; charged %d bytes, %d dropped over the rate, %d by the rule on B's link",
				frames, size, took, r.g.up.Load(), r.relay.dropped.Load(), r.dB.Load())
			switch {
			case c.forN && frames != 0:
				t.Errorf("lookups for N reached B: %d", frames)
			case c.forN && r.dB.Load() == 0:
				t.Error("nothing dropped on B's link: the lookups for N never came")
			case !c.forN && c.mbps == 0 && frames != 0, !c.forN && size > lanBound(c.mbps, took):
				t.Errorf("%d bytes of lookups reached B at %d Mbit/s in %v", size, c.mbps, took)
			case !c.forN && c.mbps == 0 && r.relay.dropped.Load() == 0:
				t.Error("nothing dropped over the rate: the lookups never came")
			case !c.forN && int64(size) > r.g.up.Load():
				t.Errorf("B got %d bytes of lookups, %d charged", size, r.g.up.Load())
			}
		})
	}

	// A's traffic to N as a lookup for N, its from B's port and 63 more: N
	// answers along the from (iw: pathfinder.go:66-70), to B's link. In A's
	// name the answer is N's own frame for A through B; in B's (one user's
	// devices share their keys) it is N's own to B, free where it goes out,
	// so the lookup is charged where it comes in.
	for _, c := range []struct {
		inB  bool
		mbps int
	}{{false, 0}, {false, 1}, {true, 0}, {true, 1}} {
		t.Run(fmt.Sprintf("a crafted from, in B's name %v, %d Mbit/s", c.inB, c.mbps), func(t *testing.T) {
			t.Parallel()
			r := newLANRoute(t, c.mbps, func(r *lanRoute, frame []byte) []byte {
				if frame[0] != yggTraffic {
					return frame
				}
				source := r.ka
				if c.inB {
					source = r.kb
				}
				return iwLookup(source, r.kn, append([]uint64{r.portB}, lanPorts(0, yggPathMax-1)...)...)
			}, false)
			took := r.run(2*time.Second, func() { _, _ = r.A.WriteTo([]byte("x"), iwt.Addr(r.kn[:])) })
			dest := r.ka
			if c.inB {
				dest = r.kb
			}
			frames, size := r.toB(yggPathNotify, r.kn, dest)
			t.Logf("B got %d pathNotify of N's, %d bytes, in %v; charged %d bytes, %d dropped over the rate",
				frames, size, took, r.g.up.Load(), r.relay.dropped.Load())
			if c.mbps == 0 && frames != 0 || size > lanBound(c.mbps, took) {
				t.Errorf("%d pathNotify, %d bytes, reached B at %d Mbit/s in %v", frames, size, c.mbps, took)
			}
			if r.relay.dropped.Load()+r.relay.frames.Load() == 0 {
				t.Error("nothing charged: the lookups never came")
			}
		})
	}

	// A's traffic to N as a pathNotify to N, signed, its info path B's port
	// and 63 more: N's traffic to the notify's source follows that path (iw:
	// pathfinder.go:198-210), to B's link. In A's name N's traffic is N's
	// own for A through B; in B's, N's own to B, so the notify is charged
	// where it comes in.
	for _, c := range []struct {
		inB  bool
		mbps int
	}{{false, 0}, {false, 1}, {true, 0}} {
		t.Run(fmt.Sprintf("a crafted info path, in B's name %v, %d Mbit/s", c.inB, c.mbps), func(t *testing.T) {
			t.Parallel()
			r := newLANRoute(t, c.mbps, func(r *lanRoute, frame []byte) []byte {
				if frame[0] != yggTraffic {
					return frame
				}
				source, key := r.ka, r.keys[1]
				if c.inB {
					source, key = r.kb, r.keys[2]
				}
				seq := r.seq.Add(1)
				coords := append([]uint64{r.portB}, lanPorts(seq, yggPathMax-1)...)
				return iwNotify(nil, 1, source, r.kn, seq, coords, notifyInfo(key, seq, coords))
			}, false)
			to := r.A
			if c.inB {
				to = r.B
			}
			took := r.run(2*time.Second, func() {
				_, _ = r.A.WriteTo([]byte("x"), iwt.Addr(r.kn[:])) // the lie makes it the notify
				for range 20 {
					_, _ = r.N.WriteTo([]byte("y"), iwt.Addr(iwKey(to)))
				}
			})
			frames, size := r.toB(yggTraffic, r.kn, [32]byte(iwKey(to)))
			t.Logf("B got %d traffic frames of N's, %d bytes, in %v; charged %d bytes, %d dropped over the rate",
				frames, size, took, r.g.up.Load(), r.relay.dropped.Load())
			// In B's name at a rate above 0, the notifies pass, charged: N's
			// traffic to B then carries the last one's path as often as N
			// sends to B (B's own traffic, which it asks for), and B learns
			// no more than the notifies held. Bytes then are no measure.
			if c.mbps == 0 && frames != 0 || !c.inB && size > lanBound(c.mbps, took) {
				t.Errorf("%d traffic frames, %d bytes, reached B at %d Mbit/s in %v", frames, size, c.mbps, took)
			}
			if r.relay.dropped.Load()+r.relay.frames.Load() == 0 {
				t.Error("nothing charged: the notifies never came")
			}
		})
	}

	// A's traffic to N in B's name, 50 KB of it: N sends it back to B, as
	// the node's netstack answers an echo request with the same bytes.
	// N's own to B, free where it goes out; so the traffic is charged where
	// it comes in, a neighbour's for the node.
	for _, mbps := range []int{0, 1} {
		t.Run(fmt.Sprintf("an echo in B's name, %d Mbit/s", mbps), func(t *testing.T) {
			t.Parallel()
			r := newLANRoute(t, mbps, func(r *lanRoute, frame []byte) []byte {
				if frame[0] != yggTraffic {
					return frame
				}
				return iwTraffic(nil, nil, r.kb, r.kn, ^uint64(0), make([]byte, 50_000))
			}, false)
			r.mu.Lock()
			r.echo = map[[32]byte]bool{r.kn: true}
			r.mu.Unlock()
			took := r.run(2*time.Second, func() { _, _ = r.A.WriteTo([]byte("x"), iwt.Addr(r.kn[:])) })
			frames, size := r.toB(yggTraffic, r.kn, r.kb)
			t.Logf("B got %d traffic frames of N's, %d bytes, in %v; charged %d bytes, %d dropped over the rate",
				frames, size, took, r.g.up.Load(), r.relay.dropped.Load())
			if mbps == 0 && frames != 0 || size > lanBound(mbps, took) {
				t.Errorf("%d echoes, %d bytes, reached B at %d Mbit/s in %v", frames, size, mbps, took)
			}
			if r.relay.dropped.Load()+r.relay.frames.Load() == 0 {
				t.Error("nothing charged: the traffic never came")
			}
		})
	}

	// A public peer's link (R4-18) the core dials itself, past the filter:
	// D, a device of u5 on the public mesh, reaches N through it; M, of u5
	// too, is N's client through the filter. D floods M, then M floods D,
	// each its traffic to N sent on to the other's port on N, no lookup
	// needed: each way no more than the bucket, the one way charged where it
	// goes out to M, the other where it comes in from M (it leaves through
	// the public peer, where nothing charges it).
	for _, mbps := range []int{0, 1} {
		t.Run(fmt.Sprintf("an unfiltered peer link, %d Mbit/s", mbps), func(t *testing.T) {
			t.Parallel()
			keys := iwKeys(3)
			n := &iwNet{t: t}
			N, D, M := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
			kn, kd, km := [32]byte(iwKey(N)), [32]byte(iwKey(D)), [32]byte(iwKey(M))
			relay := newYggRelay(mbps)
			g := relay.group("u5")
			groups := func() yggGroups { return yggGroups{kd: g, km: g} }
			var dM atomic.Uint64
			var portD, portM atomic.Uint64 // 0 until the flood: traffic as it is
			steer := func(dest [32]byte, port *atomic.Uint64) func([]byte) []byte {
				to := trafficTo(&dest, port, nil)
				return func(frame []byte) []byte {
					if port.Load() == 0 {
						return frame
					}
					return to(frame)
				}
			}
			n.link(D, N, iwClient{lie: steer(km, &portM)}) // the public peer's side: no filter
			n.link(M, N, iwClient{lie: steer(kd, &portD), filter: &yggLinkFilter{rule: yggRule{node: kn, key: km, groups: groups,
				public: true, linked: func() yggKeys { return yggKeys{km: true} }}, dropped: &dM}})
			if !n.reach(D, N, 15*time.Second) || !n.reach(M, N, 15*time.Second) || !n.reach(N, M, 15*time.Second) {
				t.Fatal("D or M never reached N")
			}
			ports := map[[32]byte]uint64{}
			for _, p := range N.Debug.GetPeers() {
				ports[[32]byte(p.Key)] = p.Port
			}
			// What of the one reached the other, from source to dest.
			got := func(to ed25519.PublicKey, source, dest [32]byte) (size int) {
				n.mu.Lock()
				defer n.mu.Unlock()
				for _, s := range n.frames {
					if bytes.Equal(s.to, to) && s.typ == yggTraffic && s.source == source && s.dest == dest {
						size += s.size
					}
				}
				return size
			}
			flood := func(from, to *iwn.PacketConn, port *atomic.Uint64) (time.Duration, int64) {
				port.Store(ports[[32]byte(iwKey(to))])
				defer port.Store(0)
				before := g.up.Load()
				start := time.Now()
				for time.Since(start) < 2*time.Second {
					_, _ = from.WriteTo(make([]byte, 60_000), iwt.Addr(kn[:])) // the lie sends it on to the other
					time.Sleep(200 * time.Microsecond)
				}
				time.Sleep(500 * time.Millisecond)
				return time.Since(start), g.up.Load() - before
			}
			took, charged := flood(D, M, &portM)
			toM := got(iwKey(M), kd, km)
			t.Logf("D to M: M got %d bytes in %v, %d charged", toM, took, charged)
			if mbps == 0 && toM != 0 || toM > lanBound(mbps, took) || int64(toM) > charged {
				t.Errorf("D to M: M got %d bytes in %v at %d Mbit/s, %d charged", toM, took, mbps, charged)
			}
			took, charged = flood(M, D, &portD)
			toD := got(iwKey(D), km, kd)
			t.Logf("M to D: D got %d bytes in %v, %d charged", toD, took, charged)
			if mbps == 0 && toD != 0 || toD > lanBound(mbps, took) || int64(toD) > charged {
				t.Errorf("M to D: D got %d bytes in %v at %d Mbit/s, %d charged", toD, took, mbps, charged)
			}
		})
	}
}

// Public peers (R4-18), at lan_relay_mbps 0: N; M and L its clients through
// the filter, both linked; D on an unfiltered link, a public peer's side; M,
// L and D of u5 (or M in no group). What the filter on M's link cannot see
// (lan-v1 §7.4, docs/SPEC.md §3.4):
//   - out: M's own lookup for N, free, its from D's port and data: N answers
//     along it, to D; M's own pathNotify to N, its info path D's port and
//     data: N's traffic to M follows it, to D. Both past every charge, a
//     client in no group's too. yggPathMax bounds what a path carries: one
//     of 8000 ports is dropped, and nothing of lanBig or more reaches D;
//     one of 64 passes, and D gets frames of lanCapped bytes at most;
//   - in, pinned as it is: D's traffic to M in the node's name or in L's (a
//     key linked here: one user has all of their devices' keys) reaches M
//     uncharged. In D's own name it is charged, and at 0 dropped.
func TestNekoServerYggLANPublicPeers(t *testing.T) {
	for _, c := range []struct {
		name     string
		out      byte // M's lie: a lookup or a pathNotify; 0: D's lie
		ports    int  // the path's ports, D's port first
		source   byte // D's traffic's source: 'N', 'L' or 'D'
		mGrouped bool
		big      bool // frames of lanBig or more reach M (in) or D (out); with 64 ports, of lanCapped at most
	}{
		{"out: M's lookup for N, a from of 8000", yggPathLookup, 8000, 0, true, false},
		{"out: M's lookup for N, a from of 8000, M in no group", yggPathLookup, 8000, 0, false, false},
		{"out: M's lookup for N, a from of 64", yggPathLookup, yggPathMax, 0, true, true},
		{"out: M's pathNotify to N, an info path of 8000", yggPathNotify, 8000, 0, true, false},
		{"out: M's pathNotify to N, an info path of 64", yggPathNotify, yggPathMax, 0, true, true},
		{"in: D's traffic to M in N's name", 0, 0, 'N', true, true},
		{"in: D's traffic to M in L's name", 0, 0, 'L', true, true},
		{"in: D's traffic to M in its own name", 0, 0, 'D', true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			keys := iwKeys(4)
			n := &iwNet{t: t}
			N, M, L, D := n.node(keys[0]), n.node(keys[1]), n.node(keys[2]), n.node(keys[3])
			kn, km, kl, kd := [32]byte(iwKey(N)), [32]byte(iwKey(M)), [32]byte(iwKey(L)), [32]byte(iwKey(D))
			relay := newYggRelay(0)
			g := relay.group("u5")
			groups := yggGroups{kl: g, kd: g}
			if c.mGrouped {
				groups[km] = g
			}
			rule := func(k [32]byte) yggRule {
				return yggRule{node: kn, key: k, groups: func() yggGroups { return groups }, public: true,
					linked: func() yggKeys { return yggKeys{km: true, kl: true} }}
			}
			var attack atomic.Bool
			var portM, portD uint64
			seq := uint64(time.Now().Unix()) + 1000
			lieM := func(frame []byte) []byte {
				if !attack.Load() || frame[0] != yggTraffic || c.out == 0 {
					return frame
				}
				path := append([]uint64{portD}, lanPorts(seq, c.ports-1)...)
				if c.out == yggPathLookup {
					return iwLookup(km, kn, path...)
				}
				seq++
				return iwNotify(nil, 1, km, kn, seq, path, notifyInfo(keys[1], seq, path))
			}
			lieD := func(frame []byte) []byte {
				if !attack.Load() || frame[0] != yggTraffic || c.out != 0 {
					return frame
				}
				source := map[byte][32]byte{'N': kn, 'L': kl, 'D': kd}[c.source]
				return iwTraffic([]uint64{portM}, nil, source, km, ^uint64(0), make([]byte, 50_000))
			}
			var dM, dL atomic.Uint64
			n.link(M, N, iwClient{lie: lieM, filter: &yggLinkFilter{rule: rule(km), dropped: &dM}})
			n.link(L, N, iwClient{filter: &yggLinkFilter{rule: rule(kl), dropped: &dL}})
			n.link(D, N, iwClient{lie: lieD}) // the public peer's side: no filter
			if !n.reach(D, N, 15*time.Second) || !n.reach(M, N, 15*time.Second) || !n.reach(N, M, 15*time.Second) {
				t.Fatal("D or M never reached N")
			}
			for _, p := range N.Debug.GetPeers() {
				switch [32]byte(p.Key) {
				case km:
					portM = p.Port
				case kd:
					portD = p.Port
				}
			}
			attack.Store(true)
			start := time.Now()
			for time.Since(start) < 2*time.Second {
				if c.out == 0 {
					_, _ = D.WriteTo([]byte("x"), iwt.Addr(kn[:])) // the lie makes it D's traffic to M
				} else {
					_, _ = M.WriteTo([]byte("x"), iwt.Addr(kn[:])) // the lie makes it the lookup or the notify
					for range 20 {
						_, _ = N.WriteTo([]byte("y"), iwt.Addr(km[:]))
					}
				}
				time.Sleep(time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			to := kd
			if c.out == 0 {
				to = km
			}
			var big, bytesTo, most, largest int
			n.mu.Lock()
			for _, s := range n.frames {
				if [32]byte(s.to) != to || !s.keyed || s.source == to {
					continue
				}
				bytesTo += s.size
				most, largest = max(most, s.coords), max(largest, s.size)
				if s.size >= lanBig {
					big++
				}
			}
			n.mu.Unlock()
			t.Logf("%d frames of %d bytes or more reached %x, %d bytes in all, coordinates of %d ports at most; charged %d, dropped over the rate %d, by the rule on M's link %d",
				big, lanBig, to[:2], bytesTo, most, relay.bytes.Load(), relay.dropped.Load(), dM.Load())
			switch {
			case c.big != (big > 0):
				t.Errorf("frames of %d bytes or more reached: %d, want some %v", lanBig, big, c.big)
			case most > yggPathMax || c.out != 0 && largest > lanCapped:
				t.Errorf("coordinates of %d ports, frames of %d bytes, reached D", most, largest)
			case c.out != 0 && c.ports > yggPathMax && dM.Load() == 0:
				t.Error("nothing dropped on M's link: the long paths never came")
			case c.source == 'D' && relay.dropped.Load() == 0:
				t.Error("D's own traffic never charged")
			case c.out == 0 && c.big && relay.bytes.Load()+relay.dropped.Load() != 0:
				t.Error("charged: the gap this pins is closed, and docs/SPEC.md §3.4 is out of date")
			}
		})
	}
}

// The coordinates on a client's link are as long as the tree is deep: N
// sits depth (NIKO_YGG_DEPTH, 12 when unset) hops below the root, a chain
// of routers above it as a public mesh would be, and its client C one
// below. C and N reach each other; the longest from, pathNotify path or
// info path on C's link, either way, is C's depth or N's, never more, and
// the filter drops nothing for it. Past yggPathMax (NIKO_YGG_DEPTH=64, a
// minute and more to settle: ironwood moves the tree a hop a second) C
// gets no route through the node at all.
func TestNekoServerYggPathDepth(t *testing.T) {
	t.Parallel()
	depth := 12
	if d, err := strconv.Atoi(os.Getenv("NIKO_YGG_DEPTH")); err == nil && d > 0 {
		depth = d
	}
	keys := iwKeys(depth + 2) // the least first: the root
	n := &iwNet{t: t}
	chain := make([]*iwn.PacketConn, depth+1)
	for i := range chain {
		chain[i] = n.node(keys[i])
		if i > 0 {
			n.link(chain[i], chain[i-1])
		}
	}
	N := chain[depth]
	C := n.node(keys[depth+1])
	var dropped atomic.Uint64
	n.link(C, N, filtered(N, C, &dropped, nil))
	// The tree settled, as C sees it, before anyone looks anyone up: C is
	// depth+1 below the root.
	deep := func() int {
		parents := map[[32]byte][32]byte{}
		for _, i := range C.Debug.GetTree() {
			parents[[32]byte(i.Key)] = [32]byte(i.Parent)
		}
		d, k := 0, [32]byte(iwKey(C))
		for ; d <= depth+1; d++ {
			p, ok := parents[k]
			if !ok || p == k {
				break
			}
			k = p
		}
		return d
	}
	if !waitFor(time.Duration(2*depth+20)*time.Second, func() bool { return deep() == depth+1 }) {
		t.Fatalf("the tree never settled: C %d deep", deep())
	}
	reached := n.reach(C, N, 15*time.Second) && n.reach(N, C, 15*time.Second)
	most := 0
	n.mu.Lock()
	for _, s := range n.frames {
		if bytes.Equal(s.from, iwKey(C)) || bytes.Equal(s.to, iwKey(C)) {
			most = max(most, s.coords)
		}
	}
	n.mu.Unlock()
	t.Logf("depth %d: C reached N and back %v; the longest coordinates on C's link %d ports; %d frames dropped", depth, reached, most, dropped.Load())
	switch {
	case depth+1 > yggPathMax && reached:
		t.Errorf("C %d deep reached N", depth+1)
	case depth+1 > yggPathMax:
	case !reached:
		t.Fatalf("C %d deep never reached N", depth+1)
	case most < depth || most > depth+1 || dropped.Load() != 0:
		t.Errorf("coordinates of %d ports on C's link, %d frames dropped; want %d or %d ports, none dropped", most, dropped.Load(), depth, depth+1)
	}
}
