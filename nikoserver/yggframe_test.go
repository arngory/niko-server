//go:build linux

package nikoserver

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iwn "github.com/Arceliar/ironwood/network"
	iwt "github.com/Arceliar/ironwood/types"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// Frames byte for byte as ironwood 0712ecc encodes them: a path
// (network/wire.go:80-86), traffic (traffic.go:36-49), pathLookup
// (pathfinder.go:310-320), pathNotify and its info (pathfinder.go:448-463,
// 395-405), pathBroken (pathfinder.go:514-525), the length before the type
// (peers.go:205-214).

func iwPath(b []byte, ports ...uint64) []byte {
	for _, p := range ports {
		b = binary.AppendUvarint(b, p)
	}
	return binary.AppendUvarint(b, 0)
}

func iwTraffic(path, from []uint64, source, dest [32]byte, watermark uint64, payload []byte) []byte {
	b := iwPath([]byte{yggTraffic}, path...)
	b = iwPath(b, from...)
	b = append(append(b, source[:]...), dest[:]...)
	b = binary.AppendUvarint(b, watermark)
	return append(b, payload...)
}

func iwNotify(path []uint64, watermark uint64, source, dest [32]byte, seq uint64, coords []uint64, sig [64]byte) []byte {
	b := iwPath([]byte{yggPathNotify}, path...)
	b = binary.AppendUvarint(b, watermark)
	b = append(append(b, source[:]...), dest[:]...)
	b = binary.AppendUvarint(b, seq)
	b = iwPath(b, coords...)
	return append(b, sig[:]...)
}

func iwLookup(source, dest [32]byte, from ...uint64) []byte {
	b := append(append([]byte{yggPathLookup}, source[:]...), dest[:]...)
	return iwPath(b, from...)
}

func iwBroken(path []uint64, watermark uint64, source, dest [32]byte) []byte {
	b := iwPath([]byte{yggPathBroken}, path...)
	b = binary.AppendUvarint(b, watermark)
	return append(append(b, source[:]...), dest[:]...)
}

func iwFrame(frame []byte) []byte {
	return append(binary.AppendUvarint(nil, uint64(len(frame))), frame...)
}

// Keys of the tests: the node, the link's client, another device; a, b in
// groups (when the test gives groups).
var (
	keyN    = [32]byte{0: 'N', 31: 1}
	keyK    = [32]byte{0: 'K', 31: 2}
	keyA    = [32]byte{0: 'A', 31: 3}
	keyG    = [32]byte{0: 'G', 31: 4}
	keyH    = [32]byte{0: 'H', 31: 5}
	noGroup = func() yggGroups { return nil }
)

// testGroups are groups that relay without a bound: K and G in one, A in
// another (when only is given, those keys in the one).
func testGroups(only ...[32]byte) func() yggGroups {
	relay := newYggRelay(1 << 30)
	one, other := relay.group("u1"), relay.group("u2")
	g := yggGroups{keyK: one, keyG: one, keyA: other}
	if len(only) > 0 {
		g = yggGroups{}
		for _, k := range only {
			g[k] = one
		}
	}
	return func() yggGroups { return g }
}

func TestNekoServerYggFrameKeys(t *testing.T) {
	var sig [64]byte
	sig[0], sig[63] = 0xaa, 0xbb
	traffic := iwTraffic([]uint64{1, 300}, []uint64{2}, keyK, keyN, ^uint64(0), []byte("payload"))
	notify := iwNotify([]uint64{5}, 7, keyN, keyK, 1700000000, []uint64{1, 2, 3}, sig)
	broken := iwBroken(nil, ^uint64(0), keyK, keyA)
	lookup := iwLookup(keyK, keyN, 1, 300, 2)
	cut := func(b []byte, n int) []byte { return slices.Clone(b[:len(b)-n]) }
	plus := func(b []byte, more ...byte) []byte { return append(slices.Clone(b), more...) }
	// The end of a path as two bytes, which binary.Uvarint takes as 0.
	long := []byte{yggTraffic, 0x81, 0x00, 0x80, 0x00, 0x80, 0x00}
	long = append(append(append(long, keyA[:]...), keyN[:]...), 0x05)
	// A port over 64 bits.
	overflow := append([]byte{yggPathBroken}, bytes.Repeat([]byte{0xff}, 10)...)
	overflow = append(append(append(overflow, 0x01, 0x00, 0x00), keyK[:]...), keyN[:]...)

	for _, c := range []struct {
		name         string
		frame        []byte
		keyed, ok    bool
		source, dest [32]byte
	}{
		{"traffic", traffic, true, true, keyK, keyN},
		{"traffic, empty payload", iwTraffic(nil, nil, keyA, keyK, 0, nil), true, true, keyA, keyK},
		{"traffic, paths in long uvarints", long, true, true, keyA, keyN},
		{"traffic, no watermark", iwTraffic(nil, nil, keyA, keyK, 0, nil)[:1+2+64], true, false, [32]byte{}, [32]byte{}},
		{"traffic, a key short", cut(iwTraffic(nil, nil, keyA, keyK, 0, nil), 2), true, false, [32]byte{}, [32]byte{}},
		{"traffic, path without its end", []byte{yggTraffic, 1, 2, 3}, true, false, [32]byte{}, [32]byte{}},
		{"traffic, a watermark over 64 bits", plus(iwTraffic(nil, nil, keyA, keyK, 0, nil)[:1+2+64], bytes.Repeat([]byte{0x80}, 9)...), true, false, [32]byte{}, [32]byte{}},
		{"pathNotify", notify, true, true, keyN, keyK},
		{"pathNotify, a byte more", plus(notify, 0), true, false, [32]byte{}, [32]byte{}},
		{"pathNotify, signature short", cut(notify, 1), true, false, [32]byte{}, [32]byte{}},
		{"pathNotify, no info", notify[:1+2+1+64], true, false, [32]byte{}, [32]byte{}},
		{"pathBroken", broken, true, true, keyK, keyA},
		{"pathBroken, a byte more", plus(broken, 0), true, false, [32]byte{}, [32]byte{}},
		{"pathBroken, a key short", cut(broken, 1), true, false, [32]byte{}, [32]byte{}},
		{"pathBroken, a port over 64 bits", overflow, true, false, [32]byte{}, [32]byte{}},
		{"keepalive", []byte{1}, false, true, [32]byte{}, [32]byte{}},
		{"dummy", []byte{0}, false, true, [32]byte{}, [32]byte{}},
		{"pathLookup", lookup, true, true, keyK, keyN},
		{"pathLookup, no path", iwLookup(keyA, keyK), true, true, keyA, keyK},
		{"pathLookup, a byte more", plus(lookup, 0), true, false, [32]byte{}, [32]byte{}},
		{"pathLookup, path without its end", cut(lookup, 1), true, false, [32]byte{}, [32]byte{}},
		{"pathLookup, a key short", iwLookup(keyA, keyK)[:64], true, false, [32]byte{}, [32]byte{}},
		{"sigReq, whatever is in it", []byte{2, 0xff}, false, true, [32]byte{}, [32]byte{}},
		{"a type ironwood does not know", []byte{10, 1, 2}, false, true, [32]byte{}, [32]byte{}},
		{"empty", nil, false, false, [32]byte{}, [32]byte{}},
	} {
		source, dest, keyed, ok := yggFrameKeys(c.frame)
		if keyed != c.keyed || ok != c.ok {
			t.Errorf("%s: keyed %v ok %v, want %v %v", c.name, keyed, ok, c.keyed, c.ok)
			continue
		}
		if keyed && ok && (*source != c.source || *dest != c.dest) {
			t.Errorf("%s: source %x dest %x", c.name, source[:1], dest[:1])
		}
		// Where the watermark is: ironwood's decoder reads the same value
		// there.
		if _, _, wm, _, ok := yggFrameRead(c.frame); ok && keyed && c.frame[0] != yggPathLookup {
			w, n := binary.Uvarint(c.frame[wm:])
			if n <= 0 || !yggWatermarkIs(c.frame, w) {
				t.Errorf("%s: the watermark at %d reads %d", c.name, wm, w)
			}
		}
		// The reference decoder agrees on every case.
		rs, rd, rkeyed, rok := iwRefKeys(c.frame)
		if rkeyed != keyed || rok != ok || ok && keyed && (rs != *source || rd != *dest) {
			t.Errorf("%s: the reference says keyed %v ok %v", c.name, rkeyed, rok)
		}
	}
}

// yggWatermarkIs: ironwood's decoder reads the watermark w in the frame.
func yggWatermarkIs(frame []byte, w uint64) bool {
	data := frame[1:]
	var path, from []uint64
	var watermark uint64
	if !iwChopPath(&path, &data) {
		return false
	}
	if frame[0] == yggTraffic && !iwChopPath(&from, &data) {
		return false
	}
	if frame[0] == yggTraffic {
		data = data[64:]
	}
	return iwChopUint(&watermark, &data) && watermark == w
}

func TestNekoServerYggRule(t *testing.T) {
	inGroups := testGroups()
	// K in none, G and A in one: K reaches the node only.
	notK := testGroups(keyG, keyA)
	const up, down = true, false
	const drop, pass, charge = yggDrop, yggPass, yggCharge
	addrG := [32]byte(address.AddrForKey(keyG[:]).GetKey())
	addrN := [32]byte(address.AddrForKey(keyN[:]).GetKey())
	linkedG := yggKeys{keyK: true, keyG: true}
	for _, c := range []struct {
		name         string
		groups       func() yggGroups
		fromClient   bool
		typ          byte
		source, dest [32]byte
		want         yggVerdict
		public       bool    // the node has public peers
		linked       yggKeys // with them, the keys linked here
	}{
		{"traffic K to N", noGroup, up, yggTraffic, keyK, keyN, pass, false, nil},
		{"traffic K to another", noGroup, up, yggTraffic, keyK, keyA, drop, false, nil},
		{"traffic forging N", noGroup, up, yggTraffic, keyN, keyA, drop, false, nil},
		{"traffic forging N to N", noGroup, up, yggTraffic, keyN, keyN, drop, false, nil},
		{"traffic forging another", noGroup, up, yggTraffic, keyA, keyN, drop, false, nil},
		{"traffic K to K", noGroup, up, yggTraffic, keyK, keyK, drop, false, nil},
		{"pathNotify K to N", noGroup, up, yggPathNotify, keyK, keyN, pass, false, nil},
		{"pathNotify K to another", noGroup, up, yggPathNotify, keyK, keyA, drop, false, nil},
		{"pathBroken of N's traffic to K, back to N", noGroup, up, yggPathBroken, keyN, keyK, pass, false, nil},
		{"pathBroken of K's traffic to N", noGroup, up, yggPathBroken, keyK, keyN, drop, false, nil},
		{"pathBroken of another's traffic", noGroup, up, yggPathBroken, keyA, keyK, drop, false, nil},
		{"traffic N to K", noGroup, down, yggTraffic, keyN, keyK, pass, false, nil},
		{"traffic another to K", noGroup, down, yggTraffic, keyA, keyK, drop, false, nil},
		{"traffic N to another, through K", noGroup, down, yggTraffic, keyN, keyA, drop, false, nil},
		{"pathNotify N to K", noGroup, down, yggPathNotify, keyN, keyK, pass, false, nil},
		{"pathNotify another to K", noGroup, down, yggPathNotify, keyA, keyK, drop, false, nil},
		{"pathBroken of K's traffic to N, back to K", noGroup, down, yggPathBroken, keyK, keyN, pass, false, nil},
		{"pathBroken of N's traffic to K", noGroup, down, yggPathBroken, keyN, keyK, drop, false, nil},
		{"pathBroken of K's traffic to another", noGroup, down, yggPathBroken, keyK, keyA, drop, false, nil},
		// A lookup: from the client, its source K; to the client, the node's
		// own, for K (its key, or one from its address, iw:
		// pathfinder.go:62-64).
		{"pathLookup K for N", noGroup, up, yggPathLookup, keyK, keyN, pass, false, nil},
		{"pathLookup K for another", noGroup, up, yggPathLookup, keyK, keyA, pass, false, nil},
		{"pathLookup forging N", noGroup, up, yggPathLookup, keyN, keyK, drop, false, nil},
		{"pathLookup forging another", noGroup, up, yggPathLookup, keyA, keyN, drop, false, nil},
		{"pathLookup N for K", noGroup, down, yggPathLookup, keyN, keyK, pass, false, nil},
		{"pathLookup N for K's address", noGroup, down, yggPathLookup, keyN, [32]byte(address.AddrForKey(keyK[:]).GetKey()), pass, false, nil},
		{"pathLookup N for K's subnet", noGroup, down, yggPathLookup, keyN, [32]byte(address.SubnetForKey(keyK[:]).GetKey()), pass, false, nil},
		{"pathLookup N for another", noGroup, down, yggPathLookup, keyN, keyA, drop, false, nil},
		{"pathLookup N for another's address", noGroup, down, yggPathLookup, keyN, [32]byte(address.AddrForKey(keyA[:]).GetKey()), drop, false, nil},
		{"pathLookup another for K", noGroup, down, yggPathLookup, keyA, keyK, drop, false, nil},
		{"pathLookup another for N", noGroup, down, yggPathLookup, keyA, keyN, drop, false, nil},
		// With groups: K and G in one, A in another, N in none. Free only
		// between K and N; what K sends a neighbour is charged where it goes
		// out to it, what comes to K from one, and the node's own frame for
		// another than K, as it goes out to K.
		{"group: traffic K to N", inGroups, up, yggTraffic, keyK, keyN, pass, false, nil},
		{"group: traffic N to K", inGroups, down, yggTraffic, keyN, keyK, pass, false, nil},
		{"group: pathNotify K to N", inGroups, up, yggPathNotify, keyK, keyN, pass, false, nil},
		{"group: pathNotify N to K", inGroups, down, yggPathNotify, keyN, keyK, pass, false, nil},
		{"group: pathBroken of K's traffic to N, back to K", inGroups, down, yggPathBroken, keyK, keyN, pass, false, nil},
		{"group: traffic K to G", inGroups, up, yggTraffic, keyK, keyG, pass, false, nil},
		{"group: traffic K to A", inGroups, up, yggTraffic, keyK, keyA, drop, false, nil},
		{"group: traffic A to N, through K", inGroups, up, yggTraffic, keyA, keyN, drop, false, nil},
		{"group: traffic G to K", inGroups, down, yggTraffic, keyG, keyK, charge, false, nil},
		{"group: traffic A to K", inGroups, down, yggTraffic, keyA, keyK, drop, false, nil},
		{"group: pathBroken of K's traffic to G, back to K", inGroups, down, yggPathBroken, keyK, keyG, charge, false, nil},
		{"group: pathBroken of K's traffic to A", inGroups, down, yggPathBroken, keyK, keyA, drop, false, nil},
		{"group: pathLookup A for N, through K", inGroups, up, yggPathLookup, keyA, keyN, drop, false, nil},
		{"group: pathLookup K for N", inGroups, up, yggPathLookup, keyK, keyN, pass, false, nil},
		{"group: pathLookup K for N's address", inGroups, up, yggPathLookup, keyK, addrN, pass, false, nil},
		{"group: pathLookup K for G", inGroups, up, yggPathLookup, keyK, keyG, pass, false, nil},
		{"group: pathLookup K for G's address", inGroups, up, yggPathLookup, keyK, addrG, pass, false, nil},
		{"group: pathLookup G for K", inGroups, down, yggPathLookup, keyG, keyK, charge, false, nil},
		{"group: pathLookup N for G, through K", inGroups, down, yggPathLookup, keyN, keyG, pass, false, nil},
		// A lookup is held to the rule by its source (lan-v1 §2.2): G's for
		// anyone but the node reaches K, behind which (in its Wi-Fi) the one
		// G looks for may be; the node's only for what K or its group answers
		// by key. G's for the node is for the node, which passes it on to
		// every client whose bloom claims the node, the from as G made it.
		{"group: pathLookup G for A, through K", inGroups, down, yggPathLookup, keyG, keyA, charge, false, nil},
		{"group: pathLookup G for G's address, through K", inGroups, down, yggPathLookup, keyG, addrG, charge, false, nil},
		{"group: pathLookup G for N, to K", inGroups, down, yggPathLookup, keyG, keyN, drop, false, nil},
		{"group: pathLookup G for N's address, to K", inGroups, down, yggPathLookup, keyG, addrN, drop, false, nil},
		{"group: pathLookup N for A, through K", inGroups, down, yggPathLookup, keyN, keyA, drop, false, nil},
		{"group: pathLookup N for G's address, through K", inGroups, down, yggPathLookup, keyN, addrG, drop, false, nil},
		{"group: pathLookup A for K", inGroups, down, yggPathLookup, keyA, keyK, drop, false, nil},
		{"group: pathLookup A for G, through K", inGroups, down, yggPathLookup, keyA, keyG, drop, false, nil},
		{"group: pathLookup forging N, for G", inGroups, up, yggPathLookup, keyN, keyG, drop, false, nil},
		// The node's own frames for a neighbour through K: a device behind K,
		// or what a member steered there with the path it gave the node.
		{"group: traffic N to G, through K", inGroups, down, yggTraffic, keyN, keyG, charge, false, nil},
		{"group: pathNotify N to G, through K", inGroups, down, yggPathNotify, keyN, keyG, charge, false, nil},
		{"group: pathBroken of G's traffic to N, back to G through K", inGroups, down, yggPathBroken, keyG, keyN, charge, false, nil},
		// A neighbour's frames for the node, through K: the node answers the
		// neighbour, as its own frame to it, free on its link.
		{"group: traffic G to N, through K", inGroups, up, yggTraffic, keyG, keyN, charge, false, nil},
		{"group: pathNotify G to N, through K", inGroups, up, yggPathNotify, keyG, keyN, charge, false, nil},
		{"group: pathLookup G for N, through K", inGroups, up, yggPathLookup, keyG, keyN, charge, false, nil},
		{"group: pathLookup G for N's address, through K", inGroups, up, yggPathLookup, keyG, addrN, charge, false, nil},
		{"group: pathBroken of N's traffic to G, back to N through K", inGroups, up, yggPathBroken, keyN, keyG, charge, false, nil},
		// pathBroken goes back to its source: from K, G's traffic to K's
		// side, back to G.
		{"group: pathBroken of G's traffic to K, back to G", inGroups, up, yggPathBroken, keyG, keyK, pass, false, nil},
		{"group: pathBroken of A's traffic to K, back to A", inGroups, up, yggPathBroken, keyA, keyK, drop, false, nil},
		{"group: pathBroken of G's traffic to A, back to G", inGroups, up, yggPathBroken, keyG, keyA, drop, false, nil},
		{"group: pathBroken of A's traffic to G, through K", inGroups, down, yggPathBroken, keyA, keyG, drop, false, nil},
		{"group: pathNotify G to K", inGroups, down, yggPathNotify, keyG, keyK, charge, false, nil},
		{"group: pathNotify K to G", inGroups, up, yggPathNotify, keyK, keyG, pass, false, nil},
		{"group: pathNotify A to K", inGroups, down, yggPathNotify, keyA, keyK, drop, false, nil},
		// A source forged: only one of K's group passes (behind K, in its
		// Wi-Fi, it may be), never the node's, never another group's.
		{"group: traffic forging N to G", inGroups, up, yggTraffic, keyN, keyG, drop, false, nil},
		{"group: traffic forging A to G", inGroups, up, yggTraffic, keyA, keyG, drop, false, nil},
		{"group: traffic forging A to K's own side", inGroups, up, yggTraffic, keyA, keyK, drop, false, nil},
		// With public peers: what K sends a neighbour is charged as it comes
		// in, as it may leave through them; then what comes to K from a key
		// linked here, a lookup too, was charged where it came in.
		{"public: traffic K to G", inGroups, up, yggTraffic, keyK, keyG, charge, true, linkedG},
		{"public: pathLookup K for G", inGroups, up, yggPathLookup, keyK, keyG, charge, true, linkedG},
		{"public: pathLookup K for A", inGroups, up, yggPathLookup, keyK, keyA, charge, true, linkedG},
		{"public: pathLookup K for N", inGroups, up, yggPathLookup, keyK, keyN, pass, true, linkedG},
		{"public: traffic K to N", inGroups, up, yggTraffic, keyK, keyN, pass, true, linkedG},
		{"public: traffic G to N, through K", inGroups, up, yggTraffic, keyG, keyN, charge, true, linkedG},
		{"public: traffic G linked to K", inGroups, down, yggTraffic, keyG, keyK, pass, true, linkedG},
		{"public: traffic G not linked to K", inGroups, down, yggTraffic, keyG, keyK, charge, true, yggKeys{keyK: true}},
		{"public: pathBroken of K's traffic to G linked, back to K", inGroups, down, yggPathBroken, keyK, keyG, pass, true, linkedG},
		{"public: pathLookup G linked for K", inGroups, down, yggPathLookup, keyG, keyK, pass, true, linkedG},
		{"public: pathLookup G not linked for K", inGroups, down, yggPathLookup, keyG, keyK, charge, true, yggKeys{keyK: true}},
		{"public: pathLookup G linked for N, to K", inGroups, down, yggPathLookup, keyG, keyN, drop, true, linkedG},
		{"public: traffic N to G, through K", inGroups, down, yggTraffic, keyN, keyG, charge, true, yggKeys{keyN: true, keyG: true}},
		{"public: traffic N to K", inGroups, down, yggTraffic, keyN, keyK, pass, true, linkedG},
		{"public: K in none, pathLookup K for A", notK, up, yggPathLookup, keyK, keyA, pass, true, linkedG},
		{"public: K in none, traffic G linked to K", notK, down, yggTraffic, keyG, keyK, drop, true, linkedG},
		// K in no group, G and A in one: K reaches only the node, both ways.
		{"K in none: traffic K to G", notK, up, yggTraffic, keyK, keyG, drop, false, nil},
		{"K in none: traffic G to K", notK, down, yggTraffic, keyG, keyK, drop, false, nil},
		{"K in none: traffic forging G to A", notK, up, yggTraffic, keyG, keyA, drop, false, nil},
		{"K in none: traffic forging G to N", notK, up, yggTraffic, keyG, keyN, drop, false, nil},
		{"K in none: traffic N to G, through K", notK, down, yggTraffic, keyN, keyG, drop, false, nil},
		{"K in none: pathNotify G to K", notK, down, yggPathNotify, keyG, keyK, drop, false, nil},
		{"K in none: pathBroken of K's traffic to G, back to K", notK, down, yggPathBroken, keyK, keyG, drop, false, nil},
		{"K in none: pathLookup G for K", notK, down, yggPathLookup, keyG, keyK, drop, false, nil},
		{"K in none: pathLookup forging G, for N", notK, up, yggPathLookup, keyG, keyN, drop, false, nil},
		{"K in none: traffic K to N", notK, up, yggTraffic, keyK, keyN, pass, false, nil},
		{"K in none: traffic N to K", notK, down, yggTraffic, keyN, keyK, pass, false, nil},
	} {
		r := yggRule{node: keyN, key: keyK, groups: c.groups, public: c.public, linked: func() yggKeys { return c.linked }}
		if got := r.judge(r.view(), c.fromClient, c.typ, &c.source, &c.dest); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		// The spec's own reading agrees.
		if got := testSpec(c.groups, c.public, c.linked).verdict(c.fromClient, c.typ, c.source, c.dest); got != c.want {
			t.Errorf("%s: the spec says %v, want %v", c.name, got, c.want)
		}
	}
	// No group is no group: two keys in none are not in one.
	r := yggRule{node: keyN, key: keyK, groups: func() yggGroups { return yggGroups{keyA: nil} }}
	a, n := keyA, keyN
	if r.judge(r.view(), true, yggTraffic, &keyK, &a) != yggDrop || r.judge(r.view(), true, yggTraffic, &keyK, &n) != yggPass {
		t.Error("two keys without a group pass as one group")
	}
	// Two groups of one name are one, as the backend makes them: a reload
	// gives a name the group it had.
	relay := newYggRelay(1)
	u5, again, u6 := relay.group("u5"), relay.group("u5"), relay.group("u6")
	if u5 != again || u5 == u6 {
		t.Error("a name's group is not one")
	}
}

// testSpec is the spec's world for K's link with groups: each group a name
// of its own.
func testSpec(groups func() yggGroups, public bool, linked yggKeys) lanSpec {
	s := lanSpec{node: keyN, key: keyK, group: map[[32]byte]string{}, public: public, linked: linked}
	for key, g := range groups() {
		if g != nil {
			s.group[key] = fmt.Sprintf("%p", g)
		}
	}
	return s
}

// String names a verdict in the tests' messages.
func (v yggVerdict) String() string {
	return [...]string{yggDrop: "drop", yggPass: "pass", yggCharge: "charge"}[v]
}

// The core's bloom transform made without allocating, against yggdrasil-go's
// own: keys of zeros and of ones, every count of leading zeros, random keys,
// and the keys of an address and a subnet, which are the key's own under it.
func TestYggXKey(t *testing.T) {
	check := func(k [32]byte) {
		t.Helper()
		if got, want := yggXKey(&k), [32]byte(address.SubnetForKey(k[:]).GetKey()); got != want {
			t.Fatalf("key %x: %x, want %x", k, got, want)
		}
	}
	var zeros, ones [32]byte
	for i := range ones {
		ones[i] = 0xff
	}
	check(zeros)
	check(ones)
	for z := 0; z <= 256; z++ {
		for range 50 {
			var k [32]byte
			rand.Read(k[:])
			for i := range z {
				k[i/8] &^= 0x80 >> (i % 8)
			}
			if z < 256 {
				k[z/8] |= 0x80 >> (z % 8)
			}
			check(k)
		}
	}
	for range 10000 {
		var k [32]byte
		rand.Read(k[:])
		check(k)
		addr, subnet := [32]byte(address.AddrForKey(k[:]).GetKey()), [32]byte(address.SubnetForKey(k[:]).GetKey())
		if !yggAnswers(&addr, &k) || !yggAnswers(&subnet, &k) {
			t.Fatalf("key %x: its address or subnet not answered", k)
		}
	}
	k := keyN
	if n := testing.AllocsPerRun(100, func() { _ = yggXKey(&k) }); n != 0 {
		t.Errorf("%v allocations", n)
	}
	// A rule's own keys, transformed once (prepare) or not at all yet: the
	// same answers.
	r := yggRule{node: keyN, key: keyK, groups: noGroup}
	addrN, addrK := [32]byte(address.AddrForKey(keyN[:]).GetKey()), [32]byte(address.AddrForKey(keyK[:]).GetKey())
	for range 2 {
		if !r.forNode(&addrN) || r.forNode(&addrK) || !r.answers(&addrK) || r.answers(&addrN) {
			t.Fatalf("prepared %v: whom a lookup is for, wrong", r.xNode != [32]byte{})
		}
		r.prepare()
	}
	// A filter's rule is prepared: its lookups never transform N's or K's
	// key again.
	f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: noGroup}, new(atomic.Uint64), discard{}, discard{})
	if f.rule.xNode != yggXKey(&keyN) || f.rule.xKey != yggXKey(&keyK) {
		t.Error("a filter's rule not prepared")
	}
}

// yggPathMax on a client's link, either way: a lookup's from, a
// pathNotify's path and info path of 64 ports pass, of 65 are dropped,
// counted and answered; the end of a path in two bytes is an end; traffic's
// paths are not coordinates and are not held to it.
func TestNekoServerYggPathMax(t *testing.T) {
	var sig [64]byte
	ports := func(n int) []uint64 { return lanPorts(0, n) }
	long := ports(yggPathMax + 1)
	endInTwo := append(append([]byte{yggPathLookup}, keyK[:]...), keyN[:]...)
	for range yggPathMax {
		endInTwo = append(endInTwo, 1)
	}
	endInTwo = append(endInTwo, 0x80, 0x00)
	for _, c := range []struct {
		name  string
		up    bool
		frame []byte
		pass  bool
	}{
		{"K's lookup for N, a from of 64", true, iwLookup(keyK, keyN, ports(yggPathMax)...), true},
		{"K's lookup for N, a from of 65", true, iwLookup(keyK, keyN, long...), false},
		{"K's lookup for another, a from of 65", true, iwLookup(keyK, keyA, long...), false},
		{"K's lookup, 64 ports, the end in two bytes", true, endInTwo, true},
		{"K's pathNotify to N, both paths of 64", true, iwNotify(ports(yggPathMax), 1, keyK, keyN, 1, ports(yggPathMax), sig), true},
		{"K's pathNotify to N, an info path of 65", true, iwNotify(nil, 1, keyK, keyN, 1, long, sig), false},
		{"K's pathNotify to N, a path of 65", true, iwNotify(long, 1, keyK, keyN, 1, nil, sig), false},
		{"K's traffic to N, paths of 65", true, iwTraffic(long, long, keyK, keyN, 0, nil), true},
		{"N's lookup for K, a from of 64", false, iwLookup(keyN, keyK, ports(yggPathMax)...), true},
		{"N's lookup for K, a from of 65", false, iwLookup(keyN, keyK, long...), false},
		{"N's pathNotify to K, an info path of 65", false, iwNotify(nil, 1, keyN, keyK, 1, long, sig), false},
		{"N's traffic to K, paths of 65", false, iwTraffic(long, long, keyN, keyK, 1, nil), true},
	} {
		f, core, client, dropped := testFilter(noGroup)
		// Where the frame goes, and what its sender gets if it is dropped:
		// up, the core and the client's keepalive; down, the client and its
		// ping (after the core's handshake).
		var err error
		var out []byte
		answered := false
		if c.up {
			err = f.testUp(&chunks{b: iwFrame(c.frame), n: 100})
			out, answered = core.Bytes(), bytes.Equal(client.Bytes(), yggKeepAliveFrame)
		} else {
			err = f.testDown(&chunks{b: slices.Concat([]byte("meta\x00\x00"), iwFrame(c.frame)), n: 100})
			if out = client.Bytes()[6:]; bytes.Equal(out, iwFrame(iwBroken(nil, 0, keyN, keyK))) {
				answered, out = true, nil // the ping, all that came
			}
		}
		switch {
		case err != io.EOF:
			t.Errorf("%s: %v", c.name, err)
		case c.pass && (dropped.Load() != 0 || len(out) != len(iwFrame(c.frame))):
			t.Errorf("%s: dropped (%d), %d bytes of %d went on", c.name, dropped.Load(), len(out), len(iwFrame(c.frame)))
		case !c.pass && (dropped.Load() != 1 || len(out) != 0 || !answered):
			t.Errorf("%s: dropped %d, %d bytes went on, answered %v", c.name, dropped.Load(), len(out), answered)
		}
	}
}

// chunks reads at most n bytes a time, as a TLS record or a socket gives
// them; it hides WriterTo.
type chunks struct {
	b []byte
	n int
}

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), c.n)], c.b)
	c.b = c.b[n:]
	return n, nil
}

// sink keeps what is written; it hides ReaderFrom.
type sink struct {
	bytes.Buffer
	writes int
	fail   bool
}

func (s *sink) Write(p []byte) (int, error) {
	if s.fail {
		return 0, errors.New("broken pipe")
	}
	s.writes++
	return s.Buffer.Write(p)
}

// testFilter is a filter on K's link that writes to sinks; what it injects
// waits until flushed.
func testFilter(groups func() yggGroups) (f *yggLinkFilter, core, client *sink, dropped *atomic.Uint64) {
	dropped = new(atomic.Uint64)
	core, client = &sink{}, &sink{}
	f = newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: groups}, dropped, core, client)
	return f, core, client, dropped
}

// up and down are the two copies with the injected frames flushed after.
func (f *yggLinkFilter) testUp(src io.Reader) error {
	err := f.copy(&f.core, src, true)
	_ = f.core.flush()
	_ = f.client.flush()
	return err
}

func (f *yggLinkFilter) testDown(src io.Reader) error {
	err := f.handshake(src)
	if err == nil {
		err = f.copy(&f.client, src, false)
	}
	_ = f.core.flush()
	_ = f.client.flush()
	return err
}

func TestNekoServerYggLinkFilter(t *testing.T) {
	var sig [64]byte
	big := make([]byte, 100<<10)
	rand.Read(big)
	// The largest frame: the type and body yggFrameMax bytes.
	largest := iwTraffic(nil, nil, keyK, keyN, 0, nil)
	largest = append(largest, make([]byte, yggFrameMax-len(largest))...)
	// Frames to the node reach it with the watermark 0 (yggZeroWatermark):
	// each one's watermark here takes one byte, its zero too.
	type frame struct {
		b    []byte
		pass bool
		out  []byte // what the core gets of it, if not b
	}
	up := []frame{
		{iwFrame([]byte{1}), true, nil}, // keepalive
		{iwFrame(iwTraffic([]uint64{1}, nil, keyK, keyN, 3, []byte("to the node"))), true,
			iwFrame(iwTraffic([]uint64{1}, nil, keyK, keyN, 0, []byte("to the node")))},
		{iwFrame(iwTraffic(nil, nil, keyN, keyA, 3, []byte("forged"))), false, nil},
		{iwFrame(iwNotify(nil, 1, keyK, keyN, 9, []uint64{1}, sig)), true, iwFrame(iwNotify(nil, 0, keyK, keyN, 9, []uint64{1}, sig))},
		{iwFrame(iwNotify(nil, 1, keyK, keyA, 9, []uint64{1}, sig)), false, nil},
		{iwFrame(append([]byte{5}, make([]byte, 32)...)), true, nil}, // a bloom filter: not read
		{iwFrame(iwTraffic(nil, nil, keyK, keyN, 1, big)), true, iwFrame(iwTraffic(nil, nil, keyK, keyN, 0, big))},
		{iwFrame(iwTraffic(nil, nil, keyK, keyA, 1, big)), false, nil},
		{iwFrame(largest), true, nil},
		{iwFrame(iwBroken([]uint64{4}, 2, keyN, keyK)), true, iwFrame(iwBroken([]uint64{4}, 0, keyN, keyK))},
		{iwFrame(iwBroken([]uint64{4}, 2, keyK, keyN)), false, nil},
		// A length not in the fewest bytes: ironwood takes it, and it
		// passes as it came.
		{append([]byte{0x81, 0x80, 0x00}, 1), true, nil},
		{iwFrame(iwLookup(keyK, keyN, 1, 2)), true, nil},
		{iwFrame(iwLookup(keyN, keyA)), false, nil}, // forged
		{iwFrame([]byte{2, 1, 2, 3}), true, nil},    // sigReq: not read
	}
	var stream, want []byte
	drops := 0
	for _, f := range up {
		stream = append(stream, f.b...)
		switch {
		case !f.pass:
			drops++
		case f.out != nil:
			want = append(want, f.out...)
		default:
			want = append(want, f.b...)
		}
	}
	for _, n := range []int{1, 3, 1000, 16 << 10, 64 << 10, len(stream)} {
		f, out, client, dropped := testFilter(noGroup)
		if err := f.testUp(&chunks{b: stream, n: n}); err != io.EOF {
			t.Fatalf("reads of %d: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), want) || dropped.Load() != uint64(drops) {
			t.Fatalf("reads of %d: %d bytes of %d, %d dropped of %d", n, out.Len(), len(want), dropped.Load(), drops)
		}
		if n == len(stream) && out.writes > 2*drops+2 {
			t.Errorf("one read: %d writes", out.writes)
		}
		// The client's answers to its dropped frames: keepalives, one while
		// none is written yet.
		if !bytes.Equal(client.Bytes(), yggKeepAliveFrame) {
			t.Errorf("reads of %d: the client got %x", n, client.Bytes())
		}
	}

	// The core's side: its handshake as it is, then frames to the client.
	meta := append([]byte("meta\x00\x05"), 1, 2, 3, 4, 5)
	down := slices.Concat(meta,
		iwFrame(iwTraffic(nil, nil, keyN, keyK, 1, []byte("to K"))),
		iwFrame(iwTraffic(nil, nil, keyN, keyA, 1, []byte("through K"))),
		iwFrame(iwLookup(keyN, keyK, 3)),
		iwFrame(iwLookup(keyN, keyA, 3)),
		iwFrame(iwLookup(keyA, keyN, 4)),
		iwFrame(iwBroken(nil, 1, keyK, keyN)))
	// The answers: to the core, the pathBroken the client would send for
	// the node's traffic it cannot pass on; to the client, for the rest, one
	// ping (after the frames: it waits for the flush here).
	wantDown := slices.Concat(meta, iwFrame(iwTraffic(nil, nil, keyN, keyK, 1, []byte("to K"))),
		iwFrame(iwLookup(keyN, keyK, 3)), iwFrame(iwBroken(nil, 1, keyK, keyN)), iwFrame(iwBroken(nil, 0, keyN, keyK)))
	wantCore := iwFrame(iwBroken(nil, ^uint64(0), keyN, keyA))
	for _, n := range []int{1, 4, 7, len(down)} {
		f, core, out, dropped := testFilter(noGroup)
		if err := f.testDown(&chunks{b: down, n: n}); err != io.EOF {
			t.Fatalf("down, reads of %d: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), wantDown) || dropped.Load() != 3 {
			t.Fatalf("down, reads of %d: %x, %d dropped", n, out.Bytes(), dropped.Load())
		}
		if !bytes.Equal(core.Bytes(), wantCore) {
			t.Fatalf("down, reads of %d: the core got %x", n, core.Bytes())
		}
	}

	// What ends the link; what passed before is written.
	good := iwFrame(iwTraffic(nil, nil, keyK, keyN, 0, []byte("ok")))
	for _, c := range []struct {
		name   string
		stream []byte
		down   bool
		want   []byte
		err    error
	}{
		{"a length over the largest frame", slices.Concat(good, binary.AppendUvarint(nil, yggFrameMax+1)), false, good, errYggFrame},
		{"an empty frame", slices.Concat(good, []byte{0}), false, good, errYggFrame},
		{"a length over 64 bits", slices.Concat(good, bytes.Repeat([]byte{0x80}, 10), []byte{1}), false, good, errYggFrame},
		{"ten bytes of a length, the stream's end", slices.Concat(good, bytes.Repeat([]byte{0x80}, 10)), false, good, errYggFrame},
		{"traffic ironwood refuses", slices.Concat(good, iwFrame([]byte{yggTraffic, 0, 0})), false, good, errYggFrame},
		{"the end within a frame", slices.Concat(good, good[:len(good)-1]), false, good, io.EOF},
		{"the end within a length", slices.Concat(good, []byte{0x80}), false, good, io.EOF},
		{"the core says no meta", slices.Concat([]byte("mota\x00\x00"), good), true, nil, errYggFrame},
		{"the core's meta too long", slices.Concat([]byte("meta\x04\x01"), make([]byte, 1025)), true, nil, errYggFrame},
	} {
		f, core, client, _ := testFilter(noGroup)
		var err error
		out := core
		if c.down {
			err, out = f.testDown(&chunks{b: c.stream, n: 5}), client
		} else {
			err = f.testUp(&chunks{b: c.stream, n: 5})
		}
		if err != c.err || !bytes.Equal(out.Bytes(), c.want) {
			t.Errorf("%s: %v, %d bytes written", c.name, err, out.Len())
		}
	}
	// A failed write ends the copy.
	f, core, _, _ := testFilter(noGroup)
	core.fail = true
	if err := f.testUp(&chunks{b: good, n: 100}); err == nil || err == io.EOF {
		t.Errorf("a failed write: %v", err)
	}
}

// What the filter injects for a frame it drops (yggLinkFilter.answer), byte
// for byte.
func TestNekoServerYggLinkFilterAnswers(t *testing.T) {
	ka := yggKeepAliveFrame
	var sig [64]byte
	// From the client: a keepalive back to it; the core gets one only while
	// it waits for the client (a frame of the core's passed, and nothing
	// went to it since).
	f, core, client, _ := testFilter(noGroup)
	forged := iwFrame(iwTraffic(nil, nil, keyN, keyA, 1, []byte("x")))
	if f.testUp(&chunks{b: forged, n: 100}); core.Len() != 0 || !bytes.Equal(client.Bytes(), ka) {
		t.Fatalf("a dropped frame of the client's: core %x, client %x", core.Bytes(), client.Bytes())
	}
	core.Reset()
	client.Reset()
	f.testDown(&chunks{b: slices.Concat([]byte("meta\x00\x00"), iwFrame([]byte{5, 1, 2}), iwFrame(ka[1:])), n: 100})
	if !f.core.waits.Load() {
		t.Fatal("the core's bloom filter passed, yet the core does not wait")
	}
	client.Reset()
	if f.testUp(&chunks{b: slices.Concat(forged, forged), n: 100}); !bytes.Equal(core.Bytes(), ka) || !bytes.Equal(client.Bytes(), ka) {
		t.Fatalf("dropped while the core waits: core %x, client %x", core.Bytes(), client.Bytes())
	}
	if f.core.waits.Load() {
		t.Fatal("the core got a keepalive, yet waits")
	}

	// To the client: for the node's traffic, from it or to it, the core gets
	// the pathBroken the client would send: the from path as it came, the
	// watermark ^uint64(0), the traffic's source and dest. For anything
	// else, the client gets the ping: pathBroken, an empty path, the
	// watermark 0, from N to K, 68 bytes.
	ping := slices.Concat([]byte{67, yggPathBroken, 0, 0}, keyN[:], keyK[:])
	if !bytes.Equal(ping, iwFrame(iwBroken(nil, 0, keyN, keyK))) {
		t.Fatalf("the ping %x is not ironwood's pathBroken", ping)
	}
	nonMinimal := []byte{0x81, 0x00, 0x80, 0x00} // the port 1, the end: in more bytes than needed
	traffic := slices.Concat([]byte{yggTraffic}, iwPath(nil, 9), nonMinimal, keyA[:], keyN[:], []byte{1}, []byte("p"))
	for _, c := range []struct {
		name         string
		frame        []byte
		core, client []byte
	}{
		{"the node's traffic to another", iwFrame(iwTraffic([]uint64{3}, []uint64{1, 2}, keyN, keyA, 7, []byte("p"))),
			iwFrame(iwBroken([]uint64{1, 2}, ^uint64(0), keyN, keyA)), nil},
		{"another's traffic to the node, its from path in long uvarints", iwFrame(traffic),
			iwFrame(slices.Concat([]byte{yggPathBroken}, nonMinimal, binary.AppendUvarint(nil, ^uint64(0)), keyA[:], keyN[:])), nil},
		{"another's traffic to K", iwFrame(iwTraffic(nil, []uint64{4}, keyA, keyK, 1, nil)), nil, ping},
		{"traffic between two others", iwFrame(iwTraffic(nil, []uint64{4}, keyA, keyG, 1, nil)), nil, ping},
		{"the node's traffic with a from path past what may wait", iwFrame(iwTraffic(nil, slices.Repeat([]uint64{1}, yggInjectMax), keyN, keyA, 1, nil)), nil, ping},
		{"another's lookup", iwFrame(iwLookup(keyA, keyK)), nil, ping},
		{"another's pathNotify", iwFrame(iwNotify(nil, 1, keyA, keyK, 1, nil, sig)), nil, ping},
		{"two lookups: one ping waits", slices.Concat(iwFrame(iwLookup(keyA, keyK)), iwFrame(iwLookup(keyG, keyK))), nil, ping},
	} {
		f, core, client, dropped := testFilter(noGroup)
		f.testDown(&chunks{b: slices.Concat([]byte("meta\x00\x00"), c.frame), n: 1000})
		if dropped.Load() == 0 || !bytes.Equal(core.Bytes(), c.core) || client.String() != "meta\x00\x00"+string(c.client) {
			t.Errorf("%s: dropped %d, core %x, client %x", c.name, dropped.Load(), core.Bytes(), client.Bytes())
		}
		for _, b := range [][]byte{c.core, c.client} {
			if len(b) == 0 {
				continue
			}
			b = b[len(binary.AppendUvarint(nil, uint64(len(b)))):]
			if _, _, keyed, ok := yggFrameKeys(b); !keyed || !ok {
				t.Errorf("%s: the pathBroken does not read", c.name)
			}
			if _, _, _, ok := iwRefKeys(b); !ok {
				t.Errorf("%s: ironwood would not take the pathBroken", c.name)
			}
		}
	}
	// While the client waits for the core, the node's traffic dropped on
	// its way to it may be what paid the core's debt: the client gets a
	// keepalive too.
	f, core, client, _ = testFilter(noGroup)
	if err := f.handshake(bytes.NewReader([]byte("meta\x00\x00"))); err != nil {
		t.Fatal(err)
	}
	f.testUp(&chunks{b: iwFrame(iwTraffic(nil, nil, keyK, keyN, 1, []byte("hi"))), n: 100})
	if !f.client.waits.Load() {
		t.Fatal("the client's traffic passed, yet the client does not wait")
	}
	core.Reset()
	client.Reset()
	f.copy(&f.client, &chunks{b: iwFrame(iwTraffic(nil, nil, keyN, keyA, 1, nil)), n: 100}, false)
	f.core.flush()
	f.client.flush()
	if !bytes.Equal(core.Bytes(), iwFrame(iwBroken(nil, ^uint64(0), keyN, keyA))) || !bytes.Equal(client.Bytes(), ka) {
		t.Fatalf("dropped while the client waits: core %x, client %x", core.Bytes(), client.Bytes())
	}

	// An answer that comes while the frame that asks for it is still being
	// written: the client is not left waiting (the mark comes first).
	var answered *yggLinkFilter
	hook := hookWriter(func() { _ = answered.client.write(ka) })
	answered = newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: noGroup}, new(atomic.Uint64), hook, &sink{})
	_ = answered.copy(&answered.core, &chunks{b: iwFrame(iwTraffic(nil, nil, keyK, keyN, 0, nil)), n: 100}, true)
	if answered.client.waits.Load() {
		t.Fatal("answered during the write, yet the client waits")
	}

	// From the client to the node: the watermark 0, in its own bytes.
	zero := func(n int) []byte { return append(bytes.Repeat([]byte{0x80}, n-1), 0) }
	for _, c := range []struct {
		name     string
		in, want []byte
	}{
		{"traffic to N", iwTraffic([]uint64{2}, nil, keyK, keyN, ^uint64(0), []byte("p")),
			slices.Concat([]byte{yggTraffic}, iwPath(nil, 2), iwPath(nil), keyK[:], keyN[:], zero(10), []byte("p"))},
		{"traffic to N, a short watermark", iwTraffic(nil, nil, keyK, keyN, 5, nil), iwTraffic(nil, nil, keyK, keyN, 0, nil)},
		{"pathNotify to N", iwNotify([]uint64{1}, 300, keyK, keyN, 1, []uint64{4}, sig),
			slices.Concat([]byte{yggPathNotify}, iwPath(nil, 1), zero(2), keyK[:], keyN[:], []byte{1}, iwPath(nil, 4), sig[:])},
		{"pathBroken back to N", iwBroken([]uint64{1}, 7, keyN, keyK), iwBroken([]uint64{1}, 0, keyN, keyK)},
		{"a lookup: no watermark", iwLookup(keyK, keyN, 1), iwLookup(keyK, keyN, 1)},
	} {
		f, core, _, _ := testFilter(noGroup)
		if f.testUp(&chunks{b: iwFrame(c.in), n: 7}); !bytes.Equal(core.Bytes(), iwFrame(c.want)) {
			t.Errorf("%s: the core got %x", c.name, core.Bytes())
		}
		if c.in[0] == yggTraffic {
			if _, _, _, ok := iwRefKeys(c.want); !ok {
				t.Errorf("%s: ironwood would not take it", c.name)
			}
		}
	}
	// To a group's key (G with K), the watermark stays.
	f, core, _, _ = testFilter(testGroups(keyK, keyG))
	toG := iwFrame(iwTraffic(nil, nil, keyK, keyG, 9, nil))
	if f.testUp(&chunks{b: toG, n: 100}); !bytes.Equal(core.Bytes(), toG) {
		t.Errorf("traffic to G: the core got %x", core.Bytes())
	}
}

// iwNet is ironwood on its own, as the core runs it: routers joined by
// pipes, each frame between them seen on the way, and what each router
// gets from whom.
type iwNet struct {
	t      *testing.T
	mu     sync.Mutex
	frames []iwSeen
	got    map[[2][32]byte]bool // receiver, sender
	ended  map[[32]byte]bool    // the links that ended, by their first end's key
	echo   map[[32]byte]bool    // the routers that send back what they get, as a node's netstack answers an echo
}

// iwSeen is a frame on a link, as the filter reads it.
type iwSeen struct {
	from, to     ed25519.PublicKey // the link's ends, in the frame's direction
	typ          byte
	keyed, ok    bool
	source, dest [32]byte
	size         int // the frame's type and body
	coords       int // the most ports of its coordinates (a lookup's from, a pathNotify's path or info path)
}

func (n *iwNet) node(key ed25519.PrivateKey) *iwn.PacketConn {
	// The bloom transform the core sets (ygg: src/core/core.go:96-102).
	xform := func(k ed25519.PublicKey) ed25519.PublicKey { return address.SubnetForKey(k).GetKey() }
	pc, err := iwn.NewPacketConn(key, iwn.WithPeerMaxMessageSize(yggFrameMax), iwn.WithBloomTransform(xform))
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { pc.Close() })
	self := [32]byte(iwKey(pc))
	go func() { // whatever comes, noted by sender and forgotten (or sent back)
		b := make([]byte, 65535)
		for {
			m, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			n.mu.Lock()
			if n.got == nil {
				n.got = map[[2][32]byte]bool{}
			}
			n.got[[2][32]byte{self, [32]byte(from.(iwt.Addr))}] = true
			echo := n.echo[self]
			n.mu.Unlock()
			if echo {
				_, _ = pc.WriteTo(b[:m], from)
			}
		}
	}()
	return pc
}

func iwKey(pc *iwn.PacketConn) ed25519.PublicKey { return ed25519.PublicKey(pc.LocalAddr().(iwt.Addr)) }

// iwClient makes a link a client's link to the node: through the filter,
// and with lie (when set) rewriting the client's frames before anyone
// sees them.
type iwClient struct {
	filter *yggLinkFilter
	lie    func([]byte) []byte
}

// closer is a func as an io.Closer.
type closer func()

func (c closer) Close() error { c(); return nil }

// link joins a and b, a a client of b when c is given; cut ends the link.
// The frames are seen on a's side of the filter: a's as a sends them, b's
// as the filter lets them through.
func (n *iwNet) link(a, b *iwn.PacketConn, c ...iwClient) (cut func()) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	conns := []io.Closer{a1, a2, b1, b2}
	var once sync.Once
	cut = func() { // as a link ends: whichever side goes, all of it
		once.Do(func() {
			for _, c := range conns {
				c.Close()
			}
			n.mu.Lock()
			if n.ended == nil {
				n.ended = map[[32]byte]bool{}
			}
			n.ended[[32]byte(iwKey(a))] = true
			n.mu.Unlock()
		})
	}
	var opt iwClient
	if len(c) > 0 {
		opt = c[0]
	}
	var f1, f2 net.Conn
	if opt.filter != nil {
		f1, f2 = net.Pipe()
		conns = append(conns, f1, f2, closer(opt.filter.close))
	}
	run := func(f func()) {
		go func() {
			f()
			cut()
		}()
	}
	run(func() { _ = a.HandleConn(iwKey(b), a1, 0) })
	run(func() { _ = b.HandleConn(iwKey(a), b1, 0) })
	if opt.filter == nil {
		run(func() { n.relay(a2, b2, iwKey(a), iwKey(b), opt.lie) })
		run(func() { n.relay(b2, a2, iwKey(b), iwKey(a), nil) })
	} else {
		run(func() { n.relay(a2, f1, iwKey(a), iwKey(b), opt.lie) })
		run(func() { n.relay(f1, a2, iwKey(b), iwKey(a), nil) })
		f := opt.filter
		f.attach(b2, f2)
		go f.client.run(f.done) // no handshake here
		run(func() { _ = f.up(f2) })
		run(func() { _ = f.copy(&f.client, b2, false) })
	}
	return cut
}

// relay splits the frames as ironwood reads them (peers.go:247-269), on
// its own, and has the filter's parser read each.
func (n *iwNet) relay(src, dst net.Conn, from, to ed25519.PublicKey, lie func([]byte) []byte) {
	r := bufio.NewReader(src)
	for {
		size, err := binary.ReadUvarint(r)
		if err != nil {
			return
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(r, frame); err != nil || size == 0 {
			return
		}
		if lie != nil {
			frame = lie(frame)
		}
		seen := iwSeen{from: from, to: to, typ: frame[0], size: len(frame), coords: iwCoords(frame)}
		source, dest, keyed, ok := yggFrameKeys(frame)
		seen.keyed, seen.ok = keyed, ok
		if keyed && ok {
			seen.source, seen.dest = *source, *dest
		}
		n.mu.Lock()
		n.frames = append(n.frames, seen)
		n.mu.Unlock()
		if _, err := dst.Write(iwFrame(frame)); err != nil {
			return
		}
	}
}

// iwCoords is the most ports of a frame's coordinates, as ironwood decodes
// them: a lookup's from, a pathNotify's path and info path; 0 for any other
// frame, or one that does not decode.
func iwCoords(frame []byte) int {
	if _, _, keyed, ok := iwRefKeys(frame); !keyed || !ok {
		return 0
	}
	data := frame[1:]
	var path, coords []uint64
	var u uint64
	switch frame[0] {
	case yggPathLookup:
		data = data[64:]
		iwChopPath(&coords, &data)
	case yggPathNotify:
		iwChopPath(&path, &data)
		iwChopUint(&u, &data)
		data = data[64:]
		iwChopUint(&u, &data)
		iwChopPath(&coords, &data)
	}
	return max(len(path), len(coords))
}

// up: the link that a (its first end) is on has not ended, at either end.
// (ironwood's Debug.GetPeers races with its peers' actors.)
func (n *iwNet) up(a *iwn.PacketConn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.ended[[32]byte(iwKey(a))]
}

func (n *iwNet) received(to, from *iwn.PacketConn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.got[[2][32]byte{[32]byte(iwKey(to)), [32]byte(iwKey(from))}]
}

func (n *iwNet) find(ok func(iwSeen) bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.ContainsFunc(n.frames, ok)
}

// The parser on frames that ironwood itself made: a line of routers A, B,
// C, A the root. A sends to C: a lookup, C's pathNotify back to A, A's
// traffic to C. Then C goes, and B tells A of the broken path.
func TestNekoServerYggFrameIronwood(t *testing.T) {
	var keys []ed25519.PrivateKey
	for range 3 {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y ed25519.PrivateKey) int { return bytes.Compare(x[32:], y[32:]) })
	n := &iwNet{t: t}
	a, b, c := n.node(keys[0]), n.node(keys[1]), n.node(keys[2])
	ka, kb, kc := [32]byte(iwKey(a)), [32]byte(iwKey(b)), [32]byte(iwKey(c))
	n.link(a, b)
	cutBC := n.link(b, c)

	is := func(typ byte, from, to, source, dest [32]byte) func(iwSeen) bool {
		return func(s iwSeen) bool {
			return s.typ == typ && s.keyed && s.ok && [32]byte(s.from) == from && [32]byte(s.to) == to &&
				s.source == source && s.dest == dest
		}
	}
	toC := is(yggTraffic, kb, kc, ka, kc)
	if !waitFor(20*time.Second, func() bool {
		_, _ = a.WriteTo([]byte("hello"), iwt.Addr(kc[:]))
		return n.find(toC)
	}) {
		t.Fatal("A's traffic never reached C")
	}
	for name, ok := range map[string]func(iwSeen) bool{
		"lookup A for C, on A-B":    is(yggPathLookup, ka, kb, ka, kc),
		"lookup A for C, on B-C":    is(yggPathLookup, kb, kc, ka, kc),
		"traffic A to C, on A-B":    is(yggTraffic, ka, kb, ka, kc),
		"pathNotify C to A, on C-B": is(yggPathNotify, kc, kb, kc, ka),
		"pathNotify C to A, on B-A": is(yggPathNotify, kb, ka, kc, ka),
	} {
		if !n.find(ok) {
			t.Errorf("no %s", name)
		}
	}
	cutBC()
	broken := is(yggPathBroken, kb, ka, ka, kc)
	if !waitFor(10*time.Second, func() bool {
		_, _ = a.WriteTo([]byte("hello again"), iwt.Addr(kc[:]))
		return n.find(broken)
	}) {
		t.Fatal("no pathBroken from B to A")
	}
	// Every frame of the three types read; the others not read but seen,
	// the tree, the bloom filters and the lookups among them.
	types := map[byte]bool{}
	n.mu.Lock()
	for _, s := range n.frames {
		types[s.typ] = true
		if s.keyed != (s.typ >= yggPathLookup && s.typ <= yggTraffic) || !s.ok {
			t.Errorf("type %d: keyed %v ok %v", s.typ, s.keyed, s.ok)
		}
	}
	n.mu.Unlock()
	for _, typ := range []byte{2, 3, 4, 5, 6, 7, 8, 9} {
		if !types[typ] {
			t.Errorf("no frame of type %d on the links", typ)
		}
	}
}

type discard struct{} // io.Discard without ReaderFrom

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkYggLinkFilter: the filter against io.Copy, which it replaced, on
// 4 MiB of the client's traffic to the node, read as TLS gives it (a record
// of 16 KiB at most) and as a unix socket may (64 KiB).
func BenchmarkYggLinkFilter(b *testing.B) {
	for _, payload := range []int{1280, 65535} {
		frame := iwFrame(iwTraffic([]uint64{3, 1}, []uint64{3, 2}, keyK, keyN, ^uint64(0), make([]byte, payload)))
		stream := bytes.Repeat(frame, max(1, (4<<20)/len(frame)))
		for _, read := range []int{16 << 10, 64 << 10} {
			name := fmt.Sprintf("payload=%d/read=%dK", payload, read>>10)
			b.Run(name+"/io.Copy", func(b *testing.B) {
				b.SetBytes(int64(len(stream)))
				b.ReportAllocs()
				for b.Loop() {
					_, _ = io.Copy(discard{}, &chunks{b: stream, n: read})
				}
			})
			b.Run(name+"/filter", func(b *testing.B) {
				var dropped atomic.Uint64
				f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: noGroup}, &dropped, discard{}, discard{})
				b.SetBytes(int64(len(stream)))
				b.ReportAllocs()
				for b.Loop() {
					_ = f.copy(&f.core, &chunks{b: stream, n: read}, true)
				}
			})
		}
	}
}

// BenchmarkYggLinkFilterLAN: the filter on 4 MiB of traffic of 1280 bytes
// a frame, read 16 KiB at a time, each way, with groups: free (K and N),
// charged to an unbounded bucket (where it goes out to K, or, with public
// peers, where it comes in from K), and free again for a key linked here.
func BenchmarkYggLinkFilterLAN(b *testing.B) {
	keys := yggKeys{keyK: true, keyG: true}
	linked := func() yggKeys { return keys }
	for _, c := range []struct {
		name         string
		fromClient   bool
		source, dest [32]byte
		groups       func() yggGroups
		public       bool
	}{
		{"up/none/toN", true, keyK, keyN, noGroup, false},
		{"up/grouped/toN", true, keyK, keyN, testGroups(), false},
		{"up/grouped/toG", true, keyK, keyG, testGroups(), false},
		{"up/grouped/toG/public", true, keyK, keyG, testGroups(), true},
		{"down/none/fromN", false, keyN, keyK, noGroup, false},
		{"down/grouped/fromG", false, keyG, keyK, testGroups(), false},
		{"down/grouped/fromN/toG", false, keyN, keyG, testGroups(), false},
		{"down/grouped/fromG/public", false, keyG, keyK, testGroups(), true},
	} {
		frame := iwFrame(iwTraffic([]uint64{3, 1}, []uint64{3, 2}, c.source, c.dest, ^uint64(0), make([]byte, 1280)))
		stream := bytes.Repeat(frame, (4<<20)/len(frame))
		b.Run(c.name, func(b *testing.B) {
			var dropped atomic.Uint64
			f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: c.groups, public: c.public, linked: linked}, &dropped, discard{}, discard{})
			dst := &f.client
			if c.fromClient {
				dst = &f.core
			}
			b.SetBytes(int64(len(stream)))
			b.ReportAllocs()
			for b.Loop() {
				_ = f.copy(dst, &chunks{b: stream, n: 16 << 10}, c.fromClient)
			}
			if dropped.Load() != 0 {
				b.Fatalf("%d frames dropped", dropped.Load())
			}
		})
	}
}

// BenchmarkYggLinkFilterLookups: the filter on lookups, each with a from of
// 3 ports as ironwood makes them, read 16 KiB at a time: K's own (in a
// group or not), a neighbour's for N through K, the node's for K and for
// a neighbour, a neighbour's for another to K (charged, unbounded).
func BenchmarkYggLinkFilterLookups(b *testing.B) {
	for _, c := range []struct {
		name         string
		fromClient   bool
		source, dest [32]byte
		groups       func() yggGroups
	}{
		{"up/none/K's", true, keyK, keyA, noGroup},
		{"up/grouped/K's", true, keyK, keyA, testGroups()},
		{"up/grouped/G's for N", true, keyG, keyN, testGroups()},
		{"down/none/N's for K", false, keyN, keyK, noGroup},
		{"down/grouped/N's for G", false, keyN, keyG, testGroups()},
		{"down/grouped/G's for another", false, keyG, keyA, testGroups()},
	} {
		frame := iwFrame(iwLookup(c.source, c.dest, 3, 1, 2))
		stream := bytes.Repeat(frame, (64<<10)/len(frame))
		b.Run(c.name, func(b *testing.B) {
			var dropped atomic.Uint64
			f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: c.groups}, &dropped, discard{}, discard{})
			dst := &f.client
			if c.fromClient {
				dst = &f.core
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = f.copy(dst, &chunks{b: stream, n: 16 << 10}, c.fromClient)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(stream)/len(frame)), "ns/frame")
			if dropped.Load() != 0 {
				b.Fatalf("%d frames dropped", dropped.Load())
			}
		})
	}
}

// yggAllOnes is a bloom filter frame with every bit set (iw:
// bloomfilter.go:53-81): a client that sends it gets every lookup the node
// passes on (bloomfilter.go:301-329).
func yggAllOnes(frame []byte) []byte {
	if frame[0] != 5 {
		return frame
	}
	return slices.Concat([]byte{5}, make([]byte, 16), bytes.Repeat([]byte{0xff}, 16))
}

// The filter between ironwood routers: a node N and its clients A, B and
// C, B and C lying in their bloom filters to get every lookup N passes on.
// A and N reach each other (each one's lookup passes, the other's
// pathNotify comes back); B learns nothing of A from lookups, nor reaches
// A, unless A and B are in one group. Without the filter B gets A's
// lookups: the leak the lookup rule closes. With A and B in a group (C in
// none): they reach each other, at lan_relay_mbps 0 not at all; C learns
// nothing of either, nor reaches A; no lookup for N reaches B or C; and the
// group is charged exactly what the spec (lanSpec) charges of the frames
// on the clients' links, as each client sent them and as each got them,
// with public peers or without.
func TestNekoServerYggFrameIronwoodFilter(t *testing.T) {
	for _, c := range []struct {
		name                     string
		filter, groups, nodeRoot bool
		mbps                     int // the group's bucket; -1: no bound to speak of
		public                   bool
	}{
		{"no filter", false, false, true, -1, false},
		{"filter", true, false, true, -1, false},
		{"filter, A the tree's root", true, false, false, -1, false},
		{"filter, A and B in a group", true, true, true, -1, false},
		{"filter, A and B in a group, A the tree's root", true, true, false, -1, false},
		{"filter, A and B in a group, relay 0", true, true, true, 0, false},
		{"filter, A and B in a group, public peers", true, true, true, -1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			keys := iwKeys(4)
			if !c.nodeRoot {
				keys[0], keys[1] = keys[1], keys[0]
			}
			n := &iwNet{t: t}
			N, A, B, C := n.node(keys[0]), n.node(keys[1]), n.node(keys[2]), n.node(keys[3])
			kn, ka, kb, kc := [32]byte(iwKey(N)), [32]byte(iwKey(A)), [32]byte(iwKey(B)), [32]byte(iwKey(C))
			relay := newYggRelay(1 << 30)
			if c.mbps >= 0 {
				relay = newYggRelay(c.mbps)
			}
			g := relay.group("u5")
			groups, names := yggGroups{}, map[[32]byte]string{}
			if c.groups {
				groups, names = yggGroups{ka: g, kb: g}, map[[32]byte]string{ka: "u5", kb: "u5"}
			}
			linked := yggKeys{ka: true, kb: true, kc: true}
			specs := map[[32]byte]lanSpec{} // the filtered links, by their client's key
			var dropped [3]atomic.Uint64
			clients := []iwClient{{}, {lie: yggAllOnes}, {lie: yggAllOnes}}
			for i, x := range []*iwn.PacketConn{A, B, C} {
				k := [32]byte(iwKey(x))
				if c.filter {
					clients[i].filter = &yggLinkFilter{rule: yggRule{node: kn, key: k, groups: func() yggGroups { return groups },
						public: c.public, linked: func() yggKeys { return linked }}, dropped: &dropped[i]}
					specs[k] = lanSpec{node: kn, key: k, group: names, public: c.public, linked: linked}
				}
				n.link(x, N, clients[i])
			}

			send := func(from, to *iwn.PacketConn, d time.Duration) bool {
				return waitFor(d, func() bool {
					_, _ = from.WriteTo([]byte("hello"), iwt.Addr(iwKey(to)))
					return n.received(to, from)
				})
			}
			for _, p := range []struct {
				name     string
				from, to *iwn.PacketConn
			}{{"A to N", A, N}, {"N to A", N, A}, {"B to N", B, N}, {"N to B", N, B}, {"C to N", C, N}} {
				if !send(p.from, p.to, 15*time.Second) {
					t.Fatalf("%s: nothing arrived", p.name)
				}
			}
			// What made it: A's lookup for N, N's pathNotify to A; N's lookup
			// for A, A's pathNotify to N.
			for name, want := range map[string]iwSeen{
				"A's lookup for N":    {from: ed25519.PublicKey(ka[:]), typ: yggPathLookup, source: ka, dest: kn},
				"N's pathNotify to A": {from: ed25519.PublicKey(kn[:]), typ: yggPathNotify, source: kn, dest: ka},
				"N's lookup for A":    {from: ed25519.PublicKey(kn[:]), typ: yggPathLookup, source: kn, dest: ka},
				"A's pathNotify to N": {from: ed25519.PublicKey(ka[:]), typ: yggPathNotify, source: ka, dest: kn},
			} {
				if !n.find(func(s iwSeen) bool {
					return bytes.Equal(s.from, want.from) && s.typ == want.typ && s.source == want.source && s.dest == want.dest
				}) {
					t.Errorf("no %s", name)
				}
			}
			var reached, back, cReached bool
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				reached = send(A, B, 5*time.Second)
				back = reached && send(B, A, 5*time.Second)
			}()
			go func() {
				defer wg.Done()
				cReached = send(C, A, 5*time.Second)
			}()
			wg.Wait()
			// What came to B about A: a lookup with A's key in it.
			aToB := n.find(func(s iwSeen) bool {
				return bytes.Equal(s.to, iwKey(B)) && s.typ == yggPathLookup && (s.source == ka || s.dest == ka)
			})
			switch {
			case !c.filter:
				if !aToB || !reached {
					t.Errorf("without the filter: B got A's lookup %v, A reached B %v; want both", aToB, reached)
				}
				return
			case !c.groups:
				if aToB || reached {
					t.Errorf("B got a lookup with A's key %v, A reached B %v", aToB, reached)
				}
				if dropped[1].Load() == 0 {
					t.Error("nothing dropped on B's link")
				}
			case c.mbps == 0:
				if reached || g.up.Load() != 0 || relay.frames.Load() != 0 || relay.dropped.Load() == 0 {
					t.Errorf("relay 0: A reached B %v; charged %d bytes, %d frames passed, %d dropped",
						reached, g.up.Load(), relay.frames.Load(), relay.dropped.Load())
				}
			default:
				if !reached || !back {
					t.Errorf("A and B in a group: A reached B %v, B reached A %v", reached, back)
				}
				// Charged once: what the spec charges of what the clients sent
				// and got, no more, no less.
				var want int
				if !waitFor(5*time.Second, func() bool {
					want = n.charged(specs)
					return int64(want) == g.up.Load()
				}) || want == 0 {
					t.Errorf("charged %d bytes; the spec charges %d of the frames on the links", g.up.Load(), want)
				}
				t.Logf("charged %d bytes in %d frames, as the spec says", g.up.Load(), relay.frames.Load())
			}
			// Isolation: C, in no group, gets nothing that names A or B, nor
			// reaches A; no lookup for N reaches a client but N's.
			if cReached || n.find(func(s iwSeen) bool {
				return bytes.Equal(s.to, iwKey(C)) && s.keyed && (s.source == ka || s.dest == ka || s.source == kb || s.dest == kb)
			}) {
				t.Errorf("C reached A %v, or got a frame that names A or B", cReached)
			}
			if n.find(func(s iwSeen) bool {
				return !bytes.Equal(s.to, kn[:]) && s.typ == yggPathLookup && s.source != kn && lanOwns(kn, s.dest)
			}) {
				t.Error("a lookup for N reached a client")
			}
		})
	}
}

// charged is what the spec charges of the frames on the clients' links,
// each link's spec by its client's key: as each client sent them, and as
// the filter let them through to it.
func (n *iwNet) charged(specs map[[32]byte]lanSpec) (total int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, s := range n.frames {
		if !s.keyed || !s.ok {
			continue
		}
		if spec, ok := specs[[32]byte(s.from)]; ok && spec.verdict(true, s.typ, s.source, s.dest) == yggCharge {
			total += s.size
		}
		if spec, ok := specs[[32]byte(s.to)]; ok && spec.verdict(false, s.typ, s.source, s.dest) == yggCharge {
			total += s.size
		}
	}
	return total
}

// hookWriter calls itself in each Write, as an answer that arrives then.
type hookWriter func()

func (h hookWriter) Write(p []byte) (int, error) {
	h()
	return len(p), nil
}

// overlapping is a writer that notes two Writes at once, and keeps what is
// written.
type overlapping struct {
	in, hit atomic.Int32
	mu      sync.Mutex
	b       []byte
}

func (o *overlapping) Write(p []byte) (int, error) {
	if o.in.Add(1) > 1 {
		o.hit.Add(1)
	}
	o.mu.Lock()
	o.b = append(o.b, p...)
	o.mu.Unlock()
	time.Sleep(20 * time.Microsecond)
	o.in.Add(-1)
	return len(p), nil
}

// The copy toward the client and the keepalives injected for the client's
// dropped frames go to the same conn: never two Writes at once, and the
// stream is whole frames.
func TestNekoServerYggLinkFilterWritesWhole(t *testing.T) {
	client := &overlapping{}
	var dropped atomic.Uint64
	f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: noGroup}, &dropped, discard{}, client)
	defer f.close()
	go f.client.run(f.done)
	toK := iwFrame(iwTraffic(nil, nil, keyN, keyK, 1, make([]byte, 100)))
	forged := iwFrame(iwTraffic(nil, nil, keyN, keyA, 1, nil))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = f.copy(&f.client, &chunks{b: bytes.Repeat(toK, 2000), n: 300}, false)
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			_ = f.copy(&f.core, &chunks{b: forged, n: 100}, true)
		}
	}()
	wg.Wait()
	_ = f.client.flush()
	if client.hit.Load() != 0 {
		t.Fatalf("%d Writes at once", client.hit.Load())
	}
	passed, keepalives := 0, 0
	for b := client.b; len(b) > 0; {
		size, n := binary.Uvarint(b)
		if n <= 0 || len(b) < n+int(size) {
			t.Fatalf("the stream breaks at %d bytes from its end", len(b))
		}
		switch frame := b[:n+int(size)]; {
		case bytes.Equal(frame, toK):
			passed++
		case bytes.Equal(frame, yggKeepAliveFrame):
			keepalives++
		default:
			t.Fatalf("a frame neither passed nor injected: %x", frame)
		}
		b = b[n+int(size):]
	}
	if passed != 2000 || keepalives == 0 {
		t.Fatalf("%d frames passed, %d keepalives", passed, keepalives)
	}
}

// steps reads its parts one per Read, each after its hook: a reload
// between two reads of a link.
type steps []struct {
	before func()
	b      []byte
}

func (s *steps) Read(p []byte) (int, error) {
	if len(*s) == 0 {
		return 0, io.EOF
	}
	step := &(*s)[0]
	if step.before != nil {
		step.before()
		step.before = nil
	}
	n := copy(p, step.b)
	if step.b = step.b[n:]; len(step.b) == 0 {
		*s = (*s)[1:]
	}
	return n, nil
}

// The relay on K's link (lan-v1 §4.4): what the node relays for K's group
// is charged to the group's bucket once, by its length (type and body),
// where it goes out to K (a neighbour's frame, the node's own for a
// neighbour through K), or, a neighbour's frame for the node through K,
// where it comes in; over the rate dropped and answered as any dropped
// frame. Free only between K and N; what K sends a neighbour is charged
// where it goes out to that neighbour, and here only with public peers,
// whose links no filter sees. At 0 nothing is relayed. A reload shows at
// the next read.
func TestNekoServerYggLinkFilterRelay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var sig [64]byte
	addrN := [32]byte(address.AddrForKey(keyN[:]).GetKey())
	addrG := [32]byte(address.AddrForKey(keyG[:]).GetKey())
	payload := make([]byte, 40_000)
	meta := []byte("meta\x00\x00")
	ping := iwFrame(iwBroken(nil, 0, keyN, keyK))
	nToK := iwTraffic(nil, nil, keyN, keyK, 1, payload)
	gToK := iwTraffic(nil, nil, keyG, keyK, 1, payload)
	aToK := iwTraffic(nil, nil, keyA, keyK, 1, payload)
	nNotifyG := iwNotify(nil, 1, keyN, keyG, 1, nil, sig)
	gNotifyK := iwNotify(nil, 1, keyG, keyK, 1, nil, sig)
	gLookupAddrG, gLookupN := iwLookup(keyG, addrG, 1), iwLookup(keyG, keyN, 1)
	toN, toG := iwTraffic(nil, nil, keyK, keyN, 0, payload), iwTraffic(nil, nil, keyK, keyG, 1, payload)
	kNotifyG := iwNotify(nil, 1, keyK, keyG, 1, nil, sig)
	kLookupN, kLookupAddrG := iwLookup(keyK, keyN, 1), iwLookup(keyK, addrG, 1)
	gToN, gLookupAddrN := iwTraffic(nil, nil, keyG, keyN, 0, payload), iwLookup(keyG, addrN, 1)

	// 2.5 Mbit/s: 312500 bytes a second, the burst.
	relay := newYggRelay(2)
	relay.rate, relay.burst = 312_500, 312_500
	relay.now = func() time.Time { return now }
	u1, u2 := relay.group("u1"), relay.group("u2")
	groups := yggGroups{keyK: u1, keyG: u1, keyA: u2}
	f, core, client, dropped := testFilter(func() yggGroups { return groups })

	// Down: N's own to K free, and its lookup for G; G's lookup for N
	// dropped, for N; G's lookup for another, G's notify to K, N's notify
	// to G through K, G's traffic to K charged: 7 of 40 kB fit what is left.
	down := slices.Concat(meta, iwFrame(nToK), iwFrame(iwLookup(keyN, keyG)), iwFrame(gLookupN), iwFrame(gLookupAddrG),
		iwFrame(gNotifyK), iwFrame(nNotifyG))
	for range 10 {
		down = append(down, iwFrame(gToK)...)
	}
	if err := f.testDown(&chunks{b: down, n: 5000}); err != io.EOF {
		t.Fatal(err)
	}
	charged := len(gLookupAddrG) + len(gNotifyK) + len(nNotifyG) + 7*len(gToK)
	if relay.frames.Load() != 10 || relay.dropped.Load() != 3 || relay.bytes.Load() != uint64(charged) || u1.up.Load() != int64(charged) || dropped.Load() != 1 {
		t.Fatalf("relayed %d frames, %d bytes (u1 %d), dropped over the rate %d, by the rule %d; want 10, %d, 3, 1",
			relay.frames.Load(), relay.bytes.Load(), u1.up.Load(), relay.dropped.Load(), dropped.Load(), charged)
	}
	want := slices.Concat(meta, iwFrame(nToK), iwFrame(iwLookup(keyN, keyG)), iwFrame(gLookupAddrG), iwFrame(gNotifyK), iwFrame(nNotifyG))
	for range 7 {
		want = append(want, iwFrame(gToK)...)
	}
	if !bytes.Equal(client.Bytes(), append(want, ping...)) || core.Len() != 0 {
		t.Fatalf("down: the client got %d bytes, want %d and the ping; the core %x", client.Len(), len(want), core.Bytes())
	}

	// Up, 31691 bytes left in the bucket: K's own to N free, and its
	// lookups; what it sends G free here, charged where it goes out to G;
	// G's traffic and lookup for N, through K, charged: the lookup fits,
	// the traffic does not.
	core.Reset()
	client.Reset()
	before := relay.frames.Load()
	up := slices.Concat(iwFrame(toN), iwFrame(kLookupN), iwFrame(kLookupAddrG), iwFrame(kNotifyG), iwFrame(toG), iwFrame(gToN), iwFrame(gLookupAddrN))
	if err := f.testUp(&chunks{b: up, n: 5000}); err != io.EOF {
		t.Fatal(err)
	}
	if want := slices.Concat(up[:len(up)-len(iwFrame(gToN))-len(iwFrame(gLookupAddrN))], iwFrame(gLookupAddrN)); !bytes.Equal(core.Bytes(), want) {
		t.Fatalf("up: the core got %d bytes, want %d", core.Len(), len(want))
	}
	if relay.frames.Load() != before+1 || relay.dropped.Load() != 4 || dropped.Load() != 1 || !bytes.Equal(client.Bytes(), yggKeepAliveFrame) ||
		u1.up.Load() != int64(charged+len(gLookupAddrN)) {
		t.Fatalf("up: relayed %d frames, dropped over the rate %d, by the rule %d; the client got %x",
			relay.frames.Load()-before, relay.dropped.Load(), dropped.Load(), client.Bytes())
	}

	charged += len(gLookupAddrN)

	// A second later the bucket is full again; the next read sees K moved
	// to u2 (with A), then out of any group: G's traffic to K is charged
	// to u1, then dropped by the rule, A's charged to u2; with no group, N
	// reaches K only.
	now = now.Add(time.Second)
	f, _, client, dropped = testFilter(func() yggGroups { return groups })
	s := &steps{
		{nil, slices.Concat(meta, iwFrame(gToK))},
		{func() { groups = yggGroups{keyK: u2, keyG: u1, keyA: u2} }, slices.Concat(iwFrame(gToK), iwFrame(aToK))},
		{func() { groups = yggGroups{keyG: u1, keyA: u2} }, slices.Concat(iwFrame(aToK), iwFrame(nToK))},
	}
	if err := f.testDown(s); err != io.EOF {
		t.Fatal(err)
	}
	if want := slices.Concat(meta, iwFrame(gToK), iwFrame(aToK), iwFrame(nToK), ping); !bytes.Equal(client.Bytes(), want) || dropped.Load() != 2 ||
		u1.up.Load() != int64(charged+len(gToK)) || u2.up.Load() != int64(len(aToK)) {
		t.Fatalf("across reloads: the client got %d bytes, dropped %d, u1 %d, u2 %d", client.Len(), dropped.Load(), u1.up.Load(), u2.up.Load())
	}

	// lan_relay_mbps 0: nothing between neighbours, the node as before.
	off := newYggRelay(0)
	g := off.group("u1")
	f, core, client, dropped = testFilter(func() yggGroups { return yggGroups{keyK: g, keyG: g} })
	if err := f.testDown(&chunks{b: slices.Concat(meta, iwFrame(gToK), iwFrame(nNotifyG), iwFrame(gLookupAddrG), iwFrame(nToK), iwFrame(iwLookup(keyN, keyG))), n: 7000}); err != io.EOF {
		t.Fatal(err)
	}
	if err := f.testUp(&chunks{b: slices.Concat(iwFrame(toG), iwFrame(gToN), iwFrame(kLookupAddrG), iwFrame(gLookupAddrN), iwFrame(toN)), n: 7000}); err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(client.Bytes(), slices.Concat(meta, iwFrame(nToK), iwFrame(iwLookup(keyN, keyG)), ping, yggKeepAliveFrame)) ||
		!bytes.Equal(core.Bytes(), slices.Concat(iwFrame(toG), iwFrame(kLookupAddrG), iwFrame(toN))) ||
		off.dropped.Load() != 5 || dropped.Load() != 0 || g.up.Load() != 0 {
		t.Fatalf("relay 0: the client got %d bytes, the core %d, dropped over the rate %d, by the rule %d",
			client.Len(), core.Len(), off.dropped.Load(), dropped.Load())
	}

	// Public peers: what K sends a neighbour may leave through one, past
	// every client: charged as it comes in. What comes to K from a key
	// linked here, a lookup too, was charged where it came in from its link;
	// from one not linked (on the public mesh), here.
	for _, gLinked := range []bool{true, false} {
		open := newYggRelay(1 << 30)
		g := open.group("u1")
		linked := yggKeys{keyK: true, keyG: gLinked}
		f := newYggLinkFilter(yggRule{node: keyN, key: keyK, groups: func() yggGroups { return yggGroups{keyK: g, keyG: g} },
			public: true, linked: func() yggKeys { return linked }}, new(atomic.Uint64), &sink{}, &sink{})
		_ = f.testUp(&chunks{b: slices.Concat(iwFrame(toG), iwFrame(kLookupAddrG), iwFrame(toN), iwFrame(kLookupN)), n: 7000})
		upCharged := g.up.Load()
		_ = f.testDown(&chunks{b: slices.Concat(meta, iwFrame(gToK), iwFrame(gLookupAddrG), iwFrame(nNotifyG), iwFrame(nToK)), n: 7000})
		want := len(nNotifyG)
		if !gLinked {
			want += len(gToK) + len(gLookupAddrG)
		}
		if upCharged != int64(len(toG)+len(kLookupAddrG)) || g.up.Load()-upCharged != int64(want) {
			t.Errorf("public peers, G linked %v: charged %d up, %d down; want %d, %d",
				gLinked, upCharged, g.up.Load()-upCharged, len(toG)+len(kLookupAddrG), want)
		}
	}
}
