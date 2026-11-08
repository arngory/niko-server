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
)

// Frames byte for byte as ironwood 0712ecc encodes them: a path
// (network/wire.go:80-86), traffic (traffic.go:36-49), pathNotify and its
// info (pathfinder.go:448-463, 395-405), pathBroken (pathfinder.go:514-525),
// the length before the type (peers.go:205-214).

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
	noGroup = func(*[32]byte) yggGroup { return 0 }
)

func TestNekoServerYggFrameKeys(t *testing.T) {
	var sig [64]byte
	sig[0], sig[63] = 0xaa, 0xbb
	traffic := iwTraffic([]uint64{1, 300}, []uint64{2}, keyK, keyN, ^uint64(0), []byte("payload"))
	notify := iwNotify([]uint64{5}, 7, keyN, keyK, 1700000000, []uint64{1, 2, 3}, sig)
	broken := iwBroken(nil, ^uint64(0), keyK, keyA)
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
		{"lookup, whatever is in it", []byte{6, 0xff}, false, true, [32]byte{}, [32]byte{}},
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
		// The reference decoder agrees on every case.
		rs, rd, rkeyed, rok := iwRefKeys(c.frame)
		if rkeyed != keyed || rok != ok || ok && keyed && (rs != *source || rd != *dest) {
			t.Errorf("%s: the reference says keyed %v ok %v", c.name, rkeyed, rok)
		}
	}
}

func TestNekoServerYggRule(t *testing.T) {
	groups := map[[32]byte]yggGroup{keyK: 1, keyG: 1, keyA: 2}
	inGroups := func(k *[32]byte) yggGroup { return groups[*k] }
	const up, down = true, false
	for _, c := range []struct {
		name         string
		groups       bool
		fromClient   bool
		typ          byte
		source, dest [32]byte
		pass         bool
	}{
		{"traffic K to N", false, up, yggTraffic, keyK, keyN, true},
		{"traffic K to another", false, up, yggTraffic, keyK, keyA, false},
		{"traffic forging N", false, up, yggTraffic, keyN, keyA, false},
		{"traffic forging N to N", false, up, yggTraffic, keyN, keyN, false},
		{"traffic forging another", false, up, yggTraffic, keyA, keyN, false},
		{"traffic K to K", false, up, yggTraffic, keyK, keyK, false},
		{"pathNotify K to N", false, up, yggPathNotify, keyK, keyN, true},
		{"pathNotify K to another", false, up, yggPathNotify, keyK, keyA, false},
		{"pathBroken of N's traffic to K, back to N", false, up, yggPathBroken, keyN, keyK, true},
		{"pathBroken of K's traffic to N", false, up, yggPathBroken, keyK, keyN, false},
		{"pathBroken of another's traffic", false, up, yggPathBroken, keyA, keyK, false},
		{"traffic N to K", false, down, yggTraffic, keyN, keyK, true},
		{"traffic another to K", false, down, yggTraffic, keyA, keyK, false},
		{"traffic N to another, through K", false, down, yggTraffic, keyN, keyA, false},
		{"pathNotify N to K", false, down, yggPathNotify, keyN, keyK, true},
		{"pathNotify another to K", false, down, yggPathNotify, keyA, keyK, false},
		{"pathBroken of K's traffic to N, back to K", false, down, yggPathBroken, keyK, keyN, true},
		{"pathBroken of N's traffic to K", false, down, yggPathBroken, keyN, keyK, false},
		{"pathBroken of K's traffic to another", false, down, yggPathBroken, keyK, keyA, false},
		// With groups: K and G in one, A in another, N in none.
		{"group: traffic K to G", true, up, yggTraffic, keyK, keyG, true},
		{"group: traffic G to N, through K", true, up, yggTraffic, keyG, keyN, true},
		{"group: traffic K to A", true, up, yggTraffic, keyK, keyA, false},
		{"group: traffic A to N, through K", true, up, yggTraffic, keyA, keyN, false},
		{"group: traffic G to K", true, down, yggTraffic, keyG, keyK, true},
		{"group: traffic N to G, through K", true, down, yggTraffic, keyN, keyG, true},
		{"group: traffic A to K", true, down, yggTraffic, keyA, keyK, false},
		{"group: pathBroken of K's traffic to G, back to K", true, down, yggPathBroken, keyK, keyG, true},
		{"group: pathBroken of K's traffic to A", true, down, yggPathBroken, keyK, keyA, false},
	} {
		r := yggRule{node: keyN, key: keyK, group: noGroup}
		if c.groups {
			r.group = inGroups
		}
		if got := r.passes(c.fromClient, c.typ, &c.source, &c.dest); got != c.pass {
			t.Errorf("%s: passes %v", c.name, got)
		}
	}
	// No group is no group: two keys in none are not in one.
	r := yggRule{node: keyN, key: keyK, group: func(k *[32]byte) yggGroup { return groups[*k] }}
	delete(groups, keyK)
	a, n := keyA, keyN
	groups[keyA] = 0
	if r.passes(true, yggTraffic, &keyK, &a) || !r.passes(true, yggTraffic, &keyK, &n) {
		t.Error("two keys without a group pass as one group")
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

func TestNekoServerYggLinkFilter(t *testing.T) {
	var sig [64]byte
	big := make([]byte, 100<<10)
	rand.Read(big)
	// The largest frame: the type and body yggFrameMax bytes.
	largest := iwTraffic(nil, nil, keyK, keyN, 1, nil)
	largest = append(largest, make([]byte, yggFrameMax-len(largest))...)
	type frame struct {
		b    []byte
		pass bool
	}
	up := []frame{
		{iwFrame([]byte{1}), true}, // keepalive
		{iwFrame(iwTraffic([]uint64{1}, nil, keyK, keyN, 3, []byte("to the node"))), true},
		{iwFrame(iwTraffic(nil, nil, keyN, keyA, 3, []byte("forged"))), false},
		{iwFrame(iwNotify(nil, 1, keyK, keyN, 9, []uint64{1}, sig)), true},
		{iwFrame(iwNotify(nil, 1, keyK, keyA, 9, []uint64{1}, sig)), false},
		{iwFrame(append([]byte{5}, make([]byte, 32)...)), true}, // a bloom filter: not read
		{iwFrame(iwTraffic(nil, nil, keyK, keyN, 1, big)), true},
		{iwFrame(iwTraffic(nil, nil, keyK, keyA, 1, big)), false},
		{iwFrame(largest), true},
		{iwFrame(iwBroken([]uint64{4}, 2, keyN, keyK)), true},
		{iwFrame(iwBroken([]uint64{4}, 2, keyK, keyN)), false},
		// A length not in the fewest bytes: ironwood takes it, and it
		// passes as it came.
		{append([]byte{0x81, 0x80, 0x00}, 1), true},
		{iwFrame([]byte{6, 1, 2, 3}), true}, // a lookup: not read
	}
	var stream, want []byte
	drops := 0
	for _, f := range up {
		stream = append(stream, f.b...)
		if f.pass {
			want = append(want, f.b...)
		} else {
			drops++
		}
	}
	for _, n := range []int{1, 3, 1000, 16 << 10, 64 << 10, len(stream)} {
		var dropped atomic.Uint64
		f := &yggLinkFilter{rule: yggRule{node: keyN, key: keyK, group: noGroup}, dropped: &dropped}
		out := &sink{}
		if err := f.up(out, &chunks{b: stream, n: n}); err != io.EOF {
			t.Fatalf("reads of %d: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), want) || dropped.Load() != uint64(drops) {
			t.Fatalf("reads of %d: %d bytes of %d, %d dropped of %d", n, out.Len(), len(want), dropped.Load(), drops)
		}
		if n == len(stream) && out.writes > 2*drops+2 {
			t.Errorf("one read: %d writes", out.writes)
		}
	}

	// The core's side: its handshake as it is, then frames to the client.
	meta := append([]byte("meta\x00\x05"), 1, 2, 3, 4, 5)
	down := slices.Concat(meta,
		iwFrame(iwTraffic(nil, nil, keyN, keyK, 1, []byte("to K"))),
		iwFrame(iwTraffic(nil, nil, keyN, keyA, 1, []byte("through K"))),
		iwFrame(iwBroken(nil, 1, keyK, keyN)))
	wantDown := slices.Concat(meta, iwFrame(iwTraffic(nil, nil, keyN, keyK, 1, []byte("to K"))),
		iwFrame(iwBroken(nil, 1, keyK, keyN)))
	for _, n := range []int{1, 4, 7, len(down)} {
		var dropped atomic.Uint64
		f := &yggLinkFilter{rule: yggRule{node: keyN, key: keyK, group: noGroup}, dropped: &dropped}
		out := &sink{}
		if err := f.down(out, &chunks{b: down, n: n}); err != io.EOF {
			t.Fatalf("down, reads of %d: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), wantDown) || dropped.Load() != 1 {
			t.Fatalf("down, reads of %d: %x, %d dropped", n, out.Bytes(), dropped.Load())
		}
	}

	// What ends the link; what passed before is written.
	good := iwFrame(iwTraffic(nil, nil, keyK, keyN, 1, []byte("ok")))
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
		var dropped atomic.Uint64
		f := &yggLinkFilter{rule: yggRule{node: keyN, key: keyK, group: noGroup}, dropped: &dropped}
		out := &sink{}
		var err error
		if c.down {
			err = f.down(out, &chunks{b: c.stream, n: 5})
		} else {
			err = f.up(out, &chunks{b: c.stream, n: 5})
		}
		if err != c.err || !bytes.Equal(out.Bytes(), c.want) {
			t.Errorf("%s: %v, %d bytes written", c.name, err, out.Len())
		}
	}
	// A failed write ends the copy.
	var dropped atomic.Uint64
	f := &yggLinkFilter{rule: yggRule{node: keyN, key: keyK, group: noGroup}, dropped: &dropped}
	if err := f.up(&sink{fail: true}, &chunks{b: good, n: 100}); err == nil || err == io.EOF {
		t.Errorf("a failed write: %v", err)
	}
}

// iwNet is ironwood on its own, as the core runs it: routers joined by
// pipes, each frame between them seen on the way.
type iwNet struct {
	t      *testing.T
	mu     sync.Mutex
	frames []iwSeen
}

// iwSeen is a frame on a link, as the filter reads it.
type iwSeen struct {
	from, to     ed25519.PublicKey // the link's ends, in the frame's direction
	typ          byte
	keyed, ok    bool
	source, dest [32]byte
}

func (n *iwNet) node(key ed25519.PrivateKey) *iwn.PacketConn {
	pc, err := iwn.NewPacketConn(key, iwn.WithPeerMaxMessageSize(yggFrameMax))
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { pc.Close() })
	go func() { // whatever comes, read and forgotten
		b := make([]byte, 65535)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	return pc
}

func iwKey(pc *iwn.PacketConn) ed25519.PublicKey { return ed25519.PublicKey(pc.LocalAddr().(iwt.Addr)) }

// link joins a and b; cut ends the link.
func (n *iwNet) link(a, b *iwn.PacketConn) (cut func()) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	go func() { _ = a.HandleConn(iwKey(b), a1, 0) }()
	go func() { _ = b.HandleConn(iwKey(a), b1, 0) }()
	go n.relay(a2, b2, iwKey(a), iwKey(b))
	go n.relay(b2, a2, iwKey(b), iwKey(a))
	return func() {
		for _, c := range []net.Conn{a1, a2, b1, b2} {
			c.Close()
		}
	}
}

// relay splits the frames as ironwood reads them (peers.go:247-266), on
// its own, and has the filter's parser read each.
func (n *iwNet) relay(src, dst net.Conn, from, to ed25519.PublicKey) {
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
		seen := iwSeen{from: from, to: to, typ: frame[0]}
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
		if s.keyed != (s.typ >= yggPathNotify && s.typ <= yggTraffic) || !s.ok {
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
				f := &yggLinkFilter{rule: yggRule{node: keyN, key: keyK, group: noGroup}, dropped: &dropped}
				b.SetBytes(int64(len(stream)))
				b.ReportAllocs()
				for b.Loop() {
					_ = f.up(discard{}, &chunks{b: stream, n: read})
				}
			})
		}
	}
}
