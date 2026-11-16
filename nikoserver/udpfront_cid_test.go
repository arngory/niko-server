//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

// cidSecret is the tests' node secret of routable connection IDs;
// otherSecret another node's.
var (
	cidSecret   = bytes.Repeat([]byte{0x5a}, 32)
	otherSecret = bytes.Repeat([]byte{0x5b}, 32)
)

// cidID is the ID of a label and a counter under a node's secret.
func cidID(secret []byte, label uint16, counter uint64) [cidLen]byte {
	return labelCodec(secret, label).encode(label, counter)
}

// writeCIDLabelKey writes a backend's key of its label.
func writeCIDLabelKey(t testing.TB, dir string, secret []byte, label uint16) string {
	t.Helper()
	p := filepath.Join(dir, fmt.Sprintf("quic-cid-%d.key", label))
	if err := os.WriteFile(p, []byte(hex.EncodeToString(cidLabelKey(secret, label))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeCIDKey(t testing.TB, dir string, secret []byte) string {
	t.Helper()
	p := filepath.Join(dir, "quic-cid.key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// shortPacket is a client's 1-RTT packet to a server connection ID: a
// short header and size bytes in all, random after the ID.
func shortPacket(id [cidLen]byte, size int) []byte {
	d := make([]byte, size)
	rand.Read(d)
	d[0] = 0x40 | d[0]&0x3f
	copy(d[1:], id[:])
	return d
}

// handshakePacket is a client's Handshake packet of QUIC v1 to a server ID.
func handshakePacket(id [cidLen]byte, size int) []byte {
	d := make([]byte, size)
	rand.Read(d)
	d[0] = 0xe0 | d[0]&0x0f
	binary.BigEndian.PutUint32(d[1:5], quicV1)
	d[5] = cidLen
	copy(d[6:], id[:])
	return d
}

// obfuscate wraps a packet in salamander with a password.
func obfuscate(password string, p []byte) []byte {
	salt := make([]byte, 8)
	rand.Read(salt)
	key := blake2b.Sum256(append([]byte(password), salt...))
	out := append([]byte(nil), salt...)
	for i, b := range p {
		out = append(out, b^key[i%32])
	}
	return out
}

// cidFront is a front with routing by connection ID: plain QUIC backends
// "a" (label 1) and "b" (label 2), a salamander backend "s" (label 3) and
// a plain one without a label, "n". Its links are not up: classify only.
func cidFront(t testing.TB, withKey bool) (*udpFront, string) {
	t.Helper()
	dir := t.TempDir()
	password := "c2FsYW1hbmRlci1wYXNzd29yZA"
	pwFile := filepath.Join(dir, "salamander")
	os.WriteFile(pwFile, []byte(password+"\n"), 0o600)
	c := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{
		{SNI: []string{"a.example.com"}, Backend: "a"},
		{SNI: []string{"b.example.com"}, Backend: "b"},
		{SNI: []string{"n.example.com"}, Backend: "n"},
		{SalamanderPasswordFile: pwFile, Backend: "s"},
	}}
	if withKey {
		c.CIDKeyFile = writeCIDKey(t, dir, cidSecret)
	}
	backends := map[string]BackendRef{}
	for name, label := range map[string]int{"a": 1, "b": 2, "s": 3, "n": 0} {
		if !withKey {
			label = 0
		}
		backends[name] = BackendRef{Socket: filepath.Join(dir, name+".sock"), Mode: "packet", UID: os.Getuid(), CIDLabel: label}
	}
	fc := &FrontConfig{Schema: 1, Role: "front", UDP: c, Backends: backends}
	if errs := fc.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f, err := newUDPFront(c, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return f, password
}

func TestUDPFrontCIDClassify(t *testing.T) {
	f, password := cidFront(t, true)
	now := time.Now()
	n := 0
	key := func() flowKey { // a new client port each time
		n++
		return flowKey{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(10000+n)), netip.MustParseAddrPort("127.0.0.1:443")}
	}
	id := func(label uint16) [cidLen]byte { return cidID(cidSecret, label, uint64(n)) }
	for _, c := range []struct {
		name string
		d    []byte
		want string
	}{
		{"short header, label 1", shortPacket(id(1), 1200), "a"},
		{"short header, label 2", shortPacket(id(2), 40), "b"},
		{"handshake, label 1", handshakePacket(id(1), 1200), "a"},
		{"short header under salamander, label 3", obfuscate(password, shortPacket(id(3), 1200)), "s"},
		{"handshake under salamander, label 3", obfuscate(password, handshakePacket(id(3), 1200)), "s"},
		// A salamander backend's label in the clear, a plain one's under
		// salamander: neither is that backend's packet.
		{"label 3 in the clear", shortPacket(id(3), 1200), ""},
		{"label 1 under salamander", obfuscate(password, shortPacket(id(1), 1200)), ""},
		{"label 3 under another password", obfuscate("another", shortPacket(id(3), 1200)), ""},
		{"a label no backend has", shortPacket(id(9), 1200), ""},
		{"another node's key", shortPacket(cidID(otherSecret, 1, 7), 1200), ""},
		{"too short to be a packet", shortPacket(id(1), minCIDPacket-1), ""},
		{"too short under salamander", obfuscate(password, shortPacket(id(3), minCIDPacket-1)), ""},
		{"long header of another type", func() []byte { d := handshakePacket(id(1), 1200); d[0] = 0xd0; return d }(), ""},
		{"long header, another ID length", func() []byte { d := handshakePacket(id(1), 1200); d[5] = 4; return d }(), ""},
	} {
		link, packets := f.classify(key(), c.d, now)
		got := ""
		if link != nil {
			got = link.name
			if len(packets) != 1 || !bytes.Equal(packets[0], c.d) {
				t.Errorf("%s: forwards %d packets", c.name, len(packets))
			}
		}
		if got != c.want {
			t.Errorf("%s: backend %q, want %q", c.name, got, c.want)
		}
	}

	// An Initial goes by its name, whatever its Destination Connection ID
	// says: a client's first ID is its own.
	initial := handshakePacket(id(1), 1200)
	initial[0] = 0xc0 | initial[0]&0x0f
	if link, _ := f.classify(key(), initial, now); link != nil {
		t.Fatalf("an Initial went to %s by its ID", link.name)
	}

	// A front without the key reads no labels.
	plain, _ := cidFront(t, false)
	if link, _ := plain.classify(key(), shortPacket(id(1), 1200), now); link != nil {
		t.Fatal("routed by ID without a key")
	}
}

// One source pins cidFlowBurst flows by label at once, then cidFlowRate a
// second; another source has its own share.
func TestUDPFrontCIDSourceLimit(t *testing.T) {
	f, _ := cidFront(t, true)
	now := time.Now()
	from := func(addr string, port int) flowKey {
		return flowKey{netip.AddrPortFrom(netip.MustParseAddr(addr), uint16(port)), netip.MustParseAddrPort("127.0.0.1:443")}
	}
	pinned := func(k flowKey, at time.Time) bool {
		link, _ := f.classify(k, shortPacket(cidID(cidSecret, 1, uint64(k.client.Port())), 100), at)
		return link != nil
	}
	for i := range cidFlowBurst {
		if !pinned(from("198.51.100.7", 1000+i), now) {
			t.Fatalf("flow %d refused within the burst", i)
		}
	}
	if pinned(from("198.51.100.7", 9999), now) {
		t.Fatal("past the burst")
	}
	// The same /64 is one source; another /64 is another.
	for i := range cidFlowBurst {
		pinned(from("2001:db8:0:1::1", 1000+i), now)
	}
	if pinned(from("2001:db8:0:1::2", 1), now) {
		t.Fatal("another address of the same /64 past its burst")
	}
	if !pinned(from("2001:db8:0:2::1", 1), now) || !pinned(from("198.51.100.8", 1), now) {
		t.Fatal("another source refused")
	}
	if !pinned(from("198.51.100.7", 9999), now.Add(time.Second/cidFlowRate+time.Millisecond)) {
		t.Fatal("no new flow a moment later")
	}
	// A source not seen for two generations is forgotten, its share full.
	f.expire(now.Add(3 * time.Minute))
	f.expire(now.Add(5 * time.Minute))
	if !pinned(from("198.51.100.7", 9999), now.Add(5*time.Minute)) {
		t.Fatal("refused after the source was forgotten")
	}
}

// Flows pinned by a label under salamander take the same per-source share
// as plain ones: one source pins cidFlowBurst of them, then no more.
func TestUDPFrontCIDSourceLimitSalamander(t *testing.T) {
	f, password := cidFront(t, true)
	now := time.Now()
	from := func(port int) flowKey {
		return flowKey{netip.AddrPortFrom(netip.MustParseAddr("198.51.100.9"), uint16(port)), netip.MustParseAddrPort("127.0.0.1:443")}
	}
	for i := range cidFlowBurst {
		if link, _ := f.classify(from(1000+i), obfuscate(password, shortPacket(cidID(cidSecret, 3, uint64(i)), 100)), now); link == nil || link.name != "s" {
			t.Fatalf("flow %d refused within the burst", i)
		}
	}
	if link, _ := f.classify(from(9999), obfuscate(password, shortPacket(cidID(cidSecret, 3, 9999), 100)), now); link != nil {
		t.Fatal("a salamander flow by label past the burst")
	}
	// The share is the source's, plain and salamander together.
	if link, _ := f.classify(from(9998), shortPacket(cidID(cidSecret, 1, 9998), 100), now); link != nil {
		t.Fatal("a plain flow by label past the source's burst")
	}
}

// The limiter's memory is bounded: two generations of cidSourcesMax
// sources at most, however many come. A source drained in the generation
// before stays drained in the next (its bucket is carried over); after two
// generations' worth of other sources it is forgotten and its share is
// whole again: the bound is on memory, not on the flow table (a source
// that cycles 2·cidSourcesMax addresses, an IPv6 /48, gets a share each).
func TestUDPFrontCIDSourceMemory(t *testing.T) {
	var s sourceLimits
	now := time.Now()
	a := netip.MustParseAddr("203.0.113.1")
	for range cidFlowBurst {
		s.allow(a, now)
	}
	if s.allow(a, now) {
		t.Fatal("past the burst")
	}
	addr := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 16), byte(i >> 8), byte(i), 0, 8: 1})
	}
	// One generation fills: a is carried over, still drained.
	for i := range cidSourcesMax {
		s.allow(addr(i), now)
		if len(s.sources) > cidSourcesMax || len(s.older) > cidSourcesMax {
			t.Fatalf("%d and %d sources remembered", len(s.sources), len(s.older))
		}
	}
	if s.allow(a, now) {
		t.Fatal("a source drained in the generation before has its share again")
	}
	for i := cidSourcesMax; i < 3*cidSourcesMax; i++ {
		s.allow(addr(i), now)
		if len(s.sources) > cidSourcesMax || len(s.older) > cidSourcesMax {
			t.Fatalf("%d and %d sources remembered", len(s.sources), len(s.older))
		}
	}
	if !s.allow(a, now) {
		t.Fatal("a source two generations away is still remembered")
	}
}

// A datagram no flow explains and that is no packet of ours costs the
// front no allocation: a flood of short headers, Handshakes, salamander
// look-alikes and garbage.
func TestUDPFrontCIDMissNoAllocations(t *testing.T) {
	f, password := cidFront(t, true)
	k := flowKey{netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("127.0.0.1:443")}
	junk := make([]byte, 1200)
	rand.Read(junk)
	junk[0] = 0x01
	now := time.Now()
	for _, d := range [][]byte{
		shortPacket(cidID(otherSecret, 1, 1), 1200),
		handshakePacket(cidID(otherSecret, 1, 2), 1200),
		obfuscate(password, shortPacket(cidID(otherSecret, 3, 3), 1200)),
		junk,
	} {
		if n := testing.AllocsPerRun(200, func() {
			if link, _ := f.classify(k, d, now); link != nil {
				t.Fatal("routed")
			}
		}); n != 0 {
			t.Fatalf("%x...: %v allocations", d[:2], n)
		}
	}
}

// Through the front's sockets: a client pinned by its Initial moves to a
// new port; its next packet comes from there, and the backend's answer
// goes back to it there.
func TestUDPFrontCIDNewAddress(t *testing.T) {
	dir := t.TempDir()
	uid := os.Getuid()
	masq := packetBackend(t, filepath.Join(dir, "masq.sock"))
	obfs := packetBackend(t, filepath.Join(dir, "obfs.sock"))
	password := "c2FsYW1hbmRlci1wYXNzd29yZA"
	pwFile := filepath.Join(dir, "salamander")
	os.WriteFile(pwFile, []byte(password+"\n"), 0o600)
	c := &FrontUDP{Listen: []string{"127.0.0.1:0"}, CIDKeyFile: writeCIDKey(t, dir, cidSecret), Routes: []UDPRoute{
		{SNI: []string{"h.example.com"}, Backend: "hy2-masq"},
		{SalamanderPasswordFile: pwFile, Backend: "hy2-obfs"},
	}}
	backends := map[string]BackendRef{
		"hy2-masq": {Socket: filepath.Join(dir, "masq.sock"), Mode: "packet", UID: uid, CIDLabel: 11},
		"hy2-obfs": {Socket: filepath.Join(dir, "obfs.sock"), Mode: "packet", UID: uid, CIDLabel: 12},
	}
	addr := startUDPFront(t, c, backends)
	client := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	receive := func(b *packetConn, within time.Duration) ([]byte, net.Addr, bool) {
		b.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 2048)
		n, from, err := b.ReadFrom(buf)
		if err != nil {
			return nil, nil, false
		}
		return buf[:n], from, true
	}
	for _, tc := range []struct {
		name    string
		backend *packetConn
		label   uint16
		wrap    func([]byte) []byte
	}{
		{"plain", masq, 11, func(p []byte) []byte { return p }},
		{"salamander", obfs, 12, func(p []byte) []byte { return obfuscate(password, p) }},
	} {
		moved := client()
		p := tc.wrap(shortPacket(cidID(cidSecret, tc.label, 1), 300))
		moved.Write(p)
		got, from, ok := receive(tc.backend, 2*time.Second)
		if !ok || !bytes.Equal(got, p) || from.String() != moved.LocalAddr().String() {
			t.Fatalf("%s: the backend got %d bytes from %v (%v)", tc.name, len(got), from, ok)
		}
		// The flow is pinned: what follows needs no label.
		moved.Write([]byte("anything"))
		if got, _, ok := receive(tc.backend, 2*time.Second); !ok || string(got) != "anything" {
			t.Fatalf("%s: the pinned flow lost a packet: %q", tc.name, got)
		}
		tc.backend.WriteTo([]byte("answer"), moved.LocalAddr())
		moved.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		if n, err := moved.Read(buf); err != nil || string(buf[:n]) != "answer" {
			t.Fatalf("%s: answer at the new address: %q %v", tc.name, buf[:n], err)
		}
	}
	// A label of the other backend's, or of another key, goes nowhere.
	stray := client()
	stray.Write(shortPacket(cidID(cidSecret, 12, 2), 300))
	stray.Write(shortPacket(cidID(bytes.Repeat([]byte{1}, 32), 11, 3), 300))
	if _, _, ok := receive(masq, 200*time.Millisecond); ok {
		t.Fatal("hy2-masq got a stray packet")
	}
	if _, _, ok := receive(obfs, 100*time.Millisecond); ok {
		t.Fatal("hy2-obfs got a stray packet")
	}
}

// startUDPFront runs a UDP front on loopback until the test ends, its
// links up, and returns its address (one of them, with several).
func startUDPFront(t *testing.T, c *FrontUDP, backends map[string]BackendRef) *net.UDPAddr {
	t.Helper()
	front := runUDPFront(t, c, backends)
	for _, s := range front.sockets {
		return s.LocalAddr().(*net.UDPAddr)
	}
	return nil
}

// runUDPFront runs a UDP front on loopback until the test ends, its links
// up.
func runUDPFront(t *testing.T, c *FrontUDP, backends map[string]BackendRef) *udpFront {
	t.Helper()
	fc := &FrontConfig{Schema: 1, Role: "front", UDP: c, Backends: backends}
	if errs := fc.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	front, err := newUDPFront(c, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if err := front.listen(c.Listen); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go front.run(ctx)
	for _, l := range front.links {
		for i := 0; ; i++ {
			l.access.Lock()
			up := l.conn != nil
			l.access.Unlock()
			if up {
				break
			}
			if i == 200 {
				t.Fatalf("backend %s never connected", l.name)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return front
}

// What a datagram no flow explains costs the front, by what it is: a
// short header of another key, the same under salamander (one password),
// garbage that is neither.
func BenchmarkUDPFrontCIDMiss(b *testing.B) {
	f, password := cidFront(b, true)
	k := flowKey{netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("127.0.0.1:443")}
	junk := make([]byte, 1200)
	rand.Read(junk)
	junk[0] = 0x01
	now := time.Now()
	for name, d := range map[string][]byte{
		"short":      shortPacket(cidID(otherSecret, 1, 1), 1200),
		"salamander": obfuscate(password, shortPacket(cidID(otherSecret, 3, 3), 1200)),
		"garbage":    junk,
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f.classify(k, d, now)
			}
		})
	}
	nokey, _ := cidFront(b, false)
	b.Run("garbage without a key", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			nokey.classify(k, junk, now)
		}
	})
}
