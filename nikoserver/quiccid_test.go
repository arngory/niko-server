package nikoserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Speck64/128's vector from the paper (Beaulieu et al., "The SIMON and
// SPECK Families of Lightweight Block Ciphers", appendix C), words as
// printed there.
func TestSpeckVector(t *testing.T) {
	key, _ := hex.DecodeString("1b1a1918131211100b0a090803020100")
	c := newSpeck(key)
	x, y := c.encrypt(0x3b726574, 0x7475432d)
	if x != 0x8c6fa548 || y != 0x454e028b {
		t.Fatalf("Speck64/128: %08x %08x, want 8c6fa548 454e028b", x, y)
	}
	if x, y = c.decrypt(x, y); x != 0x3b726574 || y != 0x7475432d {
		t.Fatalf("decrypt: %08x %08x", x, y)
	}
}

// cidLabelKey is a label's Speck key, as raycontrol derives it from the
// node's secret (quic-cid-route-v1 §2): HMAC-SHA256(secret,
// "quic-cid-route-v1" || BE16(label)), its first 16 bytes. niko-server
// never has the secret: the tests derive the keys they give it.
func cidLabelKey(secret []byte, label uint16) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("quic-cid-route-v1"))
	mac.Write([]byte{byte(label >> 8), byte(label)})
	return mac.Sum(nil)[:16]
}

// labelCodec is the codec of a label's key under a node's secret.
func labelCodec(secret []byte, label uint16) *cidCodec {
	return newSpeck(cidLabelKey(secret, label))
}

// The spec's example (quic-cid-route-v1 §8): raycontrol's codec checks the
// same numbers.
func TestCIDExample(t *testing.T) {
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if got := hex.EncodeToString(cidLabelKey(secret, 0x0102)); got != "167e64ae0e81012cf5f8667f5525e7ee" {
		t.Fatalf("label key %s", got)
	}
	c := labelCodec(secret, 0x0102)
	id := c.encode(0x0102, 0x030405060708) // the counter's low 40 bits: 0405060708
	if got := hex.EncodeToString(id[:]); got != cidExample {
		t.Fatalf("ID %s, want %s", got, cidExample)
	}
	if label, ok := c.label(id[:]); !ok || label != 0x0102 {
		t.Fatalf("label %#x %v", label, ok)
	}
	x, y := c.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	if x != 0x01020004 || y != 0x05060708 {
		t.Fatalf("plain %08x %08x", x, y)
	}
}

const cidExample = "0243e188ccdc1084"

// Each label has its own key: an ID reads as its label under that key
// only, not under another label's of the same node, nor another node's.
func TestCIDLabels(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	labels := []uint16{1, 2, 300, MaxCIDLabel}
	for i, label := range labels {
		c := labelCodec(secret, label)
		neighbour := labelCodec(secret, labels[(i+1)%len(labels)])
		other := labelCodec(bytes.Repeat([]byte{8}, 32), label)
		if c.rk == neighbour.rk || c.rk == other.rk {
			t.Fatal("two labels, or two nodes, share a key")
		}
		g, err := newCIDGenerator(c, label)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[[cidLen]byte]bool{}
		for range 1000 {
			id := g.generate()
			if seen[id] {
				t.Fatalf("label %d: %x twice", label, id)
			}
			seen[id] = true
			if got, ok := c.label(id[:]); !ok || got != label {
				t.Fatalf("label %d read as %d %v", label, got, ok)
			}
			// Another key reads no label in it, but by chance.
			for _, k := range []*cidCodec{neighbour, other} {
				if got, ok := k.label(id[:]); ok && (got == label || got == labels[(i+1)%len(labels)]) {
					t.Fatalf("another key reads label %d", got)
				}
			}
		}
	}
	if _, err := newCIDGenerator(labelCodec(secret, 1), 0); err == nil {
		t.Fatal("label 0")
	}
	// The counter wraps within its 40 bits.
	c := labelCodec(secret, 9)
	g, _ := newCIDGenerator(c, 9)
	g.next.Store(1<<cidCounterBits - 2)
	a, b := g.generate(), g.generate()
	if a != c.encode(9, 1<<cidCounterBits-1) || b != c.encode(9, 0) {
		t.Fatal("counter past 2^40")
	}
}

// An ID the generator has not issued yet, within its window, is ahead;
// one it issued, one of another label or another key, or garbage is not.
func TestCIDAhead(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, 32)
	c := labelCodec(secret, 5)
	g, _ := newCIDGenerator(c, 5)
	g.next.Store(1<<cidCounterBits - 3) // the window wraps past 2^40
	issued := [][cidLen]byte{g.generate(), g.generate(), g.generate()}
	last := g.next.Load()
	for _, id := range issued {
		if g.ahead(id[:]) {
			t.Fatalf("%x issued, read as ahead", id)
		}
	}
	const mask = 1<<cidCounterBits - 1
	for _, d := range []uint64{1, 2, 64, cidAheadWindow} {
		id := c.encode(5, (last+d)&mask)
		if !g.ahead(id[:]) {
			t.Fatalf("counter +%d not ahead", d)
		}
	}
	for _, d := range []uint64{0, cidAheadWindow + 1, 1 << 39} {
		id := c.encode(5, (last+d)&mask)
		if g.ahead(id[:]) {
			t.Fatalf("counter +%d ahead", d)
		}
	}
	next := c.encode(5, (last+1)&mask)
	if g.generate() != next || g.ahead(next[:]) {
		t.Fatal("the next ID, once issued, is still ahead")
	}
	for _, id := range [][cidLen]byte{labelCodec(secret, 6).encode(6, last+2), labelCodec(bytes.Repeat([]byte{1}, 32), 5).encode(5, last+2), {1, 2, 3}} {
		if g.ahead(id[:]) {
			t.Fatalf("%x: ahead", id)
		}
	}
	if g.ahead([]byte{1, 2, 3}) {
		t.Fatal("3 bytes")
	}
	// The label and a counter in the window, but not the zero byte: no ID
	// of the generator's.
	x, y := c.encrypt(5<<16|0x0100|uint32((last+2)>>32&0xff), uint32(last+2))
	var odd [cidLen]byte
	binary.BigEndian.PutUint32(odd[0:4], x)
	binary.BigEndian.PutUint32(odd[4:8], y)
	if g.ahead(odd[:]) {
		t.Fatal("an ID without its zero byte read as ahead")
	}
	// What the server drops: a short header for an ID ahead, of a packet
	// QUIC could open; the same bytes in a long header, or too short, pass.
	ahead := c.encode(5, (last+3)&mask)
	p := shortPacket(ahead, 100)
	if !g.dropAhead(p) {
		t.Fatal("a short header for an ID ahead passes")
	}
	for name, q := range map[string][]byte{
		"long header":  append([]byte{0xc0 | p[0]&0x0f}, p[1:]...),
		"no fixed bit": append([]byte{p[0] & 0x3f}, p[1:]...),
		"too short":    p[:minCIDPacket-1],
		"issued":       shortPacket(c.encode(5, last&mask), 100),
	} {
		if g.dropAhead(q) {
			t.Errorf("%s: dropped", name)
		}
	}
}

// Random IDs read as a label under its key about 2^-24 of the time: none
// in a million, by a wide margin.
func TestCIDRandomMiss(t *testing.T) {
	c := labelCodec(bytes.Repeat([]byte{1}, 32), 5)
	r := rand.New(rand.NewPCG(1, 2))
	var id [cidLen]byte
	hits := 0
	for range 1 << 20 {
		binary.BigEndian.PutUint64(id[:], r.Uint64())
		if label, ok := c.label(id[:]); ok && label == 5 {
			hits++
		}
	}
	if hits > 2 {
		t.Fatalf("%d random IDs of 2^20 read as label 5", hits)
	}
}

func TestClientCID(t *testing.T) {
	id := bytes.Repeat([]byte{0xaa}, cidLen)
	short := append(append([]byte{0x41}, id...), make([]byte, 20)...)
	if got := clientCID(short, len(short)); !bytes.Equal(got, id) {
		t.Fatalf("short header: %x", got)
	}
	if clientCID(short, minCIDPacket-1) != nil {
		t.Fatal("too short a packet")
	}
	if clientCID([]byte{0x41, 1, 2}, 100) != nil {
		t.Fatal("too short a head")
	}
	long := func(first byte, version uint32, idLen byte) []byte {
		b := binary.BigEndian.AppendUint32([]byte{first}, version)
		b = append(b, idLen)
		return append(append(b, id...), make([]byte, 30)...)
	}
	for _, c := range []struct {
		head []byte
		ok   bool
	}{
		{long(0xe0, quicV1, cidLen), true},  // Handshake v1
		{long(0xf0, quicV2, cidLen), true},  // Handshake v2
		{long(0xc0, quicV1, cidLen), false}, // Initial v1: routed by name
		{long(0xd0, quicV2, cidLen), false}, // Initial v2
		{long(0xd0, quicV1, cidLen), false}, // 0-RTT v1: the client's ID
		{long(0xe0, quicV1, 4), false},      // another length
		{long(0xe0, 0x1a2a3a4a, cidLen), false},
		{append([]byte{0x01}, short[1:]...), false}, // no fixed bit
		{append([]byte{0x81}, short[1:]...), false},
	} {
		got := clientCID(c.head[:cidHead], len(c.head))
		if (got != nil) != c.ok || got != nil && !bytes.Equal(got, id) {
			t.Errorf("%x: %x, want %v", c.head[:6], got, c.ok)
		}
	}
}

// The front reads its backends' labels' keys (a line "<label> <key>"
// each), a backend its own label's key (16 bytes); neither takes the
// other's, nor the node's secret, and errors tell nothing of the keys.
func TestReadCIDKeys(t *testing.T) {
	dir := t.TempDir()
	secret := bytes.Repeat([]byte{3}, 32)
	k4, k9 := hex.EncodeToString(cidLabelKey(secret, 4)), hex.EncodeToString(cidLabelKey(secret, 9))
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	front := write("front", "4 "+k4+"\n\n9 "+k9+"\n")
	keys, err := readCIDKeys(front)
	if err != nil || len(keys) != 2 || keys[4].rk != labelCodec(secret, 4).rk || keys[9].rk != labelCodec(secret, 9).rk {
		t.Fatalf("front's keys: %d, %v", len(keys), err)
	}
	backend := write("backend", k4+"\n")
	if c, err := readCIDLabelKey(backend); err != nil || c.rk != labelCodec(secret, 4).rk {
		t.Fatalf("backend's key: %v", err)
	}
	if _, err := readCIDLabelKey(front); err == nil {
		t.Fatal("the front's file read as a backend's key")
	}
	if _, err := readCIDKeys(backend); err == nil {
		t.Fatal("a backend's key read as the front's file")
	}
	for name, content := range map[string]string{
		"the secret":     "4 " + hex.EncodeToString(secret),
		"short key":      "4 0102",
		"not hex":        "4 zz" + k4[4:],
		"label 0":        "0 " + k4,
		"label 65536":    "65536 " + k4,
		"no label":       k4,
		"three fields":   "4 " + k4 + " 5",
		"a label twice":  "4 " + k4 + "\n4 " + k9,
		"a signed label": "+4 " + k4,
	} {
		_, err := readCIDKeys(write("bad", content))
		if err == nil {
			t.Errorf("%s: read", name)
		} else if strings.Contains(err.Error(), k4[:8]) || strings.Contains(err.Error(), k9[:8]) {
			t.Errorf("%s: the error tells a key: %v", name, err)
		}
	}
	var many strings.Builder
	for l := range maxCIDKeys + 1 {
		fmt.Fprintf(&many, "%d %s\n", l+1, k4)
	}
	if _, err := readCIDKeys(write("many", many.String())); err == nil {
		t.Error("more than maxCIDKeys keys")
	}
	if keys, err := readCIDKeys(write("empty", "")); err != nil || len(keys) != 0 {
		t.Errorf("an empty file: %v %v", keys, err)
	}
	if _, err := readCIDKeys(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file")
	}
	for name, content := range map[string]string{"short": "0102", "not hex": "zz", "empty": "", "the secret": hex.EncodeToString(secret)} {
		if _, err := readCIDLabelKey(write("bad", content)); err == nil {
			t.Errorf("backend, %s: read", name)
		}
	}
}

// The decode path costs no allocation: a flood of short headers that are
// not ours costs the front no garbage.
func TestCIDNoAllocations(t *testing.T) {
	c := labelCodec(bytes.Repeat([]byte{4}, 32), 1)
	d := make([]byte, 1200)
	d[0] = 0x45
	if n := testing.AllocsPerRun(1000, func() {
		if id := clientCID(d[:cidHead], len(d)); id != nil {
			c.label(id)
		}
	}); n != 0 {
		t.Fatalf("%v allocations", n)
	}
}
