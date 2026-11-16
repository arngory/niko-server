package nikoserver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"path/filepath"
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

// The spec's example (quic-cid-route-v1 §8): raycontrol's codec checks the
// same numbers.
func TestCIDExample(t *testing.T) {
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	c := newCIDCodec(secret)
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

const cidExample = "61224892a4254ad8"

func TestCIDLabels(t *testing.T) {
	c := newCIDCodec(bytes.Repeat([]byte{7}, 32))
	other := newCIDCodec(bytes.Repeat([]byte{8}, 32))
	for _, label := range []uint16{1, 2, 300, MaxCIDLabel} {
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
			// Another node's key reads no label in it, but by chance.
			if got, ok := other.label(id[:]); ok && got == label {
				t.Fatalf("another key reads label %d", got)
			}
		}
	}
	if _, err := newCIDGenerator(c, 0); err == nil {
		t.Fatal("label 0")
	}
	// The counter wraps within its 40 bits.
	g, _ := newCIDGenerator(c, 9)
	g.next.Store(1<<cidCounterBits - 2)
	a, b := g.generate(), g.generate()
	if a != c.encode(9, 1<<cidCounterBits-1) || b != c.encode(9, 0) {
		t.Fatal("counter past 2^40")
	}
}

// Random IDs read as one of a few labels about labels·2^-24 of the time:
// none in a million for one label, by a wide margin.
func TestCIDRandomMiss(t *testing.T) {
	c := newCIDCodec(bytes.Repeat([]byte{1}, 32))
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

func TestReadCIDKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(hex.EncodeToString(bytes.Repeat([]byte{3}, 32))+"\n"), 0o600)
	c, err := readCIDKey(good)
	if err != nil || c.rk != newCIDCodec(bytes.Repeat([]byte{3}, 32)).rk {
		t.Fatalf("good key: %v", err)
	}
	for name, content := range map[string]string{"short": "0102", "not hex": "zz", "empty": ""} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := readCIDKey(p); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := readCIDKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file")
	}
}

// The decode path costs no allocation: a flood of short headers that are
// not ours costs the front no garbage.
func TestCIDNoAllocations(t *testing.T) {
	c := newCIDCodec(bytes.Repeat([]byte{4}, 32))
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
