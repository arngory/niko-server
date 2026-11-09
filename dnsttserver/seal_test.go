package dnsttserver

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seq(from byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

// sealQuery seals a query's inner payload as a client does (§3).
func sealQuery(k *sealKey, nonce, inner []byte) []byte {
	c := bytes.Clone(inner)
	sealXOR(&k.up, nonce, c)
	t := k.tag(k.upTag, nonce, c)
	return append(append(append([]byte(nil), nonce...), t[:]...), c...)
}

// openAnswer checks an answer's tag and takes its seal off, as a client
// does (§4): the plaintext after R and the tag, or nil.
func openAnswer(k *sealKey, a []byte) []byte {
	if len(a) < sealHeadLen {
		return nil
	}
	if t := k.tag(k.downTag, a[:sealNonceLen], a[sealHeadLen:]); !bytes.Equal(t[:], a[sealNonceLen:sealHeadLen]) {
		return nil
	}
	plain := bytes.Clone(a[sealHeadLen:])
	sealXOR(&k.down, a[:sealNonceLen], plain)
	return plain
}

// The spec's example (raycontrol docs/spec/dnsseal-v1.md §9), worked out
// apart from this code too (Python, hmac and ChaCha20 of cryptography).
func TestSealVectors(t *testing.T) {
	s, err := NewSeal(SealRequired, seq(0, 32))
	if err != nil {
		t.Fatal(err)
	}
	k := s.list()[0]
	inner := append(seq(0xc0, 8), 0x01, 0xff)
	query := sealQuery(k, seq(0xa0, 8), inner)
	answer := k.answerWith([]byte{0x00, 0x02, 0xaa, 0xbb}, 1000, seq(0xb0, 8))
	t.Logf("query payload %x", query)
	t.Logf("answer data %x", answer)
	const wantQuery = "a0a1a2a3a4a5a6a70c56c1a39145fd1ffc3688be16c2"
	const wantAnswer = "b0b1b2b3b4b5b6b7d119c872f77002e5cc82e741ca69b3f568b5facff046fa764c1646d7395735e3f34ca5e0f2082aeae570f04304a4571256c325042f0d9dd5"
	if hex.EncodeToString(query) != wantQuery || hex.EncodeToString(answer) != wantAnswer {
		t.Fatalf("vectors changed")
	}
	if got, key := s.open(query); key != k || !bytes.Equal(got, inner) {
		t.Fatalf("open: %x", got)
	}
}

// What opens and what does not: the current key, the previous one, an open
// query, a short one; answers padded to 64 within the room.
func TestSeal(t *testing.T) {
	cur, prev, other := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	s, err := NewSeal(SealOptional, cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	inner := append(seq(0x10, 8), 0xe3, 1, 2, 3)
	for name, c := range map[string]struct {
		payload []byte
		key     *sealKey
	}{
		"current":     {sealQuery(s.list()[0], seq(1, 8), inner), s.list()[0]},
		"previous":    {sealQuery(s.list()[1], seq(2, 8), inner), s.list()[1]},
		"another key": {sealQuery(newSealKey(other), seq(3, 8), inner), nil},
		"short":       {seq(0, 11), nil},
	} {
		got, key := s.open(c.payload)
		if key != c.key || (key != nil && !bytes.Equal(got, inner)) {
			t.Errorf("%s: key %p (want %p), inner %x", name, key, c.key, got)
		}
	}
	// Open queries of one session (one ClientID, the padding prefix): each
	// passes a key's tag one time in 2^32, whatever its first bytes.
	opened := 0
	for i := range 1 << 16 {
		q := append(seq(0x40, 8), 0xe3, byte(i), byte(i>>8), 0x5a, 1, 2)
		if _, key := s.open(q); key != nil {
			opened++
		}
	}
	if opened != 0 {
		t.Errorf("%d of 65536 open queries of one session opened", opened)
	}
	// Nothing under the seal can be changed on the way: a flipped bit in
	// N, the tag or the ciphertext, and no key opens the query.
	sealed := sealQuery(s.list()[0], seq(1, 8), inner)
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x10
		if _, key := s.open(bad); key != nil {
			t.Errorf("byte %d changed, and the query opened", i)
		}
	}
	off, _ := NewSeal(SealOff)
	if _, key := off.open(sealQuery(s.list()[0], seq(1, 8), inner)); key != nil {
		t.Error("a seal that is off opened a query")
	}

	k := s.list()[0]
	for _, c := range []struct{ frames, room, want int }{
		{0, 934, 64},    // an empty answer
		{4, 934, 64},    // a small one
		{52, 934, 128},  // 12+52+2 > 64
		{900, 934, 934}, // the next multiple is past the room: up to it
		{921, 934, 933}, // one byte left: no zero length, no padding
		{922, 934, 934}, // fills the room exactly: no zero length
		{0, 13, 12},     // one byte of room: R and the tag alone
	} {
		a := k.answerWith(make([]byte, c.frames), c.room, seq(0, 8))
		if len(a) != c.want {
			t.Errorf("frames %d, room %d: %d bytes, want %d", c.frames, c.room, len(a), c.want)
		}
		// Back: R and the tag, then the frames, then zeros.
		plain := openAnswer(k, a)
		if plain == nil || !bytes.Equal(plain, make([]byte, len(plain))) {
			t.Errorf("frames %d: plaintext %x", c.frames, plain)
		}
		a[len(a)-1] ^= 1
		if openAnswer(k, a) != nil {
			t.Errorf("frames %d: a changed answer opened", c.frames)
		}
	}
	// Two answers to the same frames differ (R).
	if bytes.Equal(k.answer([]byte{0, 1, 9}, 934), k.answer([]byte{0, 1, 9}, 934)) {
		t.Error("two answers alike")
	}
}

func TestLoadSeal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.keys")
	os.WriteFile(path, []byte("# current, then previous\n"+hex.EncodeToString(seq(0, 32))+"\n\n"+hex.EncodeToString(seq(1, 32))+"\n"), 0o600)
	s, err := LoadSeal(SealRequired, path)
	if err != nil || s.Keys() != 2 {
		t.Fatalf("%v %+v", err, s)
	}
	os.WriteFile(path, []byte("abcd\n"), 0o600)
	if _, err := LoadSeal(SealRequired, path); err == nil {
		t.Error("a short key loaded")
	}
	os.WriteFile(path, nil, 0o600)
	if _, err := LoadSeal(SealRequired, path); err == nil {
		t.Error("a seal without a key loaded")
	}
	for in, want := range map[string]SealMode{"": SealOff, "off": SealOff, "optional": SealOptional, "required": SealRequired} {
		if m, err := ParseSealMode(in); err != nil || m != want {
			t.Errorf("%q: %v %v", in, m, err)
		}
	}
	if _, err := ParseSealMode("on"); err == nil {
		t.Error("seal mode on taken")
	}
}

// The keys change under a running seal: a new current key, the previous
// one dropped; a file that does not parse keeps those in force.
func TestSealWatchKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seal.keys")
	a, b := seq(0, 32), seq(1, 32)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(a)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSeal(SealRequired, path)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go s.WatchKeys(path, 10*time.Millisecond, stop, t.Logf)
	opens := func(key []byte) bool {
		_, k := s.open(sealQuery(newSealKey(key), seq(1, 8), seq(0x10, 9)))
		return k != nil
	}
	wait := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !ok(); {
			if time.Now().After(deadline) {
				t.Fatalf("%s: keys %d", what, s.Keys())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !opens(a) || opens(b) {
		t.Fatal("before: wrong keys")
	}
	writeAtomic(t, path, []byte(hex.EncodeToString(b)+"\n"+hex.EncodeToString(a)+"\n"))
	wait("a new key", func() bool { return s.Keys() == 2 && opens(a) && opens(b) })
	writeAtomic(t, path, []byte("not hex at all, and longer than before to change the size\n"))
	time.Sleep(50 * time.Millisecond)
	if s.Keys() != 2 || !opens(a) || !opens(b) {
		t.Fatal("a bad file changed the keys")
	}
	writeAtomic(t, path, []byte(hex.EncodeToString(b)+"\n"))
	wait("the previous key gone", func() bool { return s.Keys() == 1 && !opens(a) && opens(b) })
}

// What a query costs that no key opens (garbage, or an open query in
// optional mode), with the most keys a seal takes.
func BenchmarkSealOpenGarbage(b *testing.B) {
	var keys [][]byte
	for i := range sealKeysMax {
		keys = append(keys, seq(byte(i), 32))
	}
	s, err := NewSeal(SealOptional, keys...)
	if err != nil {
		b.Fatal(err)
	}
	q := seq(7, 140)
	b.ReportAllocs()
	for b.Loop() {
		if _, k := s.open(q); k != nil {
			b.Fatal("opened")
		}
	}
}

// What opening a sealed query costs, the current key first.
func BenchmarkSealOpen(b *testing.B) {
	s, err := NewSeal(SealRequired, seq(0, 32), seq(1, 32))
	if err != nil {
		b.Fatal(err)
	}
	q := sealQuery(s.list()[0], seq(9, 8), seq(7, 128))
	b.ReportAllocs()
	for b.Loop() {
		if _, k := s.open(q); k == nil {
			b.Fatal("not opened")
		}
	}
}
