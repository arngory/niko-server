package dnsttserver

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
	body := append([]byte{0, 0}, inner...)
	sealXOR(&k.up, nonce, body)
	return append(append([]byte(nil), nonce...), body...)
}

// The spec's example (raycontrol docs/spec/dnsseal-v1.md §9), worked out
// apart from this code too (Python, hmac and ChaCha20 of cryptography).
func TestSealVectors(t *testing.T) {
	s, err := NewSeal(SealRequired, seq(0, 32))
	if err != nil {
		t.Fatal(err)
	}
	k := s.keys[0]
	inner := append(seq(0xc0, 8), 0x01, 0xff)
	query := sealQuery(k, seq(0xa0, 8), inner)
	answer := k.answerWith([]byte{0x00, 0x02, 0xaa, 0xbb}, 1000, seq(0xb0, 8))
	t.Logf("query payload %x", query)
	t.Logf("answer data %x", answer)
	const wantQuery = "a0a1a2a3a4a5a6a75184ff1dfa308abcd1fad419"
	const wantAnswer = "b0b1b2b3b4b5b6b7f77002e5cc82e741ca69b3f568b5facff046fa764c1646d7395735e3f34ca5e0f2082aeae570f04304a4571256c325042f0d9dd5cec5c254"
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
		"current":     {sealQuery(s.keys[0], seq(1, 8), inner), s.keys[0]},
		"previous":    {sealQuery(s.keys[1], seq(2, 8), inner), s.keys[1]},
		"another key": {sealQuery(newSealKey(other), seq(3, 8), inner), nil},
		"short":       {seq(0, 9), nil},
	} {
		got, key := s.open(c.payload)
		if key != c.key || (key != nil && !bytes.Equal(got, inner)) {
			t.Errorf("%s: key %p (want %p), inner %x", name, key, c.key, got)
		}
	}
	// An open query: one in 65536 passes the check; this one does not.
	if _, key := s.open(append(seq(0x40, 8), inner...)); key != nil {
		t.Error("an open query opened")
	}
	off, _ := NewSeal(SealOff)
	if _, key := off.open(sealQuery(s.keys[0], seq(1, 8), inner)); key != nil {
		t.Error("a seal that is off opened a query")
	}

	k := s.keys[0]
	for _, c := range []struct{ frames, room, want int }{
		{0, 934, 64},    // an empty answer
		{4, 934, 64},    // a small one
		{60, 934, 128},  // 8+60+2 > 64
		{900, 934, 934}, // the next multiple is past the room: up to it
		{925, 934, 933}, // one byte left: no zero length, no padding
		{926, 934, 934}, // fills the room exactly: no zero length
		{0, 9, 8},       // one byte of room: R alone
	} {
		a := k.answerWith(make([]byte, c.frames), c.room, seq(0, 8))
		if len(a) != c.want {
			t.Errorf("frames %d, room %d: %d bytes, want %d", c.frames, c.room, len(a), c.want)
		}
		// Back: R, then the frames, then zeros.
		plain := append([]byte(nil), a[sealNonceLen:]...)
		sealXOR(&k.down, a[:sealNonceLen], plain)
		if !bytes.Equal(plain, make([]byte, len(plain))) {
			t.Errorf("frames %d: plaintext %x", c.frames, plain)
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
	if err != nil || len(s.keys) != 2 {
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
