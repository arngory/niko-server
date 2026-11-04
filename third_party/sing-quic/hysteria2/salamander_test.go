package hysteria2

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// slowXOR is the original byte loop, the reference.
func slowXOR(dst, src []byte, key *[blake2b.Size256]byte, off int) {
	for i, c := range src {
		dst[i] = c ^ key[(off+i)%blake2b.Size256]
	}
}

func TestSalamanderXOR(t *testing.T) {
	var key [blake2b.Size256]byte
	rand.Read(key[:])
	for _, n := range []int{0, 1, 31, 32, 33, 1452, 2047, 2048, 2049, 5000} {
		for _, off := range []int{0, 5, 32, 77} {
			src := make([]byte, n)
			rand.Read(src)
			want, got := make([]byte, n), make([]byte, n)
			slowXOR(want, src, &key, off)
			SalamanderXOR(got, src, &key, off)
			if !bytes.Equal(got, want) {
				t.Fatalf("n=%d off=%d differs", n, off)
			}
			SalamanderXOR(src, src, &key, off) // in place
			if !bytes.Equal(src, want) {
				t.Fatalf("n=%d off=%d in place differs", n, off)
			}
		}
	}
	pw := bytes.Repeat([]byte("p"), 200) // longer than the stack buffer
	if salamanderKey(pw, []byte("saltsalt")) != blake2b.Sum256(append(append([]byte(nil), pw...), "saltsalt"...)) {
		t.Fatal("key of a long password")
	}
}

// A packet as large as the reader's buffer comes through whole (P-6), and
// what WriteTo sends, ReadFrom opens.
func TestSalamanderRoundTrip(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pw := []byte("password")
	sa, sb := NewSalamanderConn(a, pw), NewSalamanderConn(b, pw)
	msg := make([]byte, 1452)
	rand.Read(msg)
	sent := bytes.Clone(msg) // the vectorised writer XORs in place
	if _, err := sa.WriteTo(msg, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 1452)
	n, _, err := sb.ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1452 || !bytes.Equal(p[:n], sent) {
		t.Fatalf("got %d bytes, equal %v", n, bytes.Equal(p[:n], sent))
	}
}

func BenchmarkSalamanderXOR(b *testing.B) {
	var key [blake2b.Size256]byte
	p := make([]byte, 1452)
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		SalamanderXOR(p, p, &key, 0)
	}
}

func BenchmarkSalamanderXORBytewise(b *testing.B) {
	var key [blake2b.Size256]byte
	p := make([]byte, 1452)
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		slowXOR(p, p, &key, 0)
	}
}

func BenchmarkSalamanderKey(b *testing.B) {
	pw, salt := []byte("a-salamander-password"), []byte("saltsalt")
	b.ReportAllocs()
	for b.Loop() {
		salamanderKey(pw, salt)
	}
}
