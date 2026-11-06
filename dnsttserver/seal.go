package dnsttserver

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20"
)

// dnsseal-v1 (neko; raycontrol docs/spec/dnsseal-v1.md): the framing of
// dnstt sealed with a key of the zone, so that a DPI that knows dnstt but
// not the key sees no ClientID, no padding byte, no packet lengths and no
// KCP headers. Not a protection of the data: Noise does that.
//
//	query:  N (8) || ChaCha20(Ku, N||0^4)(00 00 || inner)
//	answer: R (8) || ChaCha20(Kd, R||0^4)(frames || 00 00 || padding)
//
// inner is what dnstt sends without the seal (with the dnsauth-v1 tag in
// front when that is on); frames are dnstt's (uint16 length, packet).

// SealMode says which queries a zone takes.
type SealMode int

const (
	// SealOff: dnstt as it is.
	SealOff SealMode = iota
	// SealOptional: sealed and open queries, each answered in its own
	// format (while clients move over).
	SealOptional
	// SealRequired: sealed queries only; an open one gets NODATA.
	SealRequired
)

// ParseSealMode reads the seal option of the dnstt backend.
func ParseSealMode(s string) (SealMode, error) {
	switch s {
	case "", "off":
		return SealOff, nil
	case "optional":
		return SealOptional, nil
	case "required":
		return SealRequired, nil
	}
	return SealOff, fmt.Errorf("seal %q: want off, optional or required", s)
}

const (
	sealNonceLen = 8
	sealCheckLen = 2
	// sealBucket: sealed answers are padded to a multiple of it.
	sealBucket = 64
	// sealKeysMax: the current key and those still accepted.
	sealKeysMax = 4
)

// sealKey is one key of the zone, as its two directions.
type sealKey struct {
	up, down [32]byte
}

func newSealKey(k []byte) *sealKey {
	var s sealKey
	copy(s.up[:], sealMAC(k, "dnsseal-v1 up"))
	copy(s.down[:], sealMAC(k, "dnsseal-v1 down"))
	return &s
}

func sealMAC(k []byte, label string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(label))
	return m.Sum(nil)
}

// sealXOR XORs p in place with ChaCha20 under key and nonce || 0^4.
func sealXOR(key *[32]byte, nonce []byte, p []byte) {
	var n [chacha20.NonceSize]byte
	copy(n[:], nonce)
	c, err := chacha20.NewUnauthenticatedCipher(key[:], n[:])
	if err != nil {
		panic(err) // fixed sizes
	}
	c.XORKeyStream(p, p)
}

// Seal is a zone's seal: its mode and keys, the current first.
type Seal struct {
	Mode SealMode
	keys []*sealKey
}

// NewSeal makes a seal from keys of 32 bytes, the current first.
func NewSeal(mode SealMode, keys ...[]byte) (*Seal, error) {
	if mode != SealOff && len(keys) == 0 {
		return nil, errors.New("seal: no key")
	}
	if len(keys) > sealKeysMax {
		return nil, fmt.Errorf("seal: %d keys, at most %d", len(keys), sealKeysMax)
	}
	s := &Seal{Mode: mode}
	for _, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("seal: a key of %d bytes, want 32", len(k))
		}
		s.keys = append(s.keys, newSealKey(k))
	}
	return s, nil
}

// LoadSeal reads the keys from a file: 64 hex digits a line, the current
// key first; blank lines and lines starting with # are skipped.
func LoadSeal(mode SealMode, path string) (*Seal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("seal key file: %v", err)
		}
		keys = append(keys, k)
	}
	return NewSeal(mode, keys...)
}

// open takes the seal off a query's payload: the inner payload and the key
// that opened it, or nil when no key does (an open query, or garbage).
func (s *Seal) open(payload []byte) ([]byte, *sealKey) {
	if s == nil || s.Mode == SealOff || len(payload) < sealNonceLen+sealCheckLen {
		return nil, nil
	}
	nonce, sealed := payload[:sealNonceLen], payload[sealNonceLen:]
	buf := make([]byte, len(sealed))
	for _, k := range s.keys {
		copy(buf, sealed)
		sealXOR(&k.up, nonce, buf)
		if buf[0] == 0 && buf[1] == 0 {
			return buf[sealCheckLen:], k
		}
	}
	return nil, nil
}

// answer seals the frames of an answer whose TXT data may take room bytes:
// a random R, then the frames, a zero length and padding up to a multiple
// of sealBucket (or up to room, when the next multiple is past it), all
// encrypted. The frames must leave room for R.
func (k *sealKey) answer(frames []byte, room int) []byte {
	return k.answerWith(frames, room, nil)
}

// answerWith is answer with R given (the tests' vectors); nil draws it.
func (k *sealKey) answerWith(frames []byte, room int, r []byte) []byte {
	out := make([]byte, sealNonceLen, max(room, sealNonceLen+len(frames)))
	if r != nil {
		copy(out, r)
	} else if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	out = append(out, frames...)
	if room-len(out) >= 2 {
		target := min((len(out)+2+sealBucket-1)/sealBucket*sealBucket, room)
		out = append(out, make([]byte, target-len(out))...) // 00 00 and padding
	}
	sealXOR(&k.down, out[:sealNonceLen], out[sealNonceLen:])
	return out
}

// Overhead is what the seal takes from each answer: R.
func (s *Seal) overhead() int {
	if s == nil || s.Mode == SealOff {
		return 0
	}
	return sealNonceLen
}
