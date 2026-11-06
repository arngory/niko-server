//go:build linux

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
	"golang.org/x/crypto/chacha20"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func hmacSHA(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// sealer is a client's side of dnsseal-v1 (raycontrol docs/spec/dnsseal-v1.md), written from the spec.
type sealer struct{ up, down, upTag, downTag []byte }

func newSealer(k []byte) *sealer {
	return &sealer{up: hmacSHA(k, []byte("dnsseal-v1 up")), down: hmacSHA(k, []byte("dnsseal-v1 down")),
		upTag: hmacSHA(k, []byte("dnsseal-v1 up tag")), downTag: hmacSHA(k, []byte("dnsseal-v1 down tag"))}
}

func xorChaCha(key, nonce8, p []byte) {
	var n [chacha20.NonceSize]byte
	copy(n[:], nonce8)
	c, err := chacha20.NewUnauthenticatedCipher(key, n[:])
	if err != nil {
		panic(err)
	}
	c.XORKeyStream(p, p)
}

// seal: N || T || C, C = ChaCha20(Ku, N||0^4)(inner), T = HMAC(Kut, N || C)[:4]
func (s *sealer) seal(inner []byte, rng *rand.Rand) []byte {
	n := binary.LittleEndian.AppendUint64(nil, rng.Uint64())
	c := append([]byte(nil), inner...)
	xorChaCha(s.up, n, c)
	out := append(n, hmacSHA(s.upTag, n, c)[:4]...)
	return append(out, c...)
}

// open: the frames of a sealed answer (until a zero length); nil when its
// tag does not fit.
func (s *sealer) open(data []byte) []byte {
	if len(data) < 12 || !bytes.Equal(data[8:12], hmacSHA(s.downTag, data[:8], data[12:])[:4]) {
		return nil
	}
	plain := append([]byte(nil), data[12:]...)
	xorChaCha(s.down, data[:8], plain)
	i := 0
	for i+2 <= len(plain) {
		l := int(binary.BigEndian.Uint16(plain[i:]))
		if l == 0 || i+2+l > len(plain) {
			break
		}
		i += 2 + l
	}
	return plain[:i]
}

// tag prepends the dnsauth-v1 tag of a device key to body (ClientID and what follows).
func tag(key *[32]byte, body []byte) []byte {
	t := dnsttserver.Tag(key, dnsttserver.EpochOf(time.Now()), body)
	return append(t[:], body...)
}

// wireQuery builds a DNS query for <labels of payload in base32>.<zone>
// with an OPT of edns (0: none). randomLabels splits into labels of 32..63.
func wireQuery(dst []byte, id uint16, payload []byte, zone string, qtype uint16, edns int, randomLabels bool, rng *rand.Rand) []byte {
	text := strings.ToLower(b32.EncodeToString(payload))
	dst = append(dst[:0], byte(id>>8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	if edns > 0 {
		dst[11] = 1
	}
	for len(text) > 0 {
		n := 63
		if randomLabels {
			n = 32 + rng.IntN(32)
		}
		n = min(n, len(text))
		dst = append(dst, byte(n))
		dst = append(dst, text[:n]...)
		text = text[n:]
	}
	dst = appendName(dst, zone)
	dst = binary.BigEndian.AppendUint16(dst, qtype)
	dst = binary.BigEndian.AppendUint16(dst, 1)
	if edns > 0 {
		dst = append(dst, 0, 0, 41, byte(edns>>8), byte(edns), 0, 0, 0, 0, 0, 0)
	}
	return dst
}

func appendName(dst []byte, name string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		dst = append(dst, byte(len(l)))
		dst = append(dst, l...)
	}
	return append(dst, 0)
}

// plainQuery: a query for name itself (the apex, a probe label).
func plainQuery(dst []byte, id uint16, name string, qtype uint16, edns int) []byte {
	dst = append(dst[:0], byte(id>>8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	if edns > 0 {
		dst[11] = 1
	}
	dst = appendName(dst, name)
	dst = binary.BigEndian.AppendUint16(dst, qtype)
	dst = binary.BigEndian.AppendUint16(dst, 1)
	if edns > 0 {
		dst = append(dst, 0, 0, 41, byte(edns>>8), byte(edns), 0, 0, 0, 0, 0, 0)
	}
	return dst
}

// KCP segment: conv | cmd | frg | wnd | ts | sn | una | len | data (little endian).
const (
	kcpPush = 81
	kcpAck  = 82
	kcpWask = 83
)

func kcpSegment(conv uint32, cmd byte, wnd uint16, sn uint32, data []byte) []byte {
	p := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint32(p[0:], conv)
	p[4] = cmd
	binary.LittleEndian.PutUint16(p[6:], wnd)
	binary.LittleEndian.PutUint32(p[8:], uint32(time.Now().UnixMilli()))
	binary.LittleEndian.PutUint32(p[12:], sn)
	binary.LittleEndian.PutUint32(p[20:], uint32(len(data)))
	copy(p[24:], data)
	return p
}

// probeLabel is a dnsprobe-v1 label (raycontrol docs/spec/dnsprobe-v1.md).
func probeLabel(key []byte, zone string, large bool, minute uint32, nonce uint64) string {
	var b [24]byte
	b[0] = 1
	if large {
		b[1] = 1
	}
	binary.BigEndian.PutUint32(b[2:6], minute)
	binary.BigEndian.PutUint64(b[6:14], nonce)
	copy(b[14:], hmacSHA(key, []byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10])
	return strings.ToLower(b32.EncodeToString(b[:]))
}
