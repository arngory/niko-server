//go:build linux

package nikoserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

// dnsprobe-v1 (raycontrol docs/spec/dnsprobe-v1.md): a client checks a
// resolver for a DNS tunnel by asking it for one label under the tunnel's
// zone. With the node's key in it, the front answers itself, before the
// backend and dnsauth; without, the query is the tunnel's like any other.
// The answer is built as dnstt builds its own, its TXT data encrypted, so
// that on the wire it is one more answer of the tunnel.
const (
	probeLabelBytes = 24
	probeLabelLen   = 39 // base32 of 24 bytes, no padding
	probeVersion    = 1
	probeSkew       = 2 // minutes either way
	probeSourcesMax = 4096
	// Token buckets: per source /24 or /48, and one for all; a small probe
	// costs 1, a large one 8.
	probeRate, probeBurst             = 20, 40
	probeGlobalRate, probeGlobalBurst = 400, 800
	probeSmallCost, probeLargeCost    = 1, 8
	// The plaintext of an answer: the token, what the node saw, and for a
	// large probe zeros up to probeLarge bytes. On the wire it follows a
	// random nonce of the answer's own.
	probeTokenLen = 16
	probeSmall    = probeTokenLen + 2 + 1 + 16
	probeLarge    = 900
	probeNonceLen = 8
	// probeBucket: the padding step of a sealed zone (dnsseal-v1).
	probeBucket = 64
	// As dnstt answers: TTL and the responder's EDNS size.
	probeTTL     = 60
	probeOPTSize = 4096
)

var probeBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) take(cost, rate, burst float64, now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

type dnsProbe struct {
	key []byte
	enc []byte // the keystream's key, from key
	now func() time.Time

	mu sync.Mutex
	// The sources' buckets in two generations: a source not seen for a
	// generation or two is forgotten, so many cannot crowd out the rest.
	sources, older map[netip.Prefix]*tokenBucket
	swapped        time.Time
	global         tokenBucket
}

// loadProbeKey reads the probe key: 32 bytes in hex.
func loadProbeKey(path string) (*dnsProbe, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("want 32 bytes in hex")
	}
	return newDNSProbe(key), nil
}

func newDNSProbe(key []byte) *dnsProbe {
	return &dnsProbe{key: key, enc: probeMAC(key, []byte("dnsprobe-v1 e")), now: time.Now,
		sources: map[netip.Prefix]*tokenBucket{}, older: map[netip.Prefix]*tokenBucket{}}
}

func probeMAC(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// probeLabel is a probe's label (for the tests and the spec's example).
func probeLabel(key []byte, zone string, large bool, minute uint32, nonce [8]byte) string {
	var b [probeLabelBytes]byte
	b[0] = probeVersion
	if large {
		b[1] = 1
	}
	binary.BigEndian.PutUint32(b[2:6], minute)
	copy(b[6:14], nonce[:])
	copy(b[14:], probeMAC(key, []byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10])
	return strings.ToLower(probeBase32.EncodeToString(b[:]))
}

// probeCrypt XORs p with the keystream of a label's bytes b and an
// answer's nonce: blocks of HMAC-SHA256(enc, b ‖ nonce ‖ uint32 counter).
// The same call decrypts. The nonce makes each answer's keystream its own:
// one who replays the label from an address of theirs learns nothing of
// another answer's plaintext.
func probeCrypt(enc, b, nonce, p []byte) {
	var ctr [4]byte
	for i := 0; i < len(p); i += sha256.Size {
		binary.BigEndian.PutUint32(ctr[:], uint32(i/sha256.Size))
		block := probeMAC(enc, b, nonce, ctr[:])
		for j := 0; j < sha256.Size && i+j < len(p); j++ {
			p[i+j] ^= block[j]
		}
	}
}

// probePlain is an answer's plaintext: the token, what the node saw (the
// EDNS size the resolver advertised, 0 for none; whether it randomised the
// name's case; its address), and zeros up to size. The token covers what
// the node saw too: a resolver cannot change it unseen.
func probePlain(key, b []byte, edns int, mixed bool, src netip.Addr, size int) []byte {
	p := make([]byte, size)
	binary.BigEndian.PutUint16(p[probeTokenLen:], uint16(edns))
	if mixed {
		p[probeTokenLen+2] = 1
	}
	a := src.As16()
	copy(p[probeTokenLen+3:], a[:])
	copy(p, probeMAC(key, []byte("dnsprobe-v1 a"), b, p[probeTokenLen:probeSmall])[:probeTokenLen])
	return p
}

// answer handles a query for name (lowercase) in zone from src: probe is
// false when it is no probe, which then goes to the backend; reply is nil
// for a probe over the rate, which gets no answer at all.
func (p *dnsProbe) answer(query []byte, name string, questionEnd int, zone string, src netip.Addr, pad bool) (reply []byte, probe bool) {
	label, ok := strings.CutSuffix(name, "."+zone)
	if !ok || len(label) != probeLabelLen || strings.Contains(label, ".") {
		return nil, false
	}
	if binary.BigEndian.Uint16(query[questionEnd-4:questionEnd-2]) != 16 { // TXT
		return nil, false
	}
	b, err := probeBase32.DecodeString(strings.ToUpper(label))
	if err != nil || len(b) != probeLabelBytes || b[0] != probeVersion || b[1] > 1 {
		return nil, false
	}
	if !hmac.Equal(b[14:], probeMAC(p.key, []byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10]) {
		return nil, false
	}
	now := p.now()
	minute := uint32(now.Unix() / 60)
	if sent := binary.BigEndian.Uint32(b[2:6]); sent+probeSkew < minute || sent > minute+probeSkew {
		return nil, false
	}
	// No replay set: the answer to a label is the same whoever asks, and
	// on the wire it is one more answer of the tunnel. A censor that
	// races the client's query to the node learns nothing, and the
	// client still gets its answer.
	large := b[1] == 1
	cost := float64(probeSmallCost)
	if large {
		cost = probeLargeCost
	}
	// The rate first: a probe over it costs no parse of the message.
	if !p.allow(src, cost, now) {
		return nil, true
	}
	q, err := dns.MessageFromWireFormat(query)
	if err != nil || len(q.Question) != 1 {
		return nil, false
	}
	var nonce [probeNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, true
	}
	return probeReply(p, q, b, query[13:13+int(query[12])], src, large, nonce, pad), true
}

// probeSeal is an answer's TXT data: the nonce, then the plaintext
// encrypted.
func probeSeal(p *dnsProbe, b, plain []byte, nonce [probeNonceLen]byte) []byte {
	probeCrypt(p.enc, b, nonce[:], plain)
	return append(nonce[:], plain...)
}

// probeReply builds the answer as dnstt does (responseFor, sendLoop): QR
// and AA, the question as asked, one TXT with TTL 60, and an OPT of 4096
// when the query had one. A large one goes out only when dnstt could carry
// as much TXT data to this requester; else the small one, as dnstt fits its
// answers to the requester.
//
// pad: the zone's dnstt answers are sealed (dnsseal-v1 §6): random bytes
// after the probe's data up to a multiple of 64, within what the requester
// can carry, as the zone's answers are padded.
func probeReply(p *dnsProbe, q dns.Message, b, rawLabel []byte, src netip.Addr, large bool, nonce [probeNonceLen]byte, pad bool) []byte {
	edns, hasOPT := 0, false
	for _, rr := range q.Additional {
		if rr.Type == dns.RRTypeOPT {
			edns, hasOPT = int(rr.Class), true
			break
		}
	}
	mixed := strings.ToLower(string(rawLabel)) != string(rawLabel)
	room := dnsttserver.MaxTXTData(max(edns, 512))
	build := func(size int) []byte {
		data := probeSeal(p, b, probePlain(p.key, b, edns, mixed, src, size), nonce)
		if pad && room-len(data) > 0 {
			target := min((len(data)+probeBucket-1)/probeBucket*probeBucket, room)
			fill := make([]byte, target-len(data))
			if _, err := rand.Read(fill); err != nil {
				return nil
			}
			data = append(data, fill...)
		}
		resp := dns.Message{ID: q.ID, Flags: 0x8400, Question: q.Question,
			Answer: []dns.RR{{Name: q.Question[0].Name, Type: q.Question[0].Type, Class: q.Question[0].Class, TTL: probeTTL,
				Data: dns.EncodeRDataTXT(data)}}}
		if hasOPT {
			resp.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: probeOPTSize, TTL: 0, Data: []byte{}}}
		}
		wire, err := resp.WireFormat()
		if err != nil {
			return nil
		}
		return wire
	}
	if large && probeNonceLen+probeLarge <= room {
		return build(probeLarge)
	}
	return build(probeSmall)
}

// allow takes the probe's cost from its source's bucket and the global
// one.
func (p *dnsProbe) allow(src netip.Addr, cost float64, now time.Time) bool {
	src = src.Unmap()
	bits := 48
	if src.Is4() {
		bits = 24
	}
	prefix, _ := src.Prefix(bits)
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.swapped) > time.Minute || len(p.sources) >= probeSourcesMax {
		p.older, p.sources, p.swapped = p.sources, map[netip.Prefix]*tokenBucket{}, now
	}
	b := p.sources[prefix]
	if b == nil {
		if b = p.older[prefix]; b == nil {
			b = &tokenBucket{}
		}
		p.sources[prefix] = b
	}
	// The source first: a busy source must not spend the others' share.
	if !b.take(cost, probeRate, probeBurst, now) {
		return false
	}
	return p.global.take(cost, probeGlobalRate, probeGlobalBurst, now)
}
