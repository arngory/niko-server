//go:build linux

package nikoserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// dnsprobe-v1 (raycontrol docs/spec/dnsprobe-v1.md): a client checks a
// resolver for a DNS tunnel by asking it for one label under the tunnel's
// zone. With the node's key in it, the front answers itself, before the
// backend and dnsauth; without, the query is the tunnel's like any other.
const (
	probeLabelBytes = 24
	probeLabelLen   = 39 // base32 of 24 bytes, no padding
	probeVersion    = 1
	probeSkew       = 2 // minutes either way
	probeKeep       = 5 // minutes a nonce is remembered
	probeSeenMax    = 8192
	probeSourcesMax = 4096
	// Token buckets: per source /24 or /48, and one for all; a small probe
	// costs 1, a large one 8.
	probeRate, probeBurst             = 20, 40
	probeGlobalRate, probeGlobalBurst = 400, 800
	probeSmallCost, probeLargeCost    = 1, 8
	// probeUDPSize is the EDNS size the answers give, and the most a large
	// one may need.
	probeUDPSize = 1232
	probeFillers = 4
	probeFiller  = 240
)

var probeBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// probeFillerString is a large answer's filler: "0123456789" 24 times.
var probeFillerString = []byte(strings.Repeat("0123456789", probeFiller/10))

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
	now func() time.Time

	mu      sync.Mutex
	seen    map[[8]byte]uint32 // nonce -> minute
	sources map[netip.Prefix]*tokenBucket
	global  tokenBucket
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
	return &dnsProbe{key: key, now: time.Now, seen: map[[8]byte]uint32{}, sources: map[netip.Prefix]*tokenBucket{}}
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

// probeToken is the first string of an answer to label bytes b.
func probeToken(key, b []byte) string {
	return "v1 " + strings.ToLower(probeBase32.EncodeToString(probeMAC(key, []byte("dnsprobe-v1 a"), b)[:16]))
}

// answer handles a query for name (lowercase) in zone from src: probe is
// false when it is no probe, which then goes to the backend; reply is nil
// for a probe over the rate, which gets no answer at all.
func (p *dnsProbe) answer(query []byte, name string, questionEnd int, zone string, src netip.Addr) (reply []byte, probe bool) {
	label, ok := strings.CutSuffix(name, "."+zone)
	if !ok || len(label) != probeLabelLen || strings.Contains(label, ".") {
		return nil, false
	}
	if binary.BigEndian.Uint16(query[questionEnd-4:questionEnd-2]) != 16 { // TXT
		return nil, false
	}
	b, err := probeBase32.DecodeString(strings.ToUpper(label))
	// The canonical form only: another spelling of the same bytes would be
	// a fresh label for the same nonce.
	if err != nil || len(b) != probeLabelBytes || b[0] != probeVersion || b[1] > 1 ||
		strings.ToLower(probeBase32.EncodeToString(b)) != label {
		return nil, false
	}
	if !hmac.Equal(b[14:], probeMAC(p.key, []byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10]) {
		return nil, false
	}
	now := p.now()
	minute := uint32(now.Unix() / 60)
	sent := binary.BigEndian.Uint32(b[2:6])
	if sent+probeSkew < minute || sent > minute+probeSkew {
		return nil, false
	}
	large := b[1] == 1
	cost := float64(probeSmallCost)
	if large {
		cost = probeLargeCost
	}
	var nonce [8]byte
	copy(nonce[:], b[6:14])

	p.mu.Lock()
	if !p.remember(nonce, minute) {
		p.mu.Unlock()
		return nil, false
	}
	allowed := p.allow(src, cost, now)
	p.mu.Unlock()
	if !allowed {
		return nil, true
	}
	return probeReply(query, questionEnd, probeToken(p.key, b), probeSeen(query, questionEnd, src), large), true
}

// probeSeen is the answer's second string: what the node saw of the query,
// for the client to learn about its resolver: the EDNS size it advertised
// (0: none), whether it randomised the name's case (0x20), and its
// address.
func probeSeen(query []byte, questionEnd int, src netip.Addr) string {
	mixed := 0
	// The first label as it came, before lowercasing.
	if n := int(query[12]); 13+n <= len(query) && bytes.ContainsFunc(query[13:13+n], func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
		mixed = 1
	}
	return fmt.Sprintf("seen edns=%d case=%d from=%s", ednsSize(query, questionEnd), mixed, src.Unmap())
}

// remember records a nonce, false for one seen within probeKeep minutes or
// when there is no room: p.mu held.
func (p *dnsProbe) remember(nonce [8]byte, minute uint32) bool {
	if _, ok := p.seen[nonce]; ok {
		return false
	}
	if len(p.seen) >= probeSeenMax {
		for n, m := range p.seen {
			if m+probeKeep < minute {
				delete(p.seen, n)
			}
		}
		if len(p.seen) >= probeSeenMax {
			return false
		}
	}
	p.seen[nonce] = minute
	return true
}

// allow takes the probe's cost from its source's bucket and the global
// one: p.mu held.
func (p *dnsProbe) allow(src netip.Addr, cost float64, now time.Time) bool {
	src = src.Unmap()
	bits := 48
	if src.Is4() {
		bits = 24
	}
	prefix, _ := src.Prefix(bits)
	b := p.sources[prefix]
	if b == nil {
		if len(p.sources) >= probeSourcesMax {
			for k, v := range p.sources {
				if now.Sub(v.last) > time.Minute {
					delete(p.sources, k)
				}
			}
			if len(p.sources) >= probeSourcesMax {
				return false
			}
		}
		b = &tokenBucket{}
		p.sources[prefix] = b
	}
	// The source first: a busy source must not spend the others' share.
	if !b.take(cost, probeRate, probeBurst, now) {
		return false
	}
	return p.global.take(cost, probeGlobalRate, probeGlobalBurst, now)
}

// ednsSize is the UDP size the query's OPT record advertises, 0 without
// one (sizes under 512 count as 512 where the answer is sized).
func ednsSize(query []byte, questionEnd int) int {
	if binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) == 0 || len(query) < questionEnd+11 {
		return 0
	}
	opt := query[questionEnd:]
	if opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != 41 {
		return 0
	}
	return int(binary.BigEndian.Uint16(opt[3:5]))
}

// probeReply answers a probe: the token, and with large the fillers. A
// large answer the query has no room for goes back empty with TC.
func probeReply(query []byte, questionEnd int, token, seen string, large bool) []byte {
	size := ednsSize(query, questionEnd)
	var rdata []byte
	for _, s := range []string{token, seen} {
		rdata = append(rdata, byte(len(s)))
		rdata = append(rdata, s...)
	}
	if large {
		for range probeFillers {
			rdata = append(rdata, probeFiller)
			rdata = append(rdata, probeFillerString...)
		}
	}
	reply := make([]byte, 0, questionEnd+12+len(rdata)+11)
	reply = append(reply, query[:questionEnd]...)
	reply[2] = 0x80 | 0x04 | query[2]&0x79 // QR, AA, opcode, RD
	reply[3] = 0                           // NOERROR
	binary.BigEndian.PutUint16(reply[4:6], 1)
	binary.BigEndian.PutUint16(reply[6:8], 1)
	binary.BigEndian.PutUint16(reply[8:10], 0)
	binary.BigEndian.PutUint16(reply[10:12], 0)
	full := len(reply) + 12 + len(rdata)
	if size > 0 {
		full += 11
	}
	limit := max(size, 512)
	if full > limit {
		reply[2] |= 0x02 // TC
		binary.BigEndian.PutUint16(reply[6:8], 0)
	} else {
		reply = append(reply, 0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 0)
		reply = binary.BigEndian.AppendUint16(reply, uint16(len(rdata)))
		reply = append(reply, rdata...)
	}
	if size > 0 {
		binary.BigEndian.PutUint16(reply[10:12], 1)
		reply = append(reply, 0, 0, 41)
		reply = binary.BigEndian.AppendUint16(reply, probeUDPSize)
		reply = append(reply, 0, 0, 0, 0, 0, 0)
	}
	return reply
}
