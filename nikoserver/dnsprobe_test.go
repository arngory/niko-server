//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// probeQuery is a TXT query for name with an OPT of size edns (0: none).
func probeQuery(name string, qtype uint16, edns int) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	if edns > 0 {
		binary.BigEndian.PutUint16(q[10:12], 1)
		q = append(q, 0, 0, 41)
		q = binary.BigEndian.AppendUint16(q, uint16(edns))
		q = append(q, 0, 0, 0, 0, 0, 0)
	}
	return q
}

// txtStrings parses a probe answer: the flags and the TXT strings.
func txtStrings(t *testing.T, reply []byte, questionEnd int) (flags uint16, strs [][]byte) {
	t.Helper()
	flags = binary.BigEndian.Uint16(reply[2:4])
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		return flags, nil
	}
	rr := reply[questionEnd:]
	if rr[0] != 0xC0 || rr[1] != 0x0C || binary.BigEndian.Uint16(rr[2:4]) != 16 || binary.BigEndian.Uint32(rr[6:10]) != 0 {
		t.Fatalf("answer RR % x", rr[:12])
	}
	n := int(binary.BigEndian.Uint16(rr[10:12]))
	data := rr[12 : 12+n]
	for len(data) > 0 {
		l := int(data[0])
		strs, data = append(strs, data[1:1+l]), data[1+l:]
	}
	return flags, strs
}

func ask(t *testing.T, p *dnsProbe, zone, label string, qtype uint16, edns int, src string) (reply []byte, probe bool, questionEnd int) {
	t.Helper()
	q := probeQuery(label+"."+zone, qtype, edns)
	name, end, ok := queryName(q)
	if !ok {
		t.Fatal("query does not parse")
	}
	reply, probe = p.answer(q, name, end, zone, netip.MustParseAddr(src))
	return reply, probe, end
}

// The spec's example (raycontrol docs/spec/dnsprobe-v1.md §7).
func TestProbeVectors(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := [8]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}
	label := probeLabel(key, "t.example.com", false, 29000000, nonce)
	b, _ := probeBase32.DecodeString(strings.ToUpper(label))
	token := probeToken(key, b)
	t.Logf("label %s, token %q", label, token)
	if len(label) != probeLabelLen || len(token) != 29 {
		t.Fatalf("label %d chars, token %d", len(label), len(token))
	}
	// Worked out apart from this code too (Python, hmac and base64).
	const wantLabel, wantToken = "aeaadoubicqkdivduss2nj2inuqqx7vwla4ifvi", "v1 7wdaqgi6x2divio2oavsyoqvg4"
	if label != wantLabel || token != wantToken {
		t.Fatalf("vectors changed: label %s, token %q", label, token)
	}
}

func TestProbe(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	zone := "t.example.com"
	now := time.Unix(1_740_000_000, 0)
	p := newDNSProbe(key)
	p.now = func() time.Time { return now }
	minute := uint32(now.Unix() / 60)
	n := byte(0)
	label := func(large bool, m uint32) string {
		n++
		return probeLabel(key, zone, large, m, [8]byte{n})
	}

	// Small, through a resolver that randomises case: the token, what the
	// node saw, no fillers.
	l := label(false, minute)
	reply, probe, end := ask(t, p, zone, strings.ToUpper(l[:5])+l[5:], 16, 1232, "198.51.100.7")
	if !probe || reply == nil {
		t.Fatal("small probe not answered")
	}
	flags, strs := txtStrings(t, reply, end)
	b, _ := probeBase32.DecodeString(strings.ToUpper(l))
	if flags&0x8400 != 0x8400 || flags&0x000f != 0 || len(strs) != 2 || string(strs[0]) != probeToken(key, b) ||
		string(strs[1]) != "seen edns=1232 case=1 from=198.51.100.7" {
		t.Fatalf("small: flags %04x, %q", flags, strs)
	}
	if !bytes.Equal(reply[len(reply)-11:len(reply)-8], []byte{0, 0, 41}) {
		t.Fatal("no OPT in the answer to a query with one")
	}

	// Large with room: the fillers, under 1232 bytes.
	reply, _, end = ask(t, p, zone, label(true, minute), 16, 1232, "198.51.100.7")
	flags, strs = txtStrings(t, reply, end)
	if flags&0x0200 != 0 || len(strs) != 6 || !probeFillersOK(strs[2:]) || len(reply) > probeUDPSize || len(reply) < 1000 {
		t.Fatalf("large: flags %04x, %d strings, %d bytes", flags, len(strs), len(reply))
	}
	// Large without EDNS, or with too little: TC and no answer.
	for _, edns := range []int{0, 512, 1000} {
		reply, _, end = ask(t, p, zone, label(true, minute), 16, edns, "198.51.100.8")
		if flags, strs = txtStrings(t, reply, end); flags&0x0200 == 0 || strs != nil {
			t.Fatalf("large with EDNS %d: flags %04x, %q", edns, flags, strs)
		}
	}
	// Small without EDNS: answered, and no OPT.
	reply, _, end = ask(t, p, zone, label(false, minute), 16, 0, "198.51.100.8")
	if flags, strs = txtStrings(t, reply, end); flags&0x0200 != 0 || len(strs) != 2 || string(strs[1]) != "seen edns=0 case=0 from=198.51.100.8" ||
		binary.BigEndian.Uint16(reply[10:12]) != 0 {
		t.Fatalf("small without EDNS: flags %04x, %q", flags, strs)
	}

	// Not a probe: for the backend.
	l = label(false, minute)
	for name, q := range map[string]struct {
		label string
		qtype uint16
	}{
		"another key":   {probeLabel(bytes.Repeat([]byte{8}, 32), zone, false, minute, [8]byte{99}), 16},
		"another zone":  {probeLabel(key, "u.example.com", false, minute, [8]byte{98}), 16},
		"stale":         {probeLabel(key, zone, false, minute-3, [8]byte{97}), 16},
		"from ahead":    {probeLabel(key, zone, false, minute+3, [8]byte{96}), 16},
		"type A":        {l, 1},
		"short":         {l[:38], 16},
		"two labels":    {l[:20] + "." + l[20:], 16},
		"tunnel":        {strings.Repeat("a", 39), 16},
		"non-canonical": {l[:38] + string(probeBase32Alt(l[38])), 16},
	} {
		if _, probe, _ := ask(t, p, zone, q.label, q.qtype, 1232, "198.51.100.9"); probe {
			t.Errorf("%s: taken for a probe", name)
		}
	}
	// A minute either way is fine, two too.
	if _, probe, _ := ask(t, p, zone, label(false, minute-2), 16, 1232, "198.51.100.9"); !probe {
		t.Error("two minutes old: refused")
	}
	// A replay: for the backend.
	l = label(false, minute)
	if _, probe, _ := ask(t, p, zone, l, 16, 1232, "198.51.100.10"); !probe {
		t.Fatal("first probe refused")
	}
	if _, probe, _ := ask(t, p, zone, l, 16, 1232, "198.51.100.10"); probe {
		t.Fatal("replay taken")
	}
}

// probeBase32Alt is another base32 character with the same top bits, for a
// non-canonical spelling of the last character (its low bits are padding).
func probeBase32Alt(c byte) byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	i := strings.IndexByte(alphabet, c)
	return alphabet[i^1]
}

// A source's bucket runs dry: no answer at all, while another source is
// still answered; the global bucket bounds them all.
func TestProbeRate(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	zone := "t.example.com"
	now := time.Unix(1_740_000_000, 0)
	p := newDNSProbe(key)
	p.now = func() time.Time { return now }
	minute := uint32(now.Unix() / 60)
	var i uint64
	probe := func(large bool, src string) []byte {
		i++
		var nonce [8]byte
		binary.BigEndian.PutUint64(nonce[:], i)
		reply, ok, _ := ask(t, p, zone, probeLabel(key, zone, large, minute, nonce), 16, 1232, src)
		if !ok {
			t.Fatal("not a probe")
		}
		return reply
	}
	answered := 0
	for range 10 {
		if probe(true, "203.0.113.5") != nil {
			answered++
		}
	}
	if answered != probeBurst/probeLargeCost {
		t.Fatalf("large from one source: %d answered, want %d", answered, probeBurst/probeLargeCost)
	}
	// The same /24: the same bucket.
	if probe(false, "203.0.113.200") != nil {
		t.Fatal("the same /24 answered past its bucket")
	}
	if probe(false, "198.51.100.1") == nil {
		t.Fatal("another source refused")
	}
	// A second later the source has 20 tokens back: two large probes.
	now = now.Add(time.Second)
	answered = 0
	for range 4 {
		if probe(true, "203.0.113.5") != nil {
			answered++
		}
	}
	if answered != 2 {
		t.Fatalf("after a second: %d large answered, want 2", answered)
	}
	// Many sources: the global bucket ends it.
	now = now.Add(time.Hour)
	minute = uint32(now.Unix() / 60)
	answered = 0
	for j := range 200 {
		if probe(true, netip.AddrFrom4([4]byte{10, byte(j), 0, 1}).String()) != nil {
			answered++
		}
	}
	if answered != probeGlobalBurst/probeLargeCost {
		t.Fatalf("from 200 sources: %d answered, want %d", answered, probeGlobalBurst/probeLargeCost)
	}
}

// probeFillersOK tells whether the strings after the token and what the
// node saw are the fillers of a large answer.
func probeFillersOK(strs [][]byte) bool {
	if len(strs) != probeFillers {
		return false
	}
	for _, s := range strs {
		if !bytes.Equal(s, probeFillerString) {
			return false
		}
	}
	return true
}
