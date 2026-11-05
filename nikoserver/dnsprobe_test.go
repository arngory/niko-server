//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// probeQuery is a query for name of qtype with an OPT of size edns (0: none).
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

// probeOpen checks an answer's shape (as dnstt's) and returns its
// decrypted plaintext, as a client reads it.
func probeOpen(t *testing.T, key []byte, label string, reply []byte, withOPT bool) []byte {
	t.Helper()
	m, err := dns.MessageFromWireFormat(reply)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || m.Flags != 0x8400 || len(m.Answer) != 1 || m.Answer[0].Type != dns.RRTypeTXT || m.Answer[0].TTL != 60 {
		t.Fatalf("answer %+v", m)
	}
	if withOPT != (len(m.Additional) == 1 && m.Additional[0].Type == dns.RRTypeOPT && m.Additional[0].Class == 4096) {
		t.Fatalf("OPT %+v (query had one: %v)", m.Additional, withOPT)
	}
	plain, err := dns.DecodeRDataTXT(m.Answer[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := probeBase32.DecodeString(strings.ToUpper(label))
	probeCrypt(probeMAC(key, []byte("dnsprobe-v1 e")), b, plain)
	if len(plain) < probeSmall || !bytes.Equal(plain[:probeTokenLen], probeMAC(key, []byte("dnsprobe-v1 a"), b, plain[probeTokenLen:probeSmall])[:probeTokenLen]) {
		t.Fatalf("token % x", plain[:probeTokenLen])
	}
	return plain
}

func ask(t *testing.T, p *dnsProbe, zone, label string, qtype uint16, edns int, src string) (reply []byte, probe bool) {
	t.Helper()
	q := probeQuery(label+"."+zone, qtype, edns)
	name, end, ok := queryName(q)
	if !ok {
		t.Fatal("query does not parse")
	}
	return p.answer(q, name, end, zone, netip.MustParseAddr(src))
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
	plain := probePlain(key, b, 1232, true, netip.MustParseAddr("198.51.100.7"), probeSmall)
	probeCrypt(probeMAC(key, []byte("dnsprobe-v1 e")), b, plain)
	t.Logf("label %s, small answer data %x", label, plain)
	// Worked out apart from this code too (Python, hmac and base64).
	const wantLabel = "aeaadoubicqkdivduss2nj2inuqqx7vwla4ifvi"
	const wantData = "42c10f1d94c67a0d8a02d86b2d81e9f1e2733f6dbdb92d439b28a37af4894debbcd0a1"
	if label != wantLabel || hex.EncodeToString(plain) != wantData {
		t.Fatalf("vectors changed: label %s, data %x", label, plain)
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
	seen := func(plain []byte) (int, byte, netip.Addr) {
		return int(binary.BigEndian.Uint16(plain[16:18])), plain[18], netip.AddrFrom16([16]byte(plain[19:35])).Unmap()
	}

	// Small, through a resolver that randomises case: the token and what
	// the node saw.
	l := label(false, minute)
	reply, probe := ask(t, p, zone, strings.ToUpper(l[:5])+l[5:], 16, 1232, "198.51.100.7")
	if !probe || reply == nil {
		t.Fatal("small probe not answered")
	}
	plain := probeOpen(t, key, l, reply, true)
	if edns, mixed, from := seen(plain); len(plain) != probeSmall || edns != 1232 || mixed != 1 || from != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("small: %d bytes, seen %d %d %s", len(plain), edns, mixed, from)
	}
	// The question as it was asked, case included.
	if !bytes.Contains(reply, []byte(strings.ToUpper(l[:5])+l[5:])) {
		t.Fatal("the question not echoed as asked")
	}

	// Large with room: zeros after what the node saw, under 1232 bytes.
	l = label(true, minute)
	reply, _ = ask(t, p, zone, l, 16, 1232, "198.51.100.7")
	plain = probeOpen(t, key, l, reply, true)
	if len(plain) != probeLarge || !bytes.Equal(plain[probeSmall:], make([]byte, probeLarge-probeSmall)) || len(reply) > 1232 || len(reply) < 900 {
		t.Fatalf("large: %d bytes of plaintext, %d on the wire", len(plain), len(reply))
	}
	// Large without room: small, as dnstt fits its answers.
	for _, edns := range []int{0, 512, 900} {
		l = label(true, minute)
		reply, _ = ask(t, p, zone, l, 16, edns, "198.51.100.8")
		plain = probeOpen(t, key, l, reply, edns > 0)
		if e, _, _ := seen(plain); len(plain) != probeSmall || e != edns {
			t.Fatalf("large with EDNS %d: %d bytes, edns %d", edns, len(plain), e)
		}
	}

	// A replay is answered the same: one more answer of the tunnel.
	l = label(false, minute)
	first, _ := ask(t, p, zone, l, 16, 1232, "198.51.100.10")
	again, probe := ask(t, p, zone, l, 16, 1232, "198.51.100.10")
	if !probe || !bytes.Equal(first, again) {
		t.Fatal("a replay answered otherwise")
	}

	// Not a probe: for the backend.
	l = label(false, minute)
	for name, q := range map[string]struct {
		label string
		qtype uint16
	}{
		"another key":  {probeLabel(bytes.Repeat([]byte{8}, 32), zone, false, minute, [8]byte{99}), 16},
		"another zone": {probeLabel(key, "u.example.com", false, minute, [8]byte{98}), 16},
		"stale":        {probeLabel(key, zone, false, minute-3, [8]byte{97}), 16},
		"from ahead":   {probeLabel(key, zone, false, minute+3, [8]byte{96}), 16},
		"type A":       {l, 1},
		"short":        {l[:38], 16},
		"two labels":   {l[:20] + "." + l[20:], 16},
		"tunnel":       {strings.Repeat("a", 39), 16},
	} {
		if _, probe := ask(t, p, zone, q.label, q.qtype, 1232, "198.51.100.9"); probe {
			t.Errorf("%s: taken for a probe", name)
		}
	}
	if _, probe := ask(t, p, zone, label(false, minute-2), 16, 1232, "198.51.100.9"); !probe {
		t.Error("two minutes old: refused")
	}
}

// A source's bucket runs dry: no answer at all, while another source is
// still answered; the global bucket bounds them all.
func TestProbeRate(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	zone := "t.example.com"
	now := time.Unix(1_740_000_000, 0)
	p := newDNSProbe(key)
	p.now = func() time.Time { return now }
	var i uint64
	probe := func(large bool, src string) []byte {
		i++
		var nonce [8]byte
		binary.BigEndian.PutUint64(nonce[:], i)
		reply, ok := ask(t, p, zone, probeLabel(key, zone, large, uint32(now.Unix()/60), nonce), 16, 1232, src)
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
	if probe(false, "203.0.113.200") != nil {
		t.Fatal("the same /24 answered past its bucket")
	}
	if probe(false, "198.51.100.1") == nil {
		t.Fatal("another source refused")
	}
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
	answered = 0
	for j := range 200 {
		if probe(true, netip.AddrFrom4([4]byte{10, byte(j), 0, 1}).String()) != nil {
			answered++
		}
	}
	if answered != probeGlobalBurst/probeLargeCost {
		t.Fatalf("from 200 sources: %d answered, want %d", answered, probeGlobalBurst/probeLargeCost)
	}
	// More sources than the map holds: the old ones go, nobody is refused
	// for want of room.
	now = now.Add(time.Hour)
	for j := range probeSourcesMax + 10 {
		p.allow(netip.AddrFrom4([4]byte{11, byte(j >> 8), byte(j), 1}), 0, now)
	}
	if len(p.sources)+len(p.older) > 2*probeSourcesMax {
		t.Fatalf("%d sources kept", len(p.sources)+len(p.older))
	}
	if !p.allow(netip.MustParseAddr("192.0.2.1"), 1, now) {
		t.Fatal("a new source refused with the map full")
	}
}
