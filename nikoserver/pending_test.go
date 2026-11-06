package nikoserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func pendingQuery(t *testing.T, id uint16, edns int) ([]byte, int) {
	t.Helper()
	name, _ := dns.ParseName("x.v.example.com")
	q := dns.Message{ID: id, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}}}
	if edns > 0 {
		q.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: uint16(edns), Data: []byte{}}}
	}
	b, err := q.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	_, end, ok := queryName(b)
	if !ok {
		t.Fatal("queryName")
	}
	return b, end
}

// An answer of size bytes to the query: its question and a TXT record.
func pendingAnswer(t *testing.T, query []byte, size int) []byte {
	t.Helper()
	m, err := dns.MessageFromWireFormat(query)
	if err != nil {
		t.Fatal(err)
	}
	m.Flags = 0x8400
	// The backend's own OPT when the query had one, as dnstt answers.
	hadOPT := len(m.Additional) > 0
	m.Additional = nil
	if hadOPT {
		m.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, Data: []byte{}}}
	}
	m.Answer = []dns.RR{{Name: m.Question[0].Name, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 60, Data: dns.EncodeRDataTXT(nil)}}
	b, _ := m.WireFormat()
	data := make([]byte, size-len(b)) // TXT strings of 255: 1 byte of length each
	m.Answer[0].Data = dns.EncodeRDataTXT(data[:len(data)-len(data)/256-1])
	b, err = m.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRequesterSize(t *testing.T) {
	for edns, want := range map[int]int{0: 512, 100: 512, 1232: 1232, 4096: 4096} {
		q, end := pendingQuery(t, 1, edns)
		if got := requesterSize(q, end); got != want {
			t.Errorf("EDNS %d: %d, want %d", edns, got, want)
		}
	}
	// Something else than an OPT: 512.
	q, end := pendingQuery(t, 1, 1232)
	q[end+2] = 1 // the record's type: A
	if got := requesterSize(q, end); got != 512 {
		t.Errorf("not an OPT: %d", got)
	}
	// An OPT after another record of the additional section, as dnstt
	// finds it (review 7: the front read 512 and cut dnstt's answers).
	name, _ := dns.ParseName("x.v.example.com")
	m := dns.Message{ID: 1, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Additional: []dns.RR{{Name: name, Type: 1, Class: dns.ClassIN, Data: []byte{1, 2, 3, 4}},
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 1232, Data: []byte{}}}}
	b, err := m.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	if _, end, _ := queryName(b); requesterSize(b, end) != 1232 {
		t.Errorf("an OPT after a compressed record: %d", requesterSize(b, end))
	}
	if requesterSize(b[:len(b)-3], end) != 512 {
		t.Error("a cut message walked")
	}
}

func TestPendingQueries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := &pendingQueries{now: func() time.Time { return now }}
	client := netip.MustParseAddrPort("198.51.100.7:5353")
	q, end := pendingQuery(t, 0x4242, 1232)
	a := pendingAnswer(t, q, 900)

	if _, ok := p.take(client, a); ok {
		t.Fatal("an answer no query waits for")
	}
	// A resolver's retry: two queries, two answers.
	p.add(client, q, end)
	p.add(client, q, end)
	for i := range 2 {
		if size, ok := p.take(client, a); !ok || size != 1232 {
			t.Fatalf("answer %d: %d %v", i, size, ok)
		}
	}
	if _, ok := p.take(client, a); ok {
		t.Fatal("a third answer to two queries")
	}
	// Another client, the same ID: not its query.
	p.add(client, q, end)
	if _, ok := p.take(netip.MustParseAddrPort("198.51.100.8:5353"), a); ok {
		t.Fatal("an answer for another client")
	}
	// The previous generation still counts; two later, gone.
	now = now.Add(pendingGeneration + time.Second)
	p.add(netip.MustParseAddrPort("198.51.100.9:1"), q, end) // turns the generations over
	if _, ok := p.take(client, a); !ok {
		t.Fatal("an answer within the second generation dropped")
	}
	p.add(client, q, end)
	now = now.Add(2*pendingGeneration + time.Second)
	if _, ok := p.take(client, a); ok {
		t.Fatal("an answer after two generations")
	}
}

func TestTruncated(t *testing.T) {
	q, end := pendingQuery(t, 0x0102, 0)
	a := pendingAnswer(t, q, 4000)
	tc := truncated(a)
	if tc == nil || len(tc) != end || !bytes.Equal(tc[:2], q[:2]) || tc[2]&0x02 == 0 ||
		binary.BigEndian.Uint16(tc[4:6]) != 1 || binary.BigEndian.Uint16(tc[6:8]) != 0 {
		t.Fatalf("truncated % x", tc)
	}
	m, err := dns.MessageFromWireFormat(tc)
	if err != nil || len(m.Answer) != 0 || m.Question[0].Name.String() != "x.v.example.com" {
		t.Fatalf("%+v %v", m, err)
	}
	if truncated(a[:20]) != nil || truncated(nil) != nil {
		t.Fatal("a cut answer truncated")
	}
	// An answer with an OPT keeps one (RFC 6891 §7, review 8): the front's.
	q, end = pendingQuery(t, 0x0103, 1232)
	tc = truncated(pendingAnswer(t, q, 4000))
	if len(tc) != end+len(truncatedOPT) || binary.BigEndian.Uint16(tc[10:12]) != 1 || !bytes.Equal(tc[end:], truncatedOPT) {
		t.Fatalf("truncated with an OPT % x", tc)
	}
	if m, err := dns.MessageFromWireFormat(tc); err != nil || len(m.Additional) != 1 || m.Additional[0].Type != dns.RRTypeOPT || m.Additional[0].Class != 4096 {
		t.Fatalf("%+v %v", m, err)
	}
}

// The front's answer path: a backend's answer goes to a query that waits
// for it and within the requester's size; larger, it goes as TC; to no
// query, it does not go at all (a forged source gets nothing larger than
// what it sent, and the node is no reflector).
func TestFrontAnswerSize(t *testing.T) {
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	local := front.LocalAddr().(*net.UDPAddr).AddrPort()
	client := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()
	f := &dnsFront{log: NewLogger("error", nil), sockets: map[netip.AddrPort]*net.UDPConn{local: front}}
	read := func() []byte {
		clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 65535)
		n, err := clientConn.Read(buf)
		if err != nil {
			return nil
		}
		return buf[:n]
	}
	for _, c := range []struct {
		edns, size int
		tc         bool
	}{
		{0, 400, false},
		{0, 4000, true}, // no OPT: 512 at most
		{1232, 1200, false},
		{1232, 4700, true}, // an MTU probe's kilobytes to a requester of 1232
		{4096, 1200, false},
		{4096, 4000, true},  // 1232 at most, whatever the OPT
		{65535, 5999, true}, // a forged OPT (review 7: 136 times the query)
	} {
		q, end := pendingQuery(t, 7, c.edns)
		a := pendingAnswer(t, q, c.size)
		f.pending.add(client, q, end)
		f.answer(client, local, a)
		got := read()
		switch {
		case got == nil:
			t.Errorf("EDNS %d, %d bytes: nothing came", c.edns, c.size)
		case c.tc && (got[2]&0x02 == 0 || len(got) > maxBackendAnswer):
			t.Errorf("EDNS %d, %d bytes: %d bytes came, TC %v", c.edns, c.size, len(got), got[2]&0x02 != 0)
		case !c.tc && !bytes.Equal(got, a):
			t.Errorf("EDNS %d, %d bytes: %d bytes came", c.edns, c.size, len(got))
		}
	}
	// No query waits: nothing goes.
	q, _ := pendingQuery(t, 8, 4096)
	f.answer(client, local, pendingAnswer(t, q, 4000))
	if got := read(); got != nil {
		t.Errorf("an answer no query waited for: %d bytes went", len(got))
	}
}

// The front's own answers carry the query's DO bit (RFC 3225 §3): the
// apex, the probe, a truncated answer (from the backend's OPT, which has
// the query's); always 0 was a mark of the tunnel.
func TestAnswersCopyDO(t *testing.T) {
	withDO := func(q []byte) []byte {
		q = append([]byte(nil), q...)
		q[len(q)-4] |= 0x80 // the last record is the OPT: its flags' first byte
		return q
	}
	optTTL := func(t *testing.T, reply []byte) uint32 {
		t.Helper()
		m, err := dns.MessageFromWireFormat(reply)
		if err != nil || len(m.Additional) != 1 || m.Additional[0].Type != dns.RRTypeOPT {
			t.Fatalf("%+v %v", m, err)
		}
		return m.Additional[0].TTL
	}
	a := newApexZone("t.example.com", []string{"ns1.example.com"}, 1_800_000_000)
	for _, do := range []bool{false, true} {
		q := probeQuery("t.example.com", 6, 1232)
		if do {
			q = withDO(q)
		}
		reply, ok := a.answer(q)
		if !ok || (optTTL(t, reply)&0x8000 != 0) != do {
			t.Fatalf("apex, DO %v: %x", do, reply)
		}
	}
	key := bytes.Repeat([]byte{7}, 32)
	p := newDNSProbe(key)
	l := probeLabel(key, "t.example.com", false, uint32(time.Now().Unix()/60), [8]byte{1})
	q := withDO(probeQuery(l+".t.example.com", 16, 1232))
	name, end, _ := queryName(q)
	if reply, probe := p.answer(q, name, end, "t.example.com", netip.MustParseAddr("198.51.100.7"), false); !probe || optTTL(t, reply)&0x8000 == 0 {
		t.Fatalf("probe: DO not copied")
	}
	q, end = pendingQuery(t, 0x0104, 1232)
	answer := withDO(pendingAnswer(t, q, 4000))
	if tc := truncated(answer); optTTL(t, tc)&0x8000 == 0 || len(tc) != end+len(truncatedOPT) {
		t.Fatalf("truncated: DO not copied: % x", tc)
	}
}
