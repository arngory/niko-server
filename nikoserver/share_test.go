//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// slipAnswer is the slipstream server's answer to a query the front passed
// on: QR and AA, the question as it came, one TXT whose name points at it,
// and an OPT of 4096 with the query's DO when it had one.
func slipAnswer(query, data []byte) []byte {
	_, end, ok := queryName(query)
	if !ok {
		panic("no query")
	}
	a := append([]byte(nil), query[:end]...)
	a[2] |= 0x84
	binary.BigEndian.PutUint16(a[6:8], 1)
	binary.BigEndian.PutUint16(a[10:12], 0)
	a = append(a, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60)
	a = binary.BigEndian.AppendUint16(a, uint16(len(data)+1))
	a = append(a, byte(len(data)))
	a = append(a, data...)
	if i := optOffset(query, end); i >= 0 {
		binary.BigEndian.PutUint16(a[10:12], 1)
		a = append(a, 0, 0, 41, 0x10, 0, 0, 0, query[i+6]&0x80, 0, 0, 0)
	}
	return a
}

// shareFront is a front with one slipstream zone, s.example.com, whose
// backend is the test's.
type shareFront struct {
	t     *testing.T
	be    *net.UnixConn
	port  int
	key   [32]byte
	stats string
}

func newShareFront(t *testing.T) *shareFront {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	f := &shareFront{t: t, stats: filepath.Join(dir, "stats.sock")}
	rand.Read(f.key[:])
	keys := filepath.Join(dir, "auth.keys")
	os.WriteFile(keys, []byte("d1 "+hex.EncodeToString(f.key[:])+"\n"), 0o600)
	sock := filepath.Join(dir, "slip.sock")
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.port = udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{fmt.Sprintf("127.0.0.1:%d", f.port)}, StatsSocket: f.stats,
		Zones: []DNSZone{{Zone: "s.example.com", Backend: "slip", Tag: "slipstream", AuthKeysFile: keys}}},
		Backends: map[string]BackendRef{"slip": {Socket: sock, Mode: "packet", UID: os.Getuid()}}}
	if errs := c.validate(); len(errs) != 0 {
		t.Fatal(errs)
	}
	go RunFront(ctx, c, NewLogger("warn", io.Discard))
	if f.be, err = ln.AcceptUnix(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.be.Close() })
	return f
}

func (f *shareFront) dial() *net.UDPConn {
	f.t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.port})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { conn.Close() })
	return conn
}

// backendRead is the next query the backend gets, with whom to answer.
func (f *shareFront) backendRead(wait time.Duration) (client, local netip.AddrPort, query []byte, ok bool) {
	buf := make([]byte, 70000)
	f.be.SetReadDeadline(time.Now().Add(wait))
	n, err := f.be.Read(buf)
	if err != nil {
		return client, local, nil, false
	}
	client, local, query, err = decodePacket(buf[:n])
	if err != nil {
		f.t.Fatal(err)
	}
	return client, local, bytes.Clone(query), true
}

func (f *shareFront) backendAnswer(client, local netip.AddrPort, answer []byte) {
	f.t.Helper()
	if _, err := f.be.Write(encodePacket(nil, client, local, answer)); err != nil {
		f.t.Fatal(err)
	}
}

func readFor(conn *net.UDPConn, wait time.Duration) []byte {
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(wait))
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// txtData is the data of an answer's one TXT, nil without one.
func txtData(a []byte) []byte {
	_, end, ok := queryName(append([]byte{a[0], a[1], a[2] &^ 0x80}, a[3:]...))
	if !ok || binary.BigEndian.Uint16(a[6:8]) != 1 || end+12 > len(a) {
		return nil
	}
	i := end
	if a[i] != 0xc0 {
		return nil
	}
	i += 2 + 10
	return a[i+1 : i+1+int(a[i])]
}

// splitLabels is a query's name in labels of n characters before the zone,
// the same data: the same field, another name.
func splitLabels(t *testing.T, q []byte, n int) []byte {
	t.Helper()
	name, end, _ := queryName(q)
	data, _ := strings.CutSuffix(name, ".s.example.com")
	data = strings.ReplaceAll(data, ".", "")
	var labels []string
	for data != "" {
		k := min(n, len(data))
		labels, data = append(labels, data[:k]), data[k:]
	}
	labels = append(labels, "s", "example", "com")
	out := append([]byte(nil), q[:12]...)
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	return append(out, q[end-4:]...)
}

// A copy of a device's query that reaches the front before the original
// (anyone on the path who is faster) no longer takes the server's answer
// from the resolver (review 2026-11-21 item 3): the original, and a
// resolver's retry, get the same answer as the copy, with their own ID
// and question, however its name is cased or split; a few times, never
// new data.
func TestTaggedZoneCopyFirstSharesAnswer(t *testing.T) {
	f := newShareFront(t)
	packet := append([]byte{0xc0, 0, 0, 0, 1, 8}, bytes.Repeat([]byte{7}, 100)...)
	q := slipQuery(t, dnsttserver.Tag2(&f.key, dnsttserver.EpochOf(time.Now()), packet), packet, "s.example.com", 16, true)
	copier, resolver := f.dial(), f.dial()

	// The copy first, until the front has its backend.
	stolen := bytes.Clone(q)
	stolen[0], stolen[1] = 0xaa, 0xaa
	var client, local netip.AddrPort
	var passed []byte
	for i := 0; ; i++ {
		copier.Write(stolen)
		var ok bool
		if client, local, passed, ok = f.backendRead(200 * time.Millisecond); ok {
			break
		}
		if i == 30 {
			t.Fatal("the backend got nothing")
		}
	}
	// The resolver's own query, after it: another ID, its name in
	// another case.
	original := bytes.Clone(q)
	original[0], original[1] = 0x12, 0x34
	for i := 12; i < len(original)-20; i++ {
		if c := original[i]; 'a' <= c && c <= 'z' && i%3 == 0 {
			original[i] = c - 'a' + 'A'
		}
	}
	resolver.Write(original)
	if _, _, _, ok := f.backendRead(200 * time.Millisecond); ok {
		t.Fatal("the original reached the backend after its copy")
	}
	data := bytes.Repeat([]byte{0x5c}, 200)
	f.backendAnswer(client, local, slipAnswer(passed, data))
	if a := readFor(copier, 2*time.Second); a == nil || !bytes.Equal(a[:2], stolen[:2]) || !bytes.Equal(txtData(a), data) {
		t.Fatalf("the copy's answer: %x", a)
	}
	a := readFor(resolver, 2*time.Second)
	_, end, _ := queryName(original)
	if a == nil {
		t.Fatal("the resolver got no answer: the copy took it")
	}
	if !bytes.Equal(a[:2], original[:2]) || a[2]&0x80 == 0 || !bytes.Equal(a[12:end], original[12:end]) || !bytes.Equal(txtData(a), data) ||
		binary.BigEndian.Uint16(a[10:12]) != 1 {
		t.Fatalf("the resolver's answer: %x", a)
	}
	// A retry with its name split otherwise and without EDNS, after the
	// answer: the same data at once, its own question, no OPT.
	retry := splitLabels(t, original, 40)
	retry[0] = 0x77
	binary.BigEndian.PutUint16(retry[10:12], 0)
	resolver.Write(retry)
	r := readFor(resolver, 2*time.Second)
	_, rend, _ := queryName(retry)
	if r == nil || r[0] != 0x77 || !bytes.Equal(r[12:rend], retry[12:rend]) || !bytes.Equal(txtData(r), data) || binary.BigEndian.Uint16(r[10:12]) != 0 {
		t.Fatalf("a retry's answer: %x", r)
	}
	if _, _, _, ok := f.backendRead(100 * time.Millisecond); ok {
		t.Fatal("a retry reached the backend")
	}
	// Past shareAnswers in all, copies get nothing.
	got := 3
	for range 6 {
		copier.Write(stolen)
		if b := readFor(copier, 300*time.Millisecond); b != nil {
			if !bytes.Equal(txtData(b), data) {
				t.Fatalf("a copy got another answer: %x", b)
			}
			got++
		}
	}
	if got != shareAnswers {
		t.Fatalf("%d answers to one field, want %d", got, shareAnswers)
	}
}

// shareReply makes an answer another query's: its ID, flags, question and
// EDNS; a question in other labels only when the answer's names all point
// at the question; within the requester's size.
func TestShareReply(t *testing.T) {
	var field [8]byte
	packet := bytes.Repeat([]byte{9}, 120)
	q := slipQuery(t, field, packet, "s.example.com", 16, true)
	data := bytes.Repeat([]byte{0x33}, 250)
	answer := slipAnswer(q, data)
	end := func(m []byte) int {
		_, e, ok := queryName(m)
		if !ok {
			t.Fatalf("no query: %x", m)
		}
		return e
	}
	split := splitLabels(t, q, 30)
	split[0], split[2] = 0x99, 0x00 // another ID, RD clear
	se := end(split)
	r := shareReply(answer, split, se)
	if r == nil || r[0] != 0x99 || r[2] != 0x84 || !bytes.Equal(r[12:se], split[12:se]) || !bytes.Equal(txtData(r), data) {
		t.Fatalf("another split: %x", r)
	}
	// An OPT as the front's, with the query's DO; none without one.
	if o := optOffset(r, se); o < 0 || !bytes.Equal(r[o-1:], []byte{0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0}) {
		t.Fatalf("the OPT: %x", r[se:])
	}
	plain := splitLabels(t, q, 57)
	pe := end(plain)
	binary.BigEndian.PutUint16(plain[10:12], 0)
	plain = plain[:pe]
	if r := shareReply(answer, plain, pe); r == nil || binary.BigEndian.Uint16(r[10:12]) != 0 || optOffset(r, pe) >= 0 {
		t.Fatalf("without EDNS: %x", r)
	}
	// Within the requester's size: 512 without an OPT. Two TXT records
	// of 250 are past it.
	qe := end(q)
	o := optOffset(answer, qe) - 1
	two := append([]byte(nil), answer[:o]...)
	two = append(two, answer[qe:o]...)
	two = append(two, answer[o:]...)
	binary.BigEndian.PutUint16(two[6:8], 2)
	if r := shareReply(two, plain, pe); r == nil || r[2]&0x02 == 0 || binary.BigEndian.Uint16(r[6:8]) != 0 || len(r) > 512 {
		t.Fatalf("past 512: %d bytes %x", len(r), r)
	}
	if r := shareReply(two, q, qe); r == nil || r[2]&0x02 != 0 || binary.BigEndian.Uint16(r[6:8]) != 2 {
		t.Fatalf("within 4096: %x", r)
	}
	// A name that is not a pointer to the question: only the same
	// question, but for case.
	odd := append([]byte(nil), answer[:qe]...)
	odd = append(odd, answer[12:qe-4]...) // the name written out
	odd = append(odd, answer[qe+2:]...)
	if r := shareReply(odd, split, se); r != nil {
		t.Fatalf("a name written out, another split: %x", r)
	}
	upper := bytes.ToUpper(q)
	if r := shareReply(odd, upper, qe); r == nil || !bytes.Equal(r[12:qe], upper[12:qe]) || !bytes.Equal(txtData2(r, qe), data) {
		t.Fatalf("a name written out, the question in another case: %x", r)
	}
	if shareReply(answer[:20], q, qe) != nil || shareReply(answer[:len(answer)-3], q, qe) != nil {
		t.Fatal("a cut answer read")
	}
}

// txtData2 is the data of the TXT right after a question ending at end,
// whose name is written out.
func txtData2(a []byte, end int) []byte {
	i, ok := skipName(a, end)
	if !ok || i+11 > len(a) {
		return nil
	}
	i += 10
	return a[i+1 : i+1+int(a[i])]
}

// A field's entry lives 5 to 10 s, as a query waiting for its answer; a
// field never passed on is no copy of one; a query the backend never got
// is forgotten.
func TestAnswerShareGenerations(t *testing.T) {
	now := time.Unix(1767268800, 0)
	s := answerShare{now: func() time.Time { return now }}
	a := netip.MustParseAddrPort("192.0.2.1:53")
	q := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 1}
	if _, handled := s.copyOf([8]byte{1}, q, len(q), a, a, netip.Addr{}, nil); handled {
		t.Fatal("a field never passed on, handled")
	}
	s.open([8]byte{1})
	s.open([8]byte{2})
	s.forget([8]byte{2})
	if _, handled := s.copyOf([8]byte{2}, q, len(q), a, a, netip.Addr{}, nil); handled {
		t.Fatal("a field forgotten, handled")
	}
	now = now.Add(pendingGeneration + time.Second)
	if _, handled := s.copyOf([8]byte{1}, q, len(q), a, a, netip.Addr{}, nil); !handled {
		t.Fatal("a field of the last generation, not handled")
	}
	if w := s.answered([8]byte{1}, append([]byte{1, 2, 0x84, 0}, q[4:]...)); len(w) != 1 {
		t.Fatalf("%d waiting", len(w))
	}
	now = now.Add(2*pendingGeneration + time.Second)
	if _, handled := s.copyOf([8]byte{1}, q, len(q), a, a, netip.Addr{}, nil); handled {
		t.Fatal("a field older than two generations, handled")
	}
}
