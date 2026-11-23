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
	"os"
	"path/filepath"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// nodataFront is a front with a dnstt zone t.example.com and a slipstream
// zone s.example.com, both delegated to ns.example.net, whose backends are
// the test's.
type nodataFront struct {
	t        *testing.T
	dnstt    *net.UnixConn
	port     int
	stats    string
	slipKeys [32]byte
}

func newNodataFront(t *testing.T) *nodataFront {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	f := &nodataFront{t: t, stats: filepath.Join(dir, "stats.sock")}
	rand.Read(f.slipKeys[:])
	keys := filepath.Join(dir, "auth.keys")
	os.WriteFile(keys, []byte("d1 "+hex.EncodeToString(f.slipKeys[:])+"\n"), 0o600)
	listen := func(name string) *net.UnixListener {
		ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: filepath.Join(dir, name), Net: "unixpacket"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		return ln
	}
	dln, sln := listen("dnstt.sock"), listen("slip.sock")
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.port = udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	ns := []string{"ns.example.net"}
	c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{fmt.Sprintf("127.0.0.1:%d", f.port)}, StatsSocket: f.stats,
		Zones: []DNSZone{{Zone: "t.example.com", Backend: "dnstt", NS: ns},
			{Zone: "s.example.com", Backend: "slip", NS: ns, Tag: "slipstream", AuthKeysFile: keys}}},
		Backends: map[string]BackendRef{"dnstt": {Socket: filepath.Join(dir, "dnstt.sock"), Mode: "packet", UID: os.Getuid()},
			"slip": {Socket: filepath.Join(dir, "slip.sock"), Mode: "packet", UID: os.Getuid()}}}
	if errs := c.validate(); len(errs) != 0 {
		t.Fatal(errs)
	}
	go RunFront(ctx, c, NewLogger("warn", io.Discard))
	if f.dnstt, err = dln.AcceptUnix(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.dnstt.Close() })
	go func() {
		if be, err := sln.AcceptUnix(); err == nil {
			<-ctx.Done()
			be.Close()
		}
	}()
	return f
}

// ednsQuery is a query of name and type with an OPT of 1232 (DO clear).
func ednsQuery(id uint16, name string, typ uint16) []byte {
	q := dnsQuery(id, name, typ)
	binary.BigEndian.PutUint16(q[10:12], 1)
	return append(q, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
}

// negativeSOA checks that a NODATA carries the zone's SOA in its authority
// section, TTL 60, its name the zone's, then the OPT.
func negativeSOA(t *testing.T, a []byte, zone string) {
	t.Helper()
	m, err := dns.MessageFromWireFormat(a)
	if err != nil {
		t.Fatalf("%v: %x", err, a)
	}
	if m.Rcode() != 0 || m.Flags&0x0400 == 0 || len(m.Answer) != 0 || len(m.Authority) != 1 || len(m.Additional) != 1 {
		t.Fatalf("not a NODATA with one authority record and an OPT: %+v", m)
	}
	soa := m.Authority[0]
	want, _ := dns.ParseName(zone)
	if soa.Type != 6 || soa.TTL != apexNegative || !bytes.EqualFold([]byte(soa.Name.String()), []byte(want.String())) {
		t.Fatalf("authority %+v", soa)
	}
	if m.Additional[0].Type != dns.RRTypeOPT {
		t.Fatalf("additional %+v", m.Additional)
	}
}

func (f *nodataFront) ask(q []byte) []byte {
	f.t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.port})
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	for range 30 {
		conn.Write(q)
		if a := readFor(conn, 200*time.Millisecond); a != nil {
			return a
		}
	}
	f.t.Fatal("no answer")
	return nil
}

// A NODATA below a zone's apex carries the zone's SOA in its authority
// section, as RFC 2308 §3 asks (review 2026-11-21 item 6): the front's own
// (a slipstream zone's query without a device's tag) and a backend's (dnstt
// answers another type than TXT so), as the apex's NODATA did. Before, a
// scanner told the tunnel's zone from an ordinary one by it, and resolvers
// did not keep the answer.
func TestNodataBelowApexHasSOA(t *testing.T) {
	f := newNodataFront(t)
	// The front's own: a slipstream zone's untagged query.
	negativeSOA(t, f.ask(ednsQuery(1, "abc.def.S.example.com", 1)), "s.example.com")

	// A backend's NODATA, as dnstt answers an A query.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := ednsQuery(2, "xyz.T.example.com", 1)
	buf := make([]byte, 70000)
	for i := 0; ; i++ {
		conn.Write(q)
		f.dnstt.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := f.dnstt.Read(buf)
		if err == nil {
			client, local, query, err := decodePacket(buf[:n])
			if err != nil {
				t.Fatal(err)
			}
			_, end, _ := queryName(query)
			nodata := append([]byte(nil), query[:end]...)
			nodata[2] |= 0x84
			nodata = append(nodata, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
			f.dnstt.Write(encodePacket(nil, client, local, nodata))
			break
		}
		if i == 30 {
			t.Fatal("dnstt got nothing")
		}
	}
	a := readFor(conn, 2*time.Second)
	if a == nil {
		t.Fatal("no answer")
	}
	negativeSOA(t, a, "t.example.com")
}

// The SOA's names read back as the apex's (MNAME, hostmaster.<zone>);
// none goes with the apex itself, an error, TC, an answer with records, or
// past the size.
func TestApexNegative(t *testing.T) {
	a := newApexZone("t.example.com", []string{"ns.example.net"}, 7)
	q := dnsQuery(5, "AbC.dEf.T.Example.COM", 1)
	_, end, _ := queryName(q)
	n := nodata(q, end)
	out := a.negative(n, end, 512)
	m, err := dns.MessageFromWireFormat(out)
	if err != nil || len(m.Authority) != 1 {
		t.Fatalf("%v %+v", err, m)
	}
	// RDATA: MNAME written out, RNAME a label and a pointer.
	rd := m.Authority[0].Data
	mname := wireName("ns.example.net")
	if !bytes.Equal(rd[:len(mname)], mname) || rd[len(mname)] != 10 || string(rd[len(mname)+1:len(mname)+11]) != "hostmaster" {
		t.Fatalf("RDATA %x", rd)
	}
	ptr := int(binary.BigEndian.Uint16(rd[len(mname)+11:]) & 0x3fff)
	if !sameNameFold(out[ptr:end-4], wireName("t.example.com")) || len(out) != len(n)+a.negativeN {
		t.Fatalf("RNAME points at %x; %d bytes, want %d", out[ptr:end-4], len(out), len(n)+a.negativeN)
	}
	if binary.BigEndian.Uint32(rd[len(rd)-4:]) != apexNegative || binary.BigEndian.Uint32(rd[len(rd)-20:]) != 7 {
		t.Fatalf("serial or minimum %x", rd[len(rd)-20:])
	}
	apex := dnsQuery(5, "t.example.com", 1)
	_, aend, _ := queryName(apex)
	refusedQ := refused(q, end)
	tc := bytes.Clone(n)
	tc[2] |= 0x02
	withAnswer := bytes.Clone(n)
	withAnswer[7] = 1
	other := dnsQuery(5, "abc.example.org", 1)
	_, oend, _ := queryName(other)
	for what, c := range map[string]struct {
		answer []byte
		end    int
		limit  int
	}{
		"the apex": {nodata(apex, aend), aend, 512}, "REFUSED": {refusedQ, end, 512}, "TC": {tc, end, 512},
		"an answer record": {withAnswer, end, 512}, "past the size": {n, end, len(n) + a.negativeN - 1},
		"another zone": {nodata(other, oend), oend, 512},
	} {
		if a.negative(c.answer, c.end, c.limit) != nil {
			t.Errorf("%s: an SOA", what)
		}
	}
	if a.negative(n, end, len(n)+a.negativeN) == nil {
		t.Error("an SOA that fits exactly left out")
	}
}
