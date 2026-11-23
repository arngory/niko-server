//go:build linux

package nikoserver

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// burstAnswers sends n queries made by q at once and counts the answers
// that come, and those of them with an authority record.
func burstAnswers(t *testing.T, port, n int, q func(id uint16) []byte) (answers, withAuthority int) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadBuffer(1 << 20)
	for i := range n {
		conn.Write(q(uint16(i)))
	}
	for {
		a := readFor(conn, 300*time.Millisecond)
		if a == nil {
			return
		}
		answers++
		if binary.BigEndian.Uint16(a[8:10]) != 0 {
			withAuthority++
		}
	}
}

// The front's own answers are rate-limited by the address they go to
// (review 2026-11-21 item 7, RRL): REFUSED and the apex's (about 2.5 times
// the query) past rrlBurst at once get none, so the node is no reflector
// for a forged source; a NODATA below the apex always goes, but without
// its SOA (some 60 bytes more) past the budget.
func TestFrontRRL(t *testing.T) {
	f := newNodataFront(t)
	f.ask(ednsQuery(1, "x.s.example.com", 1)) // the front is up: one NODATA with the SOA
	const n = 300
	if got, _ := burstAnswers(t, f.port, n, func(id uint16) []byte { return ednsQuery(id, "example.org", 1) }); got > rrlBurst+10 {
		t.Errorf("%d of %d REFUSED answered at once", got, n)
	}
	time.Sleep(time.Duration(float64(time.Second) * rrlBurst / rrlRate))
	if got, _ := burstAnswers(t, f.port, n, func(id uint16) []byte { return ednsQuery(id, "t.example.com", 6) }); got > rrlBurst+10 {
		t.Errorf("%d of %d apex SOA answered at once", got, n)
	}
	got, soa := burstAnswers(t, f.port, n, func(id uint16) []byte { return ednsQuery(id, "abc.s.example.com", 1) })
	if got != n || soa > rrlBurst+10 || soa < rrlBurst/2 {
		t.Errorf("NODATA: %d of %d answered, %d with the SOA", got, n, soa)
	}
	st, err := readFrontStats(f.stats)
	if err != nil {
		t.Fatal(err)
	}
	if st.RateLimited < 2*(n-rrlBurst-10) || st.NoSOA < n-rrlBurst-10 {
		t.Errorf("counted %d rate-limited, %d NODATA without the SOA", st.RateLimited, st.NoSOA)
	}
}

// The buckets go by the block an answer goes to, /24 or /48 (an IPv4
// mapped address as IPv4), and fill at their rates; the budget of the
// backends' answers is in bytes.
func TestFrontRRLBlocks(t *testing.T) {
	now := time.Unix(1767268800, 0)
	r := frontRRL{now: func() time.Time { return now }}
	count := func(f func() bool) int {
		n := 0
		for f() && n < 1<<20 {
			n++
		}
		return n
	}
	a, same, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.200"), netip.MustParseAddr("192.0.3.1")
	if n := count(func() bool { return r.own(a) }); n != rrlBurst {
		t.Fatalf("%d own answers at once", n)
	}
	if r.own(same) || !r.own(other) || !r.soa(a) {
		t.Fatal("blocks or buckets mixed")
	}
	now = now.Add(time.Second)
	if n := count(func() bool { return r.own(same) }); n != rrlRate {
		t.Fatalf("%d own answers a second later", n)
	}
	v6, v6same, v6other := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1:ffff::2"), netip.MustParseAddr("2001:db8:2::1")
	if n := count(func() bool { return r.data(v6, 1232) }); n != rrlDataBurst/1232 {
		t.Fatalf("%d answers of 1232 bytes at once", n)
	}
	if r.data(v6same, 1232) || !r.data(v6other, 1232) {
		t.Fatal("/48 blocks mixed")
	}
	now = now.Add(time.Second)
	if n := count(func() bool { return r.data(v6same, 1232) }); n < rrlDataRate/1232-1 || n > rrlDataRate/1232+1 {
		t.Fatalf("%d answers of 1232 bytes a second later", n)
	}
}

// TestFrontRRLDataRate: dns.rrl_data_kib sets a block's budget of the
// backends' answers; -1 lifts it.
func TestFrontRRLDataRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.7")
	r := frontRRL{dataRate: 1024, now: clock} // 1 KiB/s, 2 KiB at once
	if !r.data(addr, 2048) || r.data(addr, 1) {
		t.Fatal("a budget of 1 KiB/s does not hold 2 KiB at once and no more")
	}
	off := frontRRL{dataRate: -1024, now: clock}
	for range 100 {
		if !off.data(addr, 1<<20) {
			t.Fatal("rrl_data_kib -1 limits")
		}
	}
	def := frontRRL{now: clock}
	if !def.data(addr, rrlDataBurst) || def.data(addr, 1) {
		t.Fatal("the default budget is not rrlDataBurst at once")
	}
}
