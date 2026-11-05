package dnsttserver

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"strings"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func TestAuth(t *testing.T) {
	var alice, bob [32]byte
	rand.Read(alice[:])
	rand.Read(bob[:])
	now := time.Unix(1_800_000_000, 0)
	a := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }}
	keys := "# devices\nd-alice " + hex.EncodeToString(alice[:]) + "\n\nd-bob " + hex.EncodeToString(bob[:]) + "\n"
	if err := a.SetKeys([]byte(keys)); err != nil {
		t.Fatal(err)
	}
	body := append([]byte("CLIENTID"), []byte("\xe0padding and packets")...)
	signed := func(key *[32]byte, at time.Time) []byte {
		tag := Tag(key, EpochOf(at), body)
		return append(tag[:], body...)
	}

	// In order: a query whose tag failed is remembered, so a copy of
	// alice's tag with the body tampered with comes after alice's own.
	for _, c := range []struct {
		name    string
		payload []byte
		mode    AuthMode
		ok      bool
		rest    []byte
	}{
		{"alice", signed(&alice, now), AuthRequired, true, body},
		{"bob, the epoch before", signed(&bob, now.Add(-AuthEpoch)), AuthRequired, true, body},
		{"alice, the epoch after", signed(&alice, now.Add(AuthEpoch)), AuthRequired, true, body},
		{"alice, two epochs late", signed(&alice, now.Add(-2*AuthEpoch)), AuthRequired, false, nil},
		{"untagged, required", body, AuthRequired, false, nil},
		{"untagged, optional", body, AuthOptional, true, body},
		{"tagged, optional", signed(&bob, now), AuthOptional, true, body},
		{"untagged, off", body, AuthOff, true, body},
		{"short", []byte("short"), AuthRequired, false, nil},
		{"tampered after the tag", append(signed(&alice, now)[:len(body)+AuthTagLen-1], 'X'), AuthRequired, false, nil},
	} {
		name := c.name
		a.Mode = c.mode
		rest, ok := a.Check(c.payload)
		if ok != c.ok || !bytes.Equal(rest, c.rest) {
			t.Errorf("%s: ok %v rest %q, want %v %q", name, ok, rest, c.ok, c.rest)
		}
	}

	// A device that is gone: its tags stop, also for a session cached on it.
	a.Mode = AuthRequired
	if err := a.SetKeys([]byte("d-bob " + hex.EncodeToString(bob[:]) + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(signed(&alice, now)); ok {
		t.Fatal("a removed key still signs")
	}
	if _, ok := a.Check(signed(&bob, now)); !ok {
		t.Fatal("a kept key no longer signs")
	}
	if a.Refused.Load() == 0 || a.Valid.Load() == 0 || a.Untagged.Load() == 0 {
		t.Fatalf("counters %d %d %d", a.Valid.Load(), a.Untagged.Load(), a.Refused.Load())
	}

	for _, bad := range []string{"d-x 1234", "d-x zz" + hex.EncodeToString(bob[:])[2:], "only-one-field"} {
		if err := a.SetKeys([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// No keys at all: nothing passes in required mode.
	a.SetKeys(nil)
	if _, ok := a.Check(signed(&bob, now)); ok {
		t.Fatal("a tag passed without keys")
	}
	for _, s := range []string{"", "off", "optional", "required"} {
		if _, err := ParseAuthMode(s); err != nil {
			t.Error(s, err)
		}
	}
	if _, err := ParseAuthMode("strict"); err == nil {
		t.Error("strict accepted")
	}
}

// The real server on UDP: in required mode a query without a valid tag is
// answered NXDOMAIN, as by an empty zone; a tagged one is the tunnel's
// (NOERROR, authoritative).
func TestAuthServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := hex.DecodeString(priv)
	var dev [32]byte
	rand.Read(dev[:])
	auth := &Auth{Mode: AuthRequired}
	if err := auth.SetKeys([]byte("d1 " + hex.EncodeToString(dev[:]))); err != nil {
		t.Fatal(err)
	}
	go RunAuth(privKey, "t.example.com", pc, func(time.Duration) (net.Conn, error) { return nil, errors.New("no upstream") }, auth)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The rcode and the number of answer records.
	var askSized func(payload []byte, edns uint16) (uint16, int)
	ask := func(payload []byte) (uint16, int) { return askSized(payload, 4096) }
	askSized = func(payload []byte, edns uint16) (uint16, int) {
		t.Helper()
		enc := []byte(strings.ToLower(base32Encoding.EncodeToString(payload)))
		var labels [][]byte
		for len(enc) > 0 {
			n := min(len(enc), 63)
			labels, enc = append(labels, enc[:n]), enc[n:]
		}
		zone, _ := dns.ParseName("t.example.com")
		name, err := dns.NewName(append(labels, zone...))
		if err != nil {
			t.Fatal(err)
		}
		q := dns.Message{ID: 7, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
			Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: edns, TTL: 0, Data: []byte{}}}}
		b, err := q.WireFormat()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		r, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return r.Rcode(), len(r.Answer)
	}
	// Without a valid tag: NOERROR with no record (neko), as for every name
	// and type the tunnel does not take; with one, the tunnel's TXT.
	body := append([]byte("CLIENTID"), 0xe0) // a ClientID, no packets
	if rc, an := ask(body); rc != dns.RcodeNoError || an != 0 {
		t.Fatalf("untagged query: rcode %d, %d answers, want NODATA", rc, an)
	}
	tag := Tag(&dev, EpochOf(time.Now()), body)
	if rc, an := ask(append(tag[:], body...)); rc != dns.RcodeNoError || an != 1 {
		t.Fatalf("tagged query: rcode %d, %d answers, want the tunnel's TXT", rc, an)
	}
	var other [32]byte
	tag = Tag(&other, EpochOf(time.Now()), body)
	if rc, an := ask(append(tag[:], body...)); rc != dns.RcodeNoError || an != 0 {
		t.Fatalf("query tagged by another key: rcode %d, %d answers, want NODATA", rc, an)
	}
	// A probe with a small EDNS size learns nothing either: NODATA, not
	// dnstt's FORMERR for a payload size under its minimum.
	if rc, an := askSized(body, 512); rc != dns.RcodeNoError || an != 0 {
		t.Fatalf("untagged query with EDNS 512: rcode %d, %d answers, want NODATA", rc, an)
	}
	// A tagged one with EDNS 512 is served (neko): its session gets a
	// smaller MTU, where dnstt answered FORMERR.
	tag = Tag(&dev, EpochOf(time.Now()), body)
	if rc, an := askSized(append(tag[:], body...), 512); rc != dns.RcodeNoError || an != 1 {
		t.Fatalf("tagged query with EDNS 512: rcode %d, %d answers, want the tunnel's TXT", rc, an)
	}
	// Bad base32 and a payload too short for a ClientID: NODATA too.
	for _, label := range []string{"!!", "aa"} {
		n, _ := dns.ParseName(label + ".t.example.com")
		q := dns.Message{ID: 8, Flags: 0x0100, Question: []dns.Question{{Name: n, Type: dns.RRTypeTXT, Class: dns.ClassIN}}}
		b, _ := q.WireFormat()
		c.Write(b)
		buf := make([]byte, 4096)
		k, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := dns.MessageFromWireFormat(buf[:k]); r.Rcode() != dns.RcodeNoError || len(r.Answer) != 0 {
			t.Fatalf("%s: rcode %d, %d answers, want NODATA", label, r.Rcode(), len(r.Answer))
		}
	}
}

// Another type than TXT gets NODATA, not NXDOMAIN (neko): a resolver
// minimising QNAMEs asks for the names above with A or NS, and one that
// takes NXDOMAIN as "nothing below" (RFC 8020) gave up on the tunnel.
func TestNoDataForOtherTypes(t *testing.T) {
	zone, _ := dns.ParseName("t.example.com")
	for _, name := range []string{"t.example.com", "aaaa.t.example.com", "x.y.t.example.com"} {
		n, _ := dns.ParseName(name)
		for _, qtype := range []uint16{1 /* A */, 2 /* NS */, 28 /* AAAA */} {
			q := &dns.Message{ID: 1, Flags: 0x0100, Question: []dns.Question{{Name: n, Type: qtype, Class: dns.ClassIN}},
				Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 1232}}}
			resp, payload := responseFor(q, zone, nil)
			if resp == nil || resp.Rcode() != dns.RcodeNoError || resp.Flags&0x0400 == 0 || payload != nil || carriesData(resp) {
				t.Errorf("%s type %d: %+v", name, qtype, resp)
			}
		}
	}
	// TXT still carries data.
	n, _ := dns.ParseName("aaaaaaaaaaaaaaaa.t.example.com")
	q := &dns.Message{ID: 1, Flags: 0x0100, Question: []dns.Question{{Name: n, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 1232}}}
	if resp, _ := responseFor(q, zone, nil); resp == nil || !carriesData(resp) {
		t.Errorf("TXT: %+v", resp)
	}
}

// Answers fit the requester: the most data for EDNS 512 leaves a usable
// MTU, and a client's smallest size sets its session's MTU.
func TestRequesterSizes(t *testing.T) {
	if e := encodedPayload(512); e-2 < 80 || e >= encodedPayload(maxUDPPayload) {
		t.Fatalf("encoded payload for 512: %d (for %d: %d)", e, maxUDPPayload, encodedPayload(maxUDPPayload))
	}
	if encodedPayload(100) != encodedPayload(512) || encodedPayload(4096) != encodedPayload(maxUDPPayload) {
		t.Fatal("sizes outside 512..maxUDPPayload not clamped")
	}
	var sizes clientSizes
	id := turbotunnel.ClientID{1}
	sizes.note(id, 1232)
	sizes.note(id, 512)
	sizes.note(id, 1232)
	mtu := encodedPayload(maxUDPPayload) - 2
	if got := sessionMTU(mtu, &sizes, id); got != encodedPayload(512)-2 {
		t.Fatalf("session MTU %d after a 512 requester, want %d", got, encodedPayload(512)-2)
	}
	if got := sessionMTU(mtu, &sizes, turbotunnel.ClientID{2}); got != mtu {
		t.Fatalf("an unknown client: %d, want %d", got, mtu)
	}
	// Two generations: a client heard from lately survives a flood of new
	// ones; nobody is refused for want of room.
	for i := range 2*clientSizesMax - 1 {
		var other turbotunnel.ClientID
		binary.BigEndian.PutUint64(other[:], uint64(i)+100)
		sizes.note(other, 1232)
		if i == clientSizesMax/2 {
			sizes.note(id, 1232) // still heard from
		}
	}
	if got := sizes.get(id); got != 512 {
		t.Fatalf("a recent client after a flood: %d, want 512", got)
	}
	if n := len(sizes.cur) + len(sizes.prev); n > 2*clientSizesMax {
		t.Fatalf("%d clients kept", n)
	}
}

// A live session gets a smaller MTU when a smaller requester comes after
// it was accepted (a client that moves to another resolver).
func TestSessionMTULowered(t *testing.T) {
	ln, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := kcp.DialWithOptions(ln.Addr().String(), nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var sizes clientSizes
	id := turbotunnel.ClientID{9}
	full := encodedPayload(maxUDPPayload) - 2
	sizes.note(id, 1232)
	sizes.track(id, conn, full)
	sizes.note(id, 512)
	if s := sizes.sessions[id]; s == nil || s.mtu != encodedPayload(512)-2 {
		t.Fatalf("live session MTU %+v, want %d", s, encodedPayload(512)-2)
	}
	sizes.untrack(id, conn)
	if sizes.sessions[id] != nil {
		t.Fatal("session still tracked")
	}
}

// Full scans of the keys have a budget in HMACs: garbage beyond it is
// refused unread, while sessions already known go on; the budget refills.
func TestAuthScanBudget(t *testing.T) {
	var dev [32]byte
	rand.Read(dev[:])
	now := time.Unix(1_800_000_000, 0)
	// One device: 3 HMACs a scan; 6 a second (two scans at least), 12 at once.
	a := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }, ScanHMACs: 3}
	if err := a.SetKeys([]byte("d1 " + hex.EncodeToString(dev[:]))); err != nil {
		t.Fatal(err)
	}
	body := append([]byte("CLIENTID"), 0xe0)
	tag := Tag(&dev, EpochOf(now), body)
	good := append(tag[:], body...)
	if _, ok := a.Check(good); !ok { // a scan: the session is known from now on
		t.Fatal("first tagged query refused")
	}
	garbage := func(i byte) []byte {
		return append([]byte{i, 1, 2, 3, 4, 5, 6, 7}, "OTHERCID\xe0"...)
	}
	for i := range byte(10) {
		a.Check(garbage(i))
	}
	// The first query cost 1 HMAC (the key's tag of this epoch): 11 left,
	// enough for four scans of garbage before the budget is spent.
	if th := a.Throttled.Load(); th != 6 {
		t.Fatalf("throttled %d, want 6", th)
	}
	// The known session needs no scan, and a reload of the same keys keeps it.
	a.SetKeys([]byte("d1 " + hex.EncodeToString(dev[:])))
	if _, ok := a.Check(good); !ok {
		t.Fatal("known session refused over the budget")
	}
	now = now.Add(2 * time.Second)
	before := a.Throttled.Load()
	a.Check(garbage(99))
	if a.Throttled.Load() != before {
		t.Fatal("the budget did not refill")
	}
}

// An old client's untagged ClientID is remembered after a scan. While it is
// young it is scanned again only above half the budget; then never: a flood
// of untagged queries (old clients after the switch to required) leaves
// room for new sessions and costs nothing in the long run. In optional mode
// it is taken, and stays known while the client asks.
func TestAuthUnknownHeads(t *testing.T) {
	var dev [32]byte
	rand.Read(dev[:])
	now := time.Unix(1_800_000_000, 0)
	keys := []byte("d1 " + hex.EncodeToString(dev[:]))
	old := append([]byte("OLDCLIEN"), "\xe0 packets of an old client"...)

	r := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }, ScanHMACs: 3}
	r.SetKeys(keys)
	for range 100 {
		if _, ok := r.Check(old); ok {
			t.Fatal("untagged query taken in required mode")
		}
	}
	body := append([]byte("NEWCLIEN"), 0xe0)
	tag := Tag(&dev, EpochOf(now), body)
	if _, ok := r.Check(append(tag[:], body...)); !ok {
		t.Fatalf("a new session after an untagged flood: throttled %d", r.Throttled.Load())
	}
	// Past the rescan window the old client is free, even with a full
	// budget.
	now = now.Add(time.Hour)
	r.Check(old) // refills
	before := r.tokens
	for range 100 {
		r.Check(old)
	}
	if r.tokens != before {
		t.Fatalf("an old client past the window cost %v HMACs", before-r.tokens)
	}

	o := &Auth{Mode: AuthOptional, Now: func() time.Time { return now }, ScanHMACs: 0.001}
	o.SetKeys(keys)
	if rest, ok := o.Check(old); !ok || !bytes.Equal(rest, old) {
		t.Fatal("untagged query refused in optional mode")
	}
	// Short payloads cost nothing and are not remembered: they cannot push
	// the old client out. The old client keeps asking through it all.
	for i := range 3 * authCacheMax {
		var short [12]byte
		binary.BigEndian.PutUint64(short[:], uint64(i))
		o.Check(short[:])
		if i%1000 == 0 {
			if _, ok := o.Check(old); !ok {
				t.Fatalf("old client refused after %d short queries", i)
			}
		}
	}
	if len(o.unknown)+len(o.unknownPrev) != 1 {
		t.Fatalf("unknown %d+%d", len(o.unknown), len(o.unknownPrev))
	}
	// Generations turn over while the old client asks: it moves along.
	for i := range 3 * authCacheMax {
		o.remember([8]byte{byte(i), byte(i >> 8), byte(i >> 16), 1})
		if _, ok := o.known([8]byte(old[:8]), now); i%1000 == 0 && !ok {
			t.Fatalf("old client forgotten after %d others", i)
		}
	}
}

// A device id with two keys (one being replaced): a session on either is
// checked on the cached path, without a scan.
func TestAuthTwoKeysOneID(t *testing.T) {
	var k1, k2 [32]byte
	rand.Read(k1[:])
	rand.Read(k2[:])
	now := time.Unix(1_800_000_000, 0)
	a := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }, ScanHMACs: 6}
	a.SetKeys([]byte("d1 " + hex.EncodeToString(k1[:]) + "\nd1 " + hex.EncodeToString(k2[:])))
	body := append([]byte("SESSION1"), 0xe0)
	signed := func(k *[32]byte) []byte {
		tag := Tag(k, EpochOf(now), body)
		return append(tag[:], body...)
	}
	if _, ok := a.Check(signed(&k1)); !ok {
		t.Fatal("first key refused")
	}
	for range 20 {
		if _, ok := a.Check(signed(&k1)); !ok {
			t.Fatal("first key refused on the cached path")
		}
	}
	if a.Throttled.Load() != 0 {
		t.Fatalf("throttled %d: the cached path scanned", a.Throttled.Load())
	}
}

// What a garbage query costs with 100 devices: 3 HMACs a device, no
// allocation per HMAC.
func BenchmarkAuthGarbage(b *testing.B) {
	var keys strings.Builder
	for i := range 100 {
		var k [32]byte
		rand.Read(k[:])
		keys.WriteString("d" + strings.Repeat("x", i%7) + hex.EncodeToString(k[:4]) + " " + hex.EncodeToString(k[:]) + "\n")
	}
	a := &Auth{Mode: AuthRequired, ScanHMACs: 1e12}
	if err := a.SetKeys([]byte(keys.String())); err != nil {
		b.Fatal(err)
	}
	q := make([]byte, 120)
	rand.Read(q)
	b.ReportAllocs()
	var n uint64
	for b.Loop() {
		n++ // a new head every time: a full scan each
		binary.BigEndian.PutUint64(q, n)
		a.Check(q)
	}
}

// The client's vector (Niko, T2): K for device key 11 x 32, node 33 x 16,
// service 3 (dnsauth-v1 §2), the payload 00..17 at 1767268800.
func TestTagVector(t *testing.T) {
	k, _ := hex.DecodeString("2f9bd5e6fc2ef3f56206998eee87f2d4b798a66c3c846ef34eff2f2647599bd5")
	var key [32]byte
	copy(key[:], k)
	payload := make([]byte, 0x18)
	for i := range payload {
		payload[i] = byte(i)
	}
	e := EpochOf(time.Unix(1767268800, 0))
	if tag := Tag(&key, e, payload); e != 2945448 || hex.EncodeToString(tag[:]) != "67e1435d89134138" {
		t.Fatalf("epoch %d tag %x", e, tag)
	}
}

// Someone who sees a query on the way copies its tag into garbage: the head
// is remembered, but the session's own queries, the resolver's retransmit
// included, still pass; so does a new session's first query while the node
// has budget to spare.
func TestAuthCopiedTag(t *testing.T) {
	var dev [32]byte
	rand.Read(dev[:])
	now := time.Unix(1_800_000_000, 0)
	for _, mode := range []AuthMode{AuthRequired, AuthOptional} {
		a := &Auth{Mode: mode, Now: func() time.Time { return now }}
		a.SetKeys([]byte("d1 " + hex.EncodeToString(dev[:])))
		query := func(cid string, n byte) []byte {
			body := append([]byte(cid), 0xe0, n)
			tag := Tag(&dev, EpochOf(now), body)
			return append(tag[:], body...)
		}
		poison := func(q []byte) { a.Check(append(bytes.Clone(q[:AuthTagLen]), "GARBAGE!"...)) }

		// An established session.
		if _, ok := a.Check(query("SESSION1", 0)); !ok {
			t.Fatal("first query refused")
		}
		q := query("SESSION1", 1)
		if rest, ok := a.Check(q); !ok || !bytes.Equal(rest, q[AuthTagLen:]) {
			t.Fatalf("mode %d: query refused", mode)
		}
		poison(q)
		if rest, ok := a.Check(q); !ok || !bytes.Equal(rest, q[AuthTagLen:]) {
			t.Fatalf("mode %d: the retransmit after a copied tag: ok %v rest %q", mode, ok, rest)
		}
		// A new session's first query, copied before it arrives.
		n := query("SESSION2", 0)
		poison(n)
		if rest, ok := a.Check(n); !ok || !bytes.Equal(rest, n[AuthTagLen:]) {
			t.Fatalf("mode %d: a new session after a copied tag: ok %v rest %q", mode, ok, rest)
		}
	}
}

// A budget set below two full scans (auth_scan_hmacs < 6 x devices) is
// raised to two, so the genuine query right behind a copied tag is scanned.
func TestAuthSmallBudgetCopiedTag(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var keys strings.Builder
	var dev [32]byte
	for i := range 50 {
		rand.Read(dev[:])
		fmt.Fprintf(&keys, "d%d %s\n", i, hex.EncodeToString(dev[:]))
	}
	a := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }, ScanHMACs: 100} // 150 a scan
	a.SetKeys([]byte(keys.String()))
	body := append([]byte("SESSION1"), 0xe0)
	tag := Tag(&dev, EpochOf(now), body)
	q := append(tag[:], body...)
	a.Check(append(bytes.Clone(q[:AuthTagLen]), "GARBAGE!"...))
	now = now.Add(10 * time.Millisecond) // the genuine query right behind
	if _, ok := a.Check(q); !ok {
		t.Fatal("the genuine query after a copied tag")
	}
}

// capture is a PacketConn that keeps what is written to it.
type capture struct {
	net.PacketConn
	out chan []byte
}

func (c capture) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.out <- append([]byte(nil), p...)
	return len(p), nil
}

// A packet too large for every answer to this requester (a session older
// than its smaller resolver) waits in the stash; the answer takes the
// smaller packets behind it, ACKs among them, instead of going out empty.
func TestSendLoopOversizeWaits(t *testing.T) {
	tt := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, time.Minute)
	defer tt.Close()
	id := turbotunnel.ClientID{7}
	big := bytes.Repeat([]byte{1}, encodedPayload(maxUDPPayload)-2)
	small := []byte("ack")
	if !tt.Stash(big, id) {
		t.Fatal("stash")
	}
	tt.WriteTo(small, id)
	out := make(chan []byte, 4)
	ch := make(chan *record, 1)
	go sendLoop(capture{out: out}, tt, ch)
	zone, _ := dns.ParseName("x.t.example.com")
	ch <- &record{Resp: &dns.Message{ID: 1, Flags: 0x8400, Question: []dns.Question{{Name: zone, Type: dns.RRTypeTXT, Class: dns.ClassIN}}},
		Addr: turbotunnel.DummyAddr{}, ClientID: id, Size: 512}
	var wire []byte
	select {
	case wire = <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if len(wire) > 512 {
		t.Fatalf("answer of %d bytes to a 512 requester", len(wire))
	}
	m, _ := dns.MessageFromWireFormat(wire)
	data, _ := dns.DecodeRDataTXT(m.Answer[0].Data)
	if !bytes.Equal(data, append([]byte{0, 3}, small...)) {
		t.Fatalf("answer data %q, want the small packet", data)
	}
	select {
	case p := <-tt.Unstash(id):
		if !bytes.Equal(p, big) {
			t.Fatal("another packet stashed")
		}
	default:
		t.Fatal("the large packet is gone, not stashed")
	}
	close(ch)
}
