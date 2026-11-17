package nikoserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ingest is serve's decision for a datagram without the sockets: a pinned
// flow's backend, or a classified one, pinned.
func ingest(f *udpFront, key flowKey, d []byte, now time.Time) *backendLink {
	if link := f.pinned(key, d, now); link != nil {
		return link
	}
	if link, packets := f.classify(key, d, now); link != nil {
		sent := 0
		for _, p := range packets {
			sent += len(p)
		}
		f.pin(key, link, d, sent, now)
		return link
	}
	return nil
}

// serverInitial is the start of a server's Initial to a client: its
// Source Connection ID is scid.
func serverInitial(dcid, scid []byte) []byte {
	d := []byte{0xc0, 0, 0, 0, 0, byte(len(dcid))}
	binary.BigEndian.PutUint32(d[1:5], quicV1)
	d = append(d, dcid...)
	d = append(d, byte(len(scid)))
	d = append(d, scid...)
	return append(d, make([]byte, 1200)...)
}

func checkFlows(t *testing.T, f *udpFront) {
	t.Helper()
	if len(f.flows) > f.maxFlows {
		t.Fatalf("%d flows, over %d", len(f.flows), f.maxFlows)
	}
	n := 0
	for k, fl := range f.flows {
		if fl.key != k {
			t.Fatalf("flow %v keyed %v", k, fl.key)
		}
		if fl.listed {
			n++
		}
	}
	// The list, both ways: every flow on it is in the table and listed.
	walked := 0
	var prev *udpFlow
	for fl := f.unconfirmed.head; fl != nil; fl = fl.next {
		if fl.prev != prev || !fl.listed || f.flows[fl.key] != fl {
			t.Fatalf("list broken at %v", fl.key)
		}
		prev, walked = fl, walked+1
	}
	if prev != f.unconfirmed.tail || walked != f.unconfirmed.n || n != walked {
		t.Fatalf("%d flows unconfirmed, %d listed, %d walked", n, f.unconfirmed.n, walked)
	}
	// The counts by source: confirmed flows by /48, budgets' flows by /64.
	confirmed, flows := map[netip.Prefix]int32{}, map[uint64]int32{}
	for k, fl := range f.flows {
		if !fl.listed {
			confirmed[sourcePrefix(k.client.Addr(), 48)]++
		}
		p := sourceKey(k.client.Addr())
		flows[p]++
		if f.budgets[p] != fl.budget {
			t.Fatalf("flow %v: not its source's budget", k)
		}
	}
	if len(confirmed) != len(f.confirmed) || len(flows) != len(f.budgets) {
		t.Fatalf("%d sources confirmed, counted %d; %d budgets, kept %d", len(confirmed), len(f.confirmed), len(flows), len(f.budgets))
	}
	for p, n := range confirmed {
		if f.confirmed[p] != n {
			t.Fatalf("%v: %d confirmed, counted %d", p, n, f.confirmed[p])
		}
	}
	for p, n := range flows {
		if f.budgets[p].flows != n {
			t.Fatalf("%v: %d flows, its budget counts %d", p, n, f.budgets[p].flows)
		}
	}
}

// TestUDPFrontConfirmedFlows: with the table of pinned flows full of
// flows pinned by whole Initials from spoofed addresses, a real client's
// flow is pinned in the oldest one's place, and once the client sends to
// the connection ID the backend's answer named, no flood pushes it out.
// A datagram to another ID confirms nothing; with every flow confirmed a
// new one is routed but not pinned; idle flows go, listed or not.
func TestUDPFrontConfirmedFlows(t *testing.T) {
	flight := firstFlights(t, "n.example.com", 1)[0]
	front, want := desyncFront(t)
	front.maxFlows = 64
	now := time.Now()
	flood := func(from, n int) {
		for i := range n {
			k := flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte((from + i) >> 8), byte(from + i)}), 40000),
				local: netip.MustParseAddrPort("127.0.0.1:443")}
			for _, d := range flight {
				ingest(front, k, d, now)
			}
		}
		checkFlows(t, front)
	}
	flood(0, front.maxFlows)
	if len(front.flows) != front.maxFlows || front.unconfirmed.n != front.maxFlows {
		t.Fatalf("%d flows, %d unconfirmed", len(front.flows), front.unconfirmed.n)
	}
	client := flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	var got *backendLink
	for _, d := range flight {
		got = ingest(front, client, d, now)
	}
	if got != want || front.flows[client] == nil {
		t.Fatal("the client's flow was not pinned in a full table")
	}
	// Before the answer: a flood flow takes the oldest place, not the
	// client's, the newest.
	flood(front.maxFlows, 1)
	if front.flows[client] == nil {
		t.Fatal("one flood flow pushed out the client's newest flow")
	}
	// The backend answers; the client sends elsewhere, then to its ID.
	var scid [cidLen]byte
	copy(scid[:], "serverid")
	front.answered(nil, client, serverInitial([]byte{1, 2, 3, 4, 5, 6, 7, 8}, scid[:]), now)
	var other [cidLen]byte
	copy(other[:], "notmine!")
	ingest(front, client, shortPacket(other, 1200), now)
	if !front.flows[client].listed {
		t.Fatal("a datagram to another ID confirmed the flow")
	}
	ingest(front, client, shortPacket(scid, 1200), now)
	if front.flows[client].listed {
		t.Fatal("the client's datagram to the server's ID did not confirm the flow")
	}
	checkFlows(t, front)
	flood(2*front.maxFlows, 4*front.maxFlows)
	if front.flows[client] == nil {
		t.Fatal("the flood pushed out a confirmed flow")
	}
	// Every flow confirmed: a new one is routed, not pinned.
	for k, fl := range front.flows {
		if fl.listed {
			front.answered(nil, k, serverInitial(nil, scid[:]), now)
			ingest(front, k, shortPacket(scid, 1200), now)
		}
	}
	checkFlows(t, front)
	if front.unconfirmed.n != 0 {
		t.Fatalf("%d flows still unconfirmed", front.unconfirmed.n)
	}
	late := flowKey{client: netip.MustParseAddrPort("192.0.2.11:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	for _, d := range flight {
		got = ingest(front, late, d, now)
	}
	if got != want || front.flows[late] != nil {
		t.Fatalf("with every flow confirmed: routed %v, pinned %v", got == want, front.flows[late] != nil)
	}
	front.expire(now.Add(front.idle + time.Second))
	if len(front.flows) != 0 || front.unconfirmed.n != 0 {
		t.Fatalf("after idle: %d flows, %d listed", len(front.flows), front.unconfirmed.n)
	}
}

// TestUDPFrontConfirmedSalamander: a flow under salamander is confirmed
// the same way, its answer and its datagram opened with its route's
// password; a plain datagram to the same ID confirms nothing. A version
// negotiation is not the answer whose ID counts.
func TestUDPFrontConfirmedSalamander(t *testing.T) {
	front, password := cidFront(t, true)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.20:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	initial := serverInitial(nil, nil) // any long header of QUIC v1, typed Initial
	initial[0] = 0xc0
	if link := ingest(front, key, obfuscate(password, initial), now); link == nil || link.name != "s" {
		t.Fatalf("the salamander Initial went to %v", link)
	}
	fl := front.flows[key]
	if fl == nil || string(fl.password()) != password {
		t.Fatal("the flow does not know its password")
	}
	vn := serverInitial(nil, []byte("vnscid12"))
	binary.BigEndian.PutUint32(vn[1:5], 0)
	front.answered(nil, key, obfuscate(password, vn), now)
	if fl.answered {
		t.Fatal("a version negotiation was taken for the answer")
	}
	var scid [cidLen]byte
	copy(scid[:], "obfsid!!")
	front.answered(nil, key, obfuscate(password, serverInitial(nil, scid[:])), now)
	if fl.serverLen != cidLen || string(fl.serverCID[:cidLen]) != string(scid[:]) {
		t.Fatalf("server ID %x", fl.serverCID[:fl.serverLen])
	}
	ingest(front, key, shortPacket(scid, 1200), now)
	if !fl.listed {
		t.Fatal("a plain datagram confirmed a salamander flow")
	}
	ingest(front, key, obfuscate(password, shortPacket(scid, 1200)), now)
	if fl.listed {
		t.Fatal("the client's datagram under salamander did not confirm the flow")
	}
	checkFlows(t, front)
}

// TestUDPFrontSalamanderInitialSize: under salamander, an Initial of a
// datagram under 1208 bytes (its salt and 1200, RFC 9000 §14.1) is
// dropped, as a plain one under 1200: else a 15-byte datagram pins a flow.
func TestUDPFrontSalamanderInitialSize(t *testing.T) {
	front, password := cidFront(t, true)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.22:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	initial := serverInitial(nil, nil)[:minInitialDatagram]
	if link, _ := front.classify(key, obfuscate(password, initial[:minInitialDatagram-1]), now); link != nil {
		t.Fatalf("a salamander Initial of %d bytes went to %s", salamanderSalt+minInitialDatagram-1, link.name)
	}
	if link, _ := front.classify(key, obfuscate(password, initial[:7]), now); link != nil {
		t.Fatalf("a salamander Initial of %d bytes went to %s", salamanderSalt+7, link.name)
	}
	if link, _ := front.classify(key, obfuscate(password, initial), now); link == nil || link.name != "s" {
		t.Fatalf("a salamander Initial of %d bytes went to %v", salamanderSalt+minInitialDatagram, link)
	}
}

// TestUDPFrontConfirmedLabel: an ID with the flow's backend's label does
// not confirm it: anyone gets one, in the server's answer to an Initial of
// their own.
func TestUDPFrontConfirmedLabel(t *testing.T) {
	front, _ := cidFront(t, true)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.30:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	front.pin(key, front.links["a"], shortPacket(cidID(cidSecret, 1, 1), 1200), 1200, now)
	fl := front.flows[key]
	for i := range 64 {
		front.pinned(key, handshakePacket(cidID(cidSecret, 1, uint64(7+i)), 1200), now)
	}
	if !fl.listed {
		t.Fatal("packets to IDs with the flow's label confirmed it")
	}
	checkFlows(t, front)
}

// TestUDPFrontFlowDetails: the first answer's ID is the one that counts,
// not a later one's; a long header whose ID length differs, or a packet
// without QUIC's fixed bit, confirms nothing; a key is pinned once; a flow
// in use is not the oldest; listed flows idle go from the list.
func TestUDPFrontFlowDetails(t *testing.T) {
	front, link := desyncFront(t)
	front.maxFlows = 4
	now := time.Now()
	key := func(i int) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 40000), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	front.pin(key(1), link, nil, 0, now)
	front.pin(key(1), link, nil, 0, now)
	if len(front.flows) != 1 || front.unconfirmed.n != 1 {
		t.Fatal("a key pinned twice")
	}
	fl := front.flows[key(1)]
	first, later := []byte("firstid!"), []byte("laterid!")
	front.answered(nil, key(1), serverInitial(nil, first), now)
	front.answered(nil, key(1), serverInitial(nil, later), now)
	var id [cidLen]byte
	copy(id[:], later)
	front.pinned(key(1), shortPacket(id, 1200), now)
	if !fl.listed {
		t.Fatal("a later answer's ID confirmed the flow")
	}
	// A long header with an ID of 9 bytes that starts with the first ID.
	long := handshakePacket(id, 1200)
	long[5] = 9
	copy(long[6:], first)
	front.pinned(key(1), long, now)
	// A packet without the fixed bit that carries the first ID.
	copy(id[:], first)
	nofixed := shortPacket(id, 1200)
	nofixed[0] &= 0x3f
	front.pinned(key(1), nofixed, now)
	if !fl.listed {
		t.Fatal("a packet to another ID length, or without the fixed bit, confirmed the flow")
	}
	front.pinned(key(1), shortPacket(id, 1200), now)
	if fl.listed {
		t.Fatal("the first answer's ID did not confirm the flow")
	}
	front.unpin(key(1))
	front.pin(key(1), link, nil, 0, now)
	// In use, the oldest flow is not the one to go: 1 is used last.
	for i := 2; i <= 4; i++ {
		front.pin(key(i), link, nil, 0, now)
	}
	front.pinned(key(1), nofixed, now)
	front.pin(key(5), link, nil, 0, now)
	if front.flows[key(1)] == nil || front.flows[key(2)] != nil {
		t.Fatal("a flow in use went before an idle one")
	}
	checkFlows(t, front)
	// Idle, listed: gone from the table and the list.
	front.expire(now.Add(front.idle + time.Second))
	if len(front.flows) != 0 || front.unconfirmed.n != 0 || front.unconfirmed.head != nil {
		t.Fatalf("after idle: %d flows, %d listed", len(front.flows), front.unconfirmed.n)
	}
}

// TestUDPFrontServerCIDChecks: the ID is checked for maxServerCIDChecks
// datagrams after the answer, those to the ID of the client's Initial
// (sent before the answer came) not counted; an answer that names that ID
// as its own, as a refusal does, names nothing to confirm by.
func TestUDPFrontServerCIDChecks(t *testing.T) {
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.40:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	var client, server [cidLen]byte
	copy(client[:], "clientid")
	copy(server[:], "serverid")
	other := server
	other[0] ^= 1
	for _, others := range []int{maxServerCIDChecks - 1, maxServerCIDChecks} {
		front, link := desyncFront(t)
		front.pin(key, link, handshakePacket(client, 1200), 1200, now)
		fl := front.flows[key]
		front.answered(nil, key, serverInitial(client[:], server[:]), now)
		for range 2 * maxServerCIDChecks {
			front.pinned(key, handshakePacket(client, 1200), now)
		}
		for range others {
			front.pinned(key, shortPacket(other, 1200), now)
		}
		front.pinned(key, shortPacket(server, 1200), now)
		if fl.listed != (others == maxServerCIDChecks) {
			t.Fatalf("%d datagrams to other IDs: listed %v", others, fl.listed)
		}
		checkFlows(t, front)
	}
	front, link := desyncFront(t)
	front.pin(key, link, handshakePacket(client, 1200), 1200, now)
	fl := front.flows[key]
	front.answered(nil, key, serverInitial(client[:], client[:]), now)
	front.pinned(key, shortPacket(client, 1200), now)
	front.pinned(key, handshakePacket(client, 1200), now)
	if !fl.listed || !fl.answered || fl.serverLen != 0 {
		t.Fatalf("an answer naming the client's own ID: listed %v, server ID %x", fl.listed, fl.serverCID[:fl.serverLen])
	}
}

// TestUDPFrontEvictedQUIC: a real quic-go client through the front to a
// quic-go server (as Hysteria2, naive-quic and DoH3 are) with labels,
// its flow gone (pushed out by others), is pinned anew by its next packet's
// label and goes on. quic-go's client moves to an ID of an encrypted
// NEW_CONNECTION_ID as soon as the handshake is done, usually before it
// sends to the ID the server's Initial named: its flow stays listed.
func TestUDPFrontEvictedQUIC(t *testing.T) {
	front, addr := h3NodeFront(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, addr.String(), h3ClientTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(qc)
	get := func() int64 {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://h3.example.com/big", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	flows := func() int {
		front.access.Lock()
		defer front.access.Unlock()
		return len(front.flows)
	}
	if n := get(); n != 256<<10 || flows() != 1 {
		t.Fatalf("%d bytes, %d flows", n, flows())
	}
	front.access.Lock()
	for k := range front.flows {
		front.unpin(k)
	}
	front.access.Unlock()
	if n := get(); n != 256<<10 || flows() != 1 {
		t.Fatalf("after the flow went: %d bytes, %d flows", n, flows())
	}
}

// TestUDPFrontSpoofedFlights: first flights of 40 connections from a
// socket that never reads, as a spoofed source is to the front, do not
// confirm its flow. A quic-go server sends up to a datagram past three
// times what each connection got, and the front sees them all on one
// flow: bytes the backend sends prove nothing of the address.
func TestUDPFrontSpoofedFlights(t *testing.T) {
	front, addr := h3NodeFront(t, true)
	flights := firstFlights(t, "h3.example.com", 40)
	x, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	for _, flight := range flights {
		for _, p := range flight {
			x.WriteToUDP(p, addr)
		}
	}
	client := x.LocalAddr().(*net.UDPAddr).AddrPort()
	state := func() (pinned, listed bool) {
		front.access.Lock()
		defer front.access.Unlock()
		for k, fl := range front.flows { // the key's local address is the one listened on
			if k.client == client {
				return true, fl.listed
			}
		}
		return false, false
	}
	for range 30 { // 3 s
		time.Sleep(100 * time.Millisecond)
		if pinned, listed := state(); pinned && !listed {
			t.Fatal("confirmed by the answers to a source that never read them")
		}
	}
	if pinned, _ := state(); !pinned {
		t.Fatal("not pinned")
	}
}

// TestUDPFrontPathProbes: a path probe of quic-go's (a short header of
// 1200 bytes) goes within three times what the flow's client sent, the
// backend's datagrams before its first short header counted with it, a
// confirmed flow's as well; past that, once a flow, within its source's
// share of free probes; to an address with no flow, not at all. Other
// answers are not held. Under salamander a probe is 1208 bytes, opened
// with the route's password.
func TestUDPFrontPathProbes(t *testing.T) {
	front, password := cidFront(t, true)
	now := time.Now()
	key := func(i int) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 40000), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	var id [cidLen]byte
	probe := shortPacket(id, quicProbeSize)
	a := front.links["a"]
	front.pin(key(1), a, shortPacket(cidID(cidSecret, 1, 1), 100), 100, now) // 100 bytes in
	fl := front.flows[key(1)]
	if !front.answered(a, key(1), probe, now) || !fl.freeProbe {
		t.Fatal("the first probe past 3x was not free")
	}
	if front.answered(a, key(1), probe, now) {
		t.Fatal("a second probe went for 100 in")
	}
	for _, other := range [][]byte{shortPacket(id, quicProbeSize-1), shortPacket(id, quicProbeSize+1), shortPacket(id, 1252)} {
		if !front.answered(a, key(1), other, now) {
			t.Fatalf("an answer of %d bytes (not a probe) was held", len(other))
		}
	}
	front.pinned(key(1), shortPacket(id, 1200), now) // a PATH_RESPONSE: 1300 in, 3900 out
	if !front.answered(a, key(1), probe, now) || !front.answered(a, key(1), probe, now) || front.answered(a, key(1), probe, now) {
		t.Fatalf("for 1300 in, %d out: not two more probes and no third", fl.sent)
	}
	// Confirmed, the same bound.
	if !front.confirm(fl) || front.answered(a, key(1), probe, now) {
		t.Fatal("a probe past 3x went to a confirmed flow")
	}
	// The backend's long headers among its first countedAnswers datagrams
	// count with the probes, after a short header (0.5-RTT data) too.
	front.pin(key(2), a, handshakePacket(id, 1200), 2400, now) // a first flight of two: 7200 out
	f2 := front.flows[key(2)]
	front.answered(a, key(2), handshakePacket(id, 2400), now)
	front.answered(a, key(2), shortPacket(id, 100), now)
	front.answered(a, key(2), handshakePacket(id, 3600), now) // a retransmission
	if !front.answered(a, key(2), probe, now) || f2.freeProbe || f2.sent != 7200 {
		t.Fatalf("a probe within 3x with the handshake: %d counted, free %v", f2.sent, f2.freeProbe)
	}
	for range countedAnswers {
		front.answered(a, key(2), handshakePacket(id, 1300), now)
	}
	if f2.sent != 7200+(countedAnswers-3)*1300 || f2.budget.sent != uint64(f2.sent) {
		t.Fatalf("%d counted of %d answers, %d for the source", f2.sent, countedAnswers+3, f2.budget.sent)
	}
	// A new port of a source that sent much has its first probe within the
	// source's 3x, none of the source's free ones taken (a port hop, a
	// rebinding), and its second within its own.
	port := func(p uint16) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 5}), p), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	front.pin(port(1), a, shortPacket(cidID(cidSecret, 1, 1), 100), 100, now)
	for range 4 {
		front.pinned(port(1), shortPacket(id, 1200), now)
	}
	front.pin(port(2), a, shortPacket(cidID(cidSecret, 1, 2), 50), 50, now)
	if !front.answered(a, port(2), probe, now) || front.freeProbes.sources[sourcePrefix(port(2).client.Addr(), 64)] != nil {
		t.Fatal("a new port of a source that sent 4950 bytes: its probe held, or a free one taken")
	}
	if front.answered(a, port(2), probe, now) {
		t.Fatal("a second probe for 50 in")
	}
	// The same with the source's bytes all in a first flight of two
	// packets, counted at the pin.
	flight := func(p uint16) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 6}), p), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	front.pin(flight(1), a, handshakePacket(id, 1200), 2400, now)
	front.pin(flight(2), a, shortPacket(cidID(cidSecret, 1, 3), 50), 50, now)
	if !front.answered(a, flight(2), probe, now) || front.freeProbes.sources[sourcePrefix(flight(2).client.Addr(), 64)] != nil {
		t.Fatal("a new port of a source whose first flight was 2400 bytes: its probe held, or a free one taken")
	}
	// Free probes: freeProbeBurst a source (192.0.2.3, ports apart).
	from := func(port uint16) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 3}), port), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	for i := range freeProbeBurst + 1 {
		k := from(uint16(50000 + i))
		front.pin(k, a, shortPacket(cidID(cidSecret, 1, 1), 100), 100, now)
		if front.answered(a, k, probe, now) != (i < freeProbeBurst) {
			t.Fatalf("free probe %d of a source", i+1)
		}
	}
	if !front.answered(a, key(1), shortPacket(id, 1252), now) {
		t.Fatal("an answer that is not a probe was held")
	}
	// To no flow.
	if front.answered(a, key(9), probe, now) || !front.answered(a, key(9), shortPacket(id, 1252), now) {
		t.Fatal("to no flow: a probe went or another answer was held")
	}
	s := front.links["s"]
	if front.answered(s, key(9), obfuscate(password, probe), now) || !front.answered(s, key(9), probe, now) {
		t.Fatal("to no flow of a salamander link: its probe went, or a plain datagram of 1200 bytes was held")
	}
	front.pin(key(4), s, obfuscate(password, shortPacket(cidID(cidSecret, 3, 1), 100)), 108, now)
	if front.flows[key(4)] == nil || front.flows[key(4)].route == nil {
		t.Fatal("not pinned under salamander")
	}
	if !front.answered(s, key(4), obfuscate(password, probe), now) || front.answered(s, key(4), obfuscate(password, probe), now) {
		t.Fatal("under salamander: not one free probe and no second for 108 in")
	}
	checkFlows(t, front)
}

// spoofConn writes through another socket while spoof is set: the
// connection's packets come from an address that is not the client's.
type spoofConn struct {
	net.PacketConn
	spoof atomic.Pointer[net.UDPConn]
	sent  atomic.Int64 // through spoof
}

func (c *spoofConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if x := c.spoof.Load(); x != nil {
		c.sent.Add(int64(len(p)))
		return x.WriteTo(p, addr)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// TestUDPFrontReflection: 16 real quic-go connections through the front,
// each sending one small packet from a spoofed address (a socket of the
// test's that reads and counts), do not make the backend's path probes
// (1200 bytes each, whatever came from the address) reach that address
// past three times what came from it, and the one free probe of its flow.
func TestUDPFrontReflection(t *testing.T) {
	_, addr := h3NodeFront(t, true)
	// Another source than the real connections' (127.0.0.1): the spoofed
	// address has only what is sent from it.
	x, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	var got atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := x.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got.Add(int64(n))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var conns []*spoofConn
	for range 16 {
		own, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer own.Close()
		sc := &spoofConn{PacketConn: own}
		tr := &quic.Transport{Conn: sc}
		defer tr.Close()
		qc, err := tr.Dial(ctx, addr, h3ClientTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		<-qc.HandshakeComplete()
		time.Sleep(20 * time.Millisecond)
		sc.spoof.Store(x)
		str, err := qc.OpenUniStream()
		if err != nil {
			t.Fatal(err)
		}
		str.Write([]byte{0x21}) // a reserved stream type, ignored by HTTP/3
		for wait := time.Now(); sc.sent.Load() == 0 && time.Since(wait) < 2*time.Second; {
			time.Sleep(5 * time.Millisecond)
		}
		sc.spoof.Store(nil)
		conns = append(conns, sc)
	}
	time.Sleep(300 * time.Millisecond)
	var sent int64
	for _, sc := range conns {
		sent += sc.sent.Load() // a write under way when spoof went is counted by now
	}
	if sent == 0 || got.Load() > 3*sent+quicProbeSize {
		t.Fatalf("%d bytes from the spoofed address, %d to it", sent, got.Load())
	}
	t.Logf("%d bytes from the spoofed address, %d to it", sent, got.Load())
}

// TestUDPFrontClientIDs: before the first answer the IDs a client chose,
// two at most, are noted: an answer that names either as its own (a
// refusal of a later Initial, quic-go's sendError) confirms nothing, and
// datagrams to them are not counted; a third ID leaves the flow
// unconfirmed. A probe held is not the first answer.
func TestUDPFrontClientIDs(t *testing.T) {
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.50:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	var first, second, third, server [cidLen]byte
	copy(first[:], "first-id")
	copy(second[:], "second!!")
	copy(third[:], "third-id")
	copy(server[:], "serverid")
	front, link := desyncFront(t)
	front.pin(key, link, handshakePacket(first, 1200), 1200, now)
	fl := front.flows[key]
	front.pinned(key, handshakePacket(second, 1200), now)
	front.answered(nil, key, serverInitial(second[:], second[:]), now)
	front.pinned(key, shortPacket(second, 1200), now)
	if !fl.listed || fl.serverLen != 0 {
		t.Fatalf("a refusal naming the second ID: listed %v, server ID %x", fl.listed, fl.serverCID[:fl.serverLen])
	}
	front, link = desyncFront(t)
	front.pin(key, link, handshakePacket(first, 1200), 1200, now)
	fl = front.flows[key]
	front.pinned(key, handshakePacket(second, 1200), now)
	front.pinned(key, handshakePacket(third, 1200), now)
	front.answered(nil, key, serverInitial(first[:], server[:]), now)
	front.pinned(key, shortPacket(server, 1200), now)
	if !fl.listed {
		t.Fatal("a flow of three IDs of the client's was confirmed")
	}
	// A probe held does not take the place of the first answer.
	front, link = desyncFront(t)
	front.pin(key, link, shortPacket(server, 100), 100, now)
	fl = front.flows[key]
	fl.freeProbe = true
	if front.answered(nil, key, shortPacket(server, quicProbeSize), now) || fl.answered {
		t.Fatalf("a probe held: went or taken for the answer (answered %v)", fl.answered)
	}
	checkFlows(t, front)
}

// TestUDPFrontConfirmedPerSource: a source (an IPv4 address, an IPv6 /48)
// has maxConfirmed confirmed flows at most, the rest listed; one going
// frees a place.
func TestUDPFrontConfirmedPerSource(t *testing.T) {
	front, link := desyncFront(t)
	front.maxConfirmed = 2
	now := time.Now()
	local := netip.MustParseAddrPort("127.0.0.1:443")
	var server [cidLen]byte
	copy(server[:], "serverid")
	confirm := func(client string) *udpFlow {
		key := flowKey{client: netip.MustParseAddrPort(client), local: local}
		front.pin(key, link, nil, 0, now)
		front.answered(nil, key, serverInitial(nil, server[:]), now)
		front.pinned(key, shortPacket(server, 1200), now)
		return front.flows[key]
	}
	if confirm("192.0.2.60:1").listed || confirm("192.0.2.60:2").listed {
		t.Fatal("two flows of a source not confirmed")
	}
	if !confirm("192.0.2.60:3").listed {
		t.Fatal("a third flow of a source confirmed")
	}
	if confirm("192.0.2.61:1").listed {
		t.Fatal("another source's flow not confirmed")
	}
	if confirm("[2001:db8:1:1::1]:1").listed || confirm("[2001:db8:1:2::1]:1").listed || !confirm("[2001:db8:1:3::1]:1").listed {
		t.Fatal("IPv6 /48 not one source")
	}
	front.unpin(flowKey{client: netip.MustParseAddrPort("192.0.2.60:1"), local: local})
	refused := flowKey{client: netip.MustParseAddrPort("192.0.2.60:3"), local: local}
	front.pinned(refused, shortPacket(server, 1200), now)
	if front.flows[refused].listed {
		t.Fatal("a flow refused at the cap was not confirmed once a place was free")
	}
	if !confirm("192.0.2.60:4").listed {
		t.Fatal("past the cap again")
	}
	front.unpin(flowKey{client: netip.MustParseAddrPort("192.0.2.60:4"), local: local}) // listed: the count stays
	checkFlows(t, front)
	if front.confirmed[sourcePrefix(netip.MustParseAddr("192.0.2.60"), 48)] != 2 {
		t.Fatalf("%d counted", front.confirmed[sourcePrefix(netip.MustParseAddr("192.0.2.60"), 48)])
	}
	front.expire(now.Add(front.idle + time.Second))
	if len(front.confirmed) != 0 {
		t.Fatalf("counts left after every flow went: %v", front.confirmed)
	}
	checkFlows(t, front)
}

// TestUDPFrontFreeProbesTotal: free probes of all sources together are
// freeProbeTotalBurst at most at once.
func TestUDPFrontFreeProbesTotal(t *testing.T) {
	front, _ := cidFront(t, true)
	now := time.Now()
	a := front.links["a"]
	var id [cidLen]byte
	free := 0
	for i := range freeProbeTotalBurst + 64 {
		key := flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000), local: netip.MustParseAddrPort("127.0.0.1:443")}
		front.pin(key, a, shortPacket(cidID(cidSecret, 1, 1), 100), 100, now)
		if front.answered(a, key, shortPacket(id, quicProbeSize), now) {
			free++
		}
	}
	if free != freeProbeTotalBurst {
		t.Fatalf("%d free probes of %d sources, not %d", free, freeProbeTotalBurst+64, freeProbeTotalBurst)
	}
}

// TestUDPFrontConfirmedSilent: a confirmed flow the backend has not
// answered for idle/2 is listed again, whatever its client sends, and is
// confirmed anew by its next datagram to the server's ID; one the backend
// answers stays confirmed.
func TestUDPFrontConfirmedSilent(t *testing.T) {
	front, link := desyncFront(t)
	now := time.Now()
	var server [cidLen]byte
	copy(server[:], "serverid")
	other := server
	other[0] ^= 1
	confirm := func(client string) (flowKey, *udpFlow) {
		key := flowKey{client: netip.MustParseAddrPort(client), local: netip.MustParseAddrPort("127.0.0.1:443")}
		front.pin(key, link, nil, 0, now)
		front.answered(nil, key, serverInitial(nil, server[:]), now)
		for range maxServerCIDChecks - 1 {
			front.pinned(key, shortPacket(other, 1200), now)
		}
		front.pinned(key, shortPacket(server, 1200), now)
		return key, front.flows[key]
	}
	silentKey, silent := confirm("192.0.2.70:1")
	answeredKey, answered := confirm("192.0.2.71:1")
	if silent.listed || answered.listed {
		t.Fatal("not confirmed")
	}
	later := now.Add(front.idle/2 + time.Second)
	front.pinned(silentKey, shortPacket(server, 100), later)
	front.pinned(answeredKey, shortPacket(server, 100), later)
	front.answered(nil, answeredKey, shortPacket(server, 100), later)
	front.expire(later)
	if !silent.listed || answered.listed {
		t.Fatalf("after idle/2: the silent backend's flow listed %v, the answered one's %v", silent.listed, answered.listed)
	}
	checkFlows(t, front)
	// Its checks start again: one to another ID, then the server's.
	front.pinned(silentKey, shortPacket(other, 100), later)
	front.pinned(silentKey, shortPacket(server, 100), later)
	if silent.listed {
		t.Fatal("not confirmed anew")
	}
	checkFlows(t, front)
}

// TestSourceKey: a source is an IPv4 address or an IPv6 /64, a mapped
// IPv4 address the same as itself, and no IPv6 /64 an IPv4 address's.
func TestSourceKey(t *testing.T) {
	k := func(s string) uint64 { return sourceKey(netip.MustParseAddr(s)) }
	switch {
	case k("2001:db8:1:1::1") != k("2001:db8:1:1:ffff::2"):
		t.Fatal("one /64, two sources")
	case k("2001:db8:1:1::1") == k("2001:db8:1:2::1"):
		t.Fatal("two /64s, one source")
	case k("192.0.2.1") != k("::ffff:192.0.2.1"):
		t.Fatal("a mapped IPv4 address another source")
	case k("192.0.2.1") == k("192.0.2.2"):
		t.Fatal("two IPv4 addresses, one source")
	case k("192.0.2.1") == k("0:0:c000:201::1") || k("192.0.2.1") == k("2001:db8::"):
		t.Fatal("an IPv4 address an IPv6 /64's source")
	}
}
