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
	if link, _ := f.classify(key, d, now); link != nil {
		f.pin(key, link, d, now)
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
	front.pin(key, front.links["a"], shortPacket(cidID(cidSecret, 1, 1), 1200), now)
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
	front.pin(key(1), link, nil, now)
	front.pin(key(1), link, nil, now)
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
	front.pin(key(1), link, nil, now)
	// In use, the oldest flow is not the one to go: 1 is used last.
	for i := 2; i <= 4; i++ {
		front.pin(key(i), link, nil, now)
	}
	front.pinned(key(1), nofixed, now)
	front.pin(key(5), link, nil, now)
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
		front.pin(key, link, handshakePacket(client, 1200), now)
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
	front.pin(key, link, handshakePacket(client, 1200), now)
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
// 1200 bytes) goes to a flow not confirmed yet within three times what its
// client sent, to a confirmed one always, to an address with no flow not
// at all; other answers are not bounded. Under salamander a probe is 1208
// bytes, opened with the route's password.
func TestUDPFrontPathProbes(t *testing.T) {
	front, password := cidFront(t, true)
	now := time.Now()
	key := func(i int) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 40000), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	var id [cidLen]byte
	probe := shortPacket(id, quicProbeSize)
	a := front.links["a"]
	front.pin(key(1), a, shortPacket(cidID(cidSecret, 1, 1), 100), now) // 100 bytes in
	fl := front.flows[key(1)]
	if front.answered(a, key(1), probe, now) {
		t.Fatal("a probe of 1200 bytes went for 100 in")
	}
	for _, other := range [][]byte{shortPacket(id, quicProbeSize-1), shortPacket(id, quicProbeSize+1), handshakePacket(id, quicProbeSize)} {
		if !front.answered(a, key(1), other, now) {
			t.Fatalf("an answer of %d bytes (not a probe) was held", len(other))
		}
	}
	for range 3 {
		front.pinned(key(1), shortPacket(id, 100), now) // 400 in: 1200 out
	}
	if !front.answered(a, key(1), probe, now) {
		t.Fatal("a probe of 1200 bytes was held for 400 in")
	}
	if front.answered(a, key(1), probe, now) {
		t.Fatal("a second probe went for 400 in")
	}
	front.unconfirmed.remove(fl) // confirmed
	if !front.answered(a, key(1), probe, now) {
		t.Fatal("a probe to a confirmed flow was held")
	}
	if front.answered(a, key(9), probe, now) || !front.answered(a, key(9), shortPacket(id, 1252), now) {
		t.Fatal("to no flow: a probe went or another answer was held")
	}
	s := front.links["s"]
	if front.answered(s, key(9), obfuscate(password, probe), now) {
		t.Fatal("to no flow: a probe under salamander went")
	}
	front.pin(key(2), s, obfuscate(password, shortPacket(cidID(cidSecret, 3, 1), 100)), now)
	if front.flows[key(2)] == nil || front.flows[key(2)].route == nil {
		t.Fatal("not pinned under salamander")
	}
	if front.answered(s, key(2), obfuscate(password, probe), now) || !front.answered(s, key(2), obfuscate(password, handshakePacket(id, quicProbeSize)), now) {
		t.Fatal("under salamander: a probe went for 108 in, or a long header was held")
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
// past three times what came from it.
func TestUDPFrontReflection(t *testing.T) {
	_, addr := h3NodeFront(t, true)
	x, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
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
	var sent int64
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
		time.Sleep(30 * time.Millisecond)
		sc.spoof.Store(nil)
		sent += sc.sent.Load()
	}
	time.Sleep(300 * time.Millisecond)
	if sent == 0 || got.Load() > 3*sent {
		t.Fatalf("%d bytes from the spoofed address, %d to it", sent, got.Load())
	}
	t.Logf("%d bytes from the spoofed address, %d to it", sent, got.Load())
}
