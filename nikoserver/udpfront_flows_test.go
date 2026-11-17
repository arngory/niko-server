package nikoserver

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/netip"
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
	link, packets := f.classify(key, d, now)
	if link != nil {
		sent := 0
		for _, p := range packets {
			sent += len(p)
		}
		f.pin(key, link, d, sent, now)
	}
	return link
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
	front.answered(client, serverInitial([]byte{1, 2, 3, 4, 5, 6, 7, 8}, scid[:]), now)
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
			front.answered(k, serverInitial(nil, scid[:]), now)
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
// negotiation is not the answer whose ID counts. The backend's answers
// count without their salt.
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
	front.answered(key, obfuscate(password, vn), now)
	if fl.answered {
		t.Fatal("a version negotiation was taken for the answer")
	}
	var scid [cidLen]byte
	copy(scid[:], "obfsid!!")
	front.answered(key, obfuscate(password, serverInitial(nil, scid[:])), now)
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
	// The backend's answers count without their salt, as its QUIC counts
	// them: 720 of 100 bytes are 3 x 24000, not more.
	big := flowKey{client: netip.MustParseAddrPort("192.0.2.21:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	front.pin(big, front.links["s"], obfuscate(password, initial), 24000, now)
	fl = front.flows[big]
	if fl == nil || fl.route == nil {
		t.Fatal("not pinned under salamander")
	}
	short := make([]byte, 100)
	short[0] = 0x40
	for range 720 {
		front.answered(big, obfuscate(password, short), now)
	}
	if !fl.listed {
		t.Fatalf("confirmed at %d to %d bytes, the salt counted", fl.toClient, fl.fromClient)
	}
	front.answered(big, obfuscate(password, short), now)
	if fl.listed {
		t.Fatalf("not confirmed at %d to %d bytes", fl.toClient, fl.fromClient)
	}
	checkFlows(t, front)
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

// TestUDPFrontConfirmedBytes: the backend sending confirmBytes and more
// than three times what the client sent confirms a flow; less, or not
// more than three times, does not.
func TestUDPFrontConfirmedBytes(t *testing.T) {
	front, link := desyncFront(t)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.31:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	front.pin(key, link, nil, 2500, now)
	fl := front.flows[key]
	answer := make([]byte, 1200)
	answer[0] = 0x40 // short headers
	// Under confirmBytes: not confirmed, however far past 3x.
	for range confirmBytes / 1200 { // 54 answers, 64800 bytes
		front.answered(key, answer, now)
	}
	if !fl.listed {
		t.Fatal("confirmed under confirmBytes")
	}
	// Past confirmBytes but not past 3x: the client sent 32500 bytes, and
	// 81 answers are 97200.
	front.pinned(key, make([]byte, 30000), now)
	for range 81 - confirmBytes/1200 {
		front.answered(key, answer, now)
	}
	if !fl.listed {
		t.Fatalf("confirmed at %d to %d bytes", fl.toClient, fl.fromClient)
	}
	front.answered(key, answer, now) // 98400
	if fl.listed {
		t.Fatalf("not confirmed at %d to %d bytes", fl.toClient, fl.fromClient)
	}
	// What went to the backend with the classifying datagram counts too.
	big := flowKey{client: netip.MustParseAddrPort("192.0.2.32:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	front.pin(big, link, nil, 40000, now)
	for range 100000 / 1200 { // past confirmBytes, under 3 x 40000
		front.answered(big, answer, now)
	}
	if !front.flows[big].listed {
		t.Fatal("the bytes sent at the pin were not counted")
	}
	checkFlows(t, front)
}

// TestUDPFrontFlowDetails: the first answer's ID is the one that counts,
// not a later one's; a long header whose ID length differs, or a packet
// without QUIC's fixed bit, confirms nothing; the ID is checked for
// maxServerCIDChecks datagrams only; a key is pinned once; a flow in use
// is not the oldest; listed flows idle go from the list.
func TestUDPFrontFlowDetails(t *testing.T) {
	front, link := desyncFront(t)
	front.maxFlows = 4
	now := time.Now()
	key := func(i int) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 40000), local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	front.pin(key(1), link, nil, 2500, now)
	front.pin(key(1), link, nil, 2500, now)
	if len(front.flows) != 1 || front.unconfirmed.n != 1 {
		t.Fatal("a key pinned twice")
	}
	fl := front.flows[key(1)]
	first, later := []byte("firstid!"), []byte("laterid!")
	front.answered(key(1), serverInitial(nil, first), now)
	front.answered(key(1), serverInitial(nil, later), now)
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
	// Past maxServerCIDChecks the ID is not read any more.
	for range maxServerCIDChecks {
		front.pinned(key(1), nofixed, now)
	}
	front.pinned(key(1), shortPacket(id, 1200), now)
	if !fl.listed {
		t.Fatal("the ID was read past maxServerCIDChecks")
	}
	// In use, the oldest flow is not the one to go: 1 is used last.
	for i := 2; i <= 4; i++ {
		front.pin(key(i), link, nil, 2500, now)
	}
	front.pinned(key(1), nofixed, now)
	front.pin(key(5), link, nil, 2500, now)
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

// TestUDPFrontConfirmedQUIC: a real quic-go client through the front to a
// quic-go server (as naive-quic and DoH3 are), with labels and without,
// confirms its flow by what the server sends once it has validated the
// address: quic-go's client moves to an ID of an encrypted
// NEW_CONNECTION_ID as soon as the handshake is done, usually before it
// ever sends to the ID the server's Initial named.
func TestUDPFrontConfirmedQUIC(t *testing.T) {
	for _, withCID := range []bool{false, true} {
		front, addr := h3NodeFront(t, withCID)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		qc, err := quic.DialAddr(ctx, addr.String(), h3ClientTLS, &quic.Config{})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cc := (&http3.Transport{}).NewClientConn(qc)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://h3.example.com/big", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		front.access.Lock()
		flows, confirmed := len(front.flows), 0
		for _, fl := range front.flows {
			if !fl.listed {
				confirmed++
			}
		}
		front.access.Unlock()
		qc.CloseWithError(0, "")
		cancel()
		if n < 2*confirmBytes || flows != 1 || confirmed != 1 {
			t.Fatalf("labels %v: %d bytes down, %d flows, %d confirmed", withCID, n, flows, confirmed)
		}
	}
}
