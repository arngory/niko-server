package nikoserver

import (
	"context"
	"encoding/binary"
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
	link, _ := f.classify(key, d, now)
	if link != nil {
		f.pin(key, link, d, now)
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
	checkFlows(t, front)
}

// TestUDPFrontConfirmedQUIC: a real quic-go client through the front to a
// quic-go server (as naive-quic and DoH3 are). With labels its flow is
// confirmed once the handshake is done: it sends to IDs with the
// backend's label. Without, it is not: quic-go's client moves to an ID of
// an encrypted NEW_CONNECTION_ID as soon as the handshake is done, never
// to the one the server's Initial named, and its flow stays one a full
// table may give up for a newer one.
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
		if _, err := h3Get(ctx, cc, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		front.access.Lock()
		n, confirmed := len(front.flows), 0
		for _, fl := range front.flows {
			if !fl.listed {
				confirmed++
			}
		}
		front.access.Unlock()
		qc.CloseWithError(0, "")
		cancel()
		want := 0
		if withCID {
			want = 1
		}
		if n != 1 || confirmed != want {
			t.Fatalf("labels %v: %d flows, %d confirmed", withCID, n, confirmed)
		}
	}
}

// TestUDPFrontConfirmedLabel: with labels, a client's packet to an ID with
// its flow's backend's label confirms the flow; to another backend's
// label, or to a random ID, it does not.
func TestUDPFrontConfirmedLabel(t *testing.T) {
	front, _ := cidFront(t, true)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.30:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	front.pin(key, front.links["a"], shortPacket(cidID(cidSecret, 1, 1), 1200), now)
	fl := front.flows[key]
	if fl == nil || fl.route == nil || fl.route.codec == nil || fl.route.label != 1 {
		t.Fatal("the flow does not know its label")
	}
	var random [cidLen]byte
	copy(random[:], "random!!")
	for _, d := range [][]byte{shortPacket(random, 1200), shortPacket(cidID(cidSecret, 2, 1), 1200)} {
		front.pinned(key, d, now)
		if !fl.listed {
			t.Fatal("a packet to another ID confirmed the flow")
		}
	}
	front.pinned(key, handshakePacket(cidID(cidSecret, 1, 7), 1200), now)
	if fl.listed {
		t.Fatal("a packet to an ID with the flow's label did not confirm it")
	}
	checkFlows(t, front)
}
