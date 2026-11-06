package dnsttserver

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// feedConn is a PacketConn whose reads come from a channel and whose writes
// go to another.
type feedConn struct {
	net.PacketConn
	in  chan []byte
	out chan []byte
}

func (c feedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b, ok := <-c.in
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, b), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}, nil
}

func (c feedConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.out <- append([]byte(nil), p...)
	return len(p), nil
}


func sealedPollQuery(t *testing.T, k *sealKey, nonce, inner []byte, zone string) []byte {
	t.Helper()
	payload := sealQuery(k, nonce, inner)
	text := strings.ToLower(base32Encoding.EncodeToString(payload))
	var labels [][]byte
	for len(text) > 0 {
		n := min(len(text), 40)
		labels, text = append(labels, []byte(text[:n])), text[n:]
	}
	z, _ := dns.ParseName(zone)
	name, err := dns.NewName(append(labels, z...))
	if err != nil {
		t.Fatal(err)
	}
	q := dns.Message{ID: 7, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 1232, TTL: 0, Data: []byte{}}}}
	w, err := q.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// Two different sealed polls of one client (new N each, as §3 says; the
// same inner payload: ClientID and a padding frame of length 0) within
// the memo's generation are two queries, not a retry: the second gets the
// data that came meanwhile, not the first answer again.
func TestSealedPollsNotMemoized(t *testing.T) {
	seal, err := NewSeal(SealRequired, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	k := seal.list()[0]
	zone := "t.example.com"
	domain, _ := dns.ParseName(zone)
	tt := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, time.Minute)
	defer tt.Close()
	conn := feedConn{in: make(chan []byte, 4), out: make(chan []byte, 4)}
	ch := make(chan *record, 4)
	go recvLoop(domain, conn, tt, ch, nil, seal, &clientSizes{overhead: seal.overhead()})
	go sendLoop(conn, tt, ch)

	id := turbotunnel.ClientID{1, 2, 3, 4, 5, 6, 7, 8}
	inner := append(id[:], 0xe0) // ClientID, a padding frame of 0 bytes
	ask := func(nonce []byte) []byte {
		conn.in <- sealedPollQuery(t, k, nonce, inner, zone)
		select {
		case w := <-conn.out:
			m, err := dns.MessageFromWireFormat(w)
			if err != nil || len(m.Answer) != 1 {
				t.Fatalf("answer %+v %v", m, err)
			}
			d, _ := dns.DecodeRDataTXT(m.Answer[0].Data)
			return d
		case <-time.After(5 * time.Second):
			t.Fatal("no answer")
			return nil
		}
	}
	first := ask(seq(0x10, 8))
	// Downstream data for the client arrives now.
	tt.WriteTo([]byte("downstream packet"), id)
	second := ask(seq(0x20, 8)) // another poll: other N, same inner
	plain := func(d []byte) []byte {
		p := append([]byte(nil), d[8:]...)
		sealXOR(&k.down, d[:8], p)
		return p
	}
	t.Logf("first  R=%x plain[:20]=%x", first[:8], plain(first)[:20])
	t.Logf("second R=%x plain[:20]=%x", second[:8], plain(second)[:20])
	if bytes.Equal(first, second) {
		t.Errorf("a new poll (another N) got the earlier answer replayed; the queued packet did not go out")
	}
}
// TestSendLoopStashSwap with a seal: the stash holds a packet too large for
// this requester; a packet too large for a sealed answer to it (though it
// would fit an open one) does not take its place.
func TestSendLoopSealedStashSwap(t *testing.T) {
	s, _ := NewSeal(SealRequired, bytes.Repeat([]byte{4}, 32))
	tt := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, time.Minute)
	defer tt.Close()
	id := turbotunnel.ClientID{9}
	room := encodedPayload(512)
	big := bytes.Repeat([]byte{1}, encodedPayload(maxUDPPayload)-2-8)
	// 2+len > room-8 (does not fit a sealed answer), 2+len <= room
	mid := bytes.Repeat([]byte{2}, room-2-4)
	small := []byte("ack")
	if !tt.Stash(big, id) {
		t.Fatal("stash")
	}
	tt.WriteTo(mid, id)
	tt.WriteTo(small, id)
	out := make(chan []byte, 4)
	ch := make(chan *record, 1)
	go sendLoop(capture{out: out}, tt, ch)
	zone, _ := dns.ParseName("x.t.example.com")
	ch <- &record{Resp: &dns.Message{ID: 1, Flags: 0x8400, Question: []dns.Question{{Name: zone, Type: dns.RRTypeTXT, Class: dns.ClassIN}}},
		Addr: turbotunnel.DummyAddr{}, ClientID: id, Size: 512, Seal: s.list()[0]}
	select {
	case <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	close(ch)
	select {
	case p := <-tt.Unstash(id):
		if !bytes.Equal(p, big) {
			t.Errorf("stash now holds %d bytes (does not fit a sealed answer to this requester either); the %d-byte packet that a larger resolver could carry was dropped", len(p), len(big))
		}
	default:
		t.Fatal("nothing stashed")
	}
}
