package hysteria2

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// A session's conn that ends takes only itself out of the session map
// (neko): a datagram of the same number between its cancel and its
// onDestroy makes a new conn, which must stay; were it taken out, the next
// datagram would make a third, and the second would be left running
// unseen, holding what its handler holds until its idle time.
func TestUDPConnDestroyKeepsItsSuccessor(t *testing.T) {
	s := &serverSession[string]{ctx: context.Background(), udpConnMap: make(map[uint32]*udpPacketConn)}
	old := s.newUDPConn(7)
	old.closeWithError(errors.New("refused")) // its ctx ends first
	next := s.newUDPConn(7)                   // a datagram comes meanwhile
	old.Close()                               // then its onDestroy runs
	if got := s.udpConnMap[7]; got != next {
		t.Fatalf("the session's conn after the old one's end: %p, want the new one %p", got, next)
	}
	next.Close()
	if _, ok := s.udpConnMap[7]; ok {
		t.Fatal("a conn that ended is still in the map")
	}
}

// fragment is a datagram of a client's session: fragment id of total, of
// size bytes.
func fragment(packetID uint16, id, total uint8, size int) *udpMessage {
	m := allocMessage()
	m.sessionID, m.packetID, m.fragmentID, m.fragmentTotal, m.destination = 1, packetID, id, total, "192.0.2.1:53"
	m.data = buf.NewSize(size)
	m.data.Extend(size)
	return m
}

// A client's fragments of packets it never completes are kept for a few
// packets only (neko: udpDefragPackets), and a packet whose fragments
// carry more than a UDP payload can is dropped (udpMaxPacketBytes): before,
// the fragments of up to 65536 packets stayed 10 s, 255 of up to a
// datagram each. The number of fragments is the client's: 64 KiB in
// fragments of 900 bytes (a long destination in each header, a small MTU)
// completes.
func TestUDPDefragmenterBounded(t *testing.T) {
	d := newUDPDefragger()
	for id := range 1000 {
		if m := d.feed(fragment(uint16(id), 0, 40, 1200)); m != nil {
			t.Fatal("a packet of one fragment in 40 completed")
		}
	}
	kept := 0
	d.packetMap.Range(func(uint16, *packetItem) { kept++ })
	if kept > 4 {
		t.Fatalf("the fragments of %d packets kept", kept)
	}
	// 200 fragments of 1200 bytes: past 64 KiB at the 55th, dropped; what
	// comes after starts again and never holds more than 64 KiB.
	for id := range uint8(200) {
		if m := d.feed(fragment(5000, id, 200, 1200)); m != nil {
			t.Fatal("a packet of 240000 bytes completed")
		}
		if it, ok := d.packetMap.Load(5000); ok && it.bytes > 65535 {
			t.Fatalf("a packet's fragments hold %d bytes", it.bytes)
		}
	}
	held := 0
	if it, ok := d.packetMap.Load(5000); ok {
		for _, m := range it.messages {
			if m != nil {
				held += m.data.Len()
			}
		}
	}
	if held > 65535 {
		t.Fatalf("a packet past 64 KiB holds %d bytes", held)
	}
	// Packets of two and of 72 fragments (64800 bytes) complete.
	for _, total := range []uint8{2, 72} {
		var m *udpMessage
		for id := range total {
			m = d.feed(fragment(6000+uint16(total), id, total, 900))
		}
		if m == nil || m.data.Len() != int(total)*900 {
			t.Fatalf("a packet of %d fragments: %v", total, m)
		}
		m.releaseMessage()
	}
}

// A session's queue of datagrams for its reader is bounded in bytes (neko:
// udpQueueBytes), not only in messages: 64 reassembled ones of 64 KiB were
// 4 MiB a session while its reader waited.
func TestUDPQueueBounded(t *testing.T) {
	s := &serverSession[string]{ctx: context.Background(), udpConnMap: make(map[uint32]*udpPacketConn)}
	c := s.newUDPConn(1)
	defer c.Close()
	var queued int
	for range 64 {
		c.inputPacket(fragment(0, 0, 1, 60000))
	}
	for len(c.data) > 0 {
		p := <-c.data
		c.took(p)
		queued += p.data.Len()
		p.releaseMessage()
	}
	if queued > 128<<10 || queued == 0 {
		t.Fatalf("%d bytes queued", queued)
	}
	// Small ones fill the messages as before.
	for range 64 {
		c.inputPacket(fragment(0, 0, 1, 100))
	}
	if len(c.data) != 64 {
		t.Fatalf("%d small datagrams queued, want 64", len(c.data))
	}
}
