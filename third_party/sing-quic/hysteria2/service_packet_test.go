package hysteria2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/quic-go/quicvarint"

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
	// 200 fragments of 1200 bytes: past the bound at the 70th or so,
	// dropped; what comes after starts again and never holds more.
	for id := range uint8(200) {
		if m := d.feed(fragment(5000, id, 200, 1200)); m != nil {
			t.Fatal("a packet of 240000 bytes completed")
		}
		if held := keptOf(d, 5000); held > udpMaxPacketBytes {
			t.Fatalf("a packet's fragments keep %d bytes", held)
		}
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

// keptOf is what the fragments of a packet keep, counted from the
// fragments themselves.
func keptOf(d *udpDefragger, packetID uint16) (n int) {
	if it, ok := d.packetMap.Load(packetID); ok {
		for _, m := range it.messages {
			if m != nil {
				n += m.footprint()
			}
		}
	}
	return n
}

// A message counts at what it keeps, the whole datagram and its
// destination, not at its payload: 255 fragments of no data, each in a
// datagram of 1.4 KB with a long destination, kept about 360 KB a packet
// while the bound saw nothing (neko, review). A destination longer than a
// name and a port, which an IPv6 literal's zone can make a kilobyte, is no
// message; the queue counts the same.
func TestUDPDatagramFootprint(t *testing.T) {
	dest := "[fe80::1%" + strings.Repeat("z", 280) + "]:53"
	d := newUDPDefragger()
	for id := range uint8(255) {
		m := fragment(7000, id, 255, 1)
		m.destination, m.held = dest, 1400
		if d.feed(m) != nil {
			t.Fatal("completed")
		}
		if held := keptOf(d, 7000); held > udpMaxPacketBytes {
			t.Fatalf("255 fragments of no data keep %d bytes, past %d", held, udpMaxPacketBytes)
		}
	}
	for _, dest := range []string{"[fe80::1%" + strings.Repeat("z", 1300) + "]:53", strings.Repeat("a", 301)} {
		b := []byte{0, 0, 0, 1, 0, 1, 0, 1}
		b = quicvarint.Append(b, uint64(len(dest)))
		b = append(b, dest...)
		if err := decodeUDPMessage(allocMessage(), append(b, "data"...)); err == nil {
			t.Errorf("a destination of %d bytes decoded", len(dest))
		}
	}
	b := []byte{0, 0, 0, 1, 0, 1, 0, 1}
	b = quicvarint.Append(b, uint64(len("192.0.2.1:53")))
	b = append(b, "192.0.2.1:53data"...)
	m := allocMessage()
	if err := decodeUDPMessage(m, b); err != nil || m.held != cap(b) || m.data.Len() != 4 {
		t.Fatalf("a datagram of %d bytes: %v, held %d", len(b), err, m.held)
	}
	s := &serverSession[string]{ctx: context.Background(), udpConnMap: make(map[uint32]*udpPacketConn)}
	c := s.newUDPConn(1)
	defer c.Close()
	for range 64 {
		m := fragment(0, 0, 1, 1)
		m.destination, m.held = dest, 4000
		c.inputPacket(m)
	}
	if n := c.queued.Load(); n > udpQueueBytes || len(c.data) > udpQueueBytes/4000 {
		t.Fatalf("64 datagrams of 4000 bytes and no data: %d bytes, %d queued", n, len(c.data))
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
