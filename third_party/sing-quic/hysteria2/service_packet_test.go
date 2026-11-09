package hysteria2

import (
	"context"
	"errors"
	"testing"
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
