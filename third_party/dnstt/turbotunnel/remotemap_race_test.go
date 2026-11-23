package turbotunnel

import (
	"net"
	"sync"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

// TestWriteToWhileExpiring: (neko) packets written to a peer while the
// remote map expires its send queue are queued or dropped, never sent on
// the closed queue (which panicked, and was a race under -race).
func TestWriteToWhileExpiring(t *testing.T) {
	c := NewQueuePacketConn(testAddr("local"), time.Millisecond)
	defer c.Close()
	var wg sync.WaitGroup
	stop := time.Now().Add(300 * time.Millisecond)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		addr := net.Addr(testAddr(string(rune('a' + w))))
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				if _, err := c.WriteTo([]byte{1}, addr); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
