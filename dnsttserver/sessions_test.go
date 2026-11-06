package dnsttserver

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func clientID(i int) turbotunnel.ClientID {
	var id turbotunnel.ClientID
	binary.BigEndian.PutUint64(id[:], uint64(i)+1)
	return id
}

// A flood of fresh ClientIDs gets no more sessions than the table allows,
// at no faster rate; sessions that never finish their handshake give their
// place back; established ones count against MaxSessions only.
func TestSessionTable(t *testing.T) {
	defer func(s, h int, r float64) { MaxSessions, MaxHandshakes, NewSessionsPerSecond = s, h, r }(MaxSessions, MaxHandshakes, NewSessionsPerSecond)
	MaxSessions, MaxHandshakes, NewSessionsPerSecond = 8, 4, 2

	tab := newSessionTable()
	admitted := 0
	for i := range 100 {
		if tab.admit(clientID(i)) {
			admitted++
		}
	}
	if admitted != MaxHandshakes {
		t.Fatalf("a flood admitted %d, want the %d handshakes", admitted, MaxHandshakes)
	}
	// An admitted ClientID passes again; KCP's session for it is taken,
	// one for a ClientID never admitted is refused.
	if !tab.admit(clientID(0)) || !tab.add(clientID(0)) || tab.add(clientID(99)) {
		t.Fatal("add")
	}
	// The handshake done: its place among the handshakes is free, but the
	// rate holds the next ones back (the burst is spent).
	tab.established(clientID(0))
	if tab.admit(clientID(200)) {
		t.Fatal("admitted over the rate")
	}
	tab.last = tab.last.Add(-time.Second) // a second later: 2 more tokens
	if !tab.admit(clientID(200)) {
		t.Fatal("not admitted within the rate")
	}
	// Admissions KCP never made a session of go after pendingTimeout, when
	// the table is full of handshakes.
	for id, e := range tab.open {
		if e.state == sessionPending {
			e.since = e.since.Add(-pendingTimeout)
			tab.open[id] = e
		}
	}
	tab.swept, tab.last = time.Time{}, tab.last.Add(-10*time.Second)
	if !tab.admit(clientID(300)) {
		t.Fatal("stale admissions kept their places")
	}
	if !tab.has(clientID(0)) || tab.has(clientID(1)) || !tab.has(clientID(300)) {
		t.Fatal("has")
	}
	// Removed, a session's ClientID is gone: KCP's last output to it is
	// dropped, not queued.
	tab.remove(clientID(0))
	if tab.has(clientID(0)) {
		t.Fatal("removed, still there")
	}
}

// KCP's output to a ClientID outside the table makes no queue for it.
func TestSessionConnDrops(t *testing.T) {
	tt := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, time.Minute)
	defer tt.Close()
	tab := newSessionTable()
	conn := sessionConn{tt, tab}
	in, out := clientID(1), clientID(2)
	tab.admit(in)
	conn.WriteTo([]byte("for a session"), in)
	conn.WriteTo([]byte("for no session"), out)
	select {
	case p := <-tt.OutgoingQueue(in):
		if string(p) != "for a session" {
			t.Fatalf("%q", p)
		}
	default:
		t.Fatal("nothing queued for the session")
	}
	select {
	case p := <-tt.OutgoingQueue(out):
		t.Fatalf("queued for no session: %q", p)
	default:
	}
}

// The first Noise message of a sane length passes; a longer one is
// refused before noise allocates it.
func TestHandshakeReaderLength(t *testing.T) {
	for _, c := range []struct {
		n  uint16
		ok bool
	}{{48, true}, {512, true}, {513, false}, {65535, false}} {
		msg := binary.BigEndian.AppendUint16(nil, c.n)
		msg = append(msg, make([]byte, min(int(c.n), 600))...)
		r := &handshakeReader{ReadWriteCloser: nopRWC{bytes.NewReader(msg)}}
		// One byte at a time: the length is checked across reads.
		var err error
		for i := 0; i < 2 && err == nil; i++ {
			_, err = r.Read(make([]byte, 1))
		}
		if (err == nil) != c.ok {
			t.Errorf("first message of %d: %v", c.n, err)
		}
	}
}

type nopRWC struct{ io.Reader }

func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }
