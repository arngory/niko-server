package dnsttserver

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// startPacket is the first KCP segment of a dnstt session: PUSH, sn 0,
// with the length of the Noise first message as its data.
func startPacket() []byte {
	p := make([]byte, kcpHeader+2)
	binary.LittleEndian.PutUint32(p[0:4], 0x1234)
	p[4] = kcpPush
	binary.LittleEndian.PutUint32(p[20:24], 2)
	p[25] = noiseFirst
	return p
}

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
		if tab.admit(clientID(i), startPacket(), nil) {
			admitted++
		}
	}
	if admitted != MaxHandshakes {
		t.Fatalf("a flood admitted %d, want the %d handshakes", admitted, MaxHandshakes)
	}
	// An admitted ClientID passes again; KCP's session for it is taken,
	// one for a ClientID never admitted is refused.
	if !tab.admit(clientID(0), startPacket(), nil) || !tab.add(clientID(0)) || tab.add(clientID(99)) {
		t.Fatal("add")
	}
	// The handshake done: its place among the handshakes is free, but the
	// rate holds the next ones back (the burst is spent).
	tab.established(clientID(0))
	if tab.admit(clientID(200), startPacket(), nil) {
		t.Fatal("admitted over the rate")
	}
	tab.last = tab.last.Add(-time.Second) // a second later: 2 more tokens
	if !tab.admit(clientID(200), startPacket(), nil) {
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
	if !tab.admit(clientID(300), startPacket(), nil) {
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
	tab.admit(in, startPacket(), nil)
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

// Only what can open a session gets a new ClientID in: random bytes, a
// later segment, an ACK, a fragment, data that is no Noise first message.
func TestLooksLikeStart(t *testing.T) {
	if !looksLikeStart(startPacket()) {
		t.Fatal("a session's first segment refused")
	}
	whole := append(startPacket(), make([]byte, noiseFirst)...) // with the message itself
	binary.LittleEndian.PutUint32(whole[20:24], 2+noiseFirst)
	if !looksLikeStart(whole) {
		t.Fatal("the whole first message refused")
	}
	for name, change := range map[string]func(p []byte) []byte{
		"short":         func(p []byte) []byte { return p[:kcpHeader+1] },
		"ack":           func(p []byte) []byte { p[4] = 82; return p },
		"fragment":      func(p []byte) []byte { p[5] = 1; return p },
		"sn 1":          func(p []byte) []byte { p[12] = 1; return p },
		"other length":  func(p []byte) []byte { p[25] = 49; return p },
		"len past data": func(p []byte) []byte { binary.LittleEndian.PutUint32(p[20:24], 3); return p },
	} {
		if looksLikeStart(change(startPacket())) {
			t.Errorf("%s: taken", name)
		}
	}
	tab := newSessionTable()
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 37)
	}
	if tab.admit(clientID(1), random, nil) || tab.has(clientID(1)) {
		t.Fatal("random bytes admitted")
	}
}

// One dnsauth device gets MaxSessionsPerDevice at once (review 8: one
// device key could take every session); other devices and untagged
// ClientIDs are not held back by it, and a closed session frees a place.
func TestSessionTablePerDevice(t *testing.T) {
	defer func(d int, r float64) { MaxSessionsPerDevice, NewSessionsPerSecond = d, r }(MaxSessionsPerDevice, NewSessionsPerSecond)
	MaxSessionsPerDevice, NewSessionsPerSecond = 3, 1000
	tab := newSessionTable()
	dev := func(d string) func() string { return func() string { return d } }
	for i := range 3 {
		if !tab.admit(clientID(i), startPacket(), dev("a")) {
			t.Fatalf("device a's session %d refused", i)
		}
	}
	if tab.admit(clientID(10), startPacket(), dev("a")) {
		t.Fatal("device a over its bound")
	}
	// Established sessions count too.
	tab.add(clientID(0))
	tab.established(clientID(0))
	if tab.admit(clientID(10), startPacket(), dev("a")) {
		t.Fatal("device a over its bound with one established")
	}
	if !tab.admit(clientID(11), startPacket(), dev("b")) || !tab.admit(clientID(12), startPacket(), dev("")) || !tab.admit(clientID(13), startPacket(), nil) {
		t.Fatal("another device, or an untagged ClientID, held back")
	}
	// A session of a's closes: its place goes to a's next one.
	tab.remove(clientID(1))
	if !tab.admit(clientID(10), startPacket(), dev("a")) {
		t.Fatal("device a's place not freed")
	}
	// A ClientID in the table passes whatever its device's count.
	if !tab.admit(clientID(2), startPacket(), dev("a")) {
		t.Fatal("an admitted ClientID refused")
	}
}
