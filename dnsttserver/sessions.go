package dnsttserver

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// Bounds on the KCP sessions (neko, load test 2026-11): KCP opens a session
// for any packet of 24 bytes or more from a ClientID it does not know, and
// nothing closed one whose Noise handshake never came (a goroutine, ~15 KB
// and a 10 ms timer each, for ever). A flood of fresh ClientIDs filled
// memory and CPU wherever queries need no device tag (auth off or
// optional, or seal alone: its key is in every link).
var (
	// MaxSessions bounds the KCP sessions; a new ClientID's packets are not
	// given to KCP while it is full. 512: an idle session holds about 160
	// KB, a busy one 0.6 to 0.75 MiB, and smux 256 KiB more at most.
	MaxSessions = 512
	// MaxHandshakes bounds the sessions whose Noise handshake is not done:
	// fake ones cannot take more than these from MaxSessions.
	MaxHandshakes = 128
	// HandshakeTimeout closes a session whose handshake is not done by then.
	HandshakeTimeout = 20 * time.Second
	// maxHandshakeMessage bounds the client's first Noise message (48
	// bytes for dnstt's NK): its length prefix sized an allocation of up to
	// 64 KiB, kept while the handshake waited for the rest.
	maxHandshakeMessage = 512
	// remoteTimeout is how long a ClientID's queues outlive its last query
	// or packet (dnstt: 4 minutes). Clients poll every 10 s at most, and
	// smux sends a keepalive every 10 s.
	remoteTimeout = time.Minute
)

// sessionTable is the ClientIDs that may have a KCP session (neko):
// recvLoop admits a new ClientID before KCP sees its packets, while there
// is room and the rate allows; sendLoop keeps queues only for those here,
// and KCP's output to any other is dropped (sessionConn). So a ClientID
// outside the table costs no queues, and the queues of the table's
// ClientIDs are bounded by MaxSessions and NewSessionsPerSecond.
type sessionTable struct {
	mu        sync.Mutex
	open      map[turbotunnel.ClientID]*sessionEntry
	handshake int // pending or in the handshake
	tokens    float64
	last      time.Time
	swept     time.Time
}

type sessionEntry struct {
	state sessionState
	since time.Time
}

type sessionState int

const (
	sessionPending     sessionState = iota // admitted, KCP has not accepted it yet
	sessionHandshake                       // accepted, Noise handshake not done
	sessionEstablished                     // smux runs
)

var (
	// NewSessionsPerSecond bounds how fast new ClientIDs are admitted
	// (twice that at once): failed handshakes cannot churn sessions, each
	// leaving queues behind for remoteTimeout.
	NewSessionsPerSecond = 32.0
	// pendingTimeout frees an admission KCP never made a session of
	// (a packet under 24 bytes).
	pendingTimeout = 5 * time.Second
)

func newSessionTable() *sessionTable {
	return &sessionTable{open: map[turbotunnel.ClientID]*sessionEntry{}}
}

func (t *sessionTable) has(id turbotunnel.ClientID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.open[id]
	return ok
}

// admit reports whether KCP may see a packet of id: it is in the table, or
// it is let in now (pending).
func (t *sessionTable) admit(id turbotunnel.ClientID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.open[id]; ok {
		return true
	}
	now := time.Now()
	if t.handshake >= MaxHandshakes && now.Sub(t.swept) >= time.Second {
		t.swept = now
		for k, e := range t.open {
			if e.state == sessionPending && now.Sub(e.since) >= pendingTimeout {
				delete(t.open, k)
				t.handshake--
			}
		}
	}
	if len(t.open) >= MaxSessions || t.handshake >= MaxHandshakes {
		return false
	}
	burst := 2 * NewSessionsPerSecond
	if t.last.IsZero() {
		t.tokens = burst
	} else {
		t.tokens = min(burst, t.tokens+now.Sub(t.last).Seconds()*NewSessionsPerSecond)
	}
	t.last = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	t.open[id] = &sessionEntry{state: sessionPending, since: now}
	t.handshake++
	return true
}

// add takes a session KCP accepted; false: it was not admitted (or its
// admission expired), close it.
func (t *sessionTable) add(id turbotunnel.ClientID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.open[id]
	if !ok || e.state != sessionPending {
		return false
	}
	e.state, e.since = sessionHandshake, time.Now()
	return true
}

func (t *sessionTable) established(id turbotunnel.ClientID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.open[id]; ok && e.state != sessionEstablished {
		e.state = sessionEstablished
		t.handshake--
	}
}

func (t *sessionTable) remove(id turbotunnel.ClientID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.open[id]; ok {
		if e.state != sessionEstablished {
			t.handshake--
		}
		delete(t.open, id)
	}
}

// sessionConn is what KCP writes to: output for a ClientID outside the
// table (a session refused, or closed: Close flushes its last ACKs) is
// dropped instead of making queues for it.
type sessionConn struct {
	*turbotunnel.QueuePacketConn
	sessions *sessionTable
}

func (c sessionConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if id, ok := addr.(turbotunnel.ClientID); ok && !c.sessions.has(id) {
		return len(p), nil
	}
	return c.QueuePacketConn.WriteTo(p, addr)
}

var (
	errHandshakeTooLong = errors.New("first Noise message too long")
	errHandshakeTimeout = errors.New("no Noise handshake in time")
)

// handshakeReader refuses a first Noise message longer than
// maxHandshakeMessage before noise.NewServer allocates it.
type handshakeReader struct {
	io.ReadWriteCloser // the KCP session
	head               [2]byte
	n                  int
}

func (r *handshakeReader) Read(p []byte) (int, error) {
	k, err := r.ReadWriteCloser.Read(p)
	for i := 0; i < k && r.n < 2; i++ {
		r.head[r.n] = p[i]
		r.n++
		if r.n == 2 && int(binary.BigEndian.Uint16(r.head[:])) > maxHandshakeMessage {
			return 0, errHandshakeTooLong
		}
	}
	return k, err
}

var _ io.ReadWriteCloser = (*handshakeReader)(nil)

// limitedLog is log.Printf for lines a query can cause (neko): at most
// logBurst lines per logEvery, then one line with the number left out.
// dnstt logged one line for every malformed query and every session.
type limitedLog struct {
	mu      sync.Mutex
	start   time.Time
	n       int
	dropped int
}

const (
	logEvery = 10 * time.Second
	logBurst = 20
)

var queryLog limitedLog

func (l *limitedLog) Printf(format string, args ...any) {
	l.mu.Lock()
	now := time.Now()
	if now.Sub(l.start) >= logEvery {
		if l.dropped > 0 {
			log.Printf("(%d similar lines left out in %s)", l.dropped, now.Sub(l.start).Round(time.Second))
		}
		l.start, l.n, l.dropped = now, 0, 0
	}
	if l.n >= logBurst {
		l.dropped++
		l.mu.Unlock()
		return
	}
	l.n++
	l.mu.Unlock()
	log.Printf(format, args...)
}
