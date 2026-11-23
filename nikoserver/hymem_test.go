//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	M "github.com/sagernet/sing/common/metadata"
)

// hy2Seen is what a raw client learns of the server: its transport
// parameters.
type hy2Seen struct {
	mu     sync.Mutex
	params *qlog.ParametersSet
}

func (s *hy2Seen) AddProducer() qlogwriter.Recorder { return s }
func (s *hy2Seen) SupportsSchemas(string) bool      { return true }
func (s *hy2Seen) Close() error                     { return nil }

func (s *hy2Seen) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.ParametersSet); ok && p.Initiator == qlog.InitiatorRemote {
		s.mu.Lock()
		s.params = &p
		s.mu.Unlock()
	}
}

// delayedConn holds each datagram the client sends for delay: the
// server's view of the round trip, and of how late the client's ACKs come.
// With drop set it sends nothing at all: a client that stopped
// acknowledging.
type delayedConn struct {
	net.PacketConn
	delay time.Duration
	q     chan hyDelayed
	drop  atomic.Bool
}

type hyDelayed struct {
	at   time.Time
	b    []byte
	addr net.Addr
}

func newDelayedConn(pc net.PacketConn, delay time.Duration) *delayedConn {
	c := &delayedConn{PacketConn: pc, delay: delay, q: make(chan hyDelayed, 1<<16)}
	go func() {
		for d := range c.q {
			time.Sleep(time.Until(d.at))
			_, _ = c.PacketConn.WriteTo(d.b, d.addr)
		}
	}()
	return c
}

func (c *delayedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(b), nil
	}
	if c.delay == 0 {
		return c.PacketConn.WriteTo(b, addr)
	}
	c.q <- hyDelayed{time.Now().Add(c.delay), append([]byte(nil), b...), addr}
	return len(b), nil
}

// rawHy2 is a Hysteria2 client on quic-go of its own: its TLS groups, its
// windows and the delay of what it sends are the test's.
type rawHy2 struct {
	conn *quic.Conn
	h3   *http3.ClientConn
	seen *hy2Seen
	out  *delayedConn
}

func dialRawHy2(t *testing.T, ctx context.Context, server M.Socksaddr, curves []tls.CurveID, delay time.Duration) (*rawHy2, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := newDelayedConn(pc, delay)
	tr := &quic.Transport{Conn: out}
	t.Cleanup(func() { tr.Close(); pc.Close() })
	seen := &hy2Seen{}
	conf := &quic.Config{MaxIdleTimeout: 30 * time.Second,
		// A reader that keeps up, whatever the server's flight.
		InitialStreamReceiveWindow: 64 << 20, MaxStreamReceiveWindow: 64 << 20,
		InitialConnectionReceiveWindow: 64 << 20, MaxConnectionReceiveWindow: 64 << 20,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return seen }}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(dctx, net.UDPAddrFromAddrPort(server.AddrPort()), &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's server
		ServerName: "h.example.com", NextProtos: []string{"h3"}, CurvePreferences: curves}, conf)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return &rawHy2{conn: conn, h3: (&http3.Transport{}).NewClientConn(conn), seen: seen, out: out}, nil
}

// auth sends Hysteria2's auth request with a password and a receive rate
// (bytes a second; 0 asks for BBR): the status it gets, 233 when taken.
func (r *rawHy2) auth(t *testing.T, password string, rx int) int {
	t.Helper()
	st, err := r.tryAuth(password, rx)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	return st
}

// tryAuth is auth that may fail: a connection closed at once.
func (r *rawHy2) tryAuth(password string, rx int) (int, error) {
	req, _ := http.NewRequest(http.MethodPost, "https://hysteria/auth", nil)
	req.Header.Set("Hysteria-Auth", password)
	req.Header.Set("Hysteria-CC-RX", strconv.Itoa(rx))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.h3.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// stream opens a stream to addr: Hysteria2's TCP request, no padding.
// With addr "" it sends the frame's type alone, and waits.
func (r *rawHy2) stream(t *testing.T, addr string) *quic.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := r.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := quicvarint.Append(nil, 0x401)
	if addr != "" {
		b = quicvarint.Append(b, uint64(len(addr)))
		b = append(b, addr...)
		b = quicvarint.Append(b, 0)
	}
	if _, err := s.Write(b); err != nil {
		t.Fatal(err)
	}
	return s
}

// hy2MasqTLS starts a hy2-masq backend with a user and the default budget.
func hy2MasqNode(t *testing.T, ctx context.Context, lim *hyLimits, mem *hyMem, pairs ...string) *hy2Node {
	t.Helper()
	if lim == nil {
		lim = newHyLimits()
	}
	return startHy2MasqMem(t, ctx, NewLogger("warn", io.Discard), lim, mem, nil, pairs...)
}

// hy2-masq takes the handshake the site on its address takes, Go's
// groups, and a password only over X25519MLKEM768: a client without
// ML-KEM completes the handshake and gets the masquerade for a page and for
// the right password, as for a wrong one. Before v0.19.3 its handshake
// failed, while the site's under the same certificate went through.
func TestHysteriaMasqTLSAsTheSite(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := hy2MasqNode(t, ctx, nil, nil, "u1", "password-one")
	for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384} {
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{curve}, 0)
		if err != nil {
			t.Errorf("%v: the handshake failed: %v", curve, err)
			continue
		}
		if got := r.conn.ConnectionState().TLS.CurveID; got != curve {
			t.Errorf("%v: the handshake took %v", curve, got)
		}
		if st := r.auth(t, "password-one", 0); st != http.StatusNotFound {
			t.Errorf("%v: the right password got %d, want the masquerade's 404", curve, st)
		}
	}
	r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.auth(t, "not-a-password", 0); st != http.StatusNotFound {
		t.Errorf("X25519MLKEM768, a wrong password: %d", st)
	}
	if st := r.auth(t, "password-one", 0); st != 233 {
		t.Errorf("X25519MLKEM768, the right password: %d, want 233", st)
	}
	// A client offering both gets X25519MLKEM768 (Go's server takes a PQ
	// group first): Niko's clients, as before.
	r, err = dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519, tls.X25519MLKEM768}, 0)
	if err != nil || r.conn.ConnectionState().TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("X25519 and X25519MLKEM768: %v %v", err, r.conn.ConnectionState().TLS.CurveID)
	}
}

// hy2-obfs keeps the strict handshake: behind salamander no stranger sees
// one, and the users' clients offer X25519MLKEM768.
func TestHysteriaObfsTLSStrict(t *testing.T) {
	o, curve := hysteriaTLS(&BackendConfig{Kind: "hy2-obfs", TLS: &BackendTLS{}})
	if len(o.CurvePreferences) != 1 || tls.CurveID(o.CurvePreferences[0]) != tls.X25519MLKEM768 || curve != 0 {
		t.Fatalf("hy2-obfs: curves %v, auth curve %v", o.CurvePreferences, curve)
	}
	o, curve = hysteriaTLS(&BackendConfig{Kind: "hy2-masq", TLS: &BackendTLS{}})
	if len(o.CurvePreferences) != 0 || curve != tls.X25519MLKEM768 {
		t.Fatalf("hy2-masq: curves %v, auth curve %v", o.CurvePreferences, curve)
	}
}

// The server's receive windows start at quic-go's, 512 KiB a stream and
// 768 KiB a connection, not at Hysteria's 8 and 20 MiB: what any client
// sees in the transport parameters, and what one that never has its data
// read holds of the server's memory a connection, its budget aside.
func TestHysteriaWindowsStartSmall(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := hy2MasqNode(t, ctx, nil, nil, "u1", "password-one")
	r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.seen.mu.Lock()
	p := r.seen.params
	r.seen.mu.Unlock()
	if p == nil {
		t.Fatal("no transport parameters seen")
	}
	if p.InitialMaxData != hyConnWindow || p.InitialMaxStreamDataBidiRemote != hyStreamWindow {
		t.Fatalf("initial_max_data %d, initial_max_stream_data_bidi_remote %d: want %d and %d",
			p.InitialMaxData, p.InitialMaxStreamDataBidiRemote, hyConnWindow, hyStreamWindow)
	}
}

// sinkTarget is a TCP destination that reads all and says nothing, or
// (feed) writes without end and reads nothing; it counts what it read.
func sinkTarget(t *testing.T, feed bool) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if feed {
					b := make([]byte, 64<<10)
					for {
						if _, err := c.Write(b); err != nil {
							return
						}
					}
				}
				b := make([]byte, 64<<10)
				for {
					k, err := c.Read(b)
					n.Add(int64(k))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), &n
}

// memState is the budget's count, the user's and the connections'.
func (m *hyMem) state() (grown int64, by map[string]int64, conns int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	by = map[string]int64{}
	for k, v := range m.grownBy {
		by[k] = v
	}
	return m.grown, by, len(m.conns)
}

// waitReleased waits for every connection to give back what it took.
func waitReleased(t *testing.T, m *hyMem) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		grown, by, conns := m.state()
		m.mu.Lock()
		recv, recvBy := m.recvAll, len(m.recvBy)
		m.mu.Unlock()
		if grown == 0 && len(by) == 0 && conns == 0 && recv == 0 && recvBy == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the connections: %d taken, %v by user, %d connections, %d of windows", grown, by, conns, recv)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := m.overReleased.Load(); n != 0 {
		t.Fatalf("%d releases past what was taken", n)
	}
}

// flightOf is what the user's connections hold past their floors as their
// senders last saw it, each the more of its limit and its flight, and the
// user's take of the budget.
func (m *hyMem) flightOf(user string) (held, took int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		if c.user == user && c.sender != nil {
			held += max(c.sender.limit.Load(), c.sender.inFlight.Load()) - hySendFloor
		}
	}
	return held, m.grownBy[user]
}

// An upload whose reader keeps up grows the connection's window past its
// floor, from the budget, never past half the user's share; the bytes come
// back when the connection ends. A budget that has them lets it grow
// further: the share, not quic-go, is what stopped it.
func TestHysteriaUploadWindowWithinBudget(t *testing.T) {
	for _, c := range []struct {
		name   string
		budget int64
		size   int
	}{{"small", 16 << 20, 8 << 20}, {"large", 1 << 30, 16 << 20}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mem := newHyMem(c.budget, nil)
			node := hy2MasqNode(t, ctx, nil, mem, "u1", "password-one")
			to, read := sinkTarget(t, false)
			r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 20*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if st := r.auth(t, "password-one", 0); st != 233 {
				t.Fatalf("auth %d", st)
			}
			s := r.stream(t, to)
			var most atomic.Int64
			done := make(chan struct{})
			go func() {
				defer close(done)
				for ctx.Err() == nil {
					time.Sleep(5 * time.Millisecond)
					if _, by, _ := mem.state(); by["u1"] > most.Load() {
						most.Store(by["u1"])
					}
				}
			}()
			b := make([]byte, 64<<10)
			s.SetWriteDeadline(time.Now().Add(60 * time.Second))
			for sent := 0; sent < c.size; sent += len(b) {
				if _, err := s.Write(b); err != nil {
					t.Fatal(err)
				}
			}
			for deadline := time.Now().Add(30 * time.Second); read.Load() < int64(c.size)-(1<<20) && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			<-done
			half := c.budget / hyMemShares / 2
			t.Logf("budget %d MiB: the user took %d KiB at most; %d MiB read", c.budget>>20, most.Load()>>10, read.Load()>>20)
			switch {
			case most.Load() > half:
				t.Errorf("the user's windows took %d, past half its share %d", most.Load(), half)
			case c.name == "small" && most.Load() == 0:
				t.Error("the window never grew: the budget was not asked")
			case c.name == "large" && most.Load() <= 16<<20/hyMemShares/2:
				t.Errorf("with a large budget the window grew by %d only", most.Load())
			}
			r.conn.CloseWithError(0, "")
			waitReleased(t, mem)
		})
	}
}

// download reads what from sends through r for d: the bytes, and the most
// the user's connections held past their floors, and took, meanwhile.
func download(t *testing.T, r *rawHy2, mem *hyMem, from string, d time.Duration) (n, held, took int64) {
	t.Helper()
	s := r.stream(t, from)
	stop := time.Now().Add(d)
	b := make([]byte, 64<<10)
	for time.Now().Before(stop) {
		s.SetReadDeadline(stop)
		k, err := s.Read(b)
		n += int64(k)
		h, g := mem.flightOf("u1")
		held, took = max(held, h), max(took, g)
		if err != nil {
			break
		}
	}
	return n, held, took
}

// A client that holds its ACKs (here 150 ms), asking Brutal for 50 MB/s,
// gets no more in flight than the floor and its share of the budget: its
// download goes at that over its round trip, where before Brutal's window
// (rate × RTT × 2) kept tens of MiB of the server's memory in flight. With
// a budget that has room the same client goes much faster.
func TestHysteriaFlightWithinBudget(t *testing.T) {
	const delay = 150 * time.Millisecond
	var got [2]int64
	t.Run("budgets", func(t *testing.T) {
		for i, budget := range []int64{4 << 20, 1 << 30} {
			t.Run(strconv.Itoa(int(budget>>20)), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				mem := newHyMem(budget, nil)
				node := hy2MasqNode(t, ctx, nil, mem, "u1", "password-one")
				from, _ := sinkTarget(t, true)
				r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, delay)
				if err != nil {
					t.Fatal(err)
				}
				if st := r.auth(t, "password-one", 50e6); st != 233 {
					t.Fatalf("auth %d", st)
				}
				n, held, took := download(t, r, mem, from, time.Second)
				got[i] = n
				t.Logf("budget %d MiB: %d MiB in 1 s, the user took %d KiB at most", budget>>20, n>>20, took>>10)
				if share := budget / hyMemShares; held > share+64<<10 || took > share {
					t.Errorf("the user held %d past the floors and took %d, its share %d", held, took, share)
				}
				r.conn.CloseWithError(0, "")
				waitReleased(t, mem)
			})
		}
	})
	// At most floor + share in flight a round trip: (1 + 0.5) MiB / 0.15 s,
	// 10 MiB in 1 s; half again for the first round trips.
	if limit := int64(hySendFloor+(4<<20)/hyMemShares) * 10 * 3 / 2; got[0] > limit {
		t.Errorf("small budget: %d MiB in 1 s, past %d MiB", got[0]>>20, limit>>20)
	}
	if got[1] < 2*got[0] {
		t.Errorf("large budget: %d MiB, small: %d MiB: the budget was not what held it", got[1]>>20, got[0]>>20)
	}
}

// A client that stops acknowledging (it sends nothing at all) keeps what
// the server sent it in flight, and that flight stays counted, however long
// the sender has been blocked: another connection of the same user gets
// nothing of the share it holds. Before, after a second without sending
// the blocked connection gave its take back, and the user held the floors
// and two shares.
func TestHysteriaFlightUnackedStaysCounted(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := newHyMem(4<<20, nil) // a share of 512 KiB
	share := int64(4<<20) / hyMemShares
	node := hy2MasqNode(t, ctx, nil, mem, "u1", "password-one")
	from, _ := sinkTarget(t, true)
	// 50 MB/s over 50 ms: 2.5 MB in flight, past the floor and the share.
	first, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if st := first.auth(t, "password-one", 50e6); st != 233 {
		t.Fatalf("auth %d", st)
	}
	s := first.stream(t, from)
	go func() { _, _ = io.Copy(io.Discard, s) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, took := mem.flightOf("u1"); took >= share {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first download never took the share")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// No ACK from here on. quic-go's probes for the lost flight go at a
	// backed-off PTO, a second and more apart after some 3 s.
	first.out.drop.Store(true)
	time.Sleep(3 * time.Second)
	second, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if st := second.auth(t, "password-one", 50e6); st != 233 {
		t.Fatalf("auth %d", st)
	}
	n, held, took := download(t, second, mem, from, 2*time.Second)
	t.Logf("the second: %d KiB; the user held %d KiB past the floors, took %d KiB", n>>10, held>>10, took>>10)
	// The first's flight past its floor is the share; PTO probes may add a
	// few packets to it.
	if held > share+64<<10 {
		t.Errorf("the user held %d past its floors, its share %d", held, share)
	}
	if n == 0 {
		t.Error("the second connection got nothing: not even its floor")
	}
}

// A user's connections at once in a backend are bounded, all its
// credentials together. A newcomer replaces the quietest connection of its
// own credential first (a device that reconnected); else one of the user's
// others unheard for hy2UnheardAfter; else it is refused. Each is counted
// (conns), and other users' connections go on.
func TestHysteriaConnsPerUser(t *testing.T) {
	setVar(t, &usersLookEvery, 100*time.Millisecond)
	setVar(t, &hy2UnheardAfter, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.conns = 2
	node := hy2MasqNode(t, ctx, lim, nil, "u1", "pw-1", "u1-ab12", "pw-2", "u1-cd34", "pw-3", "u2", "pw-u2")
	to, _ := sinkTarget(t, false)
	dial := func(password string) (*rawHy2, bool) {
		t.Helper()
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		st, err := r.tryAuth(password, 0)
		return r, err == nil && st == 233
	}
	// busy keeps a connection heard from: a write every 20 ms until stop.
	busy := func(r *rawHy2) (stop func()) {
		s := r.stream(t, to)
		quit := make(chan struct{})
		go func() {
			for {
				select {
				case <-quit:
					return
				case <-time.After(20 * time.Millisecond):
				}
				if _, err := s.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
		return sync.OnceFunc(func() { close(quit) })
	}
	closed := func(r *rawHy2, within time.Duration) bool {
		select {
		case <-r.conn.Context().Done():
			return true
		case <-time.After(within):
			return false
		}
	}
	conns := func() int64 { return node.traffic(t).Limit["u1"]["conns"] }
	other, _ := dial("pw-u2")
	a, _ := dial("pw-1")
	defer busy(a)()
	b, _ := dial("pw-2")
	stopB := busy(b)
	// A newcomer of b's credential: b gives way, live as it is.
	c, ok := dial("pw-2")
	if !ok || !closed(b, 2*time.Second) || closed(a, 0) || closed(c, 0) {
		t.Fatalf("a newcomer of b's credential: admitted %v, b closed %v, a %v", ok, closed(b, 0), closed(a, 0))
	}
	stopB()
	stopC := busy(c)
	// A third credential, both of the others heard: refused.
	if d, ok := dial("pw-3"); ok && !closed(d, 2*time.Second) {
		t.Fatal("a newcomer admitted while all the user's connections are heard")
	}
	if closed(a, 0) || closed(c, 0) || conns() != 2 {
		t.Fatalf("after a refusal: a closed %v, c closed %v, conns %d", closed(a, 0), closed(c, 0), conns())
	}
	// c falls silent: once unheard for hy2UnheardAfter it gives way.
	stopC()
	time.Sleep(hy2UnheardAfter + 3*usersLookEvery)
	e, ok := dial("pw-3")
	if !ok || !closed(c, 2*time.Second) || closed(a, 0) || closed(e, 0) {
		t.Fatalf("after c's silence: admitted %v, c closed %v, a closed %v", ok, closed(c, 0), closed(a, 0))
	}
	if closed(other, 0) || conns() != 3 {
		t.Fatalf("u2's closed %v, conns %d", closed(other, 0), conns())
	}
}

// A user's streams waiting for their request are bounded, all its
// connections together, and each waits hy2RequestWait at most: one past
// the limit is reset at once, counted (pending), and those waiting are
// reset when their time is up.
func TestHysteriaPendingStreams(t *testing.T) {
	setVar(t, &hy2RequestWait, 500*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.pending = 2
	node := hy2MasqNode(t, ctx, lim, nil, "u1", "password-one")
	r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.auth(t, "password-one", 0); st != 233 {
		t.Fatalf("auth %d", st)
	}
	a, b := r.stream(t, ""), r.stream(t, "")
	time.Sleep(100 * time.Millisecond) // both taken
	c := r.stream(t, "")
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var se *quic.StreamError
	if _, err := c.Read(make([]byte, 1)); !errors.As(err, &se) {
		t.Fatalf("a third stream waiting for its request was not reset: %v", err)
	}
	if n := node.traffic(t).Limit["u1"]["pending"]; n != 1 {
		t.Errorf("pending refused: %d, want 1", n)
	}
	// Their time up, the server gives them up: its side ends (a FIN, or a
	// reset), and their reading is stopped.
	for name, s := range map[string]*quic.Stream{"the first": a, "the second": b} {
		s.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := s.Read(make([]byte, 1))
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("%s stream waited past hy2RequestWait: %v", name, err)
		}
	}
	// Their places are back: a stream with its request goes through.
	to, read := sinkTarget(t, false)
	s := r.stream(t, to)
	s.Write([]byte("x"))
	for deadline := time.Now().Add(5 * time.Second); read.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("a stream with its request after the others' wait: nothing reached the destination")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Streams sent right behind the auth request, as a client does that does
// not wait for the answer, are its user's once it is authenticated: under
// -race the service's state of the connection is read by them while the
// auth request writes it (it was a bool and a user apart, and a stream
// could see the one without the other).
func TestHysteriaStreamsBehindAuth(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := hy2MasqNode(t, ctx, nil, nil, "u1", "password-one")
	to, read := sinkTarget(t, false)
	for range 3 {
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		authed := make(chan int, 1)
		go func() {
			st, _ := r.tryAuth("password-one", 0)
			authed <- st
		}()
		for range 20 {
			s := r.stream(t, to)
			s.Write([]byte("x"))
		}
		if st := <-authed; st != 233 {
			t.Fatalf("auth %d", st)
		}
		s := r.stream(t, to)
		s.Write([]byte("y"))
	}
	for deadline := time.Now().Add(5 * time.Second); read.Load() < 3; {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes reached the destination", read.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeCC is a congestion controller of a fixed window.
type fakeCC struct {
	congestion.CongestionControl
	cwnd congestion.ByteCount
}

func (f *fakeCC) CanSend(bytesInFlight congestion.ByteCount) bool { return bytesInFlight < f.cwnd }
func (f *fakeCC) GetCongestionWindow() congestion.ByteCount       { return f.cwnd }
func (f *fakeCC) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}
func (f *fakeCC) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

// The accounting alone. A receive window's growth is all or nothing within
// half the user's share (the windows never give back while their
// connection lives); what a connection took before its user was known
// moves to the user; a sender takes in steps up to its controller's
// window, and when short asks no more for hyMemShortFor. When another of
// its user's is short, a sender gives back what it holds past its window
// and its flight, its flight never; and a connection's end gives all back,
// once.
func TestHyMemAccounting(t *testing.T) {
	m := newHyMem(8<<20, nil) // shares of 1 MiB, windows half of that
	end1, end2 := make(chan struct{}), make(chan struct{})
	if !m.growRecv(end1, 512<<10) {
		t.Fatal("a window's growth within half the share of the unauthenticated")
	}
	if m.growRecv(end1, 128<<10) {
		t.Fatal("a window's growth past half the share taken")
	}
	m.setUser(end1, "u1")
	if _, by, _ := m.state(); by["u1"] != 512<<10 || by[""] != 0 || m.recvBy["u1"] != 512<<10 {
		t.Fatalf("after its user is known: %v, windows %v", by, m.recvBy)
	}
	cc := &fakeCC{cwnd: 8 << 20}
	s := m.sender(end1, "u1", cc)
	if !s.CanSend(hySendFloor-1) || s.limit.Load() != hySendFloor {
		t.Fatal("under the floor: no budget asked")
	}
	if !s.CanSend(hySendFloor) || s.limit.Load() != hySendFloor+256<<10 {
		t.Fatalf("at the floor: limit %d, want a step of 256 KiB", s.limit.Load())
	}
	if !s.CanSend(hySendFloor+256<<10) || s.limit.Load() != hySendFloor+512<<10 {
		t.Fatalf("at the next step: limit %d, want the share's last 256 KiB", s.limit.Load())
	}
	// Short (it asked 320 KiB, got 256): the next asks wait hyMemShortFor.
	takes := m.takes.Load()
	for range 1000 {
		if s.CanSend(hySendFloor + 512<<10) {
			t.Fatal("past the share: sent")
		}
	}
	if n := m.takes.Load() - takes; n != 0 {
		t.Fatalf("a short sender at its limit asked the budget %d times in a row", n)
	}
	// Another of u1's is short: s's flight is at its limit and its window
	// above: it keeps all.
	s2 := m.sender(end2, "u1", &fakeCC{cwnd: 8 << 20})
	m.mu.Lock()
	m.reclaimedBy["u1"] = time.Time{}
	m.mu.Unlock()
	if s2.CanSend(hySendFloor) || s.limit.Load() != hySendFloor+512<<10 {
		t.Fatalf("a busy sender gave back: limit %d", s.limit.Load())
	}
	// s stops: no ACK comes, and it sends nothing for hyMemIdle. Its flight
	// stays counted.
	s.lastSent.Store(int64(monotime.Now().Add(-2 * hyMemIdle)))
	m.mu.Lock()
	m.reclaimedBy["u1"] = time.Time{}
	m.mu.Unlock()
	s2.shortUntil.Store(0)
	if s2.CanSend(hySendFloor) || s.limit.Load() != hySendFloor+512<<10 {
		t.Fatalf("a sender whose flight is unacknowledged gave it back: limit %d", s.limit.Load())
	}
	// Its flight acknowledged but 128 KiB, its window down to it: it gives
	// back the rest, though not idle.
	s.lastSent.Store(int64(monotime.Now()))
	s.OnPacketAcked(1, 384<<10, hySendFloor+512<<10, monotime.Now())
	cc.cwnd = hySendFloor + 128<<10
	s.CanSend(hySendFloor + 128<<10)
	m.mu.Lock()
	m.reclaimedBy["u1"] = time.Time{}
	m.mu.Unlock()
	s2.shortUntil.Store(0)
	s2.CanSend(hySendFloor) // short: s gives back
	if s.limit.Load() != hySendFloor+128<<10 {
		t.Fatalf("past its window and flight it kept %d", s.limit.Load()-hySendFloor)
	}
	s2.shortUntil.Store(0)
	if !s2.CanSend(hySendFloor) || s2.limit.Load() <= hySendFloor {
		t.Fatal("after the give back the other got nothing")
	}
	close(end1)
	close(end2)
	waitReleased(t, m)
	if s.limit.Load() != hySendFloor {
		t.Fatal("an ended connection's sender past the floor")
	}
}

// Streams that send a byte of a frame type and stop are read
// hy2PendingStreams at a time, each for hy2RequestWait at most, before a
// password as after one: 130 of them hold no 130 goroutines, are reset when
// their time is up, and a request after them is answered. Before v0.19.3
// each held a goroutine until the connection ended.
func TestHysteriaStreamsWithoutAFrame(t *testing.T) {
	setVar(t, &hy2RequestWait, 250*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := hy2MasqNode(t, ctx, nil, nil, "u1", "password-one")
	for _, authed := range []bool{false, true} {
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if authed && r.auth(t, "password-one", 0) != 233 {
			t.Fatal("auth")
		}
		before := runtime.NumGoroutine()
		var streams []*quic.Stream
		for range 130 {
			s, err := r.conn.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			s.Write([]byte{0x44}) // the first byte of 0x401's varint
			streams = append(streams, s)
		}
		time.Sleep(150 * time.Millisecond)
		if grew := runtime.NumGoroutine() - before; grew > 100 {
			t.Errorf("authenticated %v: %d goroutines for 130 streams without a frame", authed, grew)
		}
		ended, deadline := 0, time.Now().Add(10*time.Second)
		for _, s := range streams {
			s.SetReadDeadline(deadline)
			_, err := s.Read(make([]byte, 1))
			var se *quic.StreamError
			if errors.As(err, &se) {
				ended++
			}
		}
		if ended != len(streams) {
			t.Errorf("authenticated %v: %d of %d reset", authed, ended, len(streams))
		}
		if st := r.auth(t, "password-one", 0); st != 233 {
			t.Errorf("authenticated %v: a request after them: %d", authed, st)
		}
	}
}
