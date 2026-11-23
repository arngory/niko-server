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
type delayedConn struct {
	net.PacketConn
	delay time.Duration
	q     chan hyDelayed
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
}

func dialRawHy2(t *testing.T, ctx context.Context, server M.Socksaddr, curves []tls.CurveID, delay time.Duration) (*rawHy2, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: newDelayedConn(pc, delay)}
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
	return &rawHy2{conn: conn, h3: (&http3.Transport{}).NewClientConn(conn), seen: seen}, nil
}

// auth sends Hysteria2's auth request with a password and a receive rate
// (bytes a second; 0 asks for BBR): the status it gets, 233 when taken.
func (r *rawHy2) auth(t *testing.T, password string, rx int) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://hysteria/auth", nil)
	req.Header.Set("Hysteria-Auth", password)
	req.Header.Set("Hysteria-CC-RX", strconv.Itoa(rx))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.h3.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
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
		if grown == 0 && len(by) == 0 && conns == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the connections: %d taken, %v by user, %d connections", grown, by, conns)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := m.overReleased.Load(); n != 0 {
		t.Fatalf("%d releases past what was taken", n)
	}
}

// An upload whose reader keeps up grows the connection's window past its
// floor, from the budget, never past the user's share; the bytes come back
// when the connection ends. A budget that has them lets it grow further:
// the share, not quic-go, is what stopped it.
func TestHysteriaUploadWindowWithinBudget(t *testing.T) {
	for _, c := range []struct {
		name   string
		budget int64
	}{{"small", 8 << 20}, {"large", 1 << 30}} {
		t.Run(c.name, func(t *testing.T) {
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
			var most int64
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-time.After(5 * time.Millisecond):
					case <-ctx.Done():
						return
					}
					if _, by, _ := mem.state(); by["u1"] > most {
						most = by["u1"]
					}
				}
			}()
			const size = 48 << 20
			b := make([]byte, 64<<10)
			s.SetWriteDeadline(time.Now().Add(60 * time.Second))
			for sent := 0; sent < size; sent += len(b) {
				if _, err := s.Write(b); err != nil {
					t.Fatal(err)
				}
			}
			for deadline := time.Now().Add(30 * time.Second); read.Load() < size-(1<<20) && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			<-done
			share := c.budget / hyMemShares
			t.Logf("budget %d MiB: the user took %d KiB at most; %d MiB read", c.budget>>20, most>>10, read.Load()>>20)
			switch {
			case most > share:
				t.Errorf("the user took %d, past its share %d", most, share)
			case c.name == "small" && most == 0:
				t.Error("the window never grew: the budget was not asked")
			case c.name == "large" && most <= 8<<20/hyMemShares:
				t.Errorf("with a large budget the window grew by %d only", most)
			}
			r.conn.CloseWithError(0, "")
			waitReleased(t, mem)
		})
	}
}

// A client that holds its ACKs (here 300 ms), asking Brutal for 50 MB/s,
// gets no more in flight than the floor and its share of the budget: its
// download goes at that over its round trip, where before Brutal's window
// (rate × RTT × 2) kept tens of MiB of the server's memory in flight. With
// a budget that has room the same client goes much faster.
func TestHysteriaFlightWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("two downloads of 2 s")
	}
	got := map[string]int64{}
	for _, c := range []struct {
		name   string
		budget int64
	}{{"small", 4 << 20}, {"large", 1 << 30}} {
		ctx, cancel := context.WithCancel(context.Background())
		mem := newHyMem(c.budget, nil)
		node := hy2MasqNode(t, ctx, nil, mem, "u1", "password-one")
		from, _ := sinkTarget(t, true)
		const delay = 300 * time.Millisecond
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, delay)
		if err != nil {
			t.Fatal(err)
		}
		if st := r.auth(t, "password-one", 50e6); st != 233 {
			t.Fatalf("auth %d", st)
		}
		s := r.stream(t, from)
		var most int64
		stop := time.Now().Add(2 * time.Second)
		b := make([]byte, 64<<10)
		var n int64
		for time.Now().Before(stop) {
			s.SetReadDeadline(stop)
			k, err := s.Read(b)
			n += int64(k)
			if _, by, _ := mem.state(); by["u1"] > most {
				most = by["u1"]
			}
			if err != nil {
				break
			}
		}
		got[c.name] = n
		t.Logf("budget %d MiB: %d MiB in 2 s, the user took %d KiB at most", c.budget>>20, n>>20, most>>10)
		if share := c.budget / hyMemShares; most > share {
			t.Errorf("%s: the user took %d, past its share %d", c.name, most, share)
		}
		r.conn.CloseWithError(0, "")
		waitReleased(t, mem)
		cancel()
	}
	// At most floor + share in flight a round trip: (1 + 0.5) MiB / 0.3 s,
	// 10 MiB in 2 s; half again for the first round trips.
	if limit := int64(hySendFloor+(4<<20)/hyMemShares) * 2 * 10 / 3 * 3 / 2; got["small"] > limit {
		t.Errorf("small budget: %d MiB in 2 s, past %d MiB", got["small"]>>20, limit>>20)
	}
	if got["large"] < 2*got["small"] {
		t.Errorf("large budget: %d MiB, small: %d MiB: the budget was not what held it", got["large"]>>20, got["small"]>>20)
	}
}

// A user's connections at once in a backend are bounded, all its
// credentials together: past the limit the one heard from longest ago
// gives way, counted (conns), and the others of the user and other users'
// go on.
func TestHysteriaConnsPerUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.conns = 2
	node := hy2MasqNode(t, ctx, lim, nil, "u1", "password-one", "u1-ab12", "password-two", "u2", "password-three")
	to, _ := sinkTarget(t, false)
	dial := func(password string) *rawHy2 {
		t.Helper()
		r, err := dialRawHy2(t, ctx, node.server, []tls.CurveID{tls.X25519MLKEM768}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if st := r.auth(t, password, 0); st != 233 {
			t.Fatalf("auth %d", st)
		}
		return r
	}
	busy := dial("password-one")
	quiet := dial("password-two") // u1 too
	other := dial("password-three")
	// The watch looks every 5 s: by its next look the quiet one's last
	// packets are counted, and none come after.
	s := busy.stream(t, to)
	stopBusy := make(chan struct{})
	go func() {
		b := make([]byte, 1024)
		for {
			select {
			case <-stopBusy:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := s.Write(b); err != nil {
				return
			}
		}
	}()
	defer close(stopBusy)
	time.Sleep(6 * time.Second)
	third := dial("password-one")
	closed := func(r *rawHy2, within time.Duration) bool {
		select {
		case <-r.conn.Context().Done():
			return true
		case <-time.After(within):
			return false
		}
	}
	if !closed(quiet, 3*time.Second) {
		t.Fatal("the quiet connection of u1 stayed: three at once")
	}
	for name, r := range map[string]*rawHy2{"the busy one": busy, "the new one": third, "u2's": other} {
		if closed(r, 0) {
			t.Errorf("%s closed", name)
		}
	}
	if n := node.traffic(t).Limit["u1"]["conns"]; n != 1 {
		t.Errorf("conns refused: %d, want 1 (%v)", n, node.traffic(t).Limit)
	}
}

// A user's streams waiting for their request are bounded, all its
// connections together, and each waits hy2RequestWait at most: one past
// the limit is reset at once, counted (pending), and those waiting are
// reset when their time is up.
func TestHysteriaPendingStreams(t *testing.T) {
	setVar(t, &hy2RequestWait, time.Second)
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
	reset := func(s *quic.Stream, within time.Duration) bool {
		s.SetReadDeadline(time.Now().Add(within))
		_, err := s.Read(make([]byte, 1))
		var se *quic.StreamError
		return errors.As(err, &se)
	}
	a, b := r.stream(t, ""), r.stream(t, "")
	time.Sleep(200 * time.Millisecond) // both taken
	c := r.stream(t, "")
	if !reset(c, 500*time.Millisecond) {
		t.Fatal("a third stream waiting for its request was not reset")
	}
	if n := node.traffic(t).Limit["u1"]["pending"]; n != 1 {
		t.Errorf("pending refused: %d, want 1", n)
	}
	// Their time up, the server gives them up: its side ends (a FIN, or a
	// reset), and their reading is stopped.
	for name, s := range map[string]*quic.Stream{"the first": a, "the second": b} {
		s.SetReadDeadline(time.Now().Add(3 * time.Second))
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

// fakeCC is a congestion controller of a fixed window.
type fakeCC struct {
	congestion.CongestionControl
	cwnd congestion.ByteCount
}

func (f *fakeCC) CanSend(bytesInFlight congestion.ByteCount) bool { return bytesInFlight < f.cwnd }
func (f *fakeCC) GetCongestionWindow() congestion.ByteCount       { return f.cwnd }
func (f *fakeCC) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}

// The accounting alone: a receive window's growth is all or nothing within
// the budget and the user's share, what a connection took before its user
// was known moves to the user, a sender takes in steps up to its
// controller's window, and one idle for hyMemIdle gives back when another
// of its user's is short; a connection's end gives all back, once.
func TestHyMemAccounting(t *testing.T) {
	m := newHyMem(8<<20, nil) // shares of 1 MiB
	end1, end2 := make(chan struct{}), make(chan struct{})
	take := func(c *hyMemConn, n int64) int64 { // as allowRecv
		m.mu.Lock()
		got, idle, warn := m.takeLocked(c, n, true)
		c.recv += got
		m.mu.Unlock()
		m.after(idle, warn)
		return got
	}
	c1 := m.conn(end1)
	if got := take(c1, 768<<10); got != 768<<10 {
		t.Fatalf("a growth within the share of the unauthenticated: %d", got)
	}
	if got := take(c1, 512<<10); got != 0 {
		t.Fatalf("a growth past the share taken: %d", got)
	}
	m.setUser(end1, "u1")
	if _, by, _ := m.state(); by["u1"] != 768<<10 || by[""] != 0 {
		t.Fatalf("after its user is known: %v", by)
	}
	s := m.sender(end1, "u1", &fakeCC{cwnd: 8 << 20})
	if !s.CanSend(hySendFloor-1) || s.limit.Load() != hySendFloor {
		t.Fatal("under the floor: no budget asked")
	}
	if !s.CanSend(hySendFloor) || s.limit.Load() != hySendFloor+256<<10 {
		t.Fatalf("at the floor: limit %d, want a step of the share's last 256 KiB", s.limit.Load())
	}
	if s.CanSend(hySendFloor + 256<<10) {
		t.Fatal("past the share: sent")
	}
	c2 := m.conn(end2)
	m.setUser(end2, "u1")
	if got := take(c2, 128<<10); got != 0 {
		t.Fatalf("u1 at its share: %d taken", got)
	}
	// Short, the sweep asked s, which sent just now: it keeps its own.
	if s.limit.Load() != hySendFloor+256<<10 {
		t.Fatal("a sender that is not idle gave back")
	}
	s.lastSent.Store(int64(monotime.Now().Add(-2 * hyMemIdle)))
	m.mu.Lock()
	m.reclaimedBy["u1"] = time.Time{}
	m.mu.Unlock()
	take(c2, 128<<10) // short again: now s is idle and gives back
	if s.limit.Load() != hySendFloor {
		t.Fatalf("an idle sender kept %d", s.limit.Load()-hySendFloor)
	}
	if got := take(c2, 128<<10); got != 128<<10 {
		t.Fatalf("after the give back: %d", got)
	}
	if _, by, conns := m.state(); by["u1"] != 768<<10+128<<10 || conns != 2 {
		t.Fatalf("%v, %d connections", by, conns)
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
// password as after one: 200 of them hold no 200 goroutines,
// are reset when their time is up, and a request after them is answered.
// Before v0.19.3 each held a goroutine until the connection ended.
func TestHysteriaStreamsWithoutAFrame(t *testing.T) {
	setVar(t, &hy2RequestWait, 500*time.Millisecond)
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
		for range 200 {
			s, err := r.conn.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			s.Write([]byte{0x44}) // the first byte of 0x401's varint
			streams = append(streams, s)
		}
		time.Sleep(300 * time.Millisecond)
		if grew := runtime.NumGoroutine() - before; grew > 120 {
			t.Errorf("authenticated %v: %d goroutines for 200 streams without a frame", authed, grew)
		}
		ended, deadline := 0, time.Now().Add(15*time.Second)
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
