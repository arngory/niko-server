//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
)

// The per-user connection limits through a real Hysteria2 client (the
// vendored sing-quic's) and the outbound driven directly (raycontrol
// docs/spec/conn-limit-v1.md §3.2, §9 item 3).

// userCtx is a stream's context with the user of a name, as sing-quic
// gives it.
func userCtx(name string) context.Context {
	return auth.ContextWithUser(context.Background(), &hy2User{name: name, traffic: new(hy2Traffic)})
}

// holdTarget is a TCP echo on loopback that holds what connects, and says
// how many did.
func holdTarget(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int32)
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String(), accepted
}

// refusedAddr is a loopback address nothing listens on.
func refusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// openStream opens a stream to a destination through the client and says
// what the node answered: nil when the echo came back (the stream is kept
// open for the test to close), the node's refusal otherwise.
func openStream(t *testing.T, ctx context.Context, client *hysteria2.Client, to string) (net.Conn, error) {
	t.Helper()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(to))
	if err != nil {
		t.Fatalf("the client's stream: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("the request: %v", err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return conn, err
	}
	if string(b) != "ping" {
		t.Fatalf("echo %q", b)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// tooMany reports whether err is the limit's refusal as a client reads it:
// the text Niko compares.
func tooMany(err error) bool {
	return err != nil && err.Error() == "remote error: too many connections"
}

// masquerade is what someone without a password gets from the node over
// HTTP/3: for a page, and for Hysteria2's auth request with a wrong
// password. Status, headers and body, as one string.
func masquerade(t *testing.T, server M.Socksaddr) string {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "h.example.com", NextProtos: []string{"h3"}}}
	defer tr.Close()
	var out strings.Builder
	for _, req := range []struct{ method, url, auth string }{
		{http.MethodGet, "https://" + server.String() + "/", ""},
		{http.MethodPost, "https://" + server.String() + "/auth", "not-a-password"},
	} {
		r, err := http.NewRequest(req.method, req.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.auth != "" {
			r.Host = "hysteria"
			r.Header.Set("Hysteria-Auth", req.auth)
			r.Header.Set("Hysteria-CC-RX", "0")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := tr.RoundTrip(r.WithContext(ctx))
		if err != nil {
			cancel()
			t.Fatalf("%s without a password: %v", req.method, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		var headers []string
		for k, v := range resp.Header {
			if k != "Date" {
				headers = append(headers, k+": "+strings.Join(v, ","))
			}
		}
		slices.Sort(headers)
		fmt.Fprintf(&out, "%s %d %q %q\n", req.method, resp.StatusCode, headers, body)
	}
	return out.String()
}

// A user at the limit of TCP at once is refused with the text the client
// knows, while another user, and the user's streams that are open, go on;
// the credentials of one user share its places; someone without a password
// sees what they saw before; and the log names neither user nor
// destination.
func TestHysteriaConnLimitTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedLog{}
	lim := newHyLimits()
	lim.n.tcp = 4
	node := startHy2MasqWith(t, ctx, NewLogger("debug", logs), lim, nil,
		"u5-1111111111111111", "pw-5a", "u5-2222222222222222", "pw-5b", "u9-3333333333333333", "pw-9")
	target, accepted := holdTarget(t)
	before := masquerade(t, node.server)
	if !strings.HasPrefix(before, "GET 404 [\"Content-Length: 0\"] \"\"\nPOST 404 ") {
		t.Fatalf("without a password: %s", before)
	}

	a, b, other := node.client(t, ctx, "pw-5a"), node.client(t, ctx, "pw-5b"), node.client(t, ctx, "pw-9")
	var held []net.Conn
	for i, c := range []*hysteria2.Client{a, a, b, b} {
		conn, err := openStream(t, ctx, c, target)
		if err != nil {
			t.Fatalf("stream %d, within the limit: %v", i, err)
		}
		held = append(held, conn)
	}
	// The fifth, on either credential: refused, with the reason.
	for _, c := range []*hysteria2.Client{a, b} {
		if _, err := openStream(t, ctx, c, target); !tooMany(err) {
			t.Fatalf("past the limit: %v", err)
		}
	}
	if n := accepted.Load(); n != 4 {
		t.Fatalf("the destination saw %d connections: a refused stream was dialed", n)
	}
	// Another user is not touched; nor are the streams that are open.
	if _, err := openStream(t, ctx, other, target); err != nil {
		t.Fatalf("another user: %v", err)
	}
	for i, conn := range held {
		echoOnce(t, conn, fmt.Sprintf("still %d", i))
	}
	// Someone without a password sees what they saw before.
	if at := masquerade(t, node.server); at != before {
		t.Fatalf("without a password, a user at its limit:\n%s\nbefore:\n%s", at, before)
	}
	// A place given back is taken again.
	held[0].Close()
	if !waitFor(5*time.Second, func() bool {
		lim.mu.Lock()
		defer lim.mu.Unlock()
		return lim.users["u5"].tcp == 3
	}) {
		t.Fatal("a closed stream kept its place")
	}
	if _, err := openStream(t, ctx, b, target); err != nil {
		t.Fatalf("after one closed: %v", err)
	}
	if got := lim.Refused(); len(got) != 1 || got["u5"][refusedTCP] != 2 || len(got["u5"]) != 1 {
		t.Fatalf("refused: %v", got)
	}
	// Off: no limit; what is open stays. On again: the limit is back.
	lim.SetConnLimit(false)
	for range 3 {
		if _, err := openStream(t, ctx, a, target); err != nil {
			t.Fatalf("off: %v", err)
		}
	}
	echoOnce(t, held[1], "open through the switch")
	if off := masquerade(t, node.server); off != before {
		t.Fatalf("without a password, the limits off:\n%s\nbefore:\n%s", off, before)
	}
	lim.SetConnLimit(true)
	if _, err := openStream(t, ctx, a, target); !tooMany(err) {
		t.Fatalf("on again: %v", err)
	}
	// The log: at debug "too many connections", and neither the user, nor
	// a password, nor the destination.
	text := logs.String()
	if !strings.Contains(text, "DEBUG too many connections") {
		t.Fatalf("the log at debug:\n%s", text)
	}
	_, port, _ := net.SplitHostPort(target)
	for _, secret := range []string{"u5", "u9", "pw-5", "pw-9", ":" + port, port, "1111111111111111", "2222222222222222"} {
		if strings.Contains(text, secret) {
			t.Fatalf("the log has %q:\n%s", secret, text)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "too many") && line != "DEBUG too many connections" {
			t.Fatalf("a line of the limits says more than it may: %q", line)
		}
	}
}

// At the normal level the process says nothing of the limits.
func TestHysteriaConnLimitQuiet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedLog{}
	lim := newHyLimits()
	lim.n.tcp = 1
	node := startHy2MasqWith(t, ctx, NewLogger("info", logs), lim, nil, "u5", "pw-5")
	target, _ := holdTarget(t)
	c := node.client(t, ctx, "pw-5")
	if _, err := openStream(t, ctx, c, target); err != nil {
		t.Fatal(err)
	}
	if _, err := openStream(t, ctx, c, target); !tooMany(err) {
		t.Fatalf("past the limit: %v", err)
	}
	if text := logs.String(); strings.Contains(text, "too many") || strings.Contains(text, "limit") {
		t.Fatalf("the log at info:\n%s", text)
	}
}

// One QUIC connection holds 2048 streams at most (sing-quic's own ceiling
// is 2^60): the client's next one fails at once.
func TestHysteriaStreamsOfAConnection(t *testing.T) {
	if hy2MaxStreams != 2048 {
		t.Fatalf("streams of a connection: %d", hy2MaxStreams)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := startHy2Masq(t, ctx, NewLogger("error", io.Discard), "u5", "pw-5")
	client := node.client(t, ctx, "pw-5")
	target, _ := holdTarget(t)
	// The connection is up, and the auth request's stream is done.
	if _, err := openStream(t, ctx, client, target); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	opened := 1
	var failure error
	for range 3000 {
		// A stream is opened here and its request not sent: the client's
		// side of QUIC counts it against what the server allowed.
		conn, err := client.DialConn(ctx, M.ParseSocksaddr(target))
		if err != nil {
			failure = err
			break
		}
		t.Cleanup(func() { conn.Close() })
		opened++
	}
	// 2048, or one fewer if the credit of the auth request's stream has
	// not come back yet.
	if failure == nil || !strings.Contains(failure.Error(), "too many open streams") || opened < 2047 || opened > 2048 {
		t.Fatalf("%d streams opened, then: %v", opened, failure)
	}
}

// Attempts and failed dials through a real client: past the burst of
// attempts a stream waits for its token, or is refused when the token is
// too far; failed dials run the user into debt, where new streams are
// refused until it is paid off; another user is not touched.
func TestHysteriaConnLimitRateAndDebt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.tcpBurst, lim.n.tcpRate, lim.n.tcpWait = 3, 0.5, 100*time.Millisecond
	node := startHy2MasqWith(t, ctx, NewLogger("error", io.Discard), lim, nil, "u5", "pw-5", "u9", "pw-9")
	target, accepted := holdTarget(t)
	c, other := node.client(t, ctx, "pw-5"), node.client(t, ctx, "pw-9")
	for i := range 3 {
		if _, err := openStream(t, ctx, c, target); err != nil {
			t.Fatalf("stream %d of the burst: %v", i, err)
		}
	}
	start := time.Now()
	if _, err := openStream(t, ctx, c, target); !tooMany(err) {
		t.Fatalf("past the burst, the token 2 s away: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("refused after %v: it waited for a token it could not get in time", took)
	}
	if _, err := openStream(t, ctx, other, target); err != nil {
		t.Fatalf("another user: %v", err)
	}
	if got := lim.Refused()["u5"]; got[refusedRate] != 1 || accepted.Load() != 4 {
		t.Fatalf("refused %v, the destination saw %d", got, accepted.Load())
	}
	// A token near enough is waited for.
	lim.mu.Lock()
	lim.n.tcpRate, lim.n.tcpWait = 5, 500*time.Millisecond
	lim.users["u5"].attempts = bucket{0, time.Now()}
	lim.mu.Unlock()
	start = time.Now()
	if _, err := openStream(t, ctx, c, target); err != nil {
		t.Fatalf("a token 0.2 s away: %v", err)
	}
	if took := time.Since(start); took < 150*time.Millisecond {
		t.Fatalf("admitted after %v, without its token", took)
	}

	// Failed dials: two forgiven, the third runs into debt.
	lim.mu.Lock()
	lim.n.tcpRate, lim.n.tcpBurst = 1000, 1000
	lim.n.failBurst, lim.n.failRate = 2, 0.01 // a debt of minutes: the test's own time pays none of it
	lim.users["u5"].attempts = bucket{1000, time.Now()}
	lim.users["u5"].failed = bucket{2, time.Now()}
	lim.mu.Unlock()
	refused := refusedAddr(t)
	for i := range 3 {
		if _, err := openStream(t, ctx, c, refused); err == nil || err.Error() != "remote error: connection refused" {
			t.Fatalf("failed dial %d: %v", i, err)
		}
	}
	before := accepted.Load()
	if _, err := openStream(t, ctx, c, target); !tooMany(err) {
		t.Fatalf("in debt: %v", err)
	}
	if accepted.Load() != before {
		t.Fatal("a stream refused for the debt was dialed")
	}
	if _, err := openStream(t, ctx, other, target); err != nil {
		t.Fatalf("another user, not in debt: %v", err)
	}
	if got := lim.Refused()["u5"][refusedFailed]; got != 1 {
		t.Fatalf("refused for the debt: %d", got)
	}
	// Paid off (by time, at the failures' rate: the unit tests' part).
	lim.mu.Lock()
	lim.users["u5"].failed = bucket{0, time.Now()}
	lim.mu.Unlock()
	if _, err := openStream(t, ctx, c, target); err != nil {
		t.Fatalf("the debt paid: %v", err)
	}
}

// UDP sessions through a real client: a session past the user's limit is
// refused while none is quiet (counted once for its number, however many
// datagrams repeat it), and takes the quietest one's place once one is;
// the one that gave way is made anew by its next datagram; pairs past the
// user's limit are dropped while the session's own go on; another user is
// not touched.
func TestHysteriaConnLimitUDP(t *testing.T) {
	t.Setenv(unsafeAnyDestination, "1") // datagrams to the loopback targets
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.udp, lim.n.quietAfter = 2, 2*time.Second
	node := startHy2MasqWith(t, ctx, NewLogger("error", io.Discard), lim, nil, "u5", "pw-5", "u9", "pw-9")
	var targets []string
	for range 4 {
		_, pc := echoPair(t)
		targets = append(targets, pc.LocalAddr().String())
	}
	c, other := node.client(t, ctx, "pw-5"), node.client(t, ctx, "pw-9")
	listen := func(c *hysteria2.Client) net.PacketConn {
		pc, err := c.ListenPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	// silent sends n datagrams and reports that no answer came: they were
	// dropped.
	silent := func(pc net.PacketConn, to string, n int) bool {
		for i := range n {
			if _, err := pc.WriteTo(fmt.Appendf(nil, "dropped %d", i), M.ParseSocksaddr(to)); err != nil {
				t.Fatal(err)
			}
		}
		pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, _, err := pc.ReadFrom(make([]byte, 64))
		return err != nil
	}
	refused := func() map[string]int64 { return lim.Refused()["u5"] }
	s1, s2, s3, s4 := listen(c), listen(c), listen(c), listen(c)
	echoDatagram(t, s1, targets[0], "one")
	echoDatagram(t, s2, targets[0], "two")
	// The third session: refused, and counted once for all its datagrams;
	// the fourth is another session, by its number.
	if !silent(s3, targets[0], 5) {
		t.Fatal("a session past the limit was served")
	}
	if got := refused(); got[refusedUDP] != 1 || len(got) != 1 {
		t.Fatalf("refused: %v", got)
	}
	if !silent(s4, targets[0], 5) {
		t.Fatal("another session past the limit was served")
	}
	if got := refused(); got[refusedUDP] != 2 || len(got) != 1 {
		t.Fatalf("refused, two sessions: %v", got)
	}
	// Another user is not touched; the user's sessions go on.
	echoDatagram(t, listen(other), targets[0], "other")
	echoDatagram(t, s1, targets[0], "one again")
	// s1 goes quiet, s2 stays loud: s3's next datagram takes s1's place.
	for deadline := time.Now().Add(2400 * time.Millisecond); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		echoDatagram(t, s2, targets[0], "loud")
	}
	echoDatagram(t, s3, targets[0], "three at last")
	if got := refused(); got[refusedEvicted] != 1 || got[refusedUDP] != 2 {
		t.Fatalf("after a quiet session gave way: %v", got)
	}
	// s1 gave way: its next datagram makes it anew, once one of the others
	// is quiet (neither is yet: refused).
	if !silent(s1, targets[0], 1) {
		t.Fatal("made anew with no session quiet")
	}
	time.Sleep(2200 * time.Millisecond)
	echoDatagram(t, s1, targets[0], "one anew")
	if got := refused(); got[refusedEvicted] != 2 || got[refusedUDP] != 3 {
		t.Fatalf("after the evicted session came back: %v", got)
	}

	// Pairs: the user's sessions, ended and live, hold them together. The
	// sessions above have pairs with the first target, live and in the
	// journal; room for two more.
	lim.mu.Lock()
	lim.n.udp = 100
	pairs, journal := lim.users["u5"].pairs, len(lim.users["u5"].journal)
	lim.n.pairs = pairs + 2
	lim.mu.Unlock()
	if journal == 0 || pairs <= journal {
		t.Fatalf("pairs %d, of them in the journal %d: want some of ended sessions and some of live ones", pairs, journal)
	}
	p := listen(c)
	echoDatagram(t, p, targets[1], "pair")
	echoDatagram(t, p, targets[2], "pair")
	if !silent(p, targets[3], 3) {
		t.Fatal("a pair past the limit was served")
	}
	echoDatagram(t, p, targets[1], "a pair it has")
	if got := refused(); got[refusedLive] != 3 {
		t.Fatalf("refused pairs: %v", got)
	}
	// The echoes were heard: the session's pairs are answered ones, which
	// conntrack keeps 120 s.
	answered, sessions := 0, 0
	lim.mu.Lock()
	for slot := range lim.users["u5"].slots {
		sessions++
		slot.mu.Lock()
		for _, pair := range slot.peers {
			if pair.answered {
				answered++
			}
		}
		slot.mu.Unlock()
	}
	lim.mu.Unlock()
	if sessions != 3 || answered != 4 {
		t.Fatalf("%d live sessions with %d answered pairs, want 3 and 4", sessions, answered)
	}
	echoDatagram(t, listen(other), targets[3], "another user's pair")
}

// A session is quiet only when silent both ways: one that only sends, and
// one that only hears, give way to nobody.
func TestHysteriaConnLimitUDPQuiet(t *testing.T) {
	t.Setenv(unsafeAnyDestination, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.udp, lim.n.quietAfter = 2, 2*time.Second
	node := startHy2MasqWith(t, ctx, NewLogger("error", io.Discard), lim, nil, "u5", "pw-5")
	// A destination that never answers, and one that goes on talking to
	// whoever sent it a datagram.
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chatty, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); sink.Close(); chatty.Close() })
	go func() {
		_, from, err := chatty.ReadFrom(make([]byte, 64))
		for err == nil {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				_, err = chatty.WriteTo([]byte("still here"), from)
			}
		}
	}()
	c := node.client(t, ctx, "pw-5")
	listen := func() net.PacketConn {
		pc, err := c.ListenPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	sender, hearer, third := listen(), listen(), listen()
	if _, err := hearer.WriteTo([]byte("talk to me"), M.ParseSocksaddr(chatty.LocalAddr().String())); err != nil {
		t.Fatal(err)
	}
	hearer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := hearer.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatalf("the talking destination: %v", err)
	}
	for deadline := time.Now().Add(2600 * time.Millisecond); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err := sender.WriteTo([]byte("no answer wanted"), M.ParseSocksaddr(sink.LocalAddr().String())); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := third.WriteTo([]byte("room?"), M.ParseSocksaddr(sink.LocalAddr().String())); err != nil {
		t.Fatal(err)
	}
	if !waitFor(5*time.Second, func() bool { return lim.Refused()["u5"][refusedUDP] == 1 }) {
		t.Fatalf("the third session was not refused: %v", lim.Refused())
	}
	if got := lim.Refused()["u5"][refusedEvicted]; got != 0 {
		t.Fatalf("a session that sends, or one that hears, gave way: %d", got)
	}
}

// dialScript is an outbound's dial that answers by address and keeps what
// it was asked.
type dialScript struct {
	mu     sync.Mutex
	asked  []string
	answer func(ctx context.Context, address string) error
}

func (d *dialScript) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.asked = append(d.asked, address)
	d.mu.Unlock()
	if err := d.answer(ctx, address); err != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	a, b := net.Pipe()
	go func() { io.Copy(io.Discard, b); b.Close() }()
	return a, nil
}

func (d *dialScript) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.asked)
}

// A name's addresses come from the process's cache, and each address tried
// is an attempt: the first paid at the stream's admission, each next one a
// token of its own, a failure charged where a SYN went and nothing came of
// it. An address that is not public costs neither.
func TestHysteriaDialAttempts(t *testing.T) {
	lim, c := fakeHyLimits()
	var lookups atomic.Int32
	lim.resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		lookups.Add(1)
		switch name {
		case "three.test":
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")}, nil
		case "private.test":
			return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.0.2.9")}, nil
		case "gone.test":
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	}
	script := &dialScript{answer: func(_ context.Context, address string) error {
		switch address {
		case "192.0.2.1:443":
			return syscall.ECONNREFUSED
		case "192.0.2.2:443":
			return syscall.ENETUNREACH
		case "10.0.0.1:443":
			return errNotPublic
		}
		return nil
	}}
	o := &outbound{dial: script.dial, log: NewLogger("error", io.Discard), lim: lim}
	tokens := func() (attempts, failed float64) {
		lim.mu.Lock()
		defer lim.mu.Unlock()
		u := lim.userLocked("u5", c.t)
		return u.attempts.tokens, u.failed.tokens
	}
	dial := func(to string) error {
		ctx, cancel := context.WithTimeout(userCtx("u5-n"), 10*time.Second)
		defer cancel()
		conn, err := o.dialUser(ctx, "u5", M.ParseSocksaddr(to))
		if conn != nil {
			conn.Close()
		}
		return err
	}
	// Three addresses: refused (charged), no route (not charged), then in.
	// The first attempt was paid at admission; the two more pay here.
	if err := dial("three.test:443"); err != nil {
		t.Fatalf("three addresses: %v", err)
	}
	if got := script.all(); !slices.Equal(got, []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"}) {
		t.Fatalf("dialed %v", got)
	}
	if a, f := tokens(); a != 598 || f != 99 {
		t.Fatalf("attempt tokens %v (want 598), failed %v (want 99)", a, f)
	}
	// The name again: from the cache.
	if err := dial("Three.Test.:443"); err != nil || lookups.Load() != 1 {
		t.Fatalf("the name again: %v, looked up %d times", err, lookups.Load())
	}
	// No token for the next address: the dial ends with the first one's
	// failure.
	lim.mu.Lock()
	lim.users["u5"].attempts = bucket{0, c.t}
	lim.mu.Unlock()
	script.asked = nil
	if err := dial("three.test:443"); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("without a token for the next address: %v", err)
	}
	if got := script.all(); len(got) != 1 {
		t.Fatalf("dialed without a token: %v", got)
	}
	if got := lim.Refused()["u5"][refusedRate]; got != 1 {
		t.Fatalf("refused attempts: %d", got)
	}
	// An address that is not public: no SYN, no token; the next address
	// has the one paid at admission.
	script.asked = nil
	if err := dial("private.test:443"); err != nil {
		t.Fatalf("a private address first: %v", err)
	}
	if got := script.all(); len(got) != 2 {
		t.Fatalf("dialed %v", got)
	}
	if got := lim.Refused()["u5"][refusedRate]; got != 1 {
		t.Fatalf("an address not public cost a token: %d refusals", got)
	}
	// What a client hears of a name.
	for to, want := range map[string]string{
		"gone.test:443":                       "no such host",
		"broken.test:443":                     "lookup failed",
		"a..b:443":                            "no such host",
		strings.Repeat("a", 250) + ".test:80": "no such host",
	} {
		if got := dialReason(dial(to)); got != want {
			t.Errorf("%.20s: %q, want %q", to, got, want)
		}
	}
	// No lookup token: the limit's refusal.
	lim.mu.Lock()
	lim.users["u5"].lookups = bucket{0, c.t}
	lim.mu.Unlock()
	if got := dialReason(dial("new.test:443")); got != "too many connections" {
		t.Fatalf("without a lookup token: %q", got)
	}
	if got := dialReason(&net.OpError{Op: "dial", Err: errTooMany}); got != "too many connections" {
		t.Fatalf("without an attempt token: %q", got)
	}
	if got := lim.Refused()["u5"][refusedLookup]; got != 1 {
		t.Fatalf("refused lookups: %d", got)
	}
}

// A dial that timed out is charged; one given up (the backend stopping) is
// not. IPv4 and IPv6 race: the other family starts 300 ms after the first,
// or when the first failed, and the loser's connection is closed.
func TestHysteriaDialRace(t *testing.T) {
	lim := newHyLimits()
	lim.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, nil
	}
	var mu sync.Mutex
	started := map[string]time.Time{}
	slow := make(chan struct{})
	script := &dialScript{answer: func(ctx context.Context, address string) error {
		mu.Lock()
		started[address] = time.Now()
		mu.Unlock()
		if strings.HasPrefix(address, "[2001:db8::1]") {
			select {
			case <-slow:
			case <-ctx.Done():
				// Refused just as the race was lost: not the user's doing.
				return syscall.ECONNREFUSED
			}
		}
		return nil
	}}
	o := &outbound{dial: script.dial, log: NewLogger("error", io.Discard), lim: lim}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := o.dialUser(ctx, "u5", M.ParseSocksaddr("both.test:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	mu.Lock()
	gap := started["192.0.2.1:443"].Sub(started["[2001:db8::1]:443"])
	mu.Unlock()
	if gap < 250*time.Millisecond || gap > 2*time.Second {
		t.Fatalf("the other family started %v after the first", gap)
	}
	// The second attempt paid a token; the first family's dial, cancelled
	// when the race was won (it ends a moment after), charged nothing.
	time.Sleep(200 * time.Millisecond)
	lim.mu.Lock()
	a, f := lim.users["u5"].attempts.tokens, lim.users["u5"].failed.tokens
	lim.mu.Unlock()
	if a > 599.5 || a < 598.9 || f != 100 {
		t.Fatalf("attempt tokens %v, failed %v", a, f)
	}
	close(slow)

	// A timeout is charged, once an address.
	script.answer = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return os.ErrDeadlineExceeded
	}
	tctx, tcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer tcancel()
	if _, err := o.dialUser(tctx, "u6", M.ParseSocksaddr("192.0.2.7:443")); err == nil || dialReason(err) != "timeout" {
		t.Fatalf("a silent destination: %v", err)
	}
	lim.mu.Lock()
	f = lim.users["u6"].failed.tokens
	lim.mu.Unlock()
	if f != 99 {
		t.Fatalf("a timeout charged %v", 100-f)
	}
	// Given up: not charged.
	gctx, gcancel := context.WithCancel(context.Background())
	script.answer = func(ctx context.Context, _ string) error {
		gcancel()
		<-ctx.Done()
		return ctx.Err()
	}
	if _, err := o.dialUser(gctx, "u7", M.ParseSocksaddr("192.0.2.7:443")); err == nil {
		t.Fatal("a dial given up went through")
	}
	lim.mu.Lock()
	u7 := lim.users["u7"]
	lim.mu.Unlock()
	if u7 != nil && u7.failed.tokens != 100 {
		t.Fatalf("a dial given up charged %v", 100-u7.failed.tokens)
	}
}

// streamConn is a stream whose context ends when its client gives it up,
// as a QUIC stream's does.
type streamConn struct {
	*handshakeConn
	ctx context.Context
}

func (c *streamConn) Context() context.Context { return c.ctx }

// A stream takes its limits by the base name of the user in its context;
// the place is held until the stream ends; a client that gives its stream
// up while it waits for a token gets its place back at once.
func TestHysteriaStreamLimits(t *testing.T) {
	lim := newHyLimits()
	lim.n.tcp = 2
	target, _ := holdTarget(t)
	var d net.Dialer
	o := &outbound{dial: d.DialContext, log: NewLogger("error", io.Discard), lim: lim}
	start := func(name string) (*handshakeConn, chan struct{}) {
		hc := newHandshakeConn(t)
		done := make(chan struct{})
		go func() {
			o.NewConnectionEx(userCtx(name), hc, M.Socksaddr{}, M.ParseSocksaddr(target), nil)
			close(done)
		}()
		return hc, done
	}
	wait := func(hc *handshakeConn) error {
		select {
		case <-hc.ok:
			return nil
		case err := <-hc.fail:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("the client heard nothing")
			return nil
		}
	}
	first, firstDone := start("u5-aaaa")
	second, _ := start("u5-bbbb")
	if err := wait(first); err != nil {
		t.Fatal(err)
	}
	if err := wait(second); err != nil {
		t.Fatal(err)
	}
	third, _ := start("u5-cccc")
	if err := wait(third); err == nil || err.Error() != "too many connections" {
		t.Fatalf("the user's third stream: %v", err)
	}
	if hc, _ := start("u50-aaaa"); wait(hc) != nil {
		t.Fatal("u50 is not u5")
	}
	// A user without a name is limited too.
	for range 2 {
		if hc, _ := start(""); wait(hc) != nil {
			t.Fatal("a user without a name: refused within the limit")
		}
	}
	if hc, _ := start(""); wait(hc) == nil {
		t.Fatal("users without a name are limited by nothing")
	}
	// The place comes back when the stream ends, not before.
	lim.mu.Lock()
	held := lim.users["u5"].tcp
	lim.mu.Unlock()
	if held != 2 {
		t.Fatalf("places held: %d", held)
	}
	first.Close()
	<-firstDone
	if hc, _ := start("u5-cccc"); wait(hc) != nil {
		t.Fatal("after one ended: refused")
	}

	// A client gone while its stream waits for a token.
	lim2 := newHyLimits()
	lim2.n.tcpBurst, lim2.n.tcpRate, lim2.n.tcpWait = 1, 0.1, time.Hour
	o2 := &outbound{dial: d.DialContext, log: NewLogger("error", io.Discard), lim: lim2}
	if done, kind := lim2.tcpStart(context.Background(), "u5"); kind != "" {
		t.Fatal(kind)
	} else {
		done()
	}
	sctx, gone := context.WithCancel(context.Background())
	sc := &streamConn{newHandshakeConn(t), sctx}
	ended := make(chan struct{})
	go func() {
		o2.NewConnectionEx(userCtx("u5"), sc, M.Socksaddr{}, M.ParseSocksaddr(target), nil)
		close(ended)
	}()
	if !waitFor(5*time.Second, func() bool {
		lim2.mu.Lock()
		defer lim2.mu.Unlock()
		return lim2.users["u5"].tcp == 1
	}) {
		t.Fatal("the waiting stream holds no place")
	}
	gone()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("a stream given up kept waiting for its token")
	}
	lim2.mu.Lock()
	left := lim2.users["u5"].tcp
	lim2.mu.Unlock()
	if left != 0 {
		t.Fatalf("a stream given up kept its place: %d", left)
	}
}

// A session's datagrams to a name: resolved through the process's cache,
// kept by the session until the shared answer expires (no lock of the
// cache's and no memory a datagram); a lookup that timed out or got
// SERVFAIL is the session's own to remember, 30 s; no token, no such name
// and no allowed address are not.
func TestHysteriaUDPNames(t *testing.T) {
	var asked atomic.Int32
	answer := map[string]error{
		"slow.test":     &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true},
		"servfail.test": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		"nx.test":       &net.DNSError{Err: "no such host", IsNotFound: true},
	}
	lim, c := fakeHyLimits()
	lim.resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		asked.Add(1)
		if err := answer[name]; err != nil {
			return nil, err
		}
		if name == "private.test" {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("192.0.2.7")}, nil
	}
	s := &udpSession{lim: lim, user: "u5", slot: slotOf(t, lim, "u5"), ctx: context.Background(), names: map[string]udpResolved{}}
	to := func(name string) M.Socksaddr { return M.ParseSocksaddrHostPort(name, 53) }
	// The first allowed address of the name.
	if ap, ok := s.resolve(to("ok.test"), c.t); !ok || ap != netip.MustParseAddrPort("192.0.2.7:53") {
		t.Fatalf("resolved %v %v", ap, ok)
	}
	// An address: its own, when allowed; never port 0.
	if ap, ok := s.resolve(M.ParseSocksaddr("192.0.2.9:53"), c.t); !ok || ap != netip.MustParseAddrPort("192.0.2.9:53") {
		t.Fatalf("an address: %v %v", ap, ok)
	}
	for _, d := range []string{"10.0.0.1:53", "127.0.0.1:53", "192.0.2.9:0", "[::ffff:10.0.0.1]:53"} {
		if _, ok := s.resolve(M.ParseSocksaddr(d), c.t); ok {
			t.Errorf("%s allowed", d)
		}
	}
	if _, ok := s.resolve(M.ParseSocksaddrHostPort("ok.test", 0), c.t); ok {
		t.Error("port 0 allowed")
	}
	// The cache's lock held: a datagram to a kept name does not wait.
	lim.names.mu.Lock()
	done := make(chan bool, 1)
	go func() { _, ok := s.resolve(to("ok.test"), c.t); done <- ok }()
	select {
	case ok := <-done:
		lim.names.mu.Unlock()
		if !ok {
			t.Fatal("refused")
		}
	case <-time.After(2 * time.Second):
		lim.names.mu.Unlock()
		t.Fatal("a datagram to a kept name took the cache's lock")
	}
	d := to("ok.test")
	if n := testing.AllocsPerRun(100, func() { s.resolve(d, c.t) }); n != 0 {
		t.Fatalf("%v allocations a datagram", n)
	}
	c.t = c.t.Add(nameHit)
	if _, ok := s.resolve(to("ok.test"), c.t); !ok || asked.Load() != 2 {
		t.Fatalf("after the shared answer expired: %v, asked %d", ok, asked.Load())
	}
	// A timeout or SERVFAIL: the session's own to remember.
	before := asked.Load()
	for _, n := range []string{"slow.test", "servfail.test"} {
		s.resolve(to(n), c.t)
		s.resolve(to(n), c.t)
	}
	if asked.Load() != before+2 {
		t.Fatalf("a timeout or SERVFAIL looked up again within 30 s: %d", asked.Load()-before)
	}
	for _, n := range []string{"nx.test", "private.test"} {
		if _, ok := s.resolve(to(n), c.t); ok {
			t.Errorf("%s resolved", n)
		}
		if r, ok := s.names[n]; ok && !r.ip.IsValid() {
			t.Errorf("%s remembered as a failure of the session's", n)
		}
	}
	// No token: not remembered; with one again, looked up at once.
	lim.mu.Lock()
	lim.users["u5"].lookups = bucket{0, c.t}
	lim.mu.Unlock()
	before = asked.Load()
	if _, ok := s.resolve(to("later.test"), c.t); ok || asked.Load() != before {
		t.Fatal("looked up without a token")
	}
	lim.mu.Lock()
	lim.users["u5"].lookups = bucket{1, c.t}
	lim.mu.Unlock()
	if _, ok := s.resolve(to("later.test"), c.t); !ok {
		t.Fatal("a refused token remembered by the session")
	}
	// Full of failures; 30 s on, they make room. Never more than 64 names.
	clear(s.names)
	for i := range 200 {
		s.remember(fmt.Sprintf("f%d.test", i), udpResolved{until: c.t.Add(udpNameMiss)}, c.t)
	}
	if len(s.names) != 64 {
		t.Fatalf("%d names kept", len(s.names))
	}
	c.t = c.t.Add(udpNameMiss)
	lim.mu.Lock()
	lim.users["u5"].lookups = bucket{100, c.t}
	lim.mu.Unlock()
	s.resolve(to("slow.test"), c.t)
	if r, ok := s.names["slow.test"]; !ok || r.ip.IsValid() || len(s.names) != 1 {
		t.Fatalf("expired names not pruned: %d kept", len(s.names))
	}
}

// The switch: conn_limit "off" in the backend's config, or a file that
// says "off", read again on SIGHUP and at the watch's look every 5 s,
// without a restart: what is open stays.
func TestHysteriaConnLimitSwitch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, _ := holdTarget(t)
	free := func(c *hysteria2.Client, n int) error {
		for range n {
			if _, err := openStream(t, ctx, c, target); err != nil {
				return err
			}
		}
		return nil
	}
	// Off in the config: no limit, whatever a file says.
	lim := newHyLimits()
	lim.n.tcp = 1
	file := t.TempDir() + "/conn-limit"
	os.WriteFile(file, []byte("on\n"), 0o600)
	logs := &lockedLog{}
	node := startHy2MasqWith(t, ctx, NewLogger("info", logs), lim, func(c *BackendConfig) {
		c.Options.ConnLimit, c.Options.ConnLimitFile = "off", file
	}, "u5", "pw-5")
	if err := free(node.client(t, ctx, "pw-5"), 3); err != nil {
		t.Fatalf("conn_limit off: %v", err)
	}
	if !strings.Contains(logs.String(), "INFO per-user connection limits off") {
		t.Fatalf("the log:\n%s", logs)
	}

	// The file. It says off at the start.
	lim = newHyLimits()
	lim.n.tcp = 1
	os.WriteFile(file, []byte("off\n"), 0o600)
	node = startHy2MasqWith(t, ctx, NewLogger("error", io.Discard), lim, func(c *BackendConfig) {
		c.Options.ConnLimitFile = file
	}, "u5", "pw-5")
	client := node.client(t, ctx, "pw-5")
	if err := free(client, 3); err != nil {
		t.Fatalf("the file says off: %v", err)
	}
	// On, at SIGHUP (at once: the watch's own look is 5 s away at most,
	// and two changes in a row cannot both be its doing): the open streams
	// stay, a new one takes the user's one place, the next is refused.
	hup := func(content string, on bool) {
		t.Helper()
		if content == "" {
			os.Remove(file)
		} else {
			os.WriteFile(file, []byte(content), 0o600)
		}
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		if !waitFor(1500*time.Millisecond, func() bool { return lim.off.Load() != on }) {
			t.Fatalf("the file says %q: on %v after SIGHUP", content, !on)
		}
	}
	hup("on\n", true)
	if err := free(client, 1); err != nil {
		t.Fatalf("on again, the first stream: %v", err)
	}
	if err := free(client, 1); !tooMany(err) {
		t.Fatalf("on again, past the limit: %v", err)
	}
	hup("off\n", false)
	if err := free(client, 2); err != nil {
		t.Fatalf("off again: %v", err)
	}
	// On again without a signal: at the watch's next look.
	os.WriteFile(file, []byte("on\n"), 0o600)
	if !waitFor(8*time.Second, func() bool { return !lim.off.Load() }) {
		t.Fatal("not on within the watch's look")
	}
	// No file: on.
	hup("off\n", false)
	hup("", true)
}

// The refusals on the stats socket's traffic line, as rayd reads them
// (raycontrol internal/traffic, parseLine): a top-level limit object by
// base name and kind, absent while nobody was refused, and the process's
// uptime in seconds; the users' bytes as before, by the credentials' names.
// A rayd that knows neither field reads the answer as it did.
func TestHysteriaConnLimitStats(t *testing.T) {
	t.Setenv(unsafeAnyDestination, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := newHyLimits()
	lim.n.tcp, lim.n.udp = 1, 1
	node := startHy2MasqWith(t, ctx, NewLogger("error", io.Discard), lim, nil,
		"u5-1111111111111111", "pw-5a", "u5-2222222222222222", "pw-5b", "u9", "pw-9")
	// rayd's reading of the answer (raycontrol v0.24.0).
	type answer struct {
		V     int    `json:"v"`
		Boot  string `json:"boot"`
		Users map[string]struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		} `json:"users"`
		Limit  map[string]map[string]int64 `json:"limit"`
		Uptime *int64                      `json:"uptime"`
	}
	read := func() (answer, string) {
		raw := node.ask(t, "traffic\n")
		var a answer
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields() // nothing rayd does not know
		if err := d.Decode(&a); err != nil {
			t.Fatalf("traffic %s: %v", raw, err)
		}
		return a, string(raw)
	}
	// A process in its first second says so: uptime 0 is in the answer.
	if b, _ := json.Marshal(HysteriaTraffic{V: 1, Boot: "b"}); string(b) != `{"v":1,"boot":"b","users":null,"uptime":0}` {
		t.Fatalf("an empty answer: %s", b)
	}
	before, raw := read()
	if before.Limit != nil || strings.Contains(raw, "limit") {
		t.Fatalf("limit before any refusal: %s", raw)
	}
	if before.Uptime == nil || *before.Uptime < 0 || *before.Uptime > 3600 || before.V != 1 || len(before.Users) != 3 {
		t.Fatalf("before: %s", raw)
	}
	if !strings.HasPrefix(raw, `{"v":1,"boot":"`+before.Boot+`","users":{`) || !strings.HasSuffix(raw, "}\n") || strings.Count(raw, "\n") != 1 {
		t.Fatalf("the line: %q", raw)
	}

	// The stats socket is asked all the while (the race detector's part).
	stop := make(chan struct{})
	var asking sync.WaitGroup
	asking.Add(1)
	go func() {
		defer asking.Done()
		for {
			select {
			case <-stop:
				return
			default:
				read()
			}
		}
	}()
	target, _ := holdTarget(t)
	_, udp := echoPair(t)
	a, b := node.client(t, ctx, "pw-5a"), node.client(t, ctx, "pw-5b")
	if _, err := openStream(t, ctx, a, target); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*hysteria2.Client{a, b, b} {
		if _, err := openStream(t, ctx, c, target); !tooMany(err) {
			t.Fatalf("past the limit: %v", err)
		}
	}
	first, err := a.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	echoDatagram(t, first, udp.LocalAddr().String(), "one")
	second, err := b.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for range 3 {
		second.WriteTo([]byte("refused"), M.ParseSocksaddr(udp.LocalAddr().String()))
	}
	var after answer
	if !waitFor(5*time.Second, func() bool {
		after, raw = read()
		return after.Limit["u5"]["udp"] == 1
	}) {
		t.Fatalf("after the refusals: %s", raw)
	}
	close(stop)
	asking.Wait()
	// By base name, the kinds with refusals only; another user has none.
	if len(after.Limit) != 1 || len(after.Limit["u5"]) != 2 || after.Limit["u5"]["tcp"] != 3 {
		t.Fatalf("limit: %v", after.Limit)
	}
	if !strings.Contains(raw, `"limit":{"u5":{"tcp":3,"udp":1}},"uptime":`) {
		t.Fatalf("the line: %s", raw)
	}
	if !strings.HasPrefix(raw, `{"v":1,"boot":"`+before.Boot+`","users":{`) {
		t.Fatalf("the line: %s", raw)
	}
	// The bytes are the credentials', as before.
	if _, ok := after.Users["u5-1111111111111111"]; !ok || len(after.Users) != 3 {
		t.Fatalf("users: %v", after.Users)
	}
	if _, ok := after.Users["u5"]; ok {
		t.Fatalf("users by base name: %v", after.Users)
	}
	// A rayd before v0.24.0 (and niko-server's own reader of v0.15.0):
	// version, boot and users, the rest passed over.
	var old struct {
		V     int                    `json:"v"`
		Boot  string                 `json:"boot"`
		Users map[string]UserTraffic `json:"users"`
	}
	if err := json.Unmarshal([]byte(raw), &old); err != nil || old.V != 1 || old.Boot != before.Boot || len(old.Users) != 3 {
		t.Fatalf("an older reader: %+v (%v)", old, err)
	}
	// Reading resets nothing; the uptime runs on.
	if !waitFor(3*time.Second, func() bool {
		again, _ := read()
		return *again.Uptime >= 1 && *again.Uptime > *before.Uptime-1 && again.Limit["u5"]["tcp"] == 3
	}) {
		t.Fatal("a second read: the refusals or the uptime")
	}
}

// A session's own memory of a failed lookup yields to the shared cache's
// answer however the name is spelt: the cache keeps one entry a name, in
// lower case and without the final dot.
func TestHysteriaUDPNameSpelling(t *testing.T) {
	var slow atomic.Bool
	slow.Store(true)
	lim, c := fakeHyLimits()
	lim.resolve = func(context.Context, string) ([]netip.Addr, error) {
		if slow.Load() {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}
	for _, spelt := range []string{"Slow.Test", "slow.test.", "SLOW.TEST."} {
		slow.Store(true)
		lim.names = hyNames{}
		s := &udpSession{lim: lim, user: "u5", slot: slotOf(t, lim, "u5"), ctx: context.Background(), names: map[string]udpResolved{}}
		d := M.ParseSocksaddrHostPort(spelt, 53)
		if _, ok := s.resolve(d, c.t); ok {
			t.Fatalf("%s: resolved through a timeout", spelt)
		}
		// Another user's lookup gets the answer into the shared cache.
		slow.Store(false)
		if _, err := lim.lookupName(context.Background(), "u6", "slow.test"); err != nil {
			t.Fatal(err)
		}
		if ap, ok := s.resolve(d, c.t); !ok || ap != netip.MustParseAddrPort("192.0.2.7:53") {
			t.Fatalf("%s: the session's own failure did not yield to the shared answer: %v %v", spelt, ap, ok)
		}
	}
}

// A switch file that is a FIFO neither stalls the backend nor its watch:
// the limits stay on, and the log says why once, however often it looks.
func TestHysteriaConnLimitFileFIFO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fifo := t.TempDir() + "/conn-limit"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &lockedLog{}
	lim := newHyLimits()
	lim.n.tcp = 1
	node := startHy2MasqWith(t, ctx, NewLogger("warn", logs), lim, func(c *BackendConfig) { c.Options.ConnLimitFile = fifo }, "u5", "pw-5")
	target, _ := holdTarget(t)
	client := node.client(t, ctx, "pw-5")
	if _, err := openStream(t, ctx, client, target); err != nil {
		t.Fatalf("the backend with a FIFO for a switch: %v", err)
	}
	for range 3 {
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := openStream(t, ctx, client, target); !tooMany(err) {
		t.Fatalf("the limits are not on: %v", err)
	}
	if n := strings.Count(logs.String(), "conn_limit_file:"); n != 1 || !strings.Contains(logs.String(), "not a regular file") {
		t.Fatalf("the log, %d lines of the file's problem:\n%s", n, logs)
	}
	// The watch goes on: a user taken out of the users file is revoked.
	writeHy2Users(t, node.users, "u6", "pw-6")
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	if !waitFor(5*time.Second, func() bool { _, err := openStream(t, ctx, node.client(t, ctx, "pw-6"), target); return err == nil }) {
		t.Fatal("the users file was not read again")
	}
}
