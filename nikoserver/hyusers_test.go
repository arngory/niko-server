//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// lockedLog is a log the test reads while the backend writes it.
type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// writeHy2Users writes a users file of name, password pairs, and a disabled
// user beside them.
func writeHy2Users(t *testing.T, path string, pairs ...string) {
	t.Helper()
	var users []string
	for i := 0; i+1 < len(pairs); i += 2 {
		users = append(users, fmt.Sprintf(`{"name":%q,"enabled":true,"hy2":{"password":%q}}`, pairs[i], pairs[i+1]))
	}
	users = append(users, `{"name":"off","enabled":false,"hy2":{"password":"disabled-user"}}`)
	if err := os.WriteFile(path, []byte(`{"users":[`+strings.Join(users, ",")+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hy2Node is a hy2-masq backend behind the UDP front, dialing loopback
// directly.
type hy2Node struct {
	server M.Socksaddr
	users  string // the users file
	stats  string // the stats socket
}

func startHy2Masq(t *testing.T, ctx context.Context, log *Logger, pairs ...string) *hy2Node {
	t.Helper()
	dir := t.TempDir()
	uid := os.Getuid()
	cert := selfSigned(t, "h.example.com")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	node := &hy2Node{users: filepath.Join(dir, "users.json"), stats: filepath.Join(dir, "stats.sock")}
	writeHy2Users(t, node.users, pairs...)
	sock := filepath.Join(dir, "hy2-masq.sock")
	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "hy2-masq", Socket: sock, FrontUID: uid, UsersFile: node.users,
		TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}, StatsSocket: node.stats}
	if errs := c.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	ln, err := listenPacketSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	conn := newPacketConn(ln, uid, log)
	conn.port = 443
	go conn.acceptLoop()
	var direct net.Dialer
	go runHysteria(ctx, c, conn, log, direct.DialContext)
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{{SNI: []string{"h.example.com"}, Backend: "hy2-masq"}}}
	front, err := newUDPFront(fc, map[string]BackendRef{"hy2-masq": {Socket: sock, Mode: "packet", UID: uid}}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := front.listen(fc.Listen); err != nil {
		t.Fatal(err)
	}
	for _, c := range front.sockets {
		node.server = M.SocksaddrFromNetIP(c.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	go front.run(ctx)
	time.Sleep(300 * time.Millisecond) // the links come up
	return node
}

func (n *hy2Node) client(t *testing.T, ctx context.Context, password string) *hysteria2.Client {
	t.Helper()
	client, err := newHy2Client(ctx, n.server, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(nil) })
	return client
}

func newHy2Client(ctx context.Context, server M.Socksaddr, password string) (*hysteria2.Client, error) {
	tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), "h.example.com", option.OutboundTLSOptions{Enabled: true, ServerName: "h.example.com",
		Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
	if err != nil {
		return nil, err
	}
	return hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
		ServerAddress: server, Password: password, TLSConfig: tlsConfig})
}

// ask sends a line to the stats socket and returns all it answers before
// it closes.
func (n *hy2Node) ask(t *testing.T, line string) []byte {
	t.Helper()
	c, err := net.Dial("unix", n.stats)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, line)
	b, err := io.ReadAll(c)
	// A line the server stops reading leaves bytes unread: its close resets.
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("%q: %v", line, err)
	}
	return b
}

func echoOnce(t *testing.T, s net.Conn, msg string) {
	t.Helper()
	s.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(s, b); err != nil || string(b) != msg {
		t.Fatalf("echo %q: %q (%v)", msg, b, err)
	}
}

func echoDatagram(t *testing.T, pc net.PacketConn, to, msg string) {
	t.Helper()
	if _, err := pc.WriteTo([]byte(msg), M.ParseSocksaddr(to)); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != msg {
		t.Fatalf("UDP echo %q: %q (%v)", msg, b[:n], err)
	}
}

// A name gone from the users file or disabled there (expired, over its
// limit), or given another password, loses its connections at the reload,
// streams and datagram sessions; the others stay.
func TestHysteriaRevoke(t *testing.T) {
	t.Setenv(unsafeAnyDestination, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedLog{}
	node := startHy2Masq(t, ctx, NewLogger("info", logs), "u5", "pw-5", "u6", "pw-6", "u7", "pw-7", "u8", "pw-8")
	echoTCP, echoUDP := echoPair(t)

	type live struct {
		stream net.Conn
		pc     net.PacketConn
	}
	open := func(password string) live {
		t.Helper()
		c := node.client(t, ctx, password)
		s, err := c.DialConn(ctx, M.ParseSocksaddr(echoTCP.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		echoOnce(t, s, "hello")
		pc, err := c.ListenPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		echoDatagram(t, pc, echoUDP.LocalAddr().String(), "ping")
		return live{s, pc}
	}
	l5, l6, l7, l8 := open("pw-5"), open("pw-6"), open("pw-7"), open("pw-8")

	// u5 disabled, u6 with a new password, u7 as it was, u8 gone.
	if err := os.WriteFile(node.users, []byte(`{"users":[
		{"name":"u5","enabled":false,"hy2":{"password":"pw-5"}},
		{"name":"u6","enabled":true,"hy2":{"password":"pw-6b"}},
		{"name":"u7","enabled":true,"hy2":{"password":"pw-7"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	for name, l := range map[string]live{"disabled": l5, "new password": l6, "removed": l8} {
		l.stream.SetReadDeadline(start.Add(time.Second))
		_, err := l.stream.Read(make([]byte, 1))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s: the stream still open a second after the reload (%v)", name, err)
		}
		l.pc.SetReadDeadline(start.Add(time.Second))
		if _, _, err := l.pc.ReadFrom(make([]byte, 64)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s: the datagram session still open a second after the reload (%v)", name, err)
		}
		t.Logf("%s: closed %v after the reload", name, time.Since(start))
	}
	// u7 goes on, stream and datagrams.
	echoOnce(t, l7.stream, "again")
	echoDatagram(t, l7.pc, echoUDP.LocalAddr().String(), "pong")
	// One QUIC connection each for u5, u6 and u8 (a stream and a datagram
	// session in each).
	for deadline := time.Now().Add(2 * time.Second); !strings.Contains(logs.String(), "2 users, 3 connections of removed users closed"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("log:\n%s", logs)
		}
	}
	// The new password gets in, the old ones do not.
	open("pw-6b")
	for _, password := range []string{"pw-5", "pw-6", "pw-8"} {
		c := node.client(t, ctx, password)
		if _, err := c.DialConn(ctx, M.ParseSocksaddr(echoTCP.Addr().String())); err == nil {
			t.Fatalf("%s still gets in", password)
		}
	}
}

// Clients authenticate with a password while a reload takes it away: none
// of their connections stays open (the stats socket counts them), and a
// user the reload kept stays.
func TestHysteriaReloadRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := startHy2Masq(t, ctx, NewLogger("warn", io.Discard), "u5", "pw-5", "u7", "pw-7")
	echoTCP, _ := echoPair(t)
	to := M.ParseSocksaddr(echoTCP.Addr().String())
	keep := node.client(t, ctx, "pw-7")
	if _, err := keep.DialConn(ctx, to); err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		clients []*hysteria2.Client
		in      atomic.Int64
		stop    = make(chan struct{})
		wg      sync.WaitGroup
	)
	defer func() {
		for _, c := range clients {
			c.CloseWithError(nil)
		}
	}()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := newHy2Client(ctx, node.server, "pw-5")
				if err != nil {
					return
				}
				mu.Lock()
				clients = append(clients, c)
				mu.Unlock()
				dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
				// The stream's request goes with its first write; the
				// connection is authenticated by then.
				if s, err := c.DialConn(dctx, to); err == nil {
					in.Add(1)
					s.Write([]byte("x"))
				}
				dcancel()
			}
		}()
	}
	for deadline := time.Now().Add(10 * time.Second); in.Load() < 8; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no client got in before the reload")
		}
	}
	writeHy2Users(t, node.users, "u5", "pw-5b", "u7", "pw-7")
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	t.Logf("%d connections in with the old password", in.Load())
	var st HysteriaStats
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if err := json.Unmarshal(node.ask(t, "127.0.0.1 u5\n"), &st); err != nil {
			t.Fatal(err)
		}
		if len(st.Own) == 0 && st.Connections == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the reload: %d connections, %d of u5's", st.Connections, len(st.Own))
		}
	}
}

func hy2Table(table *atomic.Pointer[map[string]*hy2User]) func([]*hy2User, []string) {
	return func(users []*hy2User, passwords []string) {
		m := map[string]*hy2User{}
		for i, u := range users {
			m[passwords[i]] = u
		}
		table.Store(&m)
	}
}

// A reload keeps a user whose name and password stay, revokes the others,
// closes their connections and only theirs.
func TestHy2UsersSet(t *testing.T) {
	var table atomic.Pointer[map[string]*hy2User]
	u := newHy2Users()
	u.set([]string{"u5", "u6", "u7"}, []string{"a", "b", "c"}, hy2Table(&table))
	old := *table.Load()
	closed := map[string]bool{}
	for _, p := range []string{"a", "b", "c"} {
		if !u.admit(old[p], &hy2Conn{close: func() { closed[p] = true }}) {
			t.Fatalf("%s not admitted", p)
		}
	}
	// u5 gone, u6 with a new password, u7 as it was.
	if n := u.set([]string{"u6", "u7"}, []string{"b2", "c"}, hy2Table(&table)); n != 2 {
		t.Fatalf("%d closed, want 2", n)
	}
	now := *table.Load()
	if !closed["a"] || !closed["b"] || closed["c"] || len(now) != 2 || now["c"] != old["c"] || now["b2"] == old["b"] {
		t.Fatalf("closed %v, table %v", closed, now)
	}
	if !old["a"].revoked || !old["b"].revoked || old["c"].revoked {
		t.Fatal("revoked")
	}
	if now["b2"].name != "u6" {
		t.Fatal("u6 with its new password")
	}
	if u.admit(old["b"], &hy2Conn{close: func() {}}) {
		t.Fatal("a revoked user admitted")
	}
	// The same password under another name is another user.
	u.set([]string{"u8"}, []string{"c"}, hy2Table(&table))
	if (*table.Load())["c"] == old["c"] || !old["c"].revoked || !closed["c"] {
		t.Fatal("a password moved to another name")
	}
}

// The race of a reload with a connection between its password check and
// its ConnectionHook, the order sing-quic calls them in: the connection
// read the old table, so it must close, whichever comes first.
func TestHy2UsersReloadRace(t *testing.T) {
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:4433"))
	stats := func() hysteria2.ConnectionStats { return hysteria2.ConnectionStats{} }
	// connect is the service's side: the password check, then the hook.
	connect := func(u *hy2Users, table *atomic.Pointer[map[string]*hy2User], between func()) (closed *atomic.Bool, done chan struct{}, in bool) {
		closed, done = new(atomic.Bool), make(chan struct{})
		user := (*table.Load())["old"]
		if user == nil {
			return closed, done, false // refused at the check: a 404
		}
		between()
		connectionHook(u, &sessions{})(remote, user, stats, func() { closed.Store(true) }, done)
		return closed, done, true
	}
	reload := func(u *hy2Users, table *atomic.Pointer[map[string]*hy2User]) {
		u.set([]string{"u5"}, []string{"new"}, hy2Table(table))
	}
	setup := func() (*hy2Users, *atomic.Pointer[map[string]*hy2User]) {
		u, table := newHy2Users(), new(atomic.Pointer[map[string]*hy2User])
		u.set([]string{"u5"}, []string{"old"}, hy2Table(table))
		return u, table
	}

	// The reload between the check and the hook: the hook closes it.
	u, table := setup()
	closed, done, in := connect(u, table, func() { reload(u, table) })
	if !in || !closed.Load() {
		t.Fatal("checked against the old table, hooked after the reload: still open")
	}
	close(done)
	// The reload after the hook: the reload closes it.
	u, table = setup()
	closed, done, _ = connect(u, table, func() {})
	if closed.Load() {
		t.Fatal("closed before the reload")
	}
	reload(u, table)
	if !closed.Load() {
		t.Fatal("hooked before the reload: still open after it")
	}
	close(done)

	// Both at once, many times.
	var counts [3]int // refused at the check, closed when the hook returned, closed later by the reload
	for range 3000 {
		u, table := setup()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); reload(u, table) }()
		closed, done, in := connect(u, table, func() {})
		hookClosed := closed.Load()
		wg.Wait()
		switch {
		case !in:
			counts[0]++
		case !closed.Load():
			t.Fatal("a connection with the old password outlived the reload")
		case hookClosed:
			counts[1]++
		default:
			counts[2]++
		}
		close(done)
	}
	t.Logf("refused at the check, closed when the hook returned, closed later by the reload: %v", counts)
}
