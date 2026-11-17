//go:build linux

package nikoserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestHysteriaQUICOptions: the server's keepalive is 28 s, not sing-quic's
// 10 s, with or without salamander; DisableKeepAlive, which the silent
// client below uses, wins over a period.
func TestHysteriaQUICOptions(t *testing.T) {
	for _, salamander := range []bool{false, true} {
		o := hysteriaQUICOptions(salamander)
		c := &quic.Config{KeepAlivePeriod: 10 * time.Second, MaxIdleTimeout: 30 * time.Second} // sing-quic's defaults
		qtls.ApplyQUICOptions(c, o)
		if c.KeepAlivePeriod != 28*time.Second || c.MaxIdleTimeout != 60*time.Second {
			t.Fatalf("salamander %v: keepalive %v, idle %v", salamander, c.KeepAlivePeriod, c.MaxIdleTimeout)
		}
		if salamander != (o.InitialPacketSize == 1280-8) {
			t.Fatalf("salamander %v: first packet %d", salamander, o.InitialPacketSize)
		}
	}
	c := &quic.Config{KeepAlivePeriod: 10 * time.Second}
	qtls.ApplyQUICOptions(c, qtls.QUICOptions{KeepAlivePeriod: 25 * time.Second, DisableKeepAlive: true})
	if c.KeepAlivePeriod != 0 {
		t.Fatalf("DisableKeepAlive: %v", c.KeepAlivePeriod)
	}
}

// wireLog records each datagram a Hysteria2 client sends and gets.
type wireLog struct {
	net.Conn
	mu     sync.Mutex
	events []wireEvent
}

type wireEvent struct {
	at   time.Time
	sent bool // by the client; else from the server
}

func (c *wireLog) note(sent bool) {
	c.mu.Lock()
	c.events = append(c.events, wireEvent{time.Now(), sent})
	c.mu.Unlock()
}

func (c *wireLog) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.note(false)
	}
	return n, err
}

func (c *wireLog) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.note(true)
	}
	return n, err
}

func (c *wireLog) since(t time.Time) []wireEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []wireEvent
	for _, e := range c.events {
		if e.at.After(t) {
			out = append(out, e)
		}
	}
	return out
}

// loggingDialer hands the Hysteria2 client a socket whose datagrams are
// logged.
type loggingDialer struct {
	N.Dialer
	mu    sync.Mutex
	conn  *wireLog
	dials int
}

func (d *loggingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	l := &wireLog{Conn: c}
	d.mu.Lock()
	d.conn, d.dials = l, d.dials+1
	d.mu.Unlock()
	return l, nil
}

func (d *loggingDialer) state() (*wireLog, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conn, d.dials
}

// TestNekoServerHysteriaKeepAlive (client #148): the server pings only a
// client that has fallen silent, and then every 28 s.
//
// The server pinged every 10 s (sing-quic's default): its PING, answered at
// once, reset a client's 25 s timer before it ran out, so a phone at rest
// woke 360 times an hour. Now a client asking for 25 s, as Niko does, gets
// nothing from the server it did not ask for: over 32 s at rest every
// datagram from the server follows one of the client's (its keepalive near
// 25 s, the server's ACK). A client with no keepalive of its own (a phone
// whose CPU sleeps stops its Go timers) gets the server's PING near 28 s
// and nothing before: its answer keeps the connection and the NAT binding.
// Both connections then carry a request, with no new handshake.
func TestNekoServerHysteriaKeepAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("32 s at rest")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	log := NewLogger("warn", io.Discard)

	cert := selfSigned(t, "h.example.com")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	usersFile := filepath.Join(dir, "users.json")
	writeUsers(t, usersFile, "password-one")

	var direct net.Dialer
	sock := filepath.Join(dir, "hy2-masq.sock")
	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "hy2-masq", Socket: sock, FrontUID: uid, UsersFile: usersFile,
		TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
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
	go runHysteria(ctx, c, conn, log, direct.DialContext)
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{{SNI: []string{"h.example.com"}, Backend: "hy2-masq"}}}
	front, err := newUDPFront(fc, map[string]BackendRef{"hy2-masq": {Socket: sock, Mode: "packet", UID: uid}}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := front.listen(fc.Listen); err != nil {
		t.Fatal(err)
	}
	var server M.Socksaddr
	for _, c := range front.sockets {
		server = M.SocksaddrFromNetIP(c.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	go front.run(ctx)
	time.Sleep(300 * time.Millisecond) // the link comes up

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through hysteria") }))
	defer page.Close()
	newClient := func(o qtls.QUICOptions) (*hysteria2.Client, *loggingDialer) {
		tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), "h.example.com", option.OutboundTLSOptions{Enabled: true, ServerName: "h.example.com",
			Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
		if err != nil {
			t.Fatal(err)
		}
		d := &loggingDialer{Dialer: N.SystemDialer}
		client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: d, Logger: nopLogger(),
			ServerAddress: server, Password: "password-one", TLSConfig: tlsConfig, QUICOptions: o})
		if err != nil {
			t.Fatal(err)
		}
		return client, d
	}
	get := func(client *hysteria2.Client) {
		t.Helper()
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		stream, err := client.DialConn(dctx, M.ParseSocksaddr(page.Listener.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(stream, "GET / HTTP/1.1\r\nHost: page\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
		if err != nil {
			t.Fatal(err)
		}
		if body, _ := io.ReadAll(resp.Body); string(body) != "through hysteria" {
			t.Fatalf("body %q", body)
		}
	}
	// a: Niko's settings. b: no keepalive at all.
	a, ad := newClient(qtls.QUICOptions{KeepAlivePeriod: 25 * time.Second, IdleTimeout: 60 * time.Second})
	defer a.CloseWithError(nil)
	b, bd := newClient(qtls.QUICOptions{DisableKeepAlive: true, IdleTimeout: 60 * time.Second})
	defer b.CloseWithError(nil)
	get(a)
	get(b)

	// The streams' last frames and their ACKs settle; then both rest.
	time.Sleep(time.Second)
	rest := time.Now()
	time.Sleep(32 * time.Second)

	describe := func(evs []wireEvent) string {
		s := ""
		for _, e := range evs {
			who := "server"
			if e.sent {
				who = "client"
			}
			s += fmt.Sprintf(" %s@%.2fs", who, e.at.Sub(rest).Seconds())
		}
		return s
	}
	aLog, _ := ad.state()
	bLog, _ := bd.state()
	// a: each datagram from the server answers one of the client's sent
	// within the second before; the client's own keepalive is there.
	evs := aLog.since(rest)
	var lastSent time.Time
	pinged := false
	for _, e := range evs {
		if e.sent {
			lastSent, pinged = e.at, true
			continue
		}
		if lastSent.IsZero() || e.at.Sub(lastSent) > time.Second {
			t.Fatalf("a client asking for 25 s got a datagram the server sent on its own:%s", describe(evs))
		}
	}
	if !pinged {
		t.Fatalf("a client asking for 25 s sent no keepalive in 32 s:%s", describe(evs))
	}
	// b: the server's PING near 28 s after the last exchange (27 s after
	// the rest began), nothing before it.
	evs = bLog.since(rest)
	first := time.Duration(-1)
	for _, e := range evs {
		if !e.sent {
			first = e.at.Sub(rest)
			break
		}
	}
	if first < 25*time.Second {
		t.Fatalf("a silent client: the server's first datagram at rest at %v, want near 27 s:%s", first, describe(evs))
	}

	// Both connections carry a request, on the same socket.
	get(a)
	get(b)
	if _, n := ad.state(); n != 1 {
		t.Fatalf("a dialed %d times", n)
	}
	if _, n := bd.state(); n != 1 {
		t.Fatalf("b dialed %d times", n)
	}
}
