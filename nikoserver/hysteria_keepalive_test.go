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

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// readLog records when each datagram from the server arrives.
type readLog struct {
	net.Conn
	mu    sync.Mutex
	times []time.Time
}

func (c *readLog) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.times = append(c.times, time.Now())
		c.mu.Unlock()
	}
	return n, err
}

func (c *readLog) since(t time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, at := range c.times {
		if at.After(t) {
			n++
		}
	}
	return n
}

// loggingDialer hands the Hysteria2 client a socket whose reads are logged.
type loggingDialer struct {
	N.Dialer
	mu   sync.Mutex
	conn *readLog
}

func (d *loggingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	l := &readLog{Conn: c}
	d.mu.Lock()
	d.conn = l
	d.mu.Unlock()
	return l, nil
}

// TestNekoServerHysteriaQuietIdle: a Hysteria2 connection at rest gets
// nothing from the server; its keepalives are the client's (client #148).
// The server's own PING every 10 s (sing-quic's default) woke a phone's
// radio 360 times an hour and kept no NAT binding of the phone's open
// (RFC 4787: outbound packets refresh it). The client here asks for 25 s,
// as Niko does: over 12 s of rest the server must send nothing, where
// before it pinged at 10 s.
func TestNekoServerHysteriaQuietIdle(t *testing.T) {
	if testing.Short() {
		t.Skip("12 s of rest")
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
	tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), "h.example.com", option.OutboundTLSOptions{Enabled: true, ServerName: "h.example.com",
		Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &loggingDialer{Dialer: N.SystemDialer}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: dialer, Logger: nopLogger(),
		ServerAddress: server, Password: "password-one", TLSConfig: tlsConfig,
		QUICOptions: qtls.QUICOptions{KeepAlivePeriod: 25 * time.Second, IdleTimeout: 60 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	get := func() {
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
	get()

	// The stream's last frames and their ACKs settle, then the connection
	// rests: the client sends nothing before its 25 s, so the server's
	// keepalive, if it had one, would be the only datagram.
	time.Sleep(time.Second)
	dialer.mu.Lock()
	logged := dialer.conn
	dialer.mu.Unlock()
	if logged == nil {
		t.Fatal("the client dialed no socket")
	}
	rest := time.Now()
	time.Sleep(12 * time.Second)
	if n := logged.since(rest); n != 0 {
		t.Fatalf("the server sent %d datagrams to a connection at rest (its own keepalive)", n)
	}
	// The connection is alive at both ends: the client's next request goes
	// through on it, with no new handshake.
	get()
	if n := logged.since(rest); n == 0 {
		t.Fatal("no answer after the rest")
	}
	dialer.mu.Lock()
	again := dialer.conn
	dialer.mu.Unlock()
	if again != logged {
		t.Fatal("the client dialed again after the rest")
	}
}
