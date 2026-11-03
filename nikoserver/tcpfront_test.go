//go:build linux

package nikoserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helloBytes is what a Go TLS 1.3 client (X25519MLKEM768 offered) sends first.
func helloBytes(t *testing.T, name string, alpn ...string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		tls.Client(c, &tls.Config{ServerName: name, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
	}()
	_, raw, err := readClientHello(s)
	s.Close()
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNekoServerClientHello(t *testing.T) {
	raw := helloBytes(t, "R.Example.com", "h2", "http/1.1")
	h, got, err := readClientHello(bytes.NewReader(append(raw, "rest"...)))
	if err != nil || h.serverName != "r.example.com" || strings.Join(h.alpn, ",") != "h2,http/1.1" || !bytes.Equal(got, raw) {
		t.Fatalf("hello %+v, %d of %d bytes, %v", h, len(got), len(raw), err)
	}
	// The same ClientHello in three records, as some clients split it.
	body := raw[5:]
	var split []byte
	for _, part := range [][]byte{body[:7], body[7:300], body[300:]} {
		split = append(split, 0x16, 3, 1)
		split = binary.BigEndian.AppendUint16(split, uint16(len(part)))
		split = append(split, part...)
	}
	h, got, err = readClientHello(bytes.NewReader(split))
	if err != nil || h.serverName != "r.example.com" || !bytes.Equal(got, split) {
		t.Fatalf("split hello %+v %v", h, err)
	}
	// No SNI: routed to the default.
	if h, _, err := readClientHello(bytes.NewReader(helloBytes(t, ""))); err != nil || h.serverName != "" {
		t.Fatalf("no SNI: %+v %v", h, err)
	}
	for name, input := range map[string][]byte{
		"HTTP":        []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"alert":       {0x15, 3, 3, 0, 2, 2, 40},
		"short":       raw[:40],
		"huge":        {0x16, 3, 1, 0xff, 0xff},
		"not a hello": append([]byte{0x16, 3, 1, 0, 4}, 2, 0, 0, 0),
	} {
		if _, _, err := readClientHello(bytes.NewReader(input)); err == nil {
			t.Errorf("%s: read as a ClientHello", name)
		}
	}
}

func TestNekoServerHandoffAndProxyHeader(t *testing.T) {
	h := tcpHandoff{route: "naive", src: netip.MustParseAddrPort("203.0.113.7:51000"),
		dst: netip.MustParseAddrPort("[2001:db8::1]:443"), sni: "n.example.com", prefetch: []byte{0x16, 3, 1}}
	got, err := decodeHandoff(encodeHandoff(h))
	if err != nil || got.route != h.route || got.src != h.src || got.dst != h.dst || got.sni != h.sni || !bytes.Equal(got.prefetch, h.prefetch) {
		t.Fatalf("handoff %+v %v", got, err)
	}
	if _, err := decodeHandoff(encodeHandoff(h)[:20]); err == nil {
		t.Fatal("a cut message decoded")
	}
	v4 := proxyV2Header(netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort("198.51.100.1:443"))
	want := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12, 203, 0, 113, 7, 198, 51, 100, 1, 0xc7, 0x38, 0x01, 0xbb)
	if !bytes.Equal(v4, want) {
		t.Fatalf("PROXY v2 for IPv4:\n%x\n%x", v4, want)
	}
	mixed := proxyV2Header(netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort("[2001:db8::1]:443"))
	if len(mixed) != 16+36 || mixed[13] != 0x21 || !bytes.Equal(mixed[16:32], netip.MustParseAddr("::ffff:203.0.113.7").AsSlice()) {
		t.Fatalf("PROXY v2 for mixed families: %x", mixed)
	}
}

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS answers "<who> <server name> <client address>" on each TLS connection.
func serveTLS(ln net.Listener, who string, cert tls.Certificate) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}})
			if s.Handshake() != nil {
				return
			}
			io.WriteString(s, who+" "+s.ConnectionState().ServerName+" "+c.RemoteAddr().String()+"\n")
		}()
	}
}

// proxyListener strips the PROXY v2 header, as Xray does, and keeps the
// client address from it.
type proxyListener struct{ net.Listener }

type proxiedConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *proxiedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *proxiedConn) RemoteAddr() net.Addr       { return c.remote }

func (l proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil || !bytes.HasPrefix(head, []byte("\r\n\r\n\x00\r\nQUIT\n\x21")) {
		c.Close()
		return l.Accept()
	}
	addrs := make([]byte, binary.BigEndian.Uint16(head[14:16]))
	io.ReadFull(r, addrs)
	var remote netip.AddrPort
	if head[13] == 0x11 {
		remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(addrs[0:4])), binary.BigEndian.Uint16(addrs[8:10]))
	} else {
		remote = netip.AddrPortFrom(netip.AddrFrom16([16]byte(addrs[0:16])).Unmap(), binary.BigEndian.Uint16(addrs[32:34]))
	}
	return &proxiedConn{Conn: c, r: r, remote: net.TCPAddrFromAddrPort(remote)}, nil
}

func TestNekoServerTCPFront(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	log := NewLogger("warn", io.Discard)
	uid := os.Getuid()
	cert := selfSigned(t, "r.example.com", "n.example.com", "x.example.com")

	// An fd backend (naive, yggdrasil) and a PROXY v2 one (Xray REALITY).
	fdSock := filepath.Join(dir, "fd.sock")
	fdl, err := ListenFD(fdSock, uid, log)
	if err != nil {
		t.Fatal(err)
	}
	defer fdl.Close()
	go serveTLS(fdl, "fd", cert)
	pxSock := filepath.Join(dir, "reality.sock")
	pxl, err := net.Listen("unix", pxSock)
	if err != nil {
		t.Fatal(err)
	}
	defer pxl.Close()
	go serveTLS(proxyListener{pxl}, "proxy", cert)

	c := &FrontTCP{Listen: []string{"127.0.0.1:0"}, SniffTimeout: "1s", Default: "reality", Routes: []TCPRoute{
		{SNI: []string{"r.example.com"}, Backend: "reality"},
		{SNI: []string{"N.example.com."}, Backend: "naive"},
		{ALPN: []string{"acme-tls/1"}, Backend: "naive"},
	}}
	backends := map[string]BackendRef{
		"reality": {Socket: pxSock, Mode: "proxy-v2", UID: uid},
		"naive":   {Socket: fdSock, Mode: "fd", UID: uid},
	}
	var e configErrors
	c.validate(&e, backends)
	if len(e) > 0 {
		t.Fatal(e)
	}
	front := newTCPFront(c, backends, log)
	if err := front.listen(c.Listen); err != nil {
		t.Fatal(err)
	}
	addr := front.listeners[0].Addr().String()
	go front.run(ctx)

	ask := func(name string, alpn ...string) (string, string) {
		t.Helper()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		s := tls.Client(conn, &tls.Config{ServerName: name, NextProtos: alpn, InsecureSkipVerify: true,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}})
		s.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(s).ReadString('\n')
		if err != nil {
			return "", err.Error()
		}
		return strings.TrimSpace(line), conn.LocalAddr().String()
	}
	// The fd link connects in the background.
	for i := 0; ; i++ {
		if got, _ := ask("n.example.com"); strings.HasPrefix(got, "fd ") {
			break
		}
		if i == 50 {
			t.Fatal("the fd backend never got a connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for name, want := range map[string]string{
		"n.example.com": "fd n.example.com",
		"r.example.com": "proxy r.example.com",
		"x.example.com": "proxy x.example.com", // unknown: the default
		"":              "proxy ",
	} {
		got, local := ask(name)
		// The backend sees the client's own address, through either mode.
		if got != want+" "+local {
			t.Errorf("%q: got %q, want %q", name, got, want+" "+local)
		}
	}
	if got, _ := ask("y.example.com", "acme-tls/1"); !strings.HasPrefix(got, "fd y.example.com") {
		t.Errorf("ALPN route: %q", got)
	}

	// Not TLS: closed, nothing said.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: r.example.com\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 64)); n != 0 || err == nil || strings.Contains(err.Error(), "timeout") {
		t.Errorf("non-TLS: read %d, %v", n, err)
	}
	conn.Close()

	// Silent after connecting: closed at the sniff timeout.
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") || time.Since(start) > 2*time.Second {
		t.Errorf("silent client: %v after %v", err, time.Since(start))
	}
	conn.Close()

	// The fd backend gone: its connections close, the others still work.
	fdl.Close()
	time.Sleep(100 * time.Millisecond)
	if got, _ := ask("n.example.com"); strings.HasPrefix(got, "fd ") {
		t.Error("a connection reached a backend that is gone")
	}
	if got, _ := ask("r.example.com"); !strings.HasPrefix(got, "proxy ") {
		t.Errorf("REALITY after the fd backend left: %q", got)
	}
}
