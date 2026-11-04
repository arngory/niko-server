//go:build linux

package nikoserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func writeUsers(t *testing.T, path string, passwords ...string) {
	t.Helper()
	var users []string
	for i, p := range passwords {
		users = append(users, fmt.Sprintf(`{"name":"u-%d","enabled":true,"hy2":{"password":%q}}`, i, p))
	}
	users = append(users, `{"name":"off","enabled":false,"hy2":{"password":"disabled-user"}}`)
	if err := os.WriteFile(path, []byte(`{"users":[`+strings.Join(users, ",")+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNekoServerHysteria(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	log := NewLogger("warn", io.Discard)

	cert := selfSigned(t, "h.example.com", "x.invalid")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	usersFile := filepath.Join(dir, "users.json")
	writeUsers(t, usersFile, "password-one")
	salamander := "c2FsYW1hbmRlci1wYXNzd29yZA"
	pwFile := filepath.Join(dir, "salamander")
	os.WriteFile(pwFile, []byte(salamander+"\n"), 0o600)

	// The probe route (raycontrol's channel probes): TCP and UDP echo on one
	// loopback port.
	probeTCP, probeUDP := echoPair(t)
	probe := &ProbeRoute{Name: "probe.raycontrol.invalid", Address: probeTCP.Addr().String()}

	// The destination is on loopback, which a node never dials: the test's
	// backends dial directly.
	var direct net.Dialer
	backends := map[string]BackendRef{}
	for _, kind := range []string{"hy2-masq", "hy2-obfs"} {
		sock := filepath.Join(dir, kind+".sock")
		c := &BackendConfig{Schema: 1, Role: "backend", Kind: kind, Socket: sock, FrontUID: uid, UsersFile: usersFile,
			TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
		if kind == "hy2-obfs" {
			c.Options.ObfsPasswordFile = pwFile
		}
		c.Options.Probe = probe
		c.StatsSocket = filepath.Join(dir, kind+"-stats.sock")
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
		backends[kind] = BackendRef{Socket: sock, Mode: "packet", UID: uid}
	}
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{
		{SNI: []string{"h.example.com"}, Backend: "hy2-masq"},
		{SalamanderPasswordFile: pwFile, Backend: "hy2-obfs"},
	}}
	front, err := newUDPFront(fc, backends, log)
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
	time.Sleep(300 * time.Millisecond) // the links come up

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through hysteria") }))
	defer page.Close()
	fetch := func(name, password, obfs string) error {
		tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), name, option.OutboundTLSOptions{Enabled: true, ServerName: name,
			Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
		if err != nil {
			return err
		}
		client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
			ServerAddress: server, Password: password, SalamanderPassword: obfs, TLSConfig: tlsConfig})
		if err != nil {
			return err
		}
		defer client.CloseWithError(nil)
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := client.DialConn(dctx, M.ParseSocksaddr(page.Listener.Addr().String()))
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: page\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "through hysteria" {
			return fmt.Errorf("body %q", body)
		}
		return nil
	}
	if err := fetch("h.example.com", "password-one", ""); err != nil {
		t.Fatalf("hy2-masq: %v", err)
	}
	// The probe name leads to its address, TCP and UDP; replies come from the
	// name. Loopback by address stays out over UDP (the test dials TCP
	// directly, so only UDP shows the node's own refusal).
	probeClient := func() *hysteria2.Client {
		tlsConfig, _ := sbtls.NewClient(ctx, nopLogger(), "h.example.com", option.OutboundTLSOptions{Enabled: true, ServerName: "h.example.com",
			Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
		client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
			ServerAddress: server, Password: "password-one", TLSConfig: tlsConfig})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	pcl := probeClient()
	defer pcl.CloseWithError(nil)
	pconn, err := pcl.DialConn(ctx, M.ParseSocksaddrHostPort(probe.Name, 443))
	if err != nil {
		t.Fatalf("probe over TCP: %v", err)
	}
	pconn.SetDeadline(time.Now().Add(5 * time.Second))
	pconn.Write([]byte("probe"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(pconn, got); err != nil || string(got) != "probe" {
		t.Fatalf("probe over TCP: %q %v", got, err)
	}
	pconn.Close()
	// Session stats by client address: a Brutal client (it gives its
	// receive rate) next to the BBR one above.
	brutalTLS, _ := sbtls.NewClient(ctx, nopLogger(), "h.example.com", option.OutboundTLSOptions{Enabled: true, ServerName: "h.example.com",
		Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
	bcl, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
		ServerAddress: server, Password: "password-one", TLSConfig: brutalTLS, ReceiveBPS: 10 * hysteria.MbpsToBps})
	if err != nil {
		t.Fatal(err)
	}
	defer bcl.CloseWithError(nil)
	bconn, err := bcl.DialConn(ctx, M.ParseSocksaddrHostPort(probe.Name, 443))
	if err != nil {
		t.Fatal(err)
	}
	bconn.Write([]byte("brutal"))
	io.ReadFull(bconn, make([]byte, 6))
	defer bconn.Close()
	query := func(line string) HysteriaStats {
		c, err := net.Dial("unix", filepath.Join(dir, "hy2-masq-stats.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintln(c, line)
		var st HysteriaStats
		if err := json.NewDecoder(c).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := query("127.0.0.1")
	if st.Connections != 2 || st.RTTus.Max == 0 || st.PacketsSent == 0 || st.Brutal.Connections != 1 ||
		st.Brutal.RateBps.Max != 10*1000*1000 || st.Brutal.AckRate.Max <= 0 || st.Brutal.AckRate.Max > 1 {
		t.Fatalf("stats %+v", st)
	}
	if other := query("203.0.113.9"); other.Connections != 0 {
		t.Fatalf("another address: %+v", other)
	}
	if st.Own != nil {
		t.Fatalf("sessions one by one without a name: %+v", st.Own)
	}
	// With the user's name: that user's sessions one by one, beside the
	// aggregates of the address; another user's name sees none of them.
	own := query("127.0.0.1 u-0")
	brutal := 0
	for _, s := range own.Own {
		if s.RTTus == 0 || s.PacketsSent == 0 {
			t.Fatalf("own session %+v", s)
		}
		if s.Brutal != nil {
			brutal++
			if s.Brutal.RateBps != 10*1000*1000 || s.Brutal.AckRate <= 0 || s.Brutal.AckRate > 1 {
				t.Fatalf("own Brutal %+v", s.Brutal)
			}
		}
	}
	if len(own.Own) != 2 || brutal != 1 || own.Connections != 2 {
		t.Fatalf("own sessions %+v", own)
	}
	if got := query("127.0.0.1 u-1"); len(got.Own) != 0 || got.Connections != 2 {
		t.Fatalf("another user sees %+v", got)
	}
	if !owns("u7-n", "u7") || !owns("u7", "u7") || owns("u70", "u7") || owns("u7", "") {
		t.Fatal("owns")
	}

	ppc, err := pcl.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ppc.Close()
	target := M.ParseSocksaddrHostPort(probe.Name, 34567)
	if _, err := ppc.WriteTo([]byte("datagram"), target); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	n, from, err := ppc.ReadFrom(b)
	if err != nil || string(b[:n]) != "datagram" || M.SocksaddrFromNet(from).Fqdn != probe.Name {
		t.Fatalf("probe over UDP: %q from %v, %v", b[:n], from, err)
	}
	// sing-quic's packet conn has no read deadline: wait, then close it.
	ppc.WriteTo([]byte("loopback"), probeUDP.LocalAddr())
	leaked := make(chan string, 1)
	go func() {
		if n, _, err := ppc.ReadFrom(b); err == nil {
			leaked <- string(b[:n])
		}
	}()
	select {
	case got := <-leaked:
		t.Fatalf("loopback by address over UDP: %q", got)
	case <-time.After(500 * time.Millisecond):
		ppc.Close()
	}
	if err := fetch("x.invalid", "password-one", salamander); err != nil {
		t.Fatalf("hy2-obfs: %v", err)
	}
	for name, args := range map[string][3]string{
		"wrong password":   {"h.example.com", "password-two", ""},
		"disabled user":    {"h.example.com", "disabled-user", ""},
		"name not routed":  {"q.example.com", "password-one", ""},
		"wrong salamander": {"x.invalid", "password-one", "another-salamander"},
	} {
		if err := fetch(args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: got through", name)
		}
	}

	// A rotated password: the users file changes, SIGHUP reloads it (the
	// vendored sing-quic swaps the table atomically: no race any more).
	writeUsers(t, usersFile, "password-two")
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond)
	if err := fetch("h.example.com", "password-two", ""); err != nil {
		t.Fatalf("after the reload: %v", err)
	}
	if err := fetch("h.example.com", "password-one", ""); err == nil {
		t.Fatal("the old password still works")
	}
}

// echoPair is a TCP and a UDP echo on the same loopback port.
func echoPair(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	for range 20 {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp4", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			continue
		}
		t.Cleanup(func() { ln.Close(); pc.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { io.Copy(c, c); c.Close() }()
			}
		}()
		go func() {
			b := make([]byte, 2048)
			for {
				n, from, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				pc.WriteTo(b[:n], from)
			}
		}()
		return ln, pc
	}
	t.Fatal("no free port for TCP and UDP")
	return nil, nil
}
