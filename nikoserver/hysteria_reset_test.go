//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A Hysteria2 backend gone under a client without a word (a crash, or its
// idle timeout while the client slept) and started again: the client's next packet
// of its old connection gets a stateless reset, under the label's key,
// which the new process shares, so the client learns at once that the
// connection is gone and opens a new one. Under salamander too: the front
// passes the backend only packets with its label. Before, a client waited
// out its idle timeout (Niko: 60 s) with no internet: under salamander the
// server sent no resets, and plain it sent them under a key of its own,
// with tokens the client drops.
func TestNekoServerHysteriaResetAfterRestart(t *testing.T) {
	echo, _ := echoPair(t)
	for _, kind := range []string{"hy2-masq", "hy2-obfs"} {
		t.Run(kind, func(t *testing.T) {
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
			sock := filepath.Join(dir, kind+".sock")
			c := &BackendConfig{Schema: 1, Role: "backend", Kind: kind, Socket: sock, FrontUID: uid, UsersFile: usersFile,
				TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
			c.Options.CIDKeyFile, c.Options.CIDLabel = writeCIDLabelKey(t, dir, cidSecret, 31), 31
			route := UDPRoute{SNI: []string{"h.example.com"}, Backend: kind}
			serverName, obfs := "h.example.com", ""
			if kind == "hy2-obfs" {
				c.Options.ObfsPasswordFile = pwFile
				route = UDPRoute{SalamanderPasswordFile: pwFile, Backend: kind}
				serverName, obfs = "x.invalid", salamander
			}
			if errs := c.validate(); len(errs) > 0 {
				t.Fatal(errs)
			}
			var direct net.Dialer
			// start runs the backend, a process of its own; stop ends it
			// as a crash does, or as the server's idle timeout ends a
			// connection: the socket goes first, so no CONNECTION_CLOSE
			// reaches the client.
			start := func() (stop func()) {
				bctx, bcancel := context.WithCancel(ctx)
				conn := packetBackend(t, sock)
				conn.port = 443
				done := make(chan struct{})
				go func() { defer close(done); runHysteria(bctx, c, conn, log, direct.DialContext) }()
				return func() { conn.Close(); bcancel(); <-done }
			}
			stop := start()
			front := runUDPFront(t, &FrontUDP{Listen: []string{"127.0.0.1:0"}, CIDKeysFile: writeCIDKeys(t, dir, cidSecret, 31),
				Routes: []UDPRoute{route}}, map[string]BackendRef{kind: {Socket: sock, Mode: "packet", UID: uid, CIDLabel: 31}})
			var server *net.UDPAddr
			for _, s := range front.sockets {
				server = s.LocalAddr().(*net.UDPAddr)
			}
			// A prober's packets, a long-header-looking one and short ones,
			// get nothing: the front passes the backend only packets with
			// its label, so the resets answer its own clients only.
			probe, err := net.DialUDP("udp", nil, server)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			for _, first := range []byte{0x40, 0x4f, 0xc0} {
				p := make([]byte, 1200)
				rand.Read(p)
				p[0] = first
				probe.Write(p)
			}
			probe.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if n, err := probe.Read(make([]byte, 2048)); err == nil {
				t.Fatalf("a prober's packet got %d bytes back", n)
			}
			tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), serverName, option.OutboundTLSOptions{Enabled: true, ServerName: serverName,
				Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
				ServerAddress: M.SocksaddrFromNet(server), Password: "password-one", SalamanderPassword: obfs, TLSConfig: tlsConfig})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(nil)
			echoOnce := func(what string, within time.Duration) error {
				conn, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(within))
				if _, err := conn.Write([]byte(what)); err != nil {
					return err
				}
				got := make([]byte, len(what))
				_, err = io.ReadFull(conn, got)
				return err
			}
			if err := echoOnce("before", 5*time.Second); err != nil {
				t.Fatalf("before the restart: %v", err)
			}
			stop()
			// The next process starts its IDs from the clock's second
			// (cidStart): in the same second, the old IDs could be ahead of
			// its counter, which gives them no reset.
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(1100 * time.Millisecond)))
			defer start()()
			// The first stream after the restart may go on the old
			// connection: the reset ends it; a client then opens a new one.
			begin := time.Now()
			for {
				if err := echoOnce("after", 3*time.Second); err == nil {
					break
				}
				if time.Since(begin) > 10*time.Second {
					t.Fatal("no stream through the restarted backend in 10 s")
				}
			}
			if took := time.Since(begin); took > 5*time.Second {
				t.Fatalf("back after %v: the client waited for its idle timeout, not a reset", took)
			}
		})
	}
}

// Under salamander the server answers a short header only with an ID of its
// own it issued: a random one, another label's, one to come and a runt get
// nothing, long headers pass.
func TestCIDDropUnlabelled(t *testing.T) {
	g, err := newCIDGeneratorAt(newSpeck(cidLabelKey(cidSecret, 31)), 31, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	other, err := newCIDGeneratorAt(newSpeck(cidLabelKey(cidSecret, 32)), 32, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	short := func(id []byte) []byte {
		p := make([]byte, minCIDPacket+16)
		p[0] = 0x40
		copy(p[1:], id)
		return p
	}
	issued := g.generate()
	if g.dropUnlabelled(short(issued[:])) {
		t.Fatal("an ID it issued dropped")
	}
	next := g.next.Load() + 5
	ahead := g.codec.encode(g.label, next)
	if !g.dropUnlabelled(short(ahead[:])) {
		t.Fatal("an ID to come passed")
	}
	theirs := other.generate()
	if !g.dropUnlabelled(short(theirs[:])) {
		t.Fatal("another label's ID passed")
	}
	random := make([]byte, cidLen)
	for range 1000 {
		rand.Read(random)
		if !g.dropUnlabelled(short(random)) {
			t.Fatal("a random ID passed")
		}
	}
	if !g.dropUnlabelled([]byte{0x40, 1, 2}) {
		t.Fatal("a runt passed")
	}
	if g.dropUnlabelled(append([]byte{0xc0}, make([]byte, 1199)...)) {
		t.Fatal("a long header dropped")
	}
}
