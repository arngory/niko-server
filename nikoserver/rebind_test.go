//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// natRelay is a client's NAT: the client sends to it, it sends on to the
// server from a port of its own, and rebind gives it a new port, as a NAT
// whose mapping expired does; the old port is gone, and what comes to it
// with it. The client sees nothing of it.
type natRelay struct {
	t      *testing.T
	in     *net.UDPConn
	server *net.UDPAddr

	mu     sync.Mutex
	out    *net.UDPConn
	client *net.UDPAddr
	// up, when set before the client sends, sees each datagram of the
	// client's.
	up func([]byte)
}

func newNATRelay(t *testing.T, server *net.UDPAddr) *natRelay {
	t.Helper()
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &natRelay{t: t, in: in, server: server}
	t.Cleanup(func() {
		in.Close()
		r.mu.Lock()
		r.out.Close()
		r.mu.Unlock()
	})
	r.rebind()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client = from
			out, up := r.out, r.up
			r.mu.Unlock()
			if up != nil {
				up(buf[:n])
			}
			out.Write(buf[:n])
		}
	}()
	return r
}

// rebind moves the relay to a new port and returns it.
func (r *natRelay) rebind() *net.UDPAddr {
	out, err := net.DialUDP("udp4", nil, r.server)
	if err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	old := r.out
	r.out = out
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			client := r.client
			r.mu.Unlock()
			if client != nil {
				r.in.WriteToUDP(buf[:n], client)
			}
		}
	}()
	return out.LocalAddr().(*net.UDPAddr)
}

func (r *natRelay) addr() *net.UDPAddr { return r.in.LocalAddr().(*net.UDPAddr) }

// hysteriaNode is the Hysteria2 backends behind a UDP front on loopback,
// with routable connection IDs (labels 31 and 32) when withCID; the front
// reads the key only when frontCID.
func hysteriaNode(t *testing.T, ctx context.Context, withCID, frontCID bool) (*net.UDPAddr, string) {
	t.Helper()
	front, salamander := hysteriaFront(t, ctx, withCID, frontCID, "127.0.0.1:0")
	for _, s := range front.sockets {
		return s.LocalAddr().(*net.UDPAddr), salamander
	}
	return nil, ""
}

// hysteriaFront is hysteriaNode with the front on the addresses listen.
func hysteriaFront(t *testing.T, ctx context.Context, withCID, frontCID bool, listen ...string) (*udpFront, string) {
	t.Helper()
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
	frontKeys := writeCIDKeys(t, dir, cidSecret, 31, 32)
	var direct net.Dialer
	backends := map[string]BackendRef{}
	for i, kind := range []string{"hy2-masq", "hy2-obfs"} {
		sock := filepath.Join(dir, kind+".sock")
		c := &BackendConfig{Schema: 1, Role: "backend", Kind: kind, Socket: sock, FrontUID: uid, UsersFile: usersFile,
			TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
		if kind == "hy2-obfs" {
			c.Options.ObfsPasswordFile = pwFile
		}
		ref := BackendRef{Socket: sock, Mode: "packet", UID: uid}
		if withCID {
			// The backend has its own label's key, the front its backends'.
			c.Options.CIDKeyFile, c.Options.CIDLabel = writeCIDLabelKey(t, dir, cidSecret, uint16(31+i)), 31+i
			if frontCID {
				ref.CIDLabel = 31 + i
			}
		}
		if errs := c.validate(); len(errs) > 0 {
			t.Fatal(errs)
		}
		conn := packetBackend(t, sock)
		conn.port = 443
		go runHysteria(ctx, c, conn, log, direct.DialContext)
		backends[kind] = ref
	}
	fc := &FrontUDP{Listen: listen, Routes: []UDPRoute{
		{SNI: []string{"h.example.com"}, Backend: "hy2-masq"},
		{SalamanderPasswordFile: pwFile, Backend: "hy2-obfs"},
	}}
	if withCID && frontCID {
		fc.CIDKeysFile = frontKeys
	}
	return runUDPFront(t, fc, backends), salamander
}

// A Hysteria2 client whose NAT gives it a new port mid-connection: its
// stream goes on within a second, and new streams open on the same
// connection. The front pins the new port by the label of the server's
// connection ID, and the server moves to it once the client answered its
// PATH_CHALLENGE there (PathValidation): the front lets that probe through
// at once although the client sent less than a third of it there
// (pathProbeFree; sagernet's quic-go sends the next one only when it holds
// the first lost, a second or two later). Plain and under salamander.
// Without the labels the connection is lost, as before.
func TestNekoServerHysteriaRebind(t *testing.T) {
	echo, _ := echoPair(t)
	for _, c := range []struct {
		name               string
		withCID, frontCID  bool
		survives           bool
		serverName, obfsPW string
	}{
		{"hy2-masq", true, true, true, "h.example.com", ""},
		{"hy2-obfs", true, true, true, "x.invalid", "salamander"},
		{"hy2-masq, labels the front does not read", true, false, false, "h.example.com", ""},
		{"hy2-obfs, no labels", false, false, false, "x.invalid", "salamander"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server, salamander := hysteriaNode(t, ctx, c.withCID, c.frontCID)
			relay := newNATRelay(t, server)
			obfs := ""
			if c.obfsPW != "" {
				obfs = salamander
			}
			tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), c.serverName, option.OutboundTLSOptions{Enabled: true, ServerName: c.serverName,
				Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: nopLogger(),
				ServerAddress: M.SocksaddrFromNet(relay.addr()), Password: "password-one", SalamanderPassword: obfs, TLSConfig: tlsConfig})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(nil)
			conn, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			round := func(what string, within time.Duration) error {
				conn.SetDeadline(time.Now().Add(within))
				if _, err := conn.Write([]byte(what)); err != nil {
					return err
				}
				got := make([]byte, len(what))
				if _, err := io.ReadFull(conn, got); err != nil {
					return err
				}
				if string(got) != what {
					return fmt.Errorf("echo %q", got)
				}
				return nil
			}
			if err := round("before", 5*time.Second); err != nil {
				t.Fatalf("before the new port: %v", err)
			}
			relay.rebind()
			start := time.Now()
			err = round("after the new port", 5*time.Second)
			if !c.survives {
				if err == nil {
					t.Fatal("the connection went on without routing by ID")
				}
				return
			}
			if err != nil {
				t.Fatalf("the stream after the new port: %v", err)
			}
			if took := time.Since(start); took > time.Second {
				t.Fatalf("the stream after the new port took %v", took)
			}
			// A new stream on the same connection, and another new port.
			relay.rebind()
			second, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
			if err != nil {
				t.Fatalf("a new stream after another new port: %v", err)
			}
			defer second.Close()
			second.SetDeadline(time.Now().Add(5 * time.Second))
			second.Write([]byte("second"))
			got := make([]byte, 6)
			if _, err := io.ReadFull(second, got); err != nil || string(got) != "second" {
				t.Fatalf("the second stream: %q %v", got, err)
			}
			if err := round("first stream still", 5*time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// quicgoCIDs gives a generator's IDs to quic-go, as rayd's naive-quic and
// DoH3 take them (raycontrol internal/quiccid).
type quicgoCIDs struct{ *cidGenerator }

func (g quicgoCIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	id := g.generate()
	return quic.ConnectionIDFromBytes(id[:]), nil
}

func (quicgoCIDs) ConnectionIDLen() int { return cidLen }

// h3Node is a quic-go HTTP/3 server on a backend's packet socket, as
// rayd's naive-quic and DoH3 serve behind the front, with labelled
// connection IDs (label 41) when withCID; it answers each request with the
// client's address as the server sees it.
func h3Node(t *testing.T, withCID bool) *net.UDPAddr {
	t.Helper()
	_, addr := h3NodeFront(t, withCID)
	return addr
}

// h3NodeFront is h3Node with its front.
func h3NodeFront(t *testing.T, withCID bool) (*udpFront, *net.UDPAddr) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "h3.sock")
	pc := packetBackend(t, sock)
	tr := &quic.Transport{Conn: pc, StatelessResetKey: &quic.StatelessResetKey{1, 2, 3}}
	ref := BackendRef{Socket: sock, Mode: "packet", UID: os.Getuid()}
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{{SNI: []string{"h3.example.com"}, Backend: "h3"}}}
	if withCID {
		g, err := newCIDGenerator(labelCodec(cidSecret, 41), 41)
		if err != nil {
			t.Fatal(err)
		}
		tr.ConnectionIDGenerator = quicgoCIDs{g}
		ref.CIDLabel = 41
		fc.CIDKeysFile = writeCIDKeys(t, dir, cidSecret, 41)
	}
	cert := selfSigned(t, "h3.example.com")
	ln, err := tr.ListenEarly(http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}), &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write(make([]byte, 256<<10))
			return
		}
		io.WriteString(w, r.RemoteAddr)
	})}
	go srv.ServeListener(ln)
	// The socket before the transport: its reader waits on the front's
	// datagrams, which no deadline wakes.
	t.Cleanup(func() { srv.Close(); ln.Close(); pc.Close(); tr.Close() })
	front := runUDPFront(t, fc, map[string]BackendRef{"h3": ref})
	for _, sock := range front.sockets {
		return front, sock.LocalAddr().(*net.UDPAddr)
	}
	t.Fatal("no socket")
	return nil, nil
}

// h3Get asks the server who it thinks the client is.
func h3Get(ctx context.Context, cc *http3.ClientConn, within time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://h3.example.com/", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

var h3ClientTLS = &tls.Config{ServerName: "h3.example.com", InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}} //nolint:gosec // a test's self-signed server

// A quic-go HTTP/3 client (as naive-quic's and DoH3's) whose address
// changes mid-connection, through the front to a quic-go server on the
// IPC packet socket: by NAT rebinding, which the client does not see, and
// by its own move to a new socket (Conn.AddPath, Probe, Switch). The
// server validates the new path (quic-go's server path manager, through
// the per-packet addresses of the packet socket) and moves its answers
// there: the next request sees the new address.
func TestNekoServerQUICRebind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Run("NAT rebinding", func(t *testing.T) {
		relay := newNATRelay(t, h3Node(t, true))
		qc, err := quic.DialAddr(ctx, relay.addr().String(), h3ClientTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		cc := (&http3.Transport{}).NewClientConn(qc)
		before, err := h3Get(ctx, cc, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			port := relay.rebind()
			// The first request after the move may go out before the path
			// is validated: the server answers on the old path until then.
			var got string
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if got, err = h3Get(ctx, cc, 3*time.Second); err == nil && got == port.String() {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if got != port.String() {
				t.Fatalf("after the new port %v: the server sees %q (before %q), %v", port, got, before, err)
			}
		}
	})
	t.Run("the client moves to a new socket", func(t *testing.T) {
		server := h3Node(t, true)
		listen := func() *quic.Transport {
			s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			tr := &quic.Transport{Conn: s}
			t.Cleanup(func() { tr.Close(); s.Close() })
			return tr
		}
		first := listen()
		qc, err := first.Dial(ctx, server, h3ClientTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		cc := (&http3.Transport{}).NewClientConn(qc)
		if got, err := h3Get(ctx, cc, 5*time.Second); err != nil || got != first.Conn.LocalAddr().String() {
			t.Fatalf("first: %q %v", got, err)
		}
		next := listen()
		path, err := qc.AddPath(next)
		if err != nil {
			t.Fatal(err)
		}
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		defer pcancel()
		if err := path.Probe(pctx); err != nil {
			t.Fatalf("probe of the new path through the front: %v", err)
		}
		if err := path.Switch(); err != nil {
			t.Fatal(err)
		}
		var got string
		for i := 0; i < 50 && got != next.Conn.LocalAddr().String(); i++ {
			got, err = h3Get(ctx, cc, 3*time.Second)
			if err != nil {
				t.Fatalf("after the move: %v", err)
			}
		}
		if got != next.Conn.LocalAddr().String() {
			t.Fatalf("after the move the server sees %q, want %v", got, next.Conn.LocalAddr())
		}
	})
	t.Run("without labels the connection is lost", func(t *testing.T) {
		relay := newNATRelay(t, h3Node(t, false))
		qc, err := quic.DialAddr(ctx, relay.addr().String(), h3ClientTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		cc := (&http3.Transport{}).NewClientConn(qc)
		if _, err := h3Get(ctx, cc, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		relay.rebind()
		if got, err := h3Get(ctx, cc, 2*time.Second); err == nil {
			t.Fatalf("answered after the new port without labels: %q", got)
		}
	})
}

// How many address changes a quic-go v0.64.1 server survives (review 2 of
// quic-cid-route-v1, S1). A client with connection IDs of no length (Chromium,
// quic-go's DialAddr, sing-quic's Hysteria2) moves as often as it likes. A
// client with IDs of its own (quic-go on a Transport with a length, some
// other stacks) moves twice: at each move the server takes one of the
// client's spare IDs for its probe of the new path and, once it switched,
// neither makes it the active one nor retires the old one (path_manager.go
// SwitchToPath), so the spares run out; at the third move it skips the
// validation ("no connection ID is available") and never moves. When quic-go
// is fixed (raycontrol docs/roadmap.md), this test fails: lift the limit
// here and in spec quic-cid-route-v1 §5.
func TestNekoServerQUICRebindLimit(t *testing.T) {
	for _, c := range []struct {
		name   string
		cidLen int
		moves  int // the moves that work; one more fails, unless all do
	}{
		{"client IDs of no length", 0, 6},
		{"client IDs of 8 bytes", 8, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			relay := newNATRelay(t, h3Node(t, true))
			var qc *quic.Conn
			var err error
			if c.cidLen == 0 {
				qc, err = quic.DialAddr(ctx, relay.addr().String(), h3ClientTLS, &quic.Config{})
			} else {
				s, lerr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if lerr != nil {
					t.Fatal(lerr)
				}
				tr := &quic.Transport{Conn: s, ConnectionIDLength: c.cidLen}
				t.Cleanup(func() { tr.Close(); s.Close() })
				qc, err = tr.Dial(ctx, relay.addr(), h3ClientTLS, &quic.Config{})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer qc.CloseWithError(0, "")
			cc := (&http3.Transport{}).NewClientConn(qc)
			if _, err := h3Get(ctx, cc, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			moved := func(within time.Duration) bool {
				port := relay.rebind()
				for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
					if got, err := h3Get(ctx, cc, time.Second); err == nil && got == port.String() {
						return true
					}
				}
				return false
			}
			for i := range c.moves {
				if !moved(8 * time.Second) {
					t.Fatalf("move %d of %d failed", i+1, c.moves)
				}
			}
			if c.cidLen != 0 && moved(4*time.Second) {
				t.Fatalf("move %d worked: quic-go no longer runs out of the client's IDs; lift the limit (spec §5)", c.moves+1)
			}
		})
	}
}
