//go:build linux

package nikoserver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
)

// deviceHysteriaNode is hy2-obfs behind a UDP front that holds the
// devices' salamander passwords (salamander_passwords_file) and the
// backend none (salamander_front), with routable connection IDs (label
// 32); the front reads its file every 20 ms. It returns the front's
// address and the file.
func deviceHysteriaNode(t *testing.T, ctx context.Context, passwords ...string) (*net.UDPAddr, string) {
	t.Helper()
	dir := t.TempDir()
	uid := os.Getuid()
	cert := selfSigned(t, "x.invalid")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	usersFile := filepath.Join(dir, "users.json")
	writeUsers(t, usersFile, "password-one")
	file := filepath.Join(dir, "hy2-obfs.salamander.keys")
	writePasswords(t, file, passwords...)
	sock := filepath.Join(dir, "hy2-obfs.sock")
	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "hy2-obfs", Socket: sock, FrontUID: uid, UsersFile: usersFile,
		TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
	c.Options.SalamanderFront = true
	c.Options.CIDKeyFile, c.Options.CIDLabel = writeCIDLabelKey(t, dir, cidSecret, 32), 32
	if errs := c.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	conn := packetBackend(t, sock)
	conn.port = 443
	var direct net.Dialer
	go runHysteria(ctx, c, conn, NewLogger("warn", io.Discard), direct.DialContext)
	backends := map[string]BackendRef{"hy2-obfs": {Socket: sock, Mode: "packet", UID: uid, CIDLabel: 32}}
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, CIDKeysFile: writeCIDKeys(t, dir, cidSecret, 32),
		Routes: []UDPRoute{{SalamanderPasswordsFile: file, Backend: "hy2-obfs"}}}
	cfg := &FrontConfig{Schema: 1, Role: "front", UDP: fc, Backends: backends}
	if errs := cfg.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	front, err := newUDPFront(fc, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	front.devicesEvery = 20 * time.Millisecond
	if err := front.listen(fc.Listen); err != nil {
		t.Fatal(err)
	}
	go front.run(ctx)
	for i := 0; ; i++ {
		l := front.links["hy2-obfs"]
		l.access.Lock()
		up := l.conn != nil
		l.access.Unlock()
		if up {
			break
		}
		if i == 200 {
			t.Fatal("backend never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, s := range front.sockets {
		return s.LocalAddr().(*net.UDPAddr), file
	}
	return nil, ""
}

// hy2-obfs with a salamander password of each device, end to end with the
// sing-quic client (as Niko's): two devices, each through its own NAT, get
// their streams; one whose NAT gives it a new port goes on within a second
// (the label, under its key first); a key not on the list does not
// connect; a device removed from the file loses its open connection, the
// other keeps its own.
func TestNekoServerHysteriaDeviceKeys(t *testing.T) {
	echo, _ := echoPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b, c := devicePassword(1), devicePassword(2), devicePassword(3)
	server, file := deviceHysteriaNode(t, ctx, a, b)
	type device struct {
		relay *natRelay
		conn  net.Conn
	}
	devices := map[string]*device{}
	round := func(conn net.Conn, what string, within time.Duration) error {
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
	for _, pw := range []string{a, b} {
		relay := newNATRelay(t, server)
		client := hysteriaClient(t, ctx, "x.invalid", pw, hysteria2.ClientOptions{ServerAddress: M.SocksaddrFromNet(relay.addr())})
		conn, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := round(conn, "hello", 5*time.Second); err != nil {
			t.Fatalf("a device: %v", err)
		}
		devices[pw] = &device{relay, conn}
	}

	// A new port behind a's NAT: the same connection goes on.
	devices[a].relay.rebind()
	start := time.Now()
	if err := round(devices[a].conn, "after the new port", 5*time.Second); err != nil {
		t.Fatalf("after the new port: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("after the new port: %v", took)
	}

	// A key not on the list gets nowhere.
	dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
	defer dialCancel()
	stranger := hysteriaClient(t, dialCtx, "x.invalid", c, hysteria2.ClientOptions{ServerAddress: M.SocksaddrFromNet(server)})
	if conn, err := stranger.DialConn(dialCtx, M.SocksaddrFromNet(echo.Addr())); err == nil {
		if round(conn, "stranger", time.Second) == nil {
			t.Fatal("a key not on the list connected")
		}
		conn.Close()
	}

	// b removed: its connection is cut at once, a's goes on.
	writePasswords(t, file, a)
	time.Sleep(200 * time.Millisecond)
	if err := round(devices[b].conn, "after the removal", 2*time.Second); err == nil {
		t.Fatal("a device removed kept its connection")
	}
	if err := round(devices[a].conn, "a device kept", 5*time.Second); err != nil {
		t.Fatalf("a device kept: %v", err)
	}
}

// A device's connection through a hy2-obfs backend that went (a crash, its
// idle timeout) and came back: the backend's stateless reset, plain QUIC
// to the front, goes to the device under its key, and the client opens a
// new connection at once. A prober's datagrams, under no key on the list,
// get nothing.
func TestNekoServerHysteriaDeviceReset(t *testing.T) {
	echo, _ := echoPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	log := NewLogger("warn", io.Discard)
	cert := selfSigned(t, "x.invalid")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	usersFile := filepath.Join(dir, "users.json")
	writeUsers(t, usersFile, "password-one")
	pw := devicePassword(1)
	file := filepath.Join(dir, "hy2-obfs.salamander.keys")
	writePasswords(t, file, pw, devicePassword(2))
	sock := filepath.Join(dir, "hy2-obfs.sock")
	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "hy2-obfs", Socket: sock, FrontUID: uid, UsersFile: usersFile,
		TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile}}
	c.Options.SalamanderFront = true
	c.Options.CIDKeyFile, c.Options.CIDLabel = writeCIDLabelKey(t, dir, cidSecret, 31), 31
	if errs := c.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	var direct net.Dialer
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
		Routes: []UDPRoute{{SalamanderPasswordsFile: file, Backend: "hy2-obfs"}}},
		map[string]BackendRef{"hy2-obfs": {Socket: sock, Mode: "packet", UID: uid, CIDLabel: 31}})
	var server *net.UDPAddr
	for _, s := range front.sockets {
		server = s.LocalAddr().(*net.UDPAddr)
	}
	probe, err := net.DialUDP("udp", nil, server)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	for _, d := range [][]byte{obfuscate("not a device", initialPacket(1200)), shortPacket(cidID(cidSecret, 31, 1), 1200),
		obfuscate("not a device", shortPacket(cidID(cidSecret, 31, 1), 1200))} {
		probe.Write(d)
	}
	probe.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := probe.Read(make([]byte, 2048)); err == nil {
		t.Fatalf("a prober's packet got %d bytes back", n)
	}
	client := hysteriaClient(t, ctx, "x.invalid", pw, hysteria2.ClientOptions{ServerAddress: M.SocksaddrFromNet(server)})
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
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(1100 * time.Millisecond)))
	defer start()()
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
}
