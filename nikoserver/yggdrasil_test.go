//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	"golang.org/x/crypto/blake2b"
)

// yggClient is a Niko client's side: a Yggdrasil node with the one peer,
// and a netstack on its address.
func yggClient(t *testing.T, ctx context.Context, peer string) (*core.Core, *stack.Stack, ed25519.PublicKey) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := yggCertificate(private)
	if err != nil {
		t.Fatal(err)
	}
	node, err := core.New(cert, yggLog{NewLogger("error", io.Discard)}, core.Peer{URI: peer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Stop)
	rwc := ipv6rwc.NewReadWriteCloser(node)
	t.Cleanup(func() { rwc.Close() })
	addr, _ := netip.AddrFromSlice(node.Address())
	s, err := yggNetstack(ctx, rwc, addr, uint32(rwc.MTU()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return node, s, public
}

func peerUp(node *core.Core) bool {
	for _, p := range node.GetPeers() {
		if p.Up {
			return true
		}
	}
	return false
}

func waitFor(d time.Duration, ok func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return true
		}
	}
	return ok()
}

func writeYggUsers(t *testing.T, path string, keys ...ed25519.PublicKey) {
	t.Helper()
	users := []string{`{"name":"off","enabled":false,"yggdrasil":{"public_key":"` + strings.Repeat("ab", 32) + `"}}`}
	for i, k := range keys {
		users = append(users, fmt.Sprintf(`{"name":"u-%d","enabled":true,"yggdrasil":{"public_key":%q}}`, i, hex.EncodeToString(k)))
	}
	if err := os.WriteFile(path, []byte(`{"users":[`+strings.Join(users, ",")+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNekoServerYggdrasil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	log := NewLogger("warn", io.Discard)

	cert := selfSigned(t, "y.example.com")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	nodeKey := ed25519.NewKeyFromSeed(seed)
	nodePublic := nodeKey.Public().(ed25519.PublicKey)
	keyPath := filepath.Join(dir, "node.key")
	os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600)
	usersFile := filepath.Join(dir, "users.json")
	writeYggUsers(t, usersFile)

	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "yggdrasil", Socket: filepath.Join(dir, "ygg.sock"),
		FrontUID: uid, UsersFile: usersFile, TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile},
		Options: BackendOptions{PrivateKeyFile: keyPath, ExitPorts: []int{4433}}, Inner: echoInner(t, dir)}
	if errs := c.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- RunBackend(ctx, c, log) }()
	if !waitFor(5*time.Second, func() bool { _, err := os.Stat(c.Socket); return err == nil }) {
		t.Fatal("the backend did not listen")
	}
	backends := map[string]BackendRef{"ygg": {Socket: c.Socket, Mode: "fd", UID: uid}}
	front := newTCPFront(&FrontTCP{Listen: []string{"127.0.0.1:0"}, Default: "ygg",
		Routes: []TCPRoute{{SNI: []string{"y.example.com"}, Backend: "ygg"}}}, backends, log)
	if err := front.listen([]string{"127.0.0.1:0"}); err != nil {
		t.Fatal(err)
	}
	go front.run(ctx)
	frontAddr := front.listeners[0].Addr().String()
	peer := fmt.Sprintf("tls://%s?sni=y.example.com&key=%s", frontAddr, hex.EncodeToString(nodePublic))

	alice, aliceNet, aliceKey := yggClient(t, ctx, peer)
	bob, _, bobKey := yggClient(t, ctx, peer)
	writeYggUsers(t, usersFile, aliceKey)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(200 * time.Millisecond)
	alice.RetryPeersNow()
	if !waitFor(10*time.Second, func() bool { return peerUp(alice) }) {
		t.Fatalf("alice's link is not up: %+v", alice.GetPeers())
	}

	// Through the mesh to an exit port: inner (an echo here).
	nodeAddr := tcpip.AddrFrom16Slice(address.AddrForKey(nodePublic)[:])
	dial := func(port uint16) (*gonet.TCPConn, error) {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return gonet.DialContextTCP(dctx, aliceNet, tcpip.FullAddress{NIC: 1, Addr: nodeAddr, Port: port}, ipv6.ProtocolNumber)
	}
	conn, err := dial(4433)
	if err != nil {
		t.Fatalf("exit port: %v", err)
	}
	payload := make([]byte, 256<<10)
	rand.Read(payload)
	go conn.Write(payload)
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo through inner: %v", err)
	}
	conn.Close()
	if conn, err := dial(4434); err == nil {
		conn.Close()
		t.Fatal("a port that is not an exit port took a connection")
	}

	// A key not in the users file gets no link.
	bob.RetryPeersNow()
	if waitFor(2*time.Second, func() bool { return peerUp(bob) }) {
		t.Fatal("bob is not a user, yet his link is up")
	}

	// Users change without a restart: alice's link goes, bob's comes.
	writeYggUsers(t, usersFile, bobKey)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	if !waitFor(5*time.Second, func() bool { return !peerUp(alice) }) {
		t.Fatal("alice was removed, yet her link stays")
	}
	time.Sleep(200 * time.Millisecond)
	bob.RetryPeersNow()
	if !waitFor(10*time.Second, func() bool { return peerUp(bob) }) {
		t.Fatalf("bob's link is not up after the reload: %+v", bob.GetPeers())
	}

	// Anyone else with the name gets the site's answer, in h2 and HTTP/1.1.
	for _, h2 := range []bool{true, false} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "y.example.com", InsecureSkipVerify: true,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, ForceAttemptHTTP2: h2}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + frontAddr + "/")
		if err != nil {
			t.Fatalf("h2 %v: %v", h2, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tr.CloseIdleConnections()
		if resp.StatusCode != http.StatusNotFound || len(body) != 0 || (resp.ProtoMajor == 2) != h2 {
			t.Fatalf("h2 %v: %s %d, %d bytes", h2, resp.Proto, resp.StatusCode, len(body))
		}
	}
	// TLS without the post-quantum group is refused.
	tc, err := tls.Dial("tcp", frontAddr, &tls.Config{ServerName: "y.example.com", InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{tls.X25519}})
	if err == nil {
		err = tc.Handshake()
		tc.Close()
	}
	if err == nil {
		t.Fatal("a handshake without X25519MLKEM768 went through")
	}

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend did not stop")
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".ygg-*")); len(entries) != 0 {
		t.Fatalf("the link directory is left: %v", entries)
	}
}

func TestNekoServerYggdrasilMeta(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	// What yggdrasil-go 0.5 sends: "meta", length, TLVs, signature.
	meta := func(key ed25519.PrivateKey, extra ...byte) []byte {
		public := key.Public().(ed25519.PublicKey)
		b := []byte{0, 0, 0, 2, 0, 0, 0, 1, 0, 2, 0, 5, 0, 2, 0, 32}
		b = append(b, public...)
		b = append(b, 0, 3, 0, 1, 0)
		b = append(b, extra...)
		hash := blake2bSum(public)
		return append(b, ed25519.Sign(key, hash)...)
	}
	got, ok := yggMetaKey(meta(key))
	if !ok || !bytes.Equal(got[:], key.Public().(ed25519.PublicKey)) {
		t.Fatal("a good handshake is not read")
	}
	bad := meta(key)
	bad[len(bad)-1] ^= 1
	if _, ok := yggMetaKey(bad); ok {
		t.Fatal("a bad signature passed")
	}
	if _, ok := yggMetaKey(meta(key, 0, 9, 0, 5, 1)); ok {
		t.Fatal("a truncated field passed")
	}
	if _, ok := yggMetaKey(meta(key)[:40]); ok {
		t.Fatal("a short handshake passed")
	}
}

func blake2bSum(b []byte) []byte {
	h := blake2b.Sum512(b)
	return h[:]
}
