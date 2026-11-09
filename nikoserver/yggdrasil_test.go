//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	iwt "github.com/Arceliar/ironwood/types"
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
	return yggClientMTU(t, ctx, peer, 0)
}

// yggClientMTU is yggClient with the netstack's MTU (0: the core's, 65535).
func yggClientMTU(t *testing.T, ctx context.Context, peer string, mtu uint32) (*core.Core, *stack.Stack, ed25519.PublicKey) {
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
	if mtu == 0 {
		mtu = uint32(rwc.MTU())
	}
	s, err := yggNetstack(ctx, rwc, addr, mtu)
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

// yggNode is a Yggdrasil backend behind tcpmux, as on a node, with no
// users yet; it stops with ctx.
type yggNode struct {
	key       ed25519.PublicKey // the node's
	front     string            // tcpmux's address
	peer      string            // the node as a client's peer
	usersFile string
	stats     string // the backend's stats socket
	dir       string
	stopped   chan error
}

func startYggNode(t *testing.T, ctx context.Context, opts ...func(*BackendConfig)) *yggNode {
	t.Helper()
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
	n := &yggNode{key: nodeKey.Public().(ed25519.PublicKey), usersFile: filepath.Join(dir, "users.json"),
		stats: filepath.Join(dir, "stats.sock"), dir: dir, stopped: make(chan error, 1)}
	keyPath := filepath.Join(dir, "node.key")
	os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600)
	writeYggUsers(t, n.usersFile)

	c := &BackendConfig{Schema: 1, Role: "backend", Kind: "yggdrasil", Socket: filepath.Join(dir, "ygg.sock"),
		FrontUID: uid, UsersFile: n.usersFile, TLS: &BackendTLS{CertificateFile: certFile, KeyFile: keyFile},
		Options: BackendOptions{PrivateKeyFile: keyPath, ExitPorts: []int{4433}}, Inner: echoInner(t, dir),
		StatsSocket: n.stats}
	for _, o := range opts {
		o(c)
	}
	if errs := c.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	go func() { n.stopped <- RunBackend(ctx, c, log) }()
	if !waitFor(5*time.Second, func() bool { _, err := os.Stat(c.Socket); return err == nil }) {
		select {
		case err := <-n.stopped:
			t.Fatalf("the backend did not listen: %v", err)
		default:
			t.Fatal("the backend did not listen")
		}
	}
	backends := map[string]BackendRef{"ygg": {Socket: c.Socket, Mode: "fd", UID: uid}}
	front := newTCPFront(&FrontTCP{Listen: []string{"127.0.0.1:0"}, Default: "ygg",
		Routes: []TCPRoute{{SNI: []string{"y.example.com"}, Backend: "ygg"}}}, backends, log)
	if err := front.listen([]string{"127.0.0.1:0"}); err != nil {
		t.Fatal(err)
	}
	go front.run(ctx)
	n.front = front.listeners[0].Addr().String()
	n.peer = fmt.Sprintf("tls://%s?sni=y.example.com&key=%s", n.front, hex.EncodeToString(n.key))
	return n
}

// snapshot is what the backend's stats socket says.
func (n *yggNode) snapshot(t *testing.T) YggdrasilSnapshot {
	t.Helper()
	c, err := net.Dial("unix", n.stats)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.(*net.UnixConn).CloseWrite() // nothing to say: the snapshot at once
	var s YggdrasilSnapshot
	if err := json.NewDecoder(c).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// setUsers writes the users file and has the backend read it.
func (n *yggNode) setUsers(t *testing.T, keys ...ed25519.PublicKey) {
	t.Helper()
	writeYggUsers(t, n.usersFile, keys...)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(200 * time.Millisecond)
}

// yggDevice is a device's key in the users file and its LAN group ("":
// none), as raycontrol writes them: u<id>-<device>, the group u<id>.
type yggDevice struct {
	key ed25519.PublicKey
	lan string
}

// setLAN writes the users file with groups and has the backend read it.
func (n *yggNode) setLAN(t *testing.T, devices ...yggDevice) {
	t.Helper()
	var users []string
	for i, d := range devices {
		users = append(users, fmt.Sprintf(`{"name":"u%d-%d","enabled":true,"yggdrasil":{"public_key":%q,"lan":%q}}`,
			i, i, hex.EncodeToString(d.key), d.lan))
	}
	if err := os.WriteFile(n.usersFile, []byte(`{"users":[`+strings.Join(users, ",")+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(200 * time.Millisecond)
}

// traffic is the backend's answer to the line traffic.
func (n *yggNode) traffic(t *testing.T) HysteriaTraffic {
	t.Helper()
	c, err := net.Dial("unix", n.stats)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "traffic\n"); err != nil {
		t.Fatal(err)
	}
	var tr HysteriaTraffic
	if err := json.NewDecoder(c).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestNekoServerYggdrasil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := startYggNode(t, ctx)
	peer, frontAddr, nodePublic, usersFile, dir, stopped := n.peer, n.front, n.key, n.usersFile, n.dir, n.stopped

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

// yggHandshake is yggdrasil-go 0.5's link handshake for key, as a client
// sends it: "meta", the length, TLVs, the signature.
func yggHandshake(key ed25519.PrivateKey) []byte {
	public := key.Public().(ed25519.PublicKey)
	b := []byte{0, 0, 0, 2, 0, 0, 0, 1, 0, 2, 0, 5, 0, 2, 0, 32}
	b = append(b, public...)
	b = append(b, 0, 3, 0, 1, 0)
	b = append(b, ed25519.Sign(key, blake2bSum(public))...)
	return append(binary.BigEndian.AppendUint16([]byte("meta"), uint16(len(b))), b...)
}

// yggDial is TCP from a client's netstack to a key's address.
func yggDial(ctx context.Context, s *stack.Stack, key ed25519.PublicKey, port uint16, d time.Duration) (*gonet.TCPConn, error) {
	dctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	addr := tcpip.AddrFrom16Slice(address.AddrForKey(key)[:])
	return gonet.DialContextTCP(dctx, s, tcpip.FullAddress{NIC: 1, Addr: addr, Port: port}, ipv6.ProtocolNumber)
}

// yggAdmin takes the core's admin handlers, for its remote requests.
type yggAdmin map[string]core.AddHandlerFunc

func (a yggAdmin) AddHandler(name, _ string, _ []string, f core.AddHandlerFunc) error {
	a[name] = f
	return nil
}

func (a yggAdmin) ask(name string, key ed25519.PublicKey) error {
	_, err := a[name](json.RawMessage(`{"key":"` + hex.EncodeToString(key) + `"}`))
	return err
}

// Clients reach the node and nobody else (raycontrol lan-v1 §2): two
// devices of the node, each with a link up, and no session between them;
// no answer from the node about its peers; a frame that forges the node's
// key goes no further than the client's link.
func TestNekoServerYggdrasilIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := startYggNode(t, ctx)

	// A device that writes its own frames: its traffic and lookup for the
	// node pass, a traffic and a lookup with the node's key as their source
	// are dropped.
	xPublic, x, _ := ed25519.GenerateKey(rand.Reader)
	n.setUsers(t, xPublic)
	tc, err := tls.Dial("tcp", n.front, &tls.Config{ServerName: "y.example.com", InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tc.Write(yggHandshake(x)); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 6)
	if _, err := io.ReadFull(tc, head); err != nil || string(head[:4]) != "meta" {
		t.Fatalf("the core's handshake: %q %v", head, err)
	}
	if _, err := io.ReadFull(tc, make([]byte, binary.BigEndian.Uint16(head[4:]))); err != nil {
		t.Fatal(err)
	}
	var nk, xk, other [32]byte
	copy(nk[:], n.key)
	copy(xk[:], xPublic)
	rand.Read(other[:])
	toNode := iwFrame(iwTraffic(nil, nil, xk, nk, ^uint64(0), []byte("to the node")))
	forged := iwFrame(iwTraffic(nil, nil, nk, other, ^uint64(0), []byte("from the node, says x")))
	lookup, forgedLookup := iwFrame(iwLookup(xk, nk)), iwFrame(iwLookup(nk, other))
	if _, err := tc.Write(slices.Concat(toNode, forged, lookup, forgedLookup)); err != nil {
		t.Fatal(err)
	}
	if !waitFor(5*time.Second, func() bool { return n.snapshot(t).DroppedFrames == 2 }) {
		t.Fatalf("dropped %d frames, want the two forged", n.snapshot(t).DroppedFrames)
	}
	tc.Close()

	alice, aliceNet, aliceKey := yggClient(t, ctx, n.peer)
	bob, bobNet, bobKey := yggClient(t, ctx, n.peer)
	n.setUsers(t, aliceKey, bobKey)
	for _, c := range []*core.Core{alice, bob} {
		c.RetryPeersNow()
		if !waitFor(10*time.Second, func() bool { return peerUp(c) }) {
			t.Fatalf("a link is not up: %+v", c.GetPeers())
		}
	}
	// Both reach the node's exit port.
	for name, s := range map[string]*stack.Stack{"alice": aliceNet, "bob": bobNet} {
		conn, err := yggDial(ctx, s, n.key, 4433, 10*time.Second)
		if err != nil {
			t.Fatalf("%s to the exit port: %v", name, err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, 5)
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
			t.Fatalf("%s: the echo: %q %v", name, got, err)
		}
		conn.Close()
	}
	dropped := n.snapshot(t).DroppedFrames

	// Each listens; neither gets through to the other, by address or by
	// key. The node answers its node info (a session to it works), but not
	// getSelf, getPeers or getTree.
	admins := map[string]yggAdmin{"alice": {}, "bob": {}}
	alice.SetAdmin(admins["alice"])
	bob.SetAdmin(admins["bob"])
	for _, s := range []*stack.Stack{aliceNet, bobNet} {
		ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Port: 7}, ipv6.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("reached"))
				c.Close()
			}
		}()
	}
	type check struct {
		name   string
		answer bool // whether it should get through
		try    func() error
	}
	checks := []check{
		{"alice: the node's node info", true, func() error { return admins["alice"].ask("getNodeInfo", n.key) }},
		{"alice: the node's getSelf", false, func() error { return admins["alice"].ask("debug_remoteGetSelf", n.key) }},
		{"alice: the node's getPeers", false, func() error { return admins["alice"].ask("debug_remoteGetPeers", n.key) }},
		{"alice: the node's getTree", false, func() error { return admins["alice"].ask("debug_remoteGetTree", n.key) }},
		{"bob: the node's getPeers", false, func() error { return admins["bob"].ask("debug_remoteGetPeers", n.key) }},
		{"alice: bob's node info", false, func() error { return admins["alice"].ask("getNodeInfo", bobKey) }},
		{"bob: alice's node info", false, func() error { return admins["bob"].ask("getNodeInfo", aliceKey) }},
		{"alice: TCP to bob", false, func() error {
			c, err := yggDial(ctx, aliceNet, bobKey, 7, 6*time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}},
		{"bob: TCP to alice", false, func() error {
			c, err := yggDial(ctx, bobNet, aliceKey, 7, 6*time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}},
	}
	errs := make([]error, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.try()
		}()
	}
	// Meanwhile both links stay up: the filter answers for what it drops,
	// and ironwood ends a link whose frame gets no answer in 3 s.
	tried := make(chan struct{})
	go func() { wg.Wait(); close(tried) }()
	for down := false; !down; {
		select {
		case <-tried:
			down = true
		case <-time.After(20 * time.Millisecond):
			if !peerUp(alice) || !peerUp(bob) {
				t.Errorf("a link went down while they tried: alice %v, bob %v", peerUp(alice), peerUp(bob))
				down = true
			}
		}
	}
	<-tried
	for i, c := range checks {
		if (errs[i] == nil) != c.answer {
			t.Errorf("%s: %v, want an answer %v", c.name, errs[i], c.answer)
		}
	}
	// Alice goes on looking bob up, bob idle: his link stays (review of
	// v0.15.0: the lookups the filter dropped ended it in 3 s).
	for end := time.Now().Add(6 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		_, _ = alice.WriteTo([]byte{0}, iwt.Addr(bobKey))
		if !peerUp(alice) || !peerUp(bob) {
			t.Fatalf("a link went down: alice %v, bob %v", peerUp(alice), peerUp(bob))
		}
	}
	// What was dropped: bob's and alice's answers to each other's lookups.
	if s := n.snapshot(t); s.DroppedFrames <= dropped {
		t.Errorf("dropped %d frames, as many as before the tries", s.DroppedFrames)
	}
}

// A packet over the node's MTU gets an ICMPv6 Packet Too Big, sent to its
// source address with the packet's first bytes; the core checks that source
// against the sender's key first (the fork's ipv6rwc, 5afe92f). Before, a
// device that put another's address as the source had the node send that
// device its bytes, past the filter (the node's traffic passes).
func TestNekoServerYggdrasilPacketTooBig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := startYggNode(t, ctx)
	// Devices without a netstack: what the node sends them, read here.
	device := func() (*core.Core, ed25519.PublicKey, chan []byte) {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		cert, _ := yggCertificate(private)
		c, err := core.New(cert, yggLog{NewLogger("error", io.Discard)}, core.Peer{URI: n.peer})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Stop)
		got := make(chan []byte, 64)
		go func() {
			b := make([]byte, 65535)
			for {
				k, from, err := c.ReadFrom(b)
				if err != nil {
					return
				}
				if bytes.Equal(from.(iwt.Addr), n.key) {
					got <- append([]byte(nil), b[:k]...)
				}
			}
		}()
		return c, public, got
	}
	alice, aliceKey, toAlice := device()
	bob, bobKey, toBob := device()
	n.setUsers(t, aliceKey, bobKey)
	for _, c := range []*core.Core{alice, bob} {
		c.RetryPeersNow()
		if !waitFor(10*time.Second, func() bool { return peerUp(c) }) {
			t.Fatal("a link is not up")
		}
	}
	marker := []byte("ALICE-TO-BOB-THROUGH-THE-NODE")
	packet := func(source ed25519.PublicKey) []byte {
		p := make([]byte, 1400)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		p[6], p[7] = 59, 64 // no next header
		copy(p[8:24], address.AddrForKey(source)[:])
		copy(p[24:40], address.AddrForKey(n.key)[:])
		copy(p[40:], marker)
		return p
	}
	// A Packet Too Big with the marker in it, to who sends, within d.
	ptb := func(from *core.Core, source ed25519.PublicKey, to chan []byte, d time.Duration) bool {
		for end := time.Now().Add(d); time.Now().Before(end); {
			_, _ = from.WriteTo(packet(source), iwt.Addr(n.key))
			select {
			case p := <-to:
				if len(p) > 40 && p[6] == 58 && p[40] == 2 && bytes.Contains(p, marker) {
					return true
				}
			case <-time.After(300 * time.Millisecond):
			}
		}
		return false
	}
	if !ptb(alice, aliceKey, toAlice, 15*time.Second) || !ptb(bob, bobKey, toBob, 15*time.Second) {
		t.Fatal("an oversize packet of a device's own got no Packet Too Big")
	}
	if ptb(alice, bobKey, toBob, 5*time.Second) {
		t.Fatal("bob got alice's bytes from the node")
	}
}
