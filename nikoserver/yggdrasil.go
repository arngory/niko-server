//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	gvheader "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/net/http2"
)

// Yggdrasil (SPEC §3.4). Clients peer with the node directly: a tls:// link
// that tcpmux hands over by SNI (mode fd). The backend ends TLS (1.3,
// X25519MLKEM768 only), reads the link handshake, lets in only the keys of
// the users file, and passes the link on to the yggdrasil-go core through a
// unix socket in a private directory. The node's mesh address takes TCP on
// the exit ports and carries it to inner: what users send through the mesh
// is VLESS with ML-KEM-768 there, as the mesh's own encryption is classical.
// Clients reach the node and no one else: on each link a filter drops the
// frames between the client and another than the node (yggframe.go), and
// the core answers no one's getSelf, getPeers or getTree (DebugPrivacy).

// yggMetaMax bounds the link handshake (yggdrasil-go's is 6+80 bytes).
const yggMetaMax = 1024

func runYggdrasil(ctx context.Context, c *BackendConfig, log *Logger) error {
	key, err := readYggKey(c.Options.PrivateKeyFile)
	if err != nil {
		return envError("yggdrasil key %s: %v", c.Options.PrivateKeyFile, err)
	}
	tlsConfig, err := sbtls.NewServer(ctx, nopLogger(), option.InboundTLSOptions{
		Enabled: true,
		// What a web server offers: a client that is not a Yggdrasil node
		// gets the site's answer in either protocol.
		ALPN:             []string{"h2", "http/1.1"},
		MinVersion:       "1.3",
		CertificatePath:  c.TLS.CertificateFile,
		KeyPath:          c.TLS.KeyFile,
		CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)},
	})
	if err != nil {
		return envError("tls: %v", err)
	}
	if err := tlsConfig.Start(); err != nil {
		return envError("tls: %v", err)
	}
	defer tlsConfig.Close()

	users := &yggUsers{}
	reload := func() error {
		keys, err := readYggUsers(c.UsersFile)
		if err != nil {
			return err
		}
		if dropped := users.set(keys); dropped > 0 {
			log.Infof("%d users, %d links of removed users closed", len(keys), dropped)
		} else {
			log.Infof("%d users", len(keys))
		}
		return nil
	}
	if err := reload(); err != nil {
		return envError("users: %v", err)
	}
	go watchUsers(ctx, c.UsersFile, reload, log)

	// The core listens where only this process reaches: links come in
	// through serveLink, after the key check.
	dir, err := os.MkdirTemp(filepath.Dir(c.Socket), ".ygg-")
	if err != nil {
		return envError("link directory: %v", err)
	}
	defer os.RemoveAll(dir)
	cert, err := yggCertificate(key)
	if err != nil {
		return err
	}
	setup := []core.SetupOption{
		core.ListenAddress((&url.URL{Scheme: "unix", Path: filepath.Join(dir, "link")}).String()),
		core.NodeInfoPrivacy(true),
		// getPeers would list every connected device's key to anyone with
		// a session to the node (raycontrol lan-v1 §2.1).
		core.DebugPrivacy(true),
	}
	for _, peer := range c.Options.Peers {
		setup = append(setup, core.Peer{URI: peer})
	}
	node, err := core.New(cert, yggLog{log}, setup...)
	if err != nil {
		return envError("yggdrasil core: %v", err)
	}
	defer node.Stop()
	rwc := ipv6rwc.NewReadWriteCloser(node)
	defer rwc.Close()
	address, _ := netip.AddrFromSlice(node.Address())

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	s, err := yggNetstack(sctx, rwc, address, uint32(rwc.MTU()))
	if err != nil {
		return err
	}
	defer s.Close()
	exits := map[uint16]bool{}
	for _, port := range c.Options.ExitPorts {
		exits[uint16(port)] = true
	}
	serveExits(s, exits, c.Inner, log)

	ln, err := ListenFD(c.Socket, c.FrontUID, log)
	if err != nil {
		return envError("listen %s: %v", c.Socket, err)
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	log.Infof("yggdrasil backend on %s: address %s, public key %s, exit ports %v",
		c.Socket, address, hex.EncodeToString(node.PublicKey()), c.Options.ExitPorts)
	l := &yggLinks{tls: tlsConfig, users: users, node: [32]byte(node.PublicKey()), dir: dir, log: log}
	started := time.Now()
	defer startStats(c.StatsSocket, func() any {
		return YggdrasilSnapshot{Started: started.Unix(), DroppedFrames: l.dropped.Load()}
	}, log)()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go l.serve(ctx, conn)
	}
}

// readYggKey reads the node's key: hex of a 32-byte seed or of the 64-byte
// key yggdrasil-go keeps in its config.
func readYggKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	switch {
	case err != nil:
		return nil, errors.New("not hex")
	case len(raw) == ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case len(raw) == ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, errors.New("want 64 or 128 hex digits")
}

// yggCertificate is the node's own certificate, as yggdrasil-go makes it;
// the core wants one, though no link here uses it (the site's certificate
// ends TLS).
func yggCertificate(key ed25519.PrivateKey) (*tls.Certificate, error) {
	public := key.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hex.EncodeToString(public)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func readYggUsers(path string) (map[[32]byte]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f UsersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	keys := map[[32]byte]bool{}
	for _, u := range f.Users {
		if !u.Enabled || u.Yggdrasil == nil || u.Yggdrasil.PublicKey == "" {
			continue
		}
		raw, err := hex.DecodeString(u.Yggdrasil.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("user %s: yggdrasil.public_key is not 64 hex digits", u.Name)
		}
		keys[[32]byte(raw)] = true
	}
	return keys, nil
}

// yggUsers are the keys let in, and the links open under each: a key
// removed from the users file loses its links at once.
type yggUsers struct {
	mu    sync.Mutex
	keys  map[[32]byte]bool
	links map[[32]byte]map[net.Conn]bool
}

func (u *yggUsers) set(keys map[[32]byte]bool) (dropped int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.keys = keys
	for key, conns := range u.links {
		if keys[key] {
			continue
		}
		for conn := range conns {
			_ = conn.Close()
			dropped++
		}
		delete(u.links, key)
	}
	return dropped
}

func (u *yggUsers) admit(key [32]byte, conn net.Conn) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.keys[key] {
		return false
	}
	if u.links == nil {
		u.links = map[[32]byte]map[net.Conn]bool{}
	}
	if u.links[key] == nil {
		u.links[key] = map[net.Conn]bool{}
	}
	u.links[key][conn] = true
	return true
}

func (u *yggUsers) leave(key [32]byte, conn net.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.links[key], conn)
	if len(u.links[key]) == 0 {
		delete(u.links, key)
	}
}

// group is G(key) of the link filter (raycontrol lan-v1 §2.2): the key's
// LAN group. The users file has none yet (yggdrasil.lan comes with LAN):
// no key is in one, and a client reaches only the node.
func (u *yggUsers) group(*[32]byte) yggGroup { return 0 }

// yggMetaKey reads the key of a link handshake (yggdrasil-go's version
// metadata without a password: TLVs, then an ed25519 signature over the
// BLAKE2b-512 of the key) and checks the signature, as the core does.
func yggMetaKey(body []byte) ([32]byte, bool) {
	var key []byte
	if len(body) < ed25519.SignatureSize {
		return [32]byte{}, false
	}
	sig := body[len(body)-ed25519.SignatureSize:]
	fields := body[:len(body)-ed25519.SignatureSize]
	for len(fields) >= 4 {
		op, size := binary.BigEndian.Uint16(fields), int(binary.BigEndian.Uint16(fields[2:]))
		fields = fields[4:]
		if len(fields) < size {
			return [32]byte{}, false
		}
		if op == 2 { // the public key; the last one counts, as in the core
			key = fields[:size]
		}
		fields = fields[size:]
	}
	if len(fields) != 0 || len(key) != ed25519.PublicKeySize {
		return [32]byte{}, false
	}
	hash := blake2b.Sum512(key)
	if !ed25519.Verify(ed25519.PublicKey(key), hash[:], sig) {
		return [32]byte{}, false
	}
	return [32]byte(key), true
}

type yggLinks struct {
	tls     sbtls.ServerConfig
	users   *yggUsers
	node    [32]byte // the node's key
	dir     string
	log     *Logger
	seq     atomic.Uint64
	dropped atomic.Uint64 // frames the link filter dropped
}

// YggdrasilSnapshot is what the Yggdrasil backend gives on stats_socket
// (v0.15.0). Totals only: nothing of whose frames (raycontrol lan-v1 §4.3).
type YggdrasilSnapshot struct {
	Started       int64  `json:"started"`        // the backend's start, Unix seconds
	DroppedFrames uint64 `json:"dropped_frames"` // traffic, pathNotify, pathBroken and pathLookup on a client's link between it and another than the node: dropped
}

// serve takes one stream from tcpmux: TLS, then a Yggdrasil link of a
// user's key, or the site's answer to anything else.
func (l *yggLinks) serve(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := sbtls.ServerHandshake(hctx, raw, l.tls)
	cancel()
	if err != nil {
		l.log.Debugf("tls: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	head := make([]byte, 6)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if !bytes.Equal(head[:4], []byte("meta")) {
		siteAnswer(conn, head, conn.ConnectionState().NegotiatedProtocol)
		return
	}
	size := int(binary.BigEndian.Uint16(head[4:]))
	if size < ed25519.SignatureSize || size > yggMetaMax {
		return
	}
	meta := make([]byte, 6+size)
	copy(meta, head)
	if _, err := io.ReadFull(conn, meta[6:]); err != nil {
		return
	}
	key, ok := yggMetaKey(meta[6:])
	if !ok {
		l.log.Debugf("link: a bad handshake")
		return
	}
	if !l.users.admit(key, conn) {
		l.log.Debugf("link: key %x is not a user's", key[:4])
		return
	}
	defer l.users.leave(key, conn)
	_ = conn.SetReadDeadline(time.Time{})

	// The core tells its links apart by the peer's address: each link
	// comes from a socket of its own name (removed once connected).
	local := &net.UnixAddr{Net: "unix", Name: filepath.Join(l.dir, fmt.Sprintf("c%d", l.seq.Add(1)))}
	link, err := net.DialUnix("unix", local, &net.UnixAddr{Net: "unix", Name: filepath.Join(l.dir, "link")})
	_ = os.Remove(local.Name)
	if err != nil {
		l.log.Warnf("link to the core: %v", err)
		return
	}
	defer link.Close()
	if _, err := link.Write(meta); err != nil {
		return
	}
	// Frame by frame, through the filter; nothing of it in the log. A link
	// has no half-close: when either side ends, both do.
	f := &yggLinkFilter{rule: yggRule{node: l.node, key: key, group: l.users.group}, dropped: &l.dropped}
	done := make(chan struct{}, 2)
	go func() {
		_ = f.up(link, conn)
		done <- struct{}{}
	}()
	go func() {
		_ = f.down(conn, link)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = conn.Close()
	_ = link.Close()
}

// siteAnswer is what a web server says to a request it has nothing for:
// an empty 404, in h2 or HTTP/1.1, whichever TLS settled on.
func siteAnswer(conn net.Conn, read []byte, proto string) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c := &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(read), conn)}
	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	})
	if proto == "h2" {
		(&http2.Server{IdleTimeout: 30 * time.Second}).ServeConn(c, &http2.ServeConnOpts{Handler: notFound})
		return
	}
	done := make(chan struct{})
	srv := &http.Server{
		Handler:           notFound,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          nil,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				close(done)
			}
		},
	}
	_ = srv.Serve(&oneConn{conn: c, done: done})
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// oneConn is a listener of one connection: Accept gives it, then waits
// until it is closed.
type oneConn struct {
	conn net.Conn
	done chan struct{}
	used bool
}

func (l *oneConn) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

// yggNetstack is a gVisor stack on the node's mesh address; rwc carries its
// packets to and from the mesh until ctx ends.
func yggNetstack(ctx context.Context, rwc io.ReadWriter, address netip.Addr, mtu uint32) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol6},
	})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ep := channel.New(1024, mtu, "")
	if err := s.CreateNIC(1, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("netstack: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom16(address.As16()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("netstack: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: gvheader.IPv6EmptySubnet, NIC: 1})
	go func() { // mesh -> stack
		b := make([]byte, mtu)
		for {
			n, err := rwc.Read(b)
			if err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b[:n])})
			ep.InjectInbound(ipv6.ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()
	go func() { // stack -> mesh
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			_, _ = rwc.Write(v.AsSlice())
			v.Release()
		}
	}()
	return s, nil
}

// serveExits takes TCP to the exit ports of the node's address to inner;
// any other port gets a reset, UDP nothing.
func serveExits(s *stack.Stack, exits map[uint16]bool, inner string, log *Logger) {
	fwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		if !exits[r.ID().LocalPort] {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		// A client gone from the mesh sends no reset: keepalives find it.
		ep.SocketOptions().SetKeepAlive(true)
		idle, interval := tcpip.KeepaliveIdleOption(time.Minute), tcpip.KeepaliveIntervalOption(15*time.Second)
		_ = ep.SetSockOpt(&idle)
		_ = ep.SetSockOpt(&interval)
		go exitToInner(gonet.NewTCPConn(&wq, ep), inner, log)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func exitToInner(c *gonet.TCPConn, inner string, log *Logger) {
	defer c.Close()
	out, err := net.DialTimeout("unix", inner, 5*time.Second)
	if err != nil {
		log.Warnf("inner: %v", err)
		return
	}
	defer out.Close()
	uc := out.(*net.UnixConn)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(uc, c)
		_ = uc.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, uc)
		_ = c.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// yggLog takes the core's lines: its per-link lines (with addresses) only
// at debug.
type yggLog struct{ l *Logger }

func (y yggLog) Printf(f string, a ...any) { y.l.Debugf(f, a...) }
func (y yggLog) Println(a ...any)          { y.l.Debugf("%s", fmt.Sprint(a...)) }
func (y yggLog) Infof(f string, a ...any)  { y.l.Debugf(f, a...) }
func (y yggLog) Infoln(a ...any)           { y.l.Debugf("%s", fmt.Sprint(a...)) }
func (y yggLog) Warnf(f string, a ...any)  { y.l.Warnf(f, a...) }
func (y yggLog) Warnln(a ...any)           { y.l.Warnf("%s", fmt.Sprint(a...)) }
func (y yggLog) Errorf(f string, a ...any) { y.l.Errorf(f, a...) }
func (y yggLog) Errorln(a ...any)          { y.l.Errorf("%s", fmt.Sprint(a...)) }
func (y yggLog) Debugf(f string, a ...any) { y.l.Debugf(f, a...) }
func (y yggLog) Debugln(a ...any)          { y.l.Debugf("%s", fmt.Sprint(a...)) }
func (y yggLog) Traceln(...any)            {}
