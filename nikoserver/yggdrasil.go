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
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
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
// The keys of one LAN group, a user's devices, reach each other too, the
// node relaying at most lan_relay_mbps between them (ygglan.go).

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

	relay := newYggRelay(c.Options.lanRelayMbps())
	users := &yggUsers{node: [32]byte(key.Public().(ed25519.PublicKey)), relay: relay}
	reload := func() error {
		keys, err := readYggUsers(c.UsersFile)
		if err != nil {
			return err
		}
		// Counts only: whose keys and which groups, never (lan-v1 §4.3).
		links, exits, grouped := users.set(keys)
		if links+exits > 0 {
			log.Infof("%d users (%d in LAN groups); of removed users, %d links and %d exits closed", len(keys), grouped, links, exits)
		} else {
			log.Infof("%d users (%d in LAN groups)", len(keys), grouped)
		}
		return nil
	}
	if err := reload(); err != nil {
		return envError("users: %v", err)
	}
	go watchUsers(ctx, c.UsersFile, reload, relay.check, log)

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
	users.mu.Lock()
	users.open = newYggExitCount()
	users.mu.Unlock()
	serveExits(s, exits, c.Inner, users.exits, users.open, log)

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
	l := &yggLinks{tls: tlsConfig, users: users, node: [32]byte(node.PublicKey()), dir: dir, log: log,
		public: len(c.Options.Peers) > 0}
	started := time.Now()
	defer startStatsTraffic(c.StatsSocket, func() any {
		return YggdrasilSnapshot{Started: started.Unix(), DroppedFrames: l.dropped.Load(),
			RelayedFrames: relay.frames.Load(), RelayedBytes: relay.bytes.Load(), RelayDroppedFrames: relay.dropped.Load()}
	}, func() any { return relay.traffic() }, log)()
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

// readYggUsers reads the keys of the enabled users, each with its LAN
// group ("" none). A key that is not 64 hex digits, a group that is not
// 1-32 of a-z, 0-9 and -, or one key listed twice with two groups refuses
// the whole file: the backend keeps what it had.
func readYggUsers(path string) (map[[32]byte]yggEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f UsersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	keys := map[[32]byte]yggEntry{}
	for _, u := range f.Users {
		if !u.Enabled || u.Yggdrasil == nil || u.Yggdrasil.PublicKey == "" {
			continue
		}
		raw, err := hex.DecodeString(u.Yggdrasil.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("user %s: yggdrasil.public_key is not 64 hex digits", u.Name)
		}
		lan := u.Yggdrasil.LAN
		if lan != "" && !yggLANName.MatchString(lan) {
			return nil, fmt.Errorf("user %s: yggdrasil.lan is not 1-32 of a-z, 0-9 and -", u.Name)
		}
		key := [32]byte(raw)
		if other, ok := keys[key]; ok && other.lan != lan {
			return nil, fmt.Errorf("user %s: yggdrasil.public_key is listed before with another lan", u.Name)
		} else if ok {
			continue // the first name keeps it
		}
		keys[key] = yggEntry{lan: lan, user: yggUserOf(u.Name)}
	}
	return keys, nil
}

// yggEntry is what the users file says of a key: its LAN group ("": none)
// and whose it is.
type yggEntry struct{ lan, user string }

// yggUserOf is whose an entry of the users file is: its name up to the
// first "-". raycontrol names a user's keys u<id>, u<id>-<device>, each
// with -n or -p while a rotation has two (lan-v1 §4.3); a user's exits are
// counted together, whatever key they come from.
func yggUserOf(name string) string {
	user, _, _ := strings.Cut(name, "-")
	return user
}

// yggUsers are the keys let in, the links open under each, and the keys'
// LAN groups: a key removed from the users file loses its links at once;
// one whose group changes keeps them, and the filter sees its new group
// at its next read (yggView).
type yggUsers struct {
	node  [32]byte  // the node's key: in no group, whatever the file says
	relay *yggRelay // the groups by name
	// groups is the latest reading, for the filters: swapped whole, never
	// changed.
	groups atomic.Pointer[yggGroups]
	// linked is the keys with a link open now, for the filters with public
	// peers (yggRule.linked): swapped whole as a key gets its first link or
	// loses its last.
	linked atomic.Pointer[yggKeys]
	// addrs are the addresses and /64 subnets of the users' keys: the
	// only sources the exits take (serveExits), swapped whole.
	addrs atomic.Pointer[yggAddrs]
	// open are the exits open now, by key: a key gone from the file
	// loses them as it loses its links. Nil until serveExits.
	open *yggExitCount

	mu    sync.Mutex
	keys  map[[32]byte]yggEntry
	links map[[32]byte]map[net.Conn]bool
}

// set takes a reading of the users file: the keys, and their groups' names.
// The groups change first, then the links of the keys gone close.
func (u *yggUsers) set(keys map[[32]byte]yggEntry) (links, exits, grouped int) {
	names := map[string]bool{}
	for key, e := range keys {
		if e.lan != "" && key != u.node {
			names[e.lan] = true
		}
	}
	byName := u.relay.take(names)
	groups := yggGroups{}
	for key, e := range keys {
		if e.lan != "" && key != u.node {
			groups[key] = byName[e.lan]
		}
	}
	addrs := yggAddrs{}
	for key, e := range keys {
		if key == u.node {
			continue
		}
		user := e.user
		if user == "" {
			user = hex.EncodeToString(key[:]) // no name: a user of its own
		}
		addrs[netip.AddrFrom16(*address.AddrForKey(ed25519.PublicKey(key[:])))] = yggExitSource{key, user}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.groups.Store(&groups)
	u.addrs.Store(&addrs)
	u.keys = keys
	gone := false
	for key, conns := range u.links {
		if _, ok := keys[key]; ok {
			continue
		}
		for conn := range conns {
			_ = conn.Close()
			links++
		}
		delete(u.links, key)
		gone = true
	}
	if gone {
		u.relink()
	}
	if u.open != nil {
		exits = u.open.drop(func(key [32]byte) bool { _, ok := keys[key]; return ok })
	}
	return links, exits, len(groups)
}

// yggAddrs are the addresses of the users' keys (0x02, a /128 each), each
// to its key and user.
type yggAddrs map[netip.Addr]yggExitSource

// yggExitSource is whose an exit is.
type yggExitSource struct {
	key  [32]byte
	user string
}

// exits says whose src is, if it may reach the node's exits: the address
// of a user's key, not its subnet (Niko connects from the address, never
// from 300::/64). The mesh binds an address to its key (ipv6rwc takes from
// a key only its own addresses): with public peers anyone on the mesh
// reaches the node's address, and gets past none but its own users. An
// address holds some 112 bits of its key, past any search for another key
// with the same; and inner still asks who the client is.
func (u *yggUsers) exits(src netip.Addr) (yggExitSource, bool) {
	a := u.addrs.Load()
	if a == nil {
		return yggExitSource{}, false
	}
	e, ok := (*a)[src]
	return e, ok
}

// group is G of the link filter (raycontrol lan-v1 §2.2): the keys' LAN
// groups as the users file has them now.
func (u *yggUsers) group() yggGroups {
	if g := u.groups.Load(); g != nil {
		return *g
	}
	return nil
}

// linkedKeys is linked, for the filters.
func (u *yggUsers) linkedKeys() yggKeys {
	if k := u.linked.Load(); k != nil {
		return *k
	}
	return nil
}

// relink makes linked anew from links. Under u.mu.
func (u *yggUsers) relink() {
	keys := make(yggKeys, len(u.links))
	for key := range u.links {
		keys[key] = true
	}
	u.linked.Store(&keys)
}

func (u *yggUsers) admit(key [32]byte, conn net.Conn) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.keys[key]; !ok {
		return false
	}
	if u.links == nil {
		u.links = map[[32]byte]map[net.Conn]bool{}
	}
	if u.links[key] == nil {
		u.links[key] = map[net.Conn]bool{}
		defer u.relink()
	}
	u.links[key][conn] = true
	return true
}

func (u *yggUsers) leave(key [32]byte, conn net.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	conns, ok := u.links[key]
	if !ok {
		return // gone with its key (set)
	}
	delete(conns, conn)
	if len(conns) == 0 {
		delete(u.links, key)
		u.relink()
	}
}

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
	public  bool     // the core has public peers (yggRule.public)
	dir     string
	log     *Logger
	seq     atomic.Uint64
	dropped atomic.Uint64 // frames the link filter dropped
}

// YggdrasilSnapshot is what the Yggdrasil backend gives on stats_socket
// (v0.15.0). Totals only: nothing of whose frames (raycontrol lan-v1 §4.3);
// the bytes by group are on the traffic line (v0.16.0).
type YggdrasilSnapshot struct {
	Started       int64  `json:"started"`        // the backend's start, Unix seconds
	DroppedFrames uint64 `json:"dropped_frames"` // traffic, pathNotify, pathBroken and pathLookup on a client's link between it and another than the node or its group, or a group's lookup for the node: dropped
	// LAN (v0.16.0): the frames the node relayed for a group and their
	// bytes (type and body, as charged, once, mostly where they went out to
	// a member: yggRule.judge); and those dropped over their group's
	// lan_relay_mbps (all of them at 0).
	RelayedFrames      uint64 `json:"relayed_frames"`
	RelayedBytes       uint64 `json:"relayed_bytes"`
	RelayDroppedFrames uint64 `json:"relay_dropped_frames"`
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
	f := newYggLinkFilter(l.rule(key), &l.dropped, link, conn)
	defer f.close()
	done := make(chan struct{}, 2)
	go func() {
		_ = f.up(conn)
		done <- struct{}{}
	}()
	go func() {
		_ = f.down(link)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = conn.Close()
	_ = link.Close()
}

// rule is the filter's rule on the link of key: the groups and the keys
// linked as the users file and the links have them now.
func (l *yggLinks) rule(key [32]byte) yggRule {
	return yggRule{node: l.node, key: key, groups: l.users.group, public: l.public, linked: l.users.linkedKeys}
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

// serveExits takes TCP to the exit ports of the node's address to inner,
// from the sources allowed says whose they are, within yggExitCount's
// bounds: each holds a socket to inner before its client says who it is,
// which inner's limits count only then.
func serveExits(s *stack.Stack, exits map[uint16]bool, inner string, allowed func(netip.Addr) (yggExitSource, bool), open *yggExitCount, log *Logger) {
	fwd := tcp.NewForwarder(s, 0, yggExitsShaking*16, func(r *tcp.ForwarderRequest) {
		if !exits[r.ID().LocalPort] {
			r.Complete(true)
			return
		}
		src := netip.AddrFrom16(r.ID().RemoteAddress.As16())
		who, ok := allowed(src)
		if !ok || !open.take(who) {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		open.shook(who)
		if terr != nil {
			open.done(who, nil)
			r.Complete(true)
			return
		}
		r.Complete(false)
		// A client gone from the mesh sends no reset: keepalives find it.
		ep.SocketOptions().SetKeepAlive(true)
		idle, interval := tcpip.KeepaliveIdleOption(time.Minute), tcpip.KeepaliveIntervalOption(15*time.Second)
		_ = ep.SetSockOpt(&idle)
		_ = ep.SetSockOpt(&interval)
		conn := gonet.NewTCPConn(&wq, ep)
		open.hold(who.key, conn)
		// The key may have left the file since allowed: set swaps the
		// addresses, then drops the exits held, so one of the two sees it.
		if w, ok := allowed(src); !ok || w != who {
			_ = conn.Close()
			open.done(who, conn)
			return
		}
		go func() {
			defer open.done(who, conn)
			exitToInner(conn, inner, log)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// The exits open at once: in all, of one user (whatever key they come
// from), of one key; and of one user, those whose handshake is not done
// (an exit is taken at the SYN, and a handshake whose SYN-ACK goes
// unanswered holds its place two minutes). A user's limit is above its
// limit of TCP at once in inner (raycontrol conn-limit-v1, 1024), which
// answers first, with its reason. Past them: RST.
const (
	yggExitsMax, yggExitsPerUser, yggExitsPerKey = 4096, 1100, 512
	yggExitsShaking                              = 64
)

// yggExitCount counts the exits, and holds them by key to close those of a
// key gone (drop).
type yggExitCount struct {
	mu      sync.Mutex
	total   int
	byUser  map[string]int
	byKey   map[[32]byte]int
	shaking map[string]int
	// conns are the exits by key, and whether drop has closed them.
	conns map[[32]byte]map[io.Closer]bool
}

func newYggExitCount() *yggExitCount {
	return &yggExitCount{byUser: map[string]int{}, byKey: map[[32]byte]int{}, shaking: map[string]int{},
		conns: map[[32]byte]map[io.Closer]bool{}}
}

// take counts an exit of who, its handshake to do (shook), if the bounds
// leave a place.
func (c *yggExitCount) take(who yggExitSource) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total >= yggExitsMax || c.byUser[who.user] >= yggExitsPerUser || c.byKey[who.key] >= yggExitsPerKey ||
		c.shaking[who.user] >= yggExitsShaking {
		return false
	}
	c.total++
	c.byUser[who.user]++
	c.byKey[who.key]++
	c.shaking[who.user]++
	return true
}

// shook counts an exit's handshake done, completed or not.
func (c *yggExitCount) shook(who yggExitSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shaking[who.user]--; c.shaking[who.user] <= 0 {
		delete(c.shaking, who.user)
	}
}

// hold keeps conn under key, for drop.
func (c *yggExitCount) hold(key [32]byte, conn io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conns[key] == nil {
		c.conns[key] = map[io.Closer]bool{}
	}
	c.conns[key][conn] = false
}

// done frees an exit's place, and forgets conn when it was held.
func (c *yggExitCount) done(who yggExitSource, conn io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total--
	if c.byUser[who.user]--; c.byUser[who.user] <= 0 {
		delete(c.byUser, who.user)
	}
	if c.byKey[who.key]--; c.byKey[who.key] <= 0 {
		delete(c.byKey, who.key)
	}
	if conn != nil {
		delete(c.conns[who.key], conn)
		if len(c.conns[who.key]) == 0 {
			delete(c.conns, who.key)
		}
	}
}

// drop closes the exits of the keys keep says no to, and returns how many
// it closed now (not those an earlier drop closed that are still ending).
// Their places free as each exit ends.
func (c *yggExitCount) drop(keep func([32]byte) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, conns := range c.conns {
		if keep(key) {
			continue
		}
		for conn, closed := range conns {
			if !closed {
				_ = conn.Close()
				conns[conn] = true
				n++
			}
		}
	}
	return n
}

// yggExitLinger is how long the client's way of an exit stays once inner
// has ended its own: a client that says nothing more does not keep its
// place. A client's half-close leaves inner's way alone: inner ends it
// itself (Xray's downlink timer is one of no activity, a second by
// default), and a download after it is no shorter for it (second review).
const yggExitLinger = 5 * time.Second

// yggCopyBuf: the buffers of an exit's two ways, 16 KiB each, half of
// io.Copy's: an idle exit holds both.
var yggCopyBuf = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// yggCopy copies src to dst in a pooled buffer, past dst's ReadFrom and
// src's WriteTo, which take their own.
func yggCopy(dst io.Writer, src io.Reader) error {
	b := yggCopyBuf.Get().(*[]byte)
	defer yggCopyBuf.Put(b)
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *b)
	return err
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
	up, down := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(up)
		if yggCopy(uc, c) != nil {
			_ = uc.Close() // the client reset, or its key gone (drop): all goes
			return
		}
		_ = uc.CloseWrite()
	}()
	go func() {
		defer close(down)
		if yggCopy(c, uc) != nil {
			_ = c.Close()
			return
		}
		_ = c.CloseWrite()
	}()
	select {
	case <-up:
		<-down
	case <-down:
		t := time.AfterFunc(yggExitLinger, func() {
			_ = c.Close()
			_ = uc.Close()
		})
		defer t.Stop()
		<-up
	}
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
