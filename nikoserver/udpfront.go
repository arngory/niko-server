//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// udpFront is udpmux (SPEC §3.2): UDP 443, one socket per address, the
// datagrams of a flow (client address, local address) go to one backend.
// A flow is pinned by its first datagram that classifies: a QUIC Initial
// whose ClientHello names a routed server, or a salamander packet with a
// known password. Anything else is dropped without pinning, so fakes sent
// ahead of the real packets cannot capture the flow. A flow lives until it
// is idle for the configured time.
//
// With routable connection IDs (udp.cid_keys_file, quic-cid-route-v1) a
// flow is also pinned by a client's packet of a connection that is under
// way, from an address the front does not know yet: its server connection
// ID names the backend by a label only the node can read (the client's NAT
// gave it another port, or the client moved to a new socket). The labels
// are read only of what no flow explains, with no allocation on the way to
// a miss; flows they pin are bounded per source (cidFlowRate).
type udpFront struct {
	log        *Logger
	idle       time.Duration
	byName     map[string]*backendLink
	salamander []salamanderRoute
	links      map[string]*backendLink
	sockets    map[netip.AddrPort]*net.UDPConn
	// byLabel are the backends of plain QUIC with a label, each with its
	// label's key; a salamander backend's is its route's. None: no routing
	// by connection ID.
	byLabel []labelRoute

	access  sync.Mutex
	flows   map[flowKey]*udpFlow
	pending map[flowKey]*pendingFlow
	// cidSources bound the flows pinned by a label per source.
	cidSources sourceLimits
}

type salamanderRoute struct {
	password []byte
	link     *backendLink
	label    uint16    // its backend's label, 0 none
	codec    *cidCodec // the label's key; nil: no routing by ID
}

// labelRoute is a plain QUIC backend's label and its key.
type labelRoute struct {
	label uint16
	codec *cidCodec
	link  *backendLink
}

type flowKey struct{ client, local netip.AddrPort }

type udpFlow struct {
	link *backendLink
	last time.Time
}

// pendingFlow holds Initials whose ClientHello is not complete yet, per
// Destination Connection ID (a fake may come with its own).
type pendingFlow struct {
	created time.Time
	hellos  map[string]*pendingHello
}

type pendingHello struct {
	asm     helloAssembler
	packets [][]byte
}

const (
	maxPendingFlows   = 4096
	maxPendingPackets = 16
	maxPendingIDs     = 4
	pendingFor        = 3 * time.Second
	maxUDPFlows       = 1 << 18
	// cidFlowRate and cidFlowBurst bound the flows a source (an IPv4
	// address, an IPv6 /64) pins by a label: a client whose address
	// changes pins one per connection, a CGNAT address a few for all its
	// users. More come only of copies of packets seen on the way, each
	// from an address of its own.
	cidFlowRate  = 32
	cidFlowBurst = 128
	// cidSourcesMax: the sources remembered in a generation (a minute).
	cidSourcesMax = 16384
)

func newUDPFront(c *FrontUDP, backends map[string]BackendRef, log *Logger) (*udpFront, error) {
	f := &udpFront{log: log, idle: 60 * time.Second, byName: map[string]*backendLink{}, links: map[string]*backendLink{},
		sockets: map[netip.AddrPort]*net.UDPConn{}, flows: map[flowKey]*udpFlow{}, pending: map[flowKey]*pendingFlow{}}
	if d, err := time.ParseDuration(c.Idle); err == nil && d > 0 {
		f.idle = d
	}
	link := func(name string) *backendLink {
		if l := f.links[name]; l != nil {
			return l
		}
		l := &backendLink{name: name, ref: backends[name], log: log, out: make(chan []byte, 4096), answer: f.answer}
		f.links[name] = l
		return l
	}
	var keys map[uint16]*cidCodec
	if c.CIDKeysFile != "" {
		// Without the keys the front serves UDP 443 as before: only the
		// clients whose address changes lose their connections.
		var err error
		if keys, err = readCIDKeys(c.CIDKeysFile); err != nil {
			log.Warnf("udp.cid_keys_file %s: %v; no routing by connection ID", c.CIDKeysFile, err)
		}
	}
	// key is a backend's label's key, nil without one: a label the file
	// does not have is routed by name only.
	key := func(name string) (uint16, *cidCodec) {
		label := uint16(backends[name].CIDLabel)
		if keys == nil || label == 0 {
			return 0, nil
		}
		if keys[label] == nil {
			log.Warnf("udp.cid_keys_file has no key of label %d (backend %s): no routing by connection ID to it", label, name)
		}
		return label, keys[label]
	}
	labelled := map[string]bool{}
	for _, r := range c.Routes {
		for _, name := range r.SNI {
			f.byName[normalName(name)] = link(r.Backend)
		}
		if len(r.SNI) > 0 && !labelled[r.Backend] {
			labelled[r.Backend] = true
			if label, codec := key(r.Backend); codec != nil {
				f.byLabel = append(f.byLabel, labelRoute{label: label, codec: codec, link: link(r.Backend)})
			}
		}
		if r.SalamanderPasswordFile != "" {
			b, err := os.ReadFile(r.SalamanderPasswordFile)
			if err != nil {
				return nil, envError("salamander password: %v", err)
			}
			password := bytes.TrimRight(b, "\r\n")
			if len(password) == 0 {
				return nil, envError("salamander password %s is empty", r.SalamanderPasswordFile)
			}
			route := salamanderRoute{password: password, link: link(r.Backend)}
			route.label, route.codec = key(r.Backend)
			f.salamander = append(f.salamander, route)
		}
	}
	if keys != nil {
		labels := len(f.byLabel)
		for _, r := range f.salamander {
			if r.codec != nil {
				labels++
			}
		}
		log.Infof("routing by connection ID for %d backends", labels)
	}
	return f, nil
}

func (f *udpFront) listen(addrs []string) error {
	for _, listen := range addrs {
		addr := netip.MustParseAddrPort(listen)
		network := "udp6"
		if addr.Addr().Is4() {
			network = "udp4"
		}
		conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(addr))
		if err != nil {
			f.close()
			return envError("listen %s: %v", listen, err)
		}
		_ = conn.SetReadBuffer(8 << 20)
		_ = conn.SetWriteBuffer(8 << 20)
		probeMTU(conn, addr.Addr().Is4())
		f.sockets[addr] = conn
	}
	return nil
}

func (f *udpFront) close() {
	for _, c := range f.sockets {
		c.Close()
	}
}

func (f *udpFront) run(ctx context.Context) error {
	for _, l := range f.links {
		go l.run(ctx)
	}
	errCh := make(chan error, len(f.sockets))
	for addr, conn := range f.sockets {
		go func() { errCh <- f.serve(addr, conn) }()
	}
	sweep := time.NewTicker(min(f.idle/4, 5*time.Second))
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			f.close()
			return nil
		case err := <-errCh:
			f.close()
			return err
		case now := <-sweep.C:
			f.expire(now)
		}
	}
}

func (f *udpFront) expire(now time.Time) {
	f.access.Lock()
	defer f.access.Unlock()
	for k, fl := range f.flows {
		if now.Sub(fl.last) > f.idle {
			delete(f.flows, k)
		}
	}
	for k, p := range f.pending {
		if now.Sub(p.created) > pendingFor {
			delete(f.pending, k)
		}
	}
	f.cidSources.age(now)
}

func (f *udpFront) serve(local netip.AddrPort, conn *net.UDPConn) error {
	buffer := make([]byte, maxDatagram)
	message := make([]byte, 0, packetHeader+maxDatagram)
	for {
		n, client, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return envError("read %s: %v", local, err)
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		key := flowKey{client, local}
		datagram := buffer[:n]
		now := time.Now()

		f.access.Lock()
		flow := f.flows[key]
		if flow != nil {
			flow.last = now
		}
		f.access.Unlock()
		if flow != nil {
			flow.link.send(encodePacket(message, client, local, datagram))
			continue
		}
		link, packets := f.classify(key, datagram, now)
		if link == nil {
			continue
		}
		f.access.Lock()
		if len(f.flows) < maxUDPFlows {
			f.flows[key] = &udpFlow{link: link, last: now}
		}
		f.access.Unlock()
		for _, p := range packets {
			link.send(encodePacket(message, client, local, p))
		}
	}
}

// classify decides a new flow's backend from a datagram; it returns the
// datagrams to send (an Initial split over several returns them all).
func (f *udpFront) classify(key flowKey, d []byte, now time.Time) (*backendLink, [][]byte) {
	if len(f.byName) > 0 && isQUICInitial(d) {
		if p, err := parseQUICInitial(d); err == nil {
			return f.pendingHello(key, p, d, now)
		}
		return nil, nil
	}
	// A packet of a connection under way, by its connection ID's label:
	// plain QUIC's backends here, a salamander backend's below, each only
	// under its own obfuscation.
	// Each label has its own key: one decryption per label.
	if len(f.byLabel) > 0 {
		if id := clientCID(d[:min(len(d), cidHead)], len(d)); id != nil {
			for _, r := range f.byLabel {
				if label, ok := r.codec.label(id); ok && label == r.label {
					if !f.cidAllow(key.client, now) {
						return nil, nil
					}
					return r.link, [][]byte{append([]byte(nil), d...)}
				}
			}
		}
	}
	for _, r := range f.salamander {
		head, ok := salamanderHead(r.password, d)
		if !ok {
			continue
		}
		if isQUICInitial(head[:7]) {
			return r.link, [][]byte{append([]byte(nil), d...)}
		}
		if r.codec == nil {
			continue
		}
		if id := clientCID(head[:min(len(d)-8, cidHead)], len(d)-8); id != nil {
			if label, ok := r.codec.label(id); ok && label == r.label && f.cidAllow(key.client, now) {
				return r.link, [][]byte{append([]byte(nil), d...)}
			}
		}
	}
	return nil, nil
}

// cidAllow takes a flow pinned by a label from its source's share.
func (f *udpFront) cidAllow(client netip.AddrPort, now time.Time) bool {
	f.access.Lock()
	defer f.access.Unlock()
	return f.cidSources.allow(client.Addr(), now)
}

// sourceLimits are token buckets by source: an IPv4 address, an IPv6 /64,
// in two generations so that a source not seen for a minute or two is
// forgotten and many cannot crowd out the rest (as dnsprobe's).
type sourceLimits struct {
	sources, older map[netip.Prefix]*tokenBucket
	swapped        time.Time
}

func (s *sourceLimits) allow(src netip.Addr, now time.Time) bool {
	src = src.Unmap()
	bits := 64
	if src.Is4() {
		bits = 32
	}
	prefix, _ := src.Prefix(bits)
	if s.sources == nil || len(s.sources) >= cidSourcesMax {
		s.older, s.sources, s.swapped = s.sources, map[netip.Prefix]*tokenBucket{}, now
	}
	b := s.sources[prefix]
	if b == nil {
		if b = s.older[prefix]; b == nil {
			b = &tokenBucket{}
		}
		s.sources[prefix] = b
	}
	return b.take(1, cidFlowRate, cidFlowBurst, now)
}

// age starts a new generation once a minute.
func (s *sourceLimits) age(now time.Time) {
	if s.sources != nil && now.Sub(s.swapped) > time.Minute {
		s.older, s.sources, s.swapped = s.sources, map[netip.Prefix]*tokenBucket{}, now
	}
}

func (f *udpFront) pendingHello(key flowKey, p quicInitial, d []byte, now time.Time) (*backendLink, [][]byte) {
	f.access.Lock()
	defer f.access.Unlock()
	pf := f.pending[key]
	if pf == nil {
		if len(f.pending) >= maxPendingFlows {
			return nil, nil
		}
		pf = &pendingFlow{created: now, hellos: map[string]*pendingHello{}}
		f.pending[key] = pf
	}
	id := string(p.dcid)
	ph := pf.hellos[id]
	if ph == nil {
		if len(pf.hellos) >= maxPendingIDs {
			return nil, nil
		}
		ph = &pendingHello{}
		pf.hellos[id] = ph
	}
	if len(ph.packets) >= maxPendingPackets {
		delete(pf.hellos, id)
		return nil, nil
	}
	ph.packets = append(ph.packets, append([]byte(nil), d...))
	hello, done, err := ph.asm.add(p.crypto)
	if err != nil {
		delete(pf.hellos, id)
		return nil, nil
	}
	if !done {
		return nil, nil
	}
	delete(pf.hellos, id)
	link := f.byName[hello.serverName]
	if link == nil || hello.serverName == "" {
		return nil, nil // a name not routed here: dropped, the flow stays free
	}
	delete(f.pending, key)
	return link, ph.packets
}

// answer sends a backend's datagram from the local address the flow came to.
func (f *udpFront) answer(client, local netip.AddrPort, payload []byte) {
	conn := f.sockets[local]
	if conn == nil {
		for addr, candidate := range f.sockets {
			if addr.Addr().Is4() == client.Addr().Unmap().Is4() {
				conn = candidate
				break
			}
		}
	}
	if conn == nil {
		return
	}
	f.access.Lock()
	if fl := f.flows[flowKey{client, local}]; fl != nil {
		fl.last = time.Now()
	}
	f.access.Unlock()
	_, _ = conn.WriteToUDPAddrPort(payload, client)
}

// probeMTU does on the front's sockets what quic-go does on its own: DF
// set, and the path MTU the kernel learns from ICMP is not applied, so the
// kernel never fragments a datagram here; QUIC finds its own packet size
// (review, P-2).
func probeMTU(conn *net.UDPConn, v4 bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		if v4 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	})
}
