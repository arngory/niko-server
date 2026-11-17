//go:build linux

package nikoserver

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
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
	// pendingBytes: what the pending ClientHellos hold, packets and
	// assemblers, all flows together (maxPendingBytes); pendingOrder: the
	// pending flows' keys, oldest first.
	pendingBytes int
	pendingOrder list.List
	// cidSources bound the flows pinned by a label per source.
	cidSources sourceLimits
	// unconfirmed: the flows not confirmed yet, oldest first; maxFlows:
	// the table's bound (maxUDPFlows); plainRoutes: what a flow of a plain
	// QUIC backend with a label needs to be confirmed by it.
	unconfirmed flowList
	maxFlows    int
	plainRoutes map[*backendLink]*flowRoute
}

// flowRoute is what a pinned flow needs of its route to be confirmed: the
// salamander password its packets are under (nil: none) and its backend's
// label with the label's key (nil: none). One a route, its flows share it.
type flowRoute struct {
	password []byte
	codec    *cidCodec
	label    uint16
}

type salamanderRoute struct {
	password []byte
	link     *backendLink
	flow     *flowRoute
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
	// unconfirmed: the flow's place in udpFront.unconfirmed until the
	// client sends to a connection ID of the server's: the one the
	// backend's first answer named as its own (serverCID), which only one
	// who got that answer knows, or one with the backend's label (quic-go's
	// clients move to a new ID, given in an encrypted frame, as soon as the
	// handshake is done). Until then the flow is pinned by what anyone may
	// send from any address, and with the table full the oldest such flow
	// goes for a new one. nil: confirmed.
	listed     bool       // in udpFront.unconfirmed: not confirmed yet
	prev, next *udpFlow   // there
	key        flowKey    // its own, to go from the list
	route      *flowRoute // nil: plain, no label
	answered   bool       // the backend's first answer was read
	serverLen  uint8
	serverCID  [maxCIDLen]byte
}

// password is the salamander password of the flow's packets, nil if none.
func (fl *udpFlow) password() []byte {
	if fl.route == nil {
		return nil
	}
	return fl.route.password
}

// flowList is the flows not confirmed yet, oldest first, linked through
// them: no allocation of its own.
type flowList struct {
	head, tail *udpFlow
	n          int
}

func (l *flowList) push(fl *udpFlow) {
	fl.prev, fl.next, fl.listed = l.tail, nil, true
	if l.tail != nil {
		l.tail.next = fl
	} else {
		l.head = fl
	}
	l.tail = fl
	l.n++
}

func (l *flowList) remove(fl *udpFlow) {
	if !fl.listed {
		return
	}
	if fl.prev != nil {
		fl.prev.next = fl.next
	} else {
		l.head = fl.next
	}
	if fl.next != nil {
		fl.next.prev = fl.prev
	} else {
		l.tail = fl.prev
	}
	fl.prev, fl.next, fl.listed = nil, nil, false
	l.n--
}

// pendingFlow holds Initials whose ClientHello is not complete yet, per
// Destination Connection ID (a fake may come with its own).
type pendingFlow struct {
	created time.Time
	hellos  map[string]*pendingHello
	seq     uint64        // the last hello's; the oldest has the least
	elem    *list.Element // in udpFront.pendingOrder
}

type pendingHello struct {
	asm     helloAssembler
	packets [][]byte
	bytes   int // what it holds, overheads included, in pendingBytes
	seq     uint64
}

// oldest is the ID of the hello that came first.
func (pf *pendingFlow) oldest() string {
	var id string
	var seq uint64
	first := true
	for k, h := range pf.hellos {
		if first || h.seq < seq {
			id, seq, first = k, h.seq, false
		}
	}
	return id
}

const (
	maxPendingFlows = 4096
	// minInitialDatagram: RFC 9000 §14.1.
	minInitialDatagram = 1200
	maxPendingPackets  = 16
	maxPendingIDs      = 4
	pendingFor         = 3 * time.Second
	// maxPendingBytes bounds what all pending ClientHellos hold together,
	// datagrams (up to 64 KB, kept whole), CRYPTO data and the overheads
	// below: 16 packets of 4 hellos of 4096 flows would be gigabytes of
	// Initials anyone can make (their keys come from the packet). Past it,
	// and past maxPendingFlows, the oldest flows go, not the newcomer: a
	// flood must refill it within a real client's gap between two packets
	// of its first flight, which are sent together. 16 MiB holds some
	// 5000 first flights of two 1250-byte packets.
	maxPendingBytes = 16 << 20
	// Overheads counted with what a hello holds: the hello, a packet, a
	// CRYPTO frame (structs, slice headers, the map entry).
	pendingHelloCost  = 256
	pendingPacketCost = 48
	pendingFrameCost  = 48
	maxUDPFlows       = 1 << 18
	// maxCIDLen: RFC 9000 §17.2.
	maxCIDLen = 20
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
		sockets: map[netip.AddrPort]*net.UDPConn{}, flows: map[flowKey]*udpFlow{}, pending: map[flowKey]*pendingFlow{},
		maxFlows: maxUDPFlows}
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
			route.flow = &flowRoute{password: password, codec: route.codec, label: route.label}
			f.salamander = append(f.salamander, route)
		}
	}
	f.plainRoutes = map[*backendLink]*flowRoute{}
	for _, r := range f.byLabel {
		f.plainRoutes[r.link] = &flowRoute{codec: r.codec, label: r.label}
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
			f.unpin(k)
		}
	}
	for k, p := range f.pending {
		if now.Sub(p.created) > pendingFor {
			f.dropPending(k)
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

		if link := f.pinned(key, datagram, now); link != nil {
			link.send(encodePacket(message, client, local, datagram))
			continue
		}
		link, packets := f.classify(key, datagram, now)
		if link == nil {
			continue
		}
		f.pin(key, link, datagram, now)
		for _, p := range packets {
			link.send(encodePacket(message, client, local, p))
		}
	}
}

// classify decides a new flow's backend from a datagram; it returns the
// datagrams to send (an Initial split over several returns them all).
func (f *udpFront) classify(key flowKey, d []byte, now time.Time) (*backendLink, [][]byte) {
	if len(f.byName) > 0 && isQUICInitial(d) {
		// A client's Initial comes in a datagram of 1200 bytes or more
		// (RFC 9000 §14.1: a server discards a smaller one); so what a
		// pending ClientHello holds costs its sender as much on the wire.
		if len(d) < minInitialDatagram {
			return nil, nil
		}
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
	if pf != nil && now.Sub(pf.created) > pendingFor {
		f.dropPending(key) // its window is over, the sweep or not
		pf = nil
	}
	id := string(p.dcid)
	var ph *pendingHello
	if pf != nil {
		ph = pf.hellos[id]
	}
	fresh := ph == nil
	if fresh {
		ph = &pendingHello{}
	}
	drop := func() (*backendLink, [][]byte) {
		if !fresh {
			f.dropHello(pf, id)
			f.dropIfEmpty(key, pf)
		}
		return nil, nil
	}
	if len(ph.packets) >= maxPendingPackets {
		return drop()
	}
	hello, done, err := ph.asm.add(p.crypto)
	if err != nil {
		return drop()
	}
	ph.packets = append(ph.packets, append([]byte(nil), d...))
	if done {
		packets := ph.packets
		link := f.byName[hello.serverName]
		if link == nil || hello.serverName == "" {
			// A name not routed here: dropped, the flow stays free. A
			// whole ClientHello in one packet leaves nothing behind.
			return drop()
		}
		if pf != nil {
			f.dropPending(key)
		}
		return link, packets
	}
	// Not complete yet: it waits, and only now takes a place.
	if pf == nil {
		if len(f.pending) >= maxPendingFlows {
			f.dropPending(f.pendingOrder.Front().Value.(flowKey))
		}
		pf = &pendingFlow{created: now, hellos: map[string]*pendingHello{}}
		pf.elem = f.pendingOrder.PushBack(key)
		f.pending[key] = pf
	}
	if fresh {
		if len(pf.hellos) >= maxPendingIDs {
			// The oldest goes, not the newcomer: fakes sent before a
			// client's first flight on its 4-tuple (udp_desync) may each
			// carry a ClientHello cut short under an ID of its own, and the
			// real flight comes after them.
			f.dropHello(pf, pf.oldest())
		}
		pf.seq++
		ph.seq = pf.seq
		pf.hellos[id] = ph
	}
	f.account(ph)
	// Past the budget, the oldest flows go, this one last.
	for e := f.pendingOrder.Front(); e != nil && f.pendingBytes > maxPendingBytes; {
		next := e.Next()
		if k := e.Value.(flowKey); k != key {
			f.dropPending(k)
		}
		e = next
	}
	if f.pendingBytes > maxPendingBytes {
		// Not reached (a flow holds a few MB at most), but this one goes too.
		f.dropHello(pf, id)
		f.dropIfEmpty(key, pf)
	}
	return nil, nil
}

// account brings pendingBytes up to what ph holds now. With f.access.
func (f *udpFront) account(ph *pendingHello) {
	n := pendingHelloCost + ph.asm.size + len(ph.asm.frames)*pendingFrameCost
	for _, d := range ph.packets {
		n += len(d) + pendingPacketCost
	}
	f.pendingBytes += n - ph.bytes
	ph.bytes = n
}

// dropHello forgets one pending ClientHello. With f.access.
func (f *udpFront) dropHello(pf *pendingFlow, id string) {
	if ph := pf.hellos[id]; ph != nil {
		f.pendingBytes -= ph.bytes
		delete(pf.hellos, id)
	}
}

// dropIfEmpty forgets a flow none of whose ClientHellos waits any more.
// With f.access.
func (f *udpFront) dropIfEmpty(key flowKey, pf *pendingFlow) {
	if len(pf.hellos) == 0 {
		f.dropPending(key)
	}
}

// dropPending forgets a flow's pending ClientHellos. With f.access.
func (f *udpFront) dropPending(key flowKey) {
	pf := f.pending[key]
	if pf == nil {
		return
	}
	for id := range pf.hellos {
		f.dropHello(pf, id)
	}
	f.pendingOrder.Remove(pf.elem)
	delete(f.pending, key)
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
	f.answered(flowKey{client, local}, payload, time.Now())
	_, _ = conn.WriteToUDPAddrPort(payload, client)
}

// pinned is the backend of a pinned flow, nil if none: the datagram takes
// the flow's time, and confirms it if it goes to the connection ID the
// backend named.
func (f *udpFront) pinned(key flowKey, d []byte, now time.Time) *backendLink {
	f.access.Lock()
	defer f.access.Unlock()
	fl := f.flows[key]
	if fl == nil {
		return nil
	}
	fl.last = now
	if fl.listed && (fl.serverLen > 0 || fl.route != nil && fl.route.codec != nil) && toServer(fl, d) {
		f.unconfirmed.remove(fl)
	}
	return fl.link
}

// pin pins a flow to link by d, the datagram that classified it. With the
// table full the oldest flow not confirmed yet goes; if every flow is
// confirmed, this one is not pinned (its datagrams classify one by one).
func (f *udpFront) pin(key flowKey, link *backendLink, d []byte, now time.Time) {
	f.access.Lock()
	defer f.access.Unlock()
	if f.flows[key] != nil {
		return
	}
	if len(f.flows) >= f.maxFlows {
		if f.unconfirmed.head == nil {
			return
		}
		f.unpin(f.unconfirmed.head.key)
	}
	fl := &udpFlow{link: link, last: now, key: key, route: f.plainRoutes[link]}
	if r := f.salamanderFor(link, d); r != nil {
		fl.route = r.flow
	}
	f.unconfirmed.push(fl)
	f.flows[key] = fl
}

// unpin forgets a flow. With f.access.
func (f *udpFront) unpin(key flowKey) {
	fl := f.flows[key]
	if fl == nil {
		return
	}
	f.unconfirmed.remove(fl)
	delete(f.flows, key)
}

// answered takes the time of a backend's answer on a flow, and of its
// first answer the server's connection ID: a long header's Source
// Connection ID, which the client sends to once it has the answer.
func (f *udpFront) answered(key flowKey, payload []byte, now time.Time) {
	f.access.Lock()
	defer f.access.Unlock()
	fl := f.flows[key]
	if fl == nil {
		return
	}
	fl.last = now
	if fl.answered || !fl.listed {
		return
	}
	h, n := openHead(fl.password(), payload, 7+2*maxCIDLen)
	if n < 7 || h[0]&0x80 == 0 {
		fl.answered = true // a short header: no ID of its own to read
		return
	}
	if binary.BigEndian.Uint32(h[1:5]) == 0 {
		return // version negotiation: the next answer
	}
	fl.answered = true
	dl := int(h[5])
	if dl > maxCIDLen || 6+dl >= n {
		return
	}
	sl := int(h[6+dl])
	if sl == 0 || sl > maxCIDLen || 7+dl+sl > n {
		return
	}
	fl.serverLen = uint8(copy(fl.serverCID[:], h[7+dl:7+dl+sl]))
}

// toServer reports whether d, a client's datagram, starts with a packet to
// a connection ID of the flow's server: the one its first answer named, or
// one with the flow's label.
func toServer(fl *udpFlow, d []byte) bool {
	h, n := openHead(fl.password(), d, 6+maxCIDLen)
	if want := fl.serverCID[:fl.serverLen]; fl.serverLen > 0 {
		switch {
		case n < 1:
		case h[0]&0x80 != 0: // a long header
			if n >= 6 && int(h[5]) == len(want) && 6+len(want) <= n && bytes.Equal(h[6:6+len(want)], want) {
				return true
			}
		case h[0]&0x40 != 0: // a short header
			if 1+len(want) <= n && bytes.Equal(h[1:1+len(want)], want) {
				return true
			}
		}
	}
	if fl.route == nil || fl.route.codec == nil {
		return false
	}
	size := len(d)
	if fl.route.password != nil {
		size -= 8
	}
	id := clientCID(h[:min(n, cidHead)], size)
	if id == nil {
		return false
	}
	label, ok := fl.route.codec.label(id)
	return ok && label == fl.route.label
}

// salamanderFor is the salamander route of link that d opens under (an
// Initial, or a packet to a label of that route), nil for a plain route.
func (f *udpFront) salamanderFor(link *backendLink, d []byte) *salamanderRoute {
	for i := range f.salamander {
		r := &f.salamander[i]
		if r.link != link {
			continue
		}
		head, ok := salamanderHead(r.password, d)
		if !ok {
			continue
		}
		if isQUICInitial(head[:7]) {
			return r
		}
		if r.codec != nil {
			if id := clientCID(head[:min(len(d)-8, cidHead)], len(d)-8); id != nil {
				if label, ok := r.codec.label(id); ok && label == r.label {
					return r
				}
			}
		}
	}
	return nil
}

// openHead is up to n bytes of a datagram's start, opened under salamander
// with password if there is one, on the stack.
func openHead(password, d []byte, n int) (h [7 + 2*maxCIDLen]byte, m int) {
	n = min(n, len(h))
	if password == nil {
		return h, copy(h[:n], d)
	}
	if len(d) <= 8 {
		return h, 0
	}
	key := salamanderKey(password, d[:8])
	m = min(n, len(d)-8)
	for i := range m {
		h[i] = d[8+i] ^ key[i%len(key)]
	}
	return h, m
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
