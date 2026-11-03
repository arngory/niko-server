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
)

// udpFront is udpmux (SPEC §3.2): UDP 443, one socket per address, the
// datagrams of a flow (client address, local address) go to one backend.
// A flow is pinned by its first datagram that classifies: a QUIC Initial
// whose ClientHello names a routed server, or a salamander packet with a
// known password. Anything else is dropped without pinning, so fakes sent
// ahead of the real packets cannot capture the flow. A flow lives until it
// is idle for the configured time.
type udpFront struct {
	log        *Logger
	idle       time.Duration
	byName     map[string]*backendLink
	salamander []salamanderRoute
	links      map[string]*backendLink
	sockets    map[netip.AddrPort]*net.UDPConn

	access  sync.Mutex
	flows   map[flowKey]*udpFlow
	pending map[flowKey]*pendingFlow
}

type salamanderRoute struct {
	password []byte
	link     *backendLink
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
	for _, r := range c.Routes {
		for _, name := range r.SNI {
			f.byName[normalName(name)] = link(r.Backend)
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
			f.salamander = append(f.salamander, salamanderRoute{password: password, link: link(r.Backend)})
		}
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
	for _, r := range f.salamander {
		if open, ok := salamanderOpen(r.password, d); ok && isQUICInitial(open) {
			return r.link, [][]byte{append([]byte(nil), d...)}
		}
	}
	return nil, nil
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
