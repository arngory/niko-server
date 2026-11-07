//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// RunFront serves the front until ctx ends: the DNS front (UDP 53),
// tcpmux (TCP 443) and udpmux (UDP 443), each if configured. A backend that is down only loses
// what was sent meanwhile.
func RunFront(ctx context.Context, c *FrontConfig, log *Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	running := 0
	if c.TCP != nil {
		tcp := newTCPFront(c.TCP, c.Backends, log)
		if err := tcp.listen(c.TCP.Listen); err != nil {
			return err
		}
		log.Infof("TCP front on %s, %d routes", strings.Join(c.TCP.Listen, ", "), len(c.TCP.Routes))
		running++
		go func() { errCh <- tcp.run(ctx) }()
	}
	if c.UDP != nil {
		udp, err := newUDPFront(c.UDP, c.Backends, log)
		if err == nil {
			err = udp.listen(c.UDP.Listen)
		}
		if err != nil {
			cancel()
			for range running {
				<-errCh
			}
			return err
		}
		log.Infof("UDP front on %s, %d routes", strings.Join(c.UDP.Listen, ", "), len(c.UDP.Routes))
		running++
		go func() { errCh <- udp.run(ctx) }()
	}
	if c.DNS != nil {
		running++
		go func() { errCh <- runDNSFront(ctx, c, log) }()
	}
	var first error
	for range running {
		if err := <-errCh; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}

// listenDNS binds a DNS front socket with SO_REUSEADDR: systemd-resolved
// holds 127.0.0.53:53 and 127.0.0.54:53 with it too, so the wildcard and
// its stub share the port, the kernel giving each socket the datagrams to
// its own address (the most specific bind wins). Another socket without
// SO_REUSEADDR still cannot take the port.
func listenDNS(ctx context.Context, network string, addr netip.AddrPort) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, network, addr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func runDNSFront(ctx context.Context, c *FrontConfig, log *Logger) error {
	front := &dnsFront{log: log, zoneBackend: make(map[string]*backendLink), sockets: make(map[netip.AddrPort]*net.UDPConn),
		probeZones: map[string]bool{}, padZones: map[string]bool{}, apex: map[string]*apexZone{}, tagged: map[string]*taggedZone{}}
	if c.DNS.ProbeKeyFile != "" {
		// Without the key the front answers no probes, and goes on: the
		// tunnels, TCP and UDP 443 must not stop for a resolver check.
		// Probes then reach the backend like any query of the tunnel.
		if probe, err := loadProbeKey(c.DNS.ProbeKeyFile); err != nil {
			log.Warnf("dns.probe_key_file %s: %v; dnsprobe-v1 off", c.DNS.ProbeKeyFile, err)
		} else {
			front.probe = probe
		}
	}
	for _, listen := range c.DNS.Listen {
		addr := netip.MustParseAddrPort(listen)
		network := "udp6"
		if addr.Addr().Is4() {
			network = "udp4"
		}
		// udp6 sets IPV6_V6ONLY, so 0.0.0.0:53 and [::]:53 can both be bound
		conn, err := listenDNS(ctx, network, addr)
		if err != nil {
			front.closeAll()
			return envError("listen %s: %v", listen, err)
		}
		conn.SetReadBuffer(4 << 20)
		conn.SetWriteBuffer(4 << 20)
		front.sockets[addr] = conn
	}

	// the links answer through the front's sockets: built complete before they run
	// only the DNS backends: udpmux keeps its own links
	inDNS := map[string]bool{}
	for _, z := range c.DNS.Zones {
		inDNS[z.Backend] = true
	}
	links := make(map[string]*backendLink)
	serial := apexSerial()
	for name, ref := range c.Backends {
		if ref.Mode != "packet" || !inDNS[name] {
			continue
		}
		links[name] = &backendLink{name: name, ref: ref, log: log, out: make(chan []byte, 1024), answer: front.answer,
			bad: func() { front.stats.dropped.Add(1) }}
	}
	seenByBackend := map[string]*seenFields{} // a backend's zones share their copies
	for _, z := range c.DNS.Zones {
		zone := canonicalName(z.Zone)
		front.zones = append(front.zones, zone)
		front.zoneBackend[zone] = links[z.Backend]
		if z.Probe {
			front.probeZones[zone] = true
		}
		if z.SealPad {
			front.padZones[zone] = true
		}
		if len(z.NS) > 0 {
			front.apex[zone] = newApexZone(zone, z.NS, serial)
		}
		if z.Tag != "" {
			// dnsauth-v2 required: the key by the hint, never a scan.
			// A keys file that does not read leaves the zone without
			// keys (every query gets NOERROR) until it does: the front
			// carries TCP and UDP 443 and the other zones too (review).
			auth := &dnsttserver.DeviceAuth{Hint: dnsttserver.HintRequired}
			if err := auth.LoadKeys(z.AuthKeysFile); err != nil {
				log.Warnf("dns.zones %s auth keys %s: %v; no device's query passes until it reads", zone, z.AuthKeysFile, err)
			}
			go auth.WatchKeys(z.AuthKeysFile, 5*time.Second, ctx.Done(), log.Infof)
			seen := seenByBackend[z.Backend]
			if seen == nil {
				seen = &seenFields{early: &front.seenEarly}
				seenByBackend[z.Backend] = seen
			}
			front.tagged[zone] = newTaggedZone(zone, auth, seen)
		}
	}
	front.stats = newDNSFrontStats(front.zones)
	front.stats.replayTurns = &front.seenEarly
	defer startStats(c.DNS.StatsSocket, func() any { return front.stats.snapshot() }, log)()
	for _, link := range links {
		go link.run(ctx)
	}
	zones := front.zones
	log.Infof("DNS front on %s, zones %s", strings.Join(c.DNS.Listen, ", "), strings.Join(zones, ", "))

	errCh := make(chan error, len(front.sockets))
	for addr, conn := range front.sockets {
		go func() { errCh <- front.serve(addr, conn) }()
	}
	select {
	case <-ctx.Done():
		front.closeAll()
		return nil
	case err := <-errCh:
		front.closeAll()
		return err
	}
}

type dnsFront struct {
	log         *Logger
	probe       *dnsProbe       // dnsprobe-v1, nil without a key
	probeZones  map[string]bool // the zones it answers in
	padZones    map[string]bool // those with sealed answers (dnsseal-v1): probe answers padded as theirs
	apex        map[string]*apexZone
	zones       []string
	zoneBackend map[string]*backendLink
	sockets     map[netip.AddrPort]*net.UDPConn
	pending     pendingQueries // what the backends' answers are for
	stats       *dnsFrontStats
	tagged      map[string]*taggedZone // zones whose queries carry a device's tag (slipstream)
	seenEarly   atomic.Uint64          // their memories' generations started early
}

func (f *dnsFront) closeAll() {
	for _, conn := range f.sockets {
		conn.Close()
	}
}

func (f *dnsFront) serve(local netip.AddrPort, conn *net.UDPConn) error {
	buffer := make([]byte, maxDatagram)
	message := make([]byte, 0, packetHeader+deviceSize+maxDatagram)
	rebuilt := make([]byte, 0, maxDNSQuery) // a tagged zone's query as its backend gets it
	raw := make([]byte, 0, maxNameText)     // its name decoded
	for {
		n, client, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return envError("read %s: %v", local, err)
		}
		if n > maxDNSQuery {
			f.stats.malformed.Add(1)
			continue
		}
		query := buffer[:n]
		name, questionEnd, ok := queryName(query)
		if !ok {
			f.stats.malformed.Add(1)
			continue
		}
		zone := zoneOf(name, f.zones)
		if zone == "" {
			// not one of our zones: no open resolver here
			f.stats.refused.Add(1)
			conn.WriteToUDPAddrPort(refused(query, questionEnd), client)
			continue
		}
		f.stats.queries[zone].Add(1)
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		if a := f.apex[zone]; a != nil && name == zone {
			if reply, ok := a.answer(query); ok {
				f.stats.apex.Add(1)
				conn.WriteToUDPAddrPort(reply, client)
				continue
			}
		}
		if f.probe != nil && f.probeZones[zone] {
			if reply, probe := f.probe.answer(query, name, questionEnd, zone, client.Addr(), f.padZones[zone]); probe {
				if reply != nil {
					f.stats.probes.Add(1)
					conn.WriteToUDPAddrPort(reply, client)
				} else {
					f.stats.probesOverRate.Add(1)
				}
				f.log.Debugf("dnsprobe from %s: %d bytes", client.Addr(), len(reply))
				continue
			}
		}
		forward := query
		t := f.tagged[zone]
		var field [dnsttserver.AuthTagLen]byte
		var device [deviceSize]byte
		if t != nil {
			var verdict int
			if forward, field, device, verdict = t.check(query, name, questionEnd, rebuilt, raw); verdict != tagPassed {
				// Not a device's query, or a copy of one: the backend
				// sees nothing of it. A copy right after the original
				// gets nothing: the original's answer is on its way.
				switch verdict {
				case tagEcho:
					f.stats.replayed.Add(1)
					continue
				case tagReplayed:
					f.stats.replayed.Add(1)
				default:
					f.stats.untagged.Add(1)
				}
				conn.WriteToUDPAddrPort(nodata(query, questionEnd), client)
				continue
			}
		}
		// Waiting before the send: the backend's answer can come back
		// before this goroutine runs again. The requester's size is the
		// query's as it came.
		f.pending.add(client, query, questionEnd)
		link := f.zoneBackend[zone]
		var msg []byte
		if t != nil && link.ref.Devices {
			msg = encodePacketDevice(message, client, local, device, forward)
		} else {
			msg = encodePacket(message, client, local, forward)
		}
		if !link.send(msg) {
			f.pending.take(client, query) // the backend never got it
			if t != nil {
				t.seen.forget(field, time.Now()) // nor its packet: one retry is no copy
			}
			f.stats.backendAway.Add(1)
			continue
		}
		f.stats.forwarded.Add(1)
	}
}

// maxDNSQuery: a query over UDP is a few hundred bytes, and dnstt reads
// 4096 at most. Larger datagrams were copied whole into the queues to the
// backend (1024 each way, up to 64 MiB each).
const maxDNSQuery = 4096

// answer sends a backend's answer from the socket the query came in on:
// only to a query that waits for it, and within its requester's size
// (pendingQueries).
func (f *dnsFront) answer(client, local netip.AddrPort, payload []byte) {
	size, ok := f.pending.take(client, payload)
	if !ok {
		f.stats.unmatched.Add(1)
		f.log.Debugf("an answer to %s no query waits for: dropped", client)
		return
	}
	cut := false
	if len(payload) > min(size, maxBackendAnswer) {
		if payload = truncated(payload); payload == nil {
			f.stats.dropped.Add(1)
			return
		}
		cut = true
	}
	conn := f.sockets[local]
	if conn == nil {
		for addr, candidate := range f.sockets {
			if addr.Addr().Is4() == client.Addr().Is4() {
				conn = candidate
				break
			}
		}
	}
	if conn == nil {
		f.stats.dropped.Add(1)
		return
	}
	if _, err := conn.WriteToUDPAddrPort(payload, client); err != nil {
		f.stats.dropped.Add(1)
		return
	}
	f.stats.answers.Add(1)
	if cut {
		f.stats.truncated.Add(1)
	}
}

// backendLink is the front's connection to one backend: reconnects with backoff,
// drops datagrams while the backend is away.
type backendLink struct {
	name   string
	ref    BackendRef
	log    *Logger
	out    chan []byte
	answer func(client, local netip.AddrPort, payload []byte)
	bad    func() // a message from the backend that does not read (the DNS front's counters); nil: none

	access sync.Mutex
	conn   *net.UnixConn
}

// send queues a message for the backend, false when it is dropped: the
// backend away, or its queue full.
func (l *backendLink) send(message []byte) bool {
	l.access.Lock()
	connected := l.conn != nil
	l.access.Unlock()
	if !connected {
		return false
	}
	select {
	case l.out <- append([]byte(nil), message...):
		return true
	default:
		return false
	}
}

func (l *backendLink) run(ctx context.Context) {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		conn, err := l.dial()
		if err != nil {
			l.log.Debugf("backend %s: %v (retry in %s)", l.name, err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 5*time.Second)
			continue
		}
		backoff = 100 * time.Millisecond
		l.log.Infof("backend %s connected", l.name)
		l.serve(ctx, conn)
		l.log.Warnf("backend %s disconnected", l.name)
	}
}

func (l *backendLink) dial() (*net.UnixConn, error) {
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: l.ref.Socket, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	uid, err := peerUID(conn)
	if err != nil || uid != l.ref.UID {
		conn.Close()
		return nil, envError("%s is served by UID %d, want %d (%v)", l.ref.Socket, uid, l.ref.UID, err)
	}
	conn.SetReadBuffer(4 << 20)
	conn.SetWriteBuffer(4 << 20)
	return conn, nil
}

func (l *backendLink) serve(ctx context.Context, conn *net.UnixConn) {
	l.access.Lock()
	l.conn = conn
	l.access.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, packetHeader+maxDatagram)
		for {
			n, err := conn.Read(buffer)
			if err != nil || n == 0 {
				return
			}
			client, local, payload, err := decodePacket(buffer[:n])
			if err != nil {
				if l.bad != nil {
					l.bad()
				}
				continue
			}
			l.answer(client, local, payload)
		}
	}()
	defer func() {
		l.access.Lock()
		l.conn = nil
		l.access.Unlock()
		conn.Close()
		<-done
		// what was queued for the old connection is stale
		for len(l.out) > 0 {
			<-l.out
		}
	}()
	for {
		select {
		case message := <-l.out:
			if _, err := conn.Write(message); err != nil {
				return
			}
		case <-done:
			return
		case <-ctx.Done():
			return
		}
	}
}
