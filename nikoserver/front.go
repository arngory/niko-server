//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
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
	front := &dnsFront{log: log, zoneBackend: make(map[string]*backendLink), sockets: make(map[netip.AddrPort]*net.UDPConn)}
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
	for name, ref := range c.Backends {
		if ref.Mode != "packet" || !inDNS[name] {
			continue
		}
		links[name] = &backendLink{name: name, ref: ref, log: log, out: make(chan []byte, 1024), answer: front.answer}
	}
	for _, z := range c.DNS.Zones {
		zone := strings.ToLower(strings.TrimSuffix(z.Zone, "."))
		front.zones = append(front.zones, zone)
		front.zoneBackend[zone] = links[z.Backend]
	}
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
	zones       []string
	zoneBackend map[string]*backendLink
	sockets     map[netip.AddrPort]*net.UDPConn
}

func (f *dnsFront) closeAll() {
	for _, conn := range f.sockets {
		conn.Close()
	}
}

func (f *dnsFront) serve(local netip.AddrPort, conn *net.UDPConn) error {
	buffer := make([]byte, maxDatagram)
	message := make([]byte, 0, packetHeader+maxDatagram)
	for {
		n, client, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return envError("read %s: %v", local, err)
		}
		query := buffer[:n]
		name, questionEnd, ok := queryName(query)
		if !ok {
			continue
		}
		zone := zoneOf(name, f.zones)
		if zone == "" {
			// not one of our zones: no open resolver here
			conn.WriteToUDPAddrPort(refused(query, questionEnd), client)
			continue
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		f.zoneBackend[zone].send(encodePacket(message, client, local, query))
	}
}

// answer sends a backend's answer from the socket the query came in on.
func (f *dnsFront) answer(client, local netip.AddrPort, payload []byte) {
	conn := f.sockets[local]
	if conn == nil {
		for addr, candidate := range f.sockets {
			if addr.Addr().Is4() == client.Addr().Is4() {
				conn = candidate
				break
			}
		}
	}
	if conn != nil {
		conn.WriteToUDPAddrPort(payload, client)
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

	access sync.Mutex
	conn   *net.UnixConn
}

func (l *backendLink) send(message []byte) {
	l.access.Lock()
	connected := l.conn != nil
	l.access.Unlock()
	if !connected {
		return
	}
	select {
	case l.out <- append([]byte(nil), message...):
	default:
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
