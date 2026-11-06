//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arngory/niko-server/dnsttserver"

	mdvembed "masterdnsvpn-go/embed"
)

// ErrEnvironment marks a failure of the surroundings (sockets, key files), not of the config.
type ErrEnvironment struct{ Err error }

func (e ErrEnvironment) Error() string { return e.Err.Error() }
func (e ErrEnvironment) Unwrap() error { return e.Err }

func envError(format string, args ...any) error { return ErrEnvironment{fmt.Errorf(format, args...)} }

// RunBackend serves one backend until ctx ends or its protocol stops.
func RunBackend(ctx context.Context, c *BackendConfig, log *Logger) error {
	if c.Kind == "yggdrasil" { // streams from tcpmux, mode fd
		return runYggdrasil(ctx, c, log)
	}
	listener, err := listenPacketSocket(c.Socket)
	if err != nil {
		return envError("listen %s: %v", c.Socket, err)
	}
	conn := newPacketConn(listener, c.FrontUID, log)
	defer conn.Close()
	go conn.acceptLoop()

	dialInner := func(timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("unix", c.Inner, timeout)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	log.Infof("%s backend on %s", c.Kind, c.Socket)
	switch c.Kind {
	case "hy2-masq", "hy2-obfs":
		conn.port = 443
		dial := PublicDialer().DialContext
		if anyDestination() {
			log.Warnf("%s=1: users may reach any address, the node's own included (tests only)", unsafeAnyDestination)
			var direct net.Dialer
			dial = direct.DialContext
		}
		err := runHysteria(ctx, c, conn, log, dial)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = errors.New("hysteria2 stopped")
		}
		return err
	case "dnstt":
		key, err := dnsttserver.ReadKey(c.Options.PrivateKeyFile)
		if err != nil {
			return envError("dnstt key %s: %v", c.Options.PrivateKeyFile, err)
		}
		// dnsauth-v1: queries signed by the devices' keys (raycontrol S-9).
		mode, _ := dnsttserver.ParseAuthMode(c.Options.Auth)
		var auth *dnsttserver.Auth
		if mode != dnsttserver.AuthOff {
			auth = &dnsttserver.Auth{Mode: mode, ScanHMACs: float64(c.Options.AuthScanHMACs)}
			if err := auth.LoadKeys(c.Options.AuthKeysFile); err != nil {
				return envError("dnstt auth keys %s: %v", c.Options.AuthKeysFile, err)
			}
			go auth.WatchKeys(c.Options.AuthKeysFile, 5*time.Second, ctx.Done(), log.Infof)
			log.Infof("dnstt: queries need the device's tag (dnsauth-v1, %s)", c.Options.Auth)
		}
		// dnsseal-v1: the framing sealed with the zone's key.
		smode, _ := dnsttserver.ParseSealMode(c.Options.Seal)
		var seal *dnsttserver.Seal
		if smode != dnsttserver.SealOff {
			if seal, err = dnsttserver.LoadSeal(smode, c.Options.SealKeyFile); err != nil {
				return envError("dnstt seal keys %s: %v", c.Options.SealKeyFile, err)
			}
			// A new key, or the previous one's grace over, without a
			// restart that would end every session.
			go seal.WatchKeys(c.Options.SealKeyFile, 5*time.Second, ctx.Done(), log.Infof)
			log.Infof("dnstt: sealed framing (dnsseal-v1, %s, %d keys)", c.Options.Seal, seal.Keys())
		}
		// The counters on the stats socket, for the node's metrics.
		stats := &dnsttserver.Stats{Started: time.Now()}
		if c.StatsSocket != "" {
			stop, err := serveDNSTTStats(c.StatsSocket, stats, auth, seal, log)
			if err != nil {
				return envError("dnstt stats socket %s: %v", c.StatsSocket, err)
			}
			defer stop()
		}
		// The zone and its spares (raycontrol dnszones-v1): one tunnel.
		zones := []string{strings.TrimSuffix(c.Options.Zone, ".")}
		for _, z := range c.Options.Zones {
			zones = append(zones, strings.TrimSuffix(z, "."))
		}
		err = dnsttserver.RunZones(key, zones, conn, dialInner, auth, seal, stats)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = errors.New("dnstt stopped")
		}
		return err
	case "masterdns":
		if _, err := os.Stat(c.Options.EncryptionKeyFile); err != nil {
			return envError("masterdns key: %v", err)
		}
		err := mdvembed.RunServer(ctx, mdvembed.ServerOptions{
			Domains:  c.Options.Zones,
			Method:   *c.Options.EncryptionMethod,
			KeyFile:  c.Options.EncryptionKeyFile,
			LogLevel: strings.ToUpper(defaultLevel(c.Log.Level)),
			Conn:     conn,
			Dial:     dialInner,
			Log:      log.Writer(),
		})
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = errors.New("masterdns stopped")
		}
		return err
	}
	return fmt.Errorf("kind %q not served", c.Kind)
}

func defaultLevel(level string) string {
	if level == "" {
		return "warn"
	}
	return level
}

// packetConn is the backend's view of the DNS socket: datagrams from the
// front's connections, answers back through the latest one. It serves both
// net.PacketConn (dnstt) and the ReadFromUDP/WriteToUDP pair (MasterDnsVPN).
type packetConn struct {
	listener *net.UnixListener
	frontUID int
	log      *Logger

	in     chan inbound
	closed chan struct{}
	once   sync.Once

	access sync.Mutex
	front  *net.UnixConn
	// where each client's last query came in, for the answer's local address
	locals   map[netip.AddrPort]netip.AddrPort
	deadline time.Time
	port     int // what LocalAddr says: 53 for the DNS tunnels, 443 for QUIC
}

type inbound struct {
	client  netip.AddrPort
	payload []byte
}

func newPacketConn(listener *net.UnixListener, frontUID int, log *Logger) *packetConn {
	return &packetConn{
		listener: listener,
		frontUID: frontUID,
		log:      log,
		in:       make(chan inbound, 1024),
		closed:   make(chan struct{}),
		locals:   make(map[netip.AddrPort]netip.AddrPort),
	}
}

func (c *packetConn) acceptLoop() {
	for {
		conn, err := c.listener.AcceptUnix()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
			}
			c.log.Warnf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		uid, err := peerUID(conn)
		if err != nil || uid != c.frontUID {
			c.log.Warnf("refused a connection from UID %d (want the front, %d): %v", uid, c.frontUID, err)
			conn.Close()
			continue
		}
		conn.SetReadBuffer(4 << 20)
		conn.SetWriteBuffer(4 << 20)
		c.access.Lock()
		c.front = conn
		c.access.Unlock()
		go c.readLoop(conn)
	}
}

func (c *packetConn) readLoop(conn *net.UnixConn) {
	defer conn.Close()
	buffer := make([]byte, packetHeader+maxDatagram)
	for {
		n, err := conn.Read(buffer)
		if err != nil || n == 0 {
			return
		}
		client, local, payload, err := decodePacket(buffer[:n])
		if err != nil {
			c.log.Debugf("%v", err)
			continue
		}
		c.access.Lock()
		if len(c.locals) > 65536 {
			clear(c.locals)
		}
		c.locals[client] = local
		c.access.Unlock()
		select {
		case c.in <- inbound{client, append([]byte(nil), payload...)}:
		default:
			// the protocol is behind: drop, as a full UDP socket would
		}
	}
}

func (c *packetConn) readFrom(b []byte) (int, netip.AddrPort, error) {
	c.access.Lock()
	deadline := c.deadline
	c.access.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case packet := <-c.in:
		return copy(b, packet.payload), packet.client, nil
	case <-timeout:
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *packetConn) writeTo(b []byte, client netip.AddrPort) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.access.Lock()
	front, local := c.front, c.locals[client]
	c.access.Unlock()
	if front == nil {
		// no front connected: the answer is lost, as on a network
		return len(b), nil
	}
	if !local.IsValid() {
		local = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	msg := encodePacket(make([]byte, 0, packetHeader+len(b)), client, local, b)
	if _, err := front.Write(msg); err != nil {
		c.log.Debugf("answer to the front: %v", err)
	}
	return len(b), nil
}

// net.PacketConn (dnstt)

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, client, err := c.readFrom(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(client), nil
}

func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected address %T", addr)
	}
	return c.writeTo(b, udpAddr.AddrPort())
}

// MasterDnsVPN's UDPConn

func (c *packetConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, client, err := c.readFrom(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(client), nil
}

func (c *packetConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.writeTo(b, addr.AddrPort())
}

func (c *packetConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.listener.Close()
		c.access.Lock()
		if c.front != nil {
			c.front.Close()
		}
		c.access.Unlock()
	})
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	port := c.port
	if port == 0 {
		port = 53
	}
	return &net.UDPAddr{IP: net.IPv6unspecified, Port: port}
}

func (c *packetConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.access.Lock()
	c.deadline = t
	c.access.Unlock()
	return nil
}

func (c *packetConn) SetWriteDeadline(time.Time) error { return nil }
func (c *packetConn) SetReadBuffer(int) error          { return nil }
func (c *packetConn) SetWriteBuffer(int) error         { return nil }

// DNSTTKeypair makes a dnstt server key pair, hex, as dnstt-server -gen-key.
func DNSTTKeypair() (private, public string, err error) {
	return dnsttserver.GenerateKeypair()
}

// unsafeAnyDestination lets the backends' users reach any address, loopback
// and private ranges included: for tests on one host only. raycontrol
// never sets it.
const unsafeAnyDestination = "NIKO_SERVER_UNSAFE_ANY_DESTINATION"

func anyDestination() bool { return os.Getenv(unsafeAnyDestination) == "1" }
