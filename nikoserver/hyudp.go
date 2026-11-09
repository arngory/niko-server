//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A Hysteria2 UDP session: a socket of its own, the client's datagrams out
// to public addresses and the answers back, their payloads counted for the
// user. Under the user's limits (raycontrol docs/spec/conn-limit-v1.md
// §3.2) it holds a place among the user's sessions, taken before the
// socket is made; its pairs (the socket's port and a destination) count
// while conntrack would keep them, and a datagram to a new destination past
// the limits is dropped, as a path would drop it.
const (
	udpNames      = 64               // names a session keeps (udpResolved)
	udpNameMiss   = 30 * time.Second // a failed lookup of the session's own
	udpLookupWait = 5 * time.Second  // a datagram's wait for its name
	udpIdle       = 2 * time.Minute
)

// udpResolved is what a session knows of a name until a moment, so that
// its datagrams to it neither wait nor take the process's cache's lock: an
// allowed address, until the shared cache's answer expires; or (ip not
// valid) a lookup that timed out or got SERVFAIL, which the shared cache
// does not keep, for udpNameMiss: otherwise every datagram to such a name
// would wait for a lookup again. Anything else (no such name, no allowed
// address, no lookup token) is the shared cache's to know, or no one's.
type udpResolved struct {
	ip    netip.Addr
	until time.Time
}

// udpSession is a session's state; names belongs to the sending loop.
type udpSession struct {
	lim   *hyLimits
	user  string
	slot  *udpSlot
	ctx   context.Context
	any   bool // tests: any destination, not public ones only
	names map[string]udpResolved
}

func (o *outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := o.relayUDP(ctx, conn, source)
	if onClose != nil {
		onClose(err)
	}
}

// sessionNumber is the number the client gave the session (the vendored
// sing-quic's SessionID, neko); 0 for a conn that has none.
func sessionNumber(conn N.PacketConn) uint32 {
	if s, ok := common.Cast[interface{ SessionID() uint32 }](conn); ok {
		return s.SessionID()
	}
	return 0
}

// relayUDP carries a user's datagrams to and from public addresses and
// counts their payloads for the user: sent to a destination up, received
// from one and passed on down. client is the client's address: with the
// session's number it tells the session among the user's.
func (o *outbound) relayUDP(ctx context.Context, conn N.PacketConn, client M.Socksaddr) error {
	user, t := userFrom(ctx)
	defer t.open()()
	lim := o.limits()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// The place before the socket: a refusal, which the client repeats
	// with every datagram of the session, costs neither.
	slot, _, first := lim.udpTake(user, udpID{client.AddrPort(), sessionNumber(conn)}, cancel)
	if slot == nil {
		if first {
			o.log.Debugf("too many connections")
		}
		conn.Close()
		return errTooMany
	}
	defer lim.udpPut(slot)
	var probeAddr netip.AddrPort
	var probeFrom atomic.Pointer[M.Socksaddr] // what the client sent to: replies come from it
	if o.probe != nil {
		probeAddr, _ = netip.ParseAddrPort(o.probe.Address)
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		conn.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		udp.Close()
		conn.Close()
	}()
	go func() {
		defer cancel(nil)
		b := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdle))
			n, from, err := udp.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			buffer := buf.As(b[:n])
			// A dual-stack socket reports IPv4 senders as ::ffff:a.b.c.d.
			sender := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			m := monoAt(lim.clock())
			slot.touch(m)
			slot.heard(sender, m)
			source := M.SocksaddrFromNetIP(sender)
			if probeAddr.IsValid() && sender == probeAddr {
				if p := probeFrom.Load(); p != nil {
					source = *p
				}
			}
			if err := conn.WritePacket(buffer, source); err != nil {
				return
			}
			t.down.Add(int64(n))
		}
	}()
	s := &udpSession{lim: lim, user: user, slot: slot, ctx: ctx, any: anyDestination(), names: map[string]udpResolved{}}
	for {
		buffer := buf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		now := lim.clock()
		m := monoAt(now)
		slot.touch(m)
		if probeAddr.IsValid() && o.isProbe(destination) {
			// The probe's address on the node: no pair of the perimeter's.
			d := destination
			probeFrom.Store(&d)
			if n, err := udp.WriteToUDPAddrPort(buffer.Bytes(), probeAddr); err == nil {
				t.up.Add(int64(n))
			}
			buffer.Release()
			continue
		}
		// Not allowed, no address, or no room for a new destination:
		// dropped. So is a datagram the kernel refuses (EPERM from
		// raycontrol's guard or egress policy): the session lives on.
		if to, ok := s.resolve(destination, now); ok && slot.mayReach(to, m) {
			if n, err := udp.WriteToUDPAddrPort(buffer.Bytes(), to); err == nil {
				t.up.Add(int64(n))
			}
		}
		buffer.Release()
	}
}

func (s *udpSession) allowed(ip netip.Addr) bool { return s.any || Public(ip) }

// resolve is the address a destination may be reached at: its own, or the
// first allowed one of its name; false for none.
func (s *udpSession) resolve(d M.Socksaddr, now time.Time) (netip.AddrPort, bool) {
	if d.Port == 0 {
		return netip.AddrPort{}, false
	}
	if !d.IsFqdn() {
		ip := d.Addr.Unmap()
		return netip.AddrPortFrom(ip, d.Port), ip.IsValid() && s.allowed(ip)
	}
	name := d.Fqdn
	if n, ok := s.names[name]; ok && now.Before(n.until) {
		if n.ip.IsValid() {
			return netip.AddrPortFrom(n.ip, d.Port), true
		}
		// A failure of the session's own: the shared cache may know the
		// name since, no lookup otherwise.
		ip, until, ok := s.cachedName(name, now)
		if !ok {
			return netip.AddrPort{}, false
		}
		delete(s.names, name)
		if !until.IsZero() {
			s.remember(name, udpResolved{ip, until}, now)
		}
		return netip.AddrPortFrom(ip, d.Port), ip.IsValid()
	}
	ip, until, ok := s.cachedName(name, now)
	if !ok {
		ip, until = s.lookup(name, now)
	}
	if !until.IsZero() {
		s.remember(name, udpResolved{ip, until}, now)
	}
	return netip.AddrPortFrom(ip, d.Port), ip.IsValid()
}

// cachedName is a name's first allowed address in the process's cache, and
// until when the session may keep it (zero: not); ok false when the cache
// does not know the name.
func (s *udpSession) cachedName(name string, now time.Time) (netip.Addr, time.Time, bool) {
	addrs, until, err, ok := s.lim.names.get(name, now)
	if !ok {
		return netip.Addr{}, time.Time{}, false
	}
	ip, until := s.firstAllowed(addrs, until, err)
	return ip, until, true
}

// lookup looks a name up through the process's cache, a miss paying the
// user's lookup token: its first allowed address, and until when the
// session may keep what came of it (zero: not).
func (s *udpSession) lookup(name string, now time.Time) (netip.Addr, time.Time) {
	ctx, cancel := context.WithTimeout(s.ctx, udpLookupWait)
	addrs, until, err := s.lim.lookupNameUntil(ctx, s.user, name)
	cancel()
	if err != nil && lookupFailed(err) {
		return netip.Addr{}, now.Add(udpNameMiss)
	}
	return s.firstAllowed(addrs, until, err)
}

func (s *udpSession) firstAllowed(addrs []netip.Addr, until time.Time, err error) (netip.Addr, time.Time) {
	if err != nil {
		return netip.Addr{}, time.Time{}
	}
	for _, ip := range addrs {
		if ip = ip.Unmap(); s.allowed(ip) {
			return ip, until
		}
	}
	return netip.Addr{}, time.Time{}
}

// remember keeps what the session knows of a name: within udpNames, those
// expired going first.
func (s *udpSession) remember(name string, r udpResolved, now time.Time) {
	if _, ok := s.names[name]; !ok && len(s.names) >= udpNames {
		for n, x := range s.names {
			if !now.Before(x.until) {
				delete(s.names, n)
			}
		}
		if len(s.names) >= udpNames {
			return
		}
	}
	s.names[name] = r
}

// lookupFailed reports whether a lookup timed out or got SERVFAIL: what the
// shared cache does not keep and a session does, for itself.
func lookupFailed(err error) bool {
	var d *net.DNSError
	if errors.As(err, &d) {
		return !d.IsNotFound && (d.IsTimeout || d.IsTemporary)
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}
