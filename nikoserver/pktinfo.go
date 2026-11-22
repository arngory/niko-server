//go:build linux

package nikoserver

import (
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A front's socket bound to a wildcard address (0.0.0.0, [::]) takes the
// datagrams to every address of its family on the host, and a reply sent
// without a source goes from the address routing picks for the client: on
// a host with several (failover IPs, extra IPv4, several IPv6 of a /64) it
// need not be the one the client asked, and the client drops the reply (a
// resolver: RFC 5452 §3; a QUIC client: its connected socket). Such a
// socket asks for each datagram's destination (IP_PKTINFO, IPV6_RECVPKTINFO)
// and a reply goes from it (IP_PKTINFO, IPV6_PKTINFO on the send). A socket
// bound to one address needs none of it and reads and writes as before.
//
// The interface index of a send is 0: routing picks the interface for the
// source and the client, as it does for a socket bound to that address. The
// one a datagram came in on need not be the way back (asymmetric routes,
// policy routing by source), and on IPv4 a nonzero index forces it.

// pktinfoRoom is a read's room for control messages: one PKTINFO of either
// family (40 bytes on a 64-bit kernel), with some to spare.
const pktinfoRoom = 64

// pktinfoOn asks the kernel for the destination of each datagram on conn,
// if it is bound to a wildcard address; false when it is not, or when the
// kernel refuses (logged: the socket's replies then go from the address
// routing picks, as before).
func pktinfoOn(conn *net.UDPConn, bound netip.AddrPort, log *Logger) bool {
	if !bound.Addr().IsUnspecified() {
		return false
	}
	rc, err := conn.SyscallConn()
	if err == nil {
		cerr := rc.Control(func(fd uintptr) {
			if bound.Addr().Is4() {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			} else {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
			}
		})
		if err == nil {
			err = cerr
		}
	}
	if err != nil {
		log.Warnf("%s: the kernel gives no destination of datagrams (%v): replies go from the address routing picks", bound, err)
		return false
	}
	return true
}

// readDst reads a datagram from conn with the address it came to, when oob
// (pktinfoRoom bytes, the reading goroutine's own) is given: a socket of
// pktinfoOn. Without oob, or when the kernel names none, dst is invalid.
func readDst(conn *net.UDPConn, b, oob []byte) (n int, client netip.AddrPort, dst netip.Addr, err error) {
	if oob == nil {
		n, client, err = conn.ReadFromUDPAddrPort(b)
		return n, client, netip.Addr{}, err
	}
	n, oobn, _, client, err := conn.ReadMsgUDPAddrPort(b, oob)
	if err != nil {
		return n, client, netip.Addr{}, err
	}
	return n, client, pktinfoDst(oob[:oobn]), nil
}

// pktinfoDst is the address a reply to the datagram with these control
// messages goes from: on IPv4 the kernel's ipi_spec_dst (for a unicast
// datagram its destination; for a broadcast one, an address of the host),
// on IPv6 the destination unless it is multicast. Invalid if none: the
// reply goes from what routing picks.
func pktinfoDst(oob []byte) netip.Addr {
	for len(oob) >= unix.SizeofCmsghdr {
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			break
		}
		switch {
		case h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) >= unix.SizeofInet4Pktinfo:
			// struct in_pktinfo: ifindex (4), spec_dst (4), addr (4)
			if a := netip.AddrFrom4([4]byte(data[4:8])); !a.IsUnspecified() {
				return a
			}
			if a := netip.AddrFrom4([4]byte(data[8:12])); !a.IsUnspecified() && !a.IsMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
				return a
			}
			return netip.Addr{}
		case h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO && len(data) >= unix.SizeofInet6Pktinfo:
			// struct in6_pktinfo: addr (16), ifindex (4)
			if a := netip.AddrFrom16([16]byte(data[:16])); !a.IsMulticast() && !a.IsUnspecified() {
				return a
			}
			return netip.Addr{}
		}
		oob = rest
	}
	return netip.Addr{}
}

// writeFrom sends b to client from src (pktinfoDst's); an invalid src from
// the address routing picks, as WriteToUDPAddrPort. A source the kernel
// will not send from goes once more from what routing picks, as before
// PKTINFO: an IPv6 range routed to lo rather than assigned, with
// ip_nonlocal_bind off (EINVAL), or an address gone from the host since
// the query (ENETUNREACH on IPv4, EADDRNOTAVAIL). The reply may still
// reach a lenient client; none would.
func writeFrom(conn *net.UDPConn, b []byte, client netip.AddrPort, src netip.Addr) (int, error) {
	if !src.IsValid() {
		return conn.WriteToUDPAddrPort(b, client)
	}
	var oob [pktinfoRoom]byte
	n, _, err := conn.WriteMsgUDPAddrPort(b, pktinfoCmsg(oob[:], src), client)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENETUNREACH) {
		return conn.WriteToUDPAddrPort(b, client)
	}
	return n, err
}

// pktinfoCmsg writes into oob the control message that sends from src,
// interface index 0, and returns it.
func pktinfoCmsg(oob []byte, src netip.Addr) []byte {
	var h unix.Cmsghdr
	size := unix.SizeofInet6Pktinfo
	h.Level, h.Type = unix.IPPROTO_IPV6, unix.IPV6_PKTINFO
	if src.Is4() {
		size = unix.SizeofInet4Pktinfo
		h.Level, h.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
	}
	h.SetLen(unix.CmsgLen(size))
	oob = oob[:unix.CmsgSpace(size)]
	clear(oob)
	copy(oob, unsafe.Slice((*byte)(unsafe.Pointer(&h)), unix.SizeofCmsghdr))
	data := oob[unix.CmsgLen(0):]
	if src.Is4() {
		a := src.As4()
		copy(data[4:8], a[:]) // ipi_spec_dst: the source; ipi_addr is not read on a send
	} else {
		a := src.As16()
		copy(data[:16], a[:])
	}
	return oob
}
