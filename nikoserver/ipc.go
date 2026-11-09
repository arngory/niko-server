//go:build linux

package nikoserver

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
)

// IPC version 1, mode "packet" (docs/server/IPC.md): one SOCK_SEQPACKET message
// per datagram, both ways:
//
//	magic "NU" | version 1 | client (19) | local (19) | payload
//
// an address is family (4 or 6) | 16 bytes (IPv4 as ::ffff:a.b.c.d) | port (BE16).
const (
	packetVersion = 1
	addrSize      = 19
	packetHeader  = 2 + 1 + 2*addrSize
	maxDatagram   = 65535
)

var errBadPacket = errors.New("ipc: malformed packet message")

func putAddr(b []byte, addr netip.AddrPort) {
	if addr.Addr().Is4() || addr.Addr().Is4In6() {
		b[0] = 4
	} else {
		b[0] = 6
	}
	a16 := addr.Addr().As16()
	copy(b[1:17], a16[:])
	binary.BigEndian.PutUint16(b[17:19], addr.Port())
}

func getAddr(b []byte) (netip.AddrPort, error) {
	addr := netip.AddrFrom16([16]byte(b[1:17]))
	switch b[0] {
	case 4:
		if !addr.Is4In6() {
			return netip.AddrPort{}, errBadPacket
		}
		addr = addr.Unmap()
	case 6:
		// putAddr writes an IPv4 address, mapped or not, as 4: a mapped
		// one under 6 is not from it (one client, two keys downstream).
		if addr.Is4In6() {
			return netip.AddrPort{}, errBadPacket
		}
	default:
		return netip.AddrPort{}, errBadPacket
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[17:19])), nil
}

func encodePacket(buf []byte, client, local netip.AddrPort, payload []byte) []byte {
	buf = append(buf[:0], 'N', 'U', packetVersion)
	var a [addrSize]byte
	putAddr(a[:], client)
	buf = append(buf, a[:]...)
	putAddr(a[:], local)
	buf = append(buf, a[:]...)
	return append(buf, payload...)
}

// IPC version 2, from the DNS front to a backend with devices (a tagged
// zone's): the device whose tag the query carried, as a token of the
// front's (deviceToken); the answers stay in version 1.
//
//	magic "NU" | version 2 | client (19) | local (19) | device (8) | payload
const (
	packetVersionDevice = 2
	deviceSize          = 8
)

func encodePacketDevice(buf []byte, client, local netip.AddrPort, device [deviceSize]byte, payload []byte) []byte {
	buf = encodePacket(buf, client, local, nil)
	buf[2] = packetVersionDevice
	buf = append(buf, device[:]...)
	return append(buf, payload...)
}

func decodePacket(msg []byte) (client, local netip.AddrPort, payload []byte, err error) {
	if len(msg) < packetHeader || msg[0] != 'N' || msg[1] != 'U' || msg[2] != packetVersion {
		return client, local, nil, errBadPacket
	}
	if client, err = getAddr(msg[3 : 3+addrSize]); err != nil {
		return
	}
	if local, err = getAddr(msg[3+addrSize : packetHeader]); err != nil {
		return
	}
	return client, local, msg[packetHeader:], nil
}

// peerUID is the UID of the process at the other end of a unix socket (SO_PEERCRED).
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err == nil {
		err = credErr
	}
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}

// listenPacketSocket creates the backend's SOCK_SEQPACKET socket, mode 0660,
// as the stats sockets are: made under the process's umask, then set. Its
// directory, made by systemd (0710, docs/IPC.md), limits who can reach it
// at all, and until the chmod the umask makes it no wider: under systemd's
// 0022 it is 0755, and only its owner may connect to it. The umask is never
// changed here: it is the whole process's. A directory another goroutine
// made meanwhile got 0117 too, without its owner's search bit, and two
// sockets made at once could each restore the other's 0117 and leave it.
func listenPacketSocket(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// IPC version 1, mode "fd": one SOCK_SEQPACKET message per accepted TCP
// connection, its socket in SCM_RIGHTS (IPC.md):
//
//	magic "NKT1" | flags | route_len | route | src (19) | dst (19) |
//	sni_len | sni | prefetch_len (BE32) | prefetch
const fdMagic = "NKT1"

var errBadFDMessage = errors.New("ipc: malformed fd message")

// tcpHandoff is what travels with a passed socket.
type tcpHandoff struct {
	route    string
	src, dst netip.AddrPort
	sni      string
	prefetch []byte
}

func encodeHandoff(h tcpHandoff) []byte {
	route, sni := h.route, h.sni
	if len(route) > 255 {
		route = route[:255]
	}
	if len(sni) > 255 {
		sni = sni[:255]
	}
	b := make([]byte, 0, 4+2+len(route)+2*addrSize+1+len(sni)+4+len(h.prefetch))
	b = append(b, fdMagic...)
	b = append(b, 0, byte(len(route)))
	b = append(b, route...)
	var a [addrSize]byte
	putAddr(a[:], h.src)
	b = append(b, a[:]...)
	putAddr(a[:], h.dst)
	b = append(b, a[:]...)
	b = append(b, byte(len(sni)))
	b = append(b, sni...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.prefetch)))
	return append(b, h.prefetch...)
}

func decodeHandoff(msg []byte) (tcpHandoff, error) {
	var h tcpHandoff
	if len(msg) < 6 || string(msg[:4]) != fdMagic {
		return h, errBadFDMessage
	}
	n := int(msg[5])
	rest := msg[6:]
	if len(rest) < n+2*addrSize+1 {
		return h, errBadFDMessage
	}
	h.route, rest = string(rest[:n]), rest[n:]
	var err error
	if h.src, err = getAddr(rest[:addrSize]); err != nil {
		return h, errBadFDMessage
	}
	if h.dst, err = getAddr(rest[addrSize : 2*addrSize]); err != nil {
		return h, errBadFDMessage
	}
	rest = rest[2*addrSize:]
	n = int(rest[0])
	if len(rest) < 1+n+4 {
		return h, errBadFDMessage
	}
	h.sni, rest = string(rest[1:1+n]), rest[1+n:]
	size := binary.BigEndian.Uint32(rest[:4])
	if uint32(len(rest)-4) != size {
		return h, errBadFDMessage
	}
	h.prefetch = rest[4:]
	return h, nil
}

// proxyV2Header is the PROXY protocol v2 header for a TCP stream (IPC.md,
// mode "proxy-v2"): Xray reads the client's address from it.
func proxyV2Header(src, dst netip.AddrPort) []byte {
	b := []byte("\r\n\r\n\x00\r\nQUIT\n\x21")
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	if s.Is4() && d.Is4() {
		b = append(b, 0x11, 0, 12)
		b = append(b, s.AsSlice()...)
		b = append(b, d.AsSlice()...)
	} else {
		b = append(b, 0x21, 0, 36)
		s16, d16 := netip.AddrFrom16(s.As16()), netip.AddrFrom16(d.As16())
		b = append(b, s16.AsSlice()...)
		b = append(b, d16.AsSlice()...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}
