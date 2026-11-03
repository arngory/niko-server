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

// listenPacketSocket creates the backend's SOCK_SEQPACKET socket, mode 0660
// (its directory, made by systemd, limits who can reach it).
func listenPacketSocket(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o117)
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
