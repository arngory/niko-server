//go:build linux

package nikoserver

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// The DNS front shares UDP 53 with systemd-resolved's stub: both bind with
// SO_REUSEADDR, the stub's datagrams stay the stub's, the rest are the
// front's; a socket without SO_REUSEADDR still cannot take the port.
func TestDNSFrontSharesWithResolved(t *testing.T) {
	ctx := context.Background()
	reuse := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) })
	}}
	stub, err := reuse.ListenPacket(ctx, "udp4", "127.0.0.53:0")
	if err != nil {
		t.Skipf("no 127.0.0.53 here: %v", err)
	}
	defer stub.Close()
	port := stub.LocalAddr().(*net.UDPAddr).Port
	front, err := listenDNS(ctx, "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)))
	if err != nil {
		t.Fatalf("the front beside the stub: %v", err)
	}
	defer front.Close()
	if pc, err := net.ListenPacket("udp4", front.LocalAddr().String()); err == nil {
		pc.Close()
		t.Fatal("a socket without SO_REUSEADDR took the port")
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.WriteTo([]byte("stub"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 53), Port: port})
	c.WriteTo([]byte("front"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	buf := make([]byte, 16)
	for name, pc := range map[string]net.PacketConn{"stub": stub, "front": front} {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil || string(buf[:n]) != name {
			t.Errorf("%s got %q %v", name, buf[:n], err)
		}
	}
}
