package nikoserver

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// The front's UDP sockets never let the kernel fragment (P-2).
func TestProbeMTU(t *testing.T) {
	for _, c := range []struct {
		network, addr string
		level, opt    int
		want          int
	}{
		{"udp4", "127.0.0.1:0", unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE},
		{"udp6", "[::1]:0", unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE},
	} {
		a, err := net.ResolveUDPAddr(c.network, c.addr)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP(c.network, a)
		if err != nil {
			t.Skipf("%s: %v", c.network, err)
		}
		probeMTU(conn, c.network == "udp4")
		rc, _ := conn.SyscallConn()
		var got int
		var gerr error
		rc.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), c.level, c.opt) })
		conn.Close()
		if gerr != nil || got != c.want {
			t.Errorf("%s: mtu discover %d, %v; want %d", c.network, got, gerr, c.want)
		}
	}
}
