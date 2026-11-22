//go:build linux

package nikoserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// twoAddrs are two addresses of the host of one family, to ask a wildcard
// socket on: 127.0.0.1 and 127.0.0.2 (all of 127/8 is lo's); for IPv6 ::1
// and another of the host's, which a host without root's help may not have.
func twoAddrs(t *testing.T, v4 bool) (netip.Addr, netip.Addr) {
	t.Helper()
	if v4 {
		return netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	}
	if c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback}); err != nil {
		t.Skipf("no ::1 here: %v", err)
	} else {
		c.Close()
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		p, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(p.IP)
		if ip.Is6() && !ip.Is4In6() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return netip.IPv6Loopback(), ip
		}
	}
	t.Skip("no second IPv6 address here (one can be added to lo, as root)")
	return netip.Addr{}, netip.Addr{}
}

// wildcardPort is a port free on the family's wildcard.
func wildcardPort(t *testing.T, v4 bool) uint16 {
	t.Helper()
	network, wild := "udp6", netip.IPv6Unspecified()
	if v4 {
		network, wild = "udp4", netip.IPv4Unspecified()
	}
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(wild, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

// ask sends d from a socket of its own on from, unconnected, to addr and
// returns the reply and the address it came from.
func askFrom(t *testing.T, from netip.Addr, to netip.AddrPort, d []byte) ([]byte, netip.AddrPort) {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2048)
	for range 3 {
		if _, err := c.WriteToUDPAddrPort(d, to); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err == nil {
			return buf[:n], netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		}
	}
	t.Fatalf("no reply to a datagram to %s", to)
	return nil, netip.AddrPort{}
}

// dnsQuery is a query of name, type typ, ID id.
func dnsQuery(id uint16, name string, typ uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, wireName(name)...)
	return append(q, byte(typ>>8), byte(typ), 0, 1)
}

// The DNS front on a wildcard answers from the address each query came to,
// whichever the host's routing would pick for the client: a refusal, an
// apex answer and a backend's answer, which comes back to the front later,
// for a query to the host's second address as for one to its first.
func TestDNSFrontWildcardRepliesFromAddressAsked(t *testing.T) {
	for _, v4 := range []bool{true, false} {
		t.Run(map[bool]string{true: "IPv4", false: "IPv6"}[v4], func(t *testing.T) {
			first, second := twoAddrs(t, v4)
			port := wildcardPort(t, v4)
			wild := netip.IPv6Unspecified()
			if v4 {
				wild = netip.IPv4Unspecified()
			}
			dir := t.TempDir()
			sock := filepath.Join(dir, "be.sock")
			ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sock, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{
				Listen: []string{netip.AddrPortFrom(wild, port).String()},
				Zones:  []DNSZone{{Zone: "t.example.com", Backend: "be", NS: []string{"ns1.example.com"}}}},
				Backends: map[string]BackendRef{"be": {Socket: sock, Mode: "packet", UID: os.Getuid()}}}
			if errs := c.validate(); len(errs) != 0 {
				t.Fatal(errs)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- RunFront(ctx, c, NewLogger("warn", io.Discard)) }()
			defer func() { cancel(); <-done }()
			// The backend answers each query: its ID, QR set, to the
			// client and local the front named.
			be, err := ln.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer be.Close()
			go func() {
				buf := make([]byte, packetHeader+maxDatagram)
				out := make([]byte, 0, packetHeader+maxDatagram)
				for {
					n, err := be.Read(buf)
					if err != nil {
						return
					}
					client, local, q, err := decodePacket(buf[:n])
					if err != nil || len(q) < 12 {
						continue
					}
					a := append([]byte(nil), q...)
					a[2], a[3] = 0x81, 0x80
					be.Write(encodePacket(out, client, local, a))
				}
			}()
			time.Sleep(200 * time.Millisecond) // the front's link takes the connection

			for i, to := range []netip.Addr{second, first} {
				dst := netip.AddrPortFrom(to, port)
				for _, tc := range []struct {
					name  string
					query []byte
					rcode byte
				}{
					{"refused", dnsQuery(0x1000+uint16(i), "example.org", 1), 5},
					{"apex", dnsQuery(0x2000+uint16(i), "t.example.com", 2), 0},
					{"backend", dnsQuery(0x3000+uint16(i), "x.t.example.com", 16), 0},
				} {
					reply, from := askFrom(t, first, dst, tc.query)
					if len(reply) < 12 || reply[0] != tc.query[0] || reply[1] != tc.query[1] || reply[2]&0x80 == 0 || reply[3]&0x0f != tc.rcode {
						t.Fatalf("%s to %s: reply % x", tc.name, dst, reply)
					}
					if from != dst {
						t.Errorf("%s to %s: the reply came from %s", tc.name, dst, from)
					}
				}
			}
		})
	}
}

// The DNS front's reads and writes on a wildcard take no allocation more
// than on an address.
func TestPktinfoNoAllocations(t *testing.T) {
	port := wildcardPort(t, true)
	conn, err := listenDNS(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !pktinfoOn(conn, netip.AddrPortFrom(netip.IPv4Unspecified(), port), NewLogger("warn", io.Discard)) {
		t.Fatal("no IP_PKTINFO")
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port)
	from := client.LocalAddr().(*net.UDPAddr).AddrPort()
	buf, oob, back := make([]byte, 512), make([]byte, pktinfoRoom), make([]byte, 512)
	msg := []byte("datagram")
	var failed string // a panic inside AllocsPerRun would end the whole binary
	allocs := testing.AllocsPerRun(200, func() {
		if failed != "" {
			return
		}
		client.WriteToUDPAddrPort(msg, to)
		n, src, dst, err := readDst(conn, buf, oob)
		if err != nil || dst != to.Addr() || src != from {
			failed = fmt.Sprintf("read %d %v %v %v", n, src, dst, err)
			return
		}
		if _, err := writeFrom(conn, buf[:n], src, dst); err != nil {
			failed = fmt.Sprintf("write: %v", err)
			return
		}
		if _, got, err := client.ReadFromUDPAddrPort(back); err != nil || got != to {
			failed = fmt.Sprintf("the reply from %v (%v)", got, err)
		}
	})
	if failed != "" {
		t.Fatal(failed)
	}
	if allocs != 0 {
		t.Fatalf("%v allocations a datagram", allocs)
	}
}

// The UDP front on a wildcard sends a flow's answers from the address the
// client's datagrams came to.
func TestUDPFrontWildcardRepliesFromAddressAsked(t *testing.T) {
	for _, v4 := range []bool{true, false} {
		t.Run(map[bool]string{true: "IPv4", false: "IPv6"}[v4], func(t *testing.T) {
			first, second := twoAddrs(t, v4)
			port := wildcardPort(t, v4)
			wild := netip.IPv6Unspecified()
			if v4 {
				wild = netip.IPv4Unspecified()
			}
			dir := t.TempDir()
			masq := packetBackend(t, filepath.Join(dir, "masq.sock"))
			c := &FrontUDP{Listen: []string{netip.AddrPortFrom(wild, port).String()}, Routes: []UDPRoute{
				{SNI: []string{"h.example.com"}, Backend: "hy2-masq"},
			}}
			runUDPFront(t, c, map[string]BackendRef{
				"hy2-masq": {Socket: filepath.Join(dir, "masq.sock"), Mode: "packet", UID: os.Getuid()},
			})
			hello := initials(t, "h.example.com", quic.Version1)
			for _, to := range []netip.Addr{second, first} {
				dst := netip.AddrPortFrom(to, port)
				cl, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(first, 0)))
				if err != nil {
					t.Fatal(err)
				}
				defer cl.Close()
				for _, d := range hello {
					cl.WriteToUDPAddrPort(d, dst)
				}
				buf := make([]byte, 2048)
				masq.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, from, err := masq.ReadFrom(buf); err != nil || from.String() != cl.LocalAddr().String() {
					t.Fatalf("to %s: the backend got %v (%v)", dst, from, err)
				}
				for {
					masq.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					if _, _, err := masq.ReadFrom(buf); err != nil {
						break
					}
				}
				masq.WriteTo([]byte("answer"), cl.LocalAddr())
				cl.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, from, err := cl.ReadFromUDPAddrPort(buf)
				if err != nil || string(buf[:n]) != "answer" {
					t.Fatalf("to %s: answer %q %v", dst, buf[:n], err)
				}
				if from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); from != dst {
					t.Errorf("to %s: the answer came from %s", dst, from)
				}
			}
		})
	}
}

// What a send's control message names is what a read of it gives back, of
// either family (this checks the layouts where the kernel has no IPv6);
// no source for a multicast destination, nor without PKTINFO.
func TestPktinfoCmsg(t *testing.T) {
	var oob [pktinfoRoom]byte
	for _, s := range []string{"127.0.0.2", "192.0.2.7", "2001:db8::53", "fe80::1"} {
		a := netip.MustParseAddr(s)
		if got := pktinfoDst(pktinfoCmsg(oob[:], a)); got != a {
			t.Errorf("%s: read back %s", a, got)
		}
	}
	if got := pktinfoDst(pktinfoCmsg(oob[:], netip.MustParseAddr("ff02::fb"))); got.IsValid() {
		t.Errorf("a multicast destination: %s", got)
	}
	// IPv4: the kernel's spec_dst first; without it the header's
	// destination, unless multicast or broadcast.
	m := pktinfoCmsg(oob[:], netip.MustParseAddr("192.0.2.7"))
	data := m[len(m)-unix.CmsgSpace(unix.SizeofInet4Pktinfo)+unix.CmsgLen(0):]
	copy(data[4:8], []byte{0, 0, 0, 0})
	copy(data[8:12], []byte{198, 51, 100, 1})
	if got := pktinfoDst(m); got != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("without spec_dst: %s", got)
	}
	for _, d := range [][]byte{{224, 0, 0, 251}, {255, 255, 255, 255}} {
		copy(data[8:12], d)
		if got := pktinfoDst(m); got.IsValid() {
			t.Errorf("to %v: %s", d, got)
		}
	}
	if got := pktinfoDst(nil); got.IsValid() {
		t.Errorf("nothing: %s", got)
	}
}

// A source the kernel will not send from (not an address of the host)
// gets the reply from the address routing picks, as before PKTINFO.
func TestPktinfoForeignSource(t *testing.T) {
	port := wildcardPort(t, true)
	conn, err := listenDNS(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	to := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := writeFrom(conn, []byte("reply"), to, netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatalf("a foreign source: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 16)
	n, from, err := client.ReadFromUDPAddrPort(b)
	if err != nil || string(b[:n]) != "reply" || from.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("got %q from %v (%v)", b[:n], from, err)
	}
}
