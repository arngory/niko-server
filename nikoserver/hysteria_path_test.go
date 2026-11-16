//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func hysteriaClient(t *testing.T, ctx context.Context, name, obfs string, o hysteria2.ClientOptions) *hysteria2.Client {
	t.Helper()
	tlsConfig, err := sbtls.NewClient(ctx, nopLogger(), name, option.OutboundTLSOptions{Enabled: true, ServerName: name,
		Insecure: true, ALPN: []string{"h3"}, CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)}})
	if err != nil {
		t.Fatal(err)
	}
	o.Context, o.Dialer, o.Logger, o.Password, o.SalamanderPassword, o.TLSConfig = ctx, N.SystemDialer, nopLogger(), "password-one", obfs, tlsConfig
	client, err := hysteria2.NewClient(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(nil) })
	return client
}

// Hysteria2's port hopping through the front: the client (sing-quic, as
// sing-box's) moves its connection to a new socket and a new port of the
// node every few seconds, the same connection, as Niko can at a slot
// change (raycontrol spa-v2 §11). The front pins each new socket by the
// label; the server, which validates a new path before it sends there
// (PathValidation), answers the PATH_CHALLENGE's response and moves. The
// stream goes on throughout.
func TestNekoServerHysteriaPortHopping(t *testing.T) {
	if testing.Short() {
		t.Skip("port hops come every 5 s at the fastest")
	}
	echo, _ := echoPair(t)
	for _, c := range []struct{ name, serverName string }{{"hy2-masq", "h.example.com"}, {"hy2-obfs", "x.invalid"}} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ports := []string{freeUDPPort(t), freeUDPPort(t)}
			front, salamander := hysteriaFront(t, ctx, true, true, ports...)
			obfs := ""
			if c.name == "hy2-obfs" {
				obfs = salamander
			}
			var hop []string
			for _, p := range ports {
				ap := netip.MustParseAddrPort(p)
				hop = append(hop, fmt.Sprintf("%d:%d", ap.Port(), ap.Port()))
			}
			client := hysteriaClient(t, ctx, c.serverName, obfs, hysteria2.ClientOptions{
				ServerAddress: M.ParseSocksaddr(ports[0]), ServerPorts: hop, HopInterval: 5 * time.Second})
			conn, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			end := time.Now().Add(11500 * time.Millisecond)
			for i := 0; time.Now().Before(end); i++ {
				what := fmt.Sprintf("round %d", i)
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err := conn.Write([]byte(what)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				got := make([]byte, len(what))
				if _, err := io.ReadFull(conn, got); err != nil || string(got) != what {
					t.Fatalf("%s: %q %v", what, got, err)
				}
				time.Sleep(200 * time.Millisecond)
			}
			// The client's flows: the first socket and one per hop.
			front.access.Lock()
			flows := len(front.flows)
			front.access.Unlock()
			if flows < 3 {
				t.Fatalf("%d flows: the client did not hop twice", flows)
			}
		})
	}
}

// spoofRelay forwards a client to the front; spoof sends the client's next
// datagram from another socket of the relay's, the victim's, as a client
// that forges its source address would, and the victim counts what it gets.
type spoofRelay struct {
	in, out, victim *net.UDPConn
	mu              sync.Mutex
	client          *net.UDPAddr
	spoof           atomic.Bool
	spoofed         atomic.Int64
	victimGot       atomic.Int64
}

func newSpoofRelay(t *testing.T, server *net.UDPAddr) *spoofRelay {
	t.Helper()
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := net.DialUDP("udp4", nil, server)
	victim, _ := net.DialUDP("udp4", nil, server)
	r := &spoofRelay{in: in, out: out, victim: victim}
	t.Cleanup(func() { in.Close(); out.Close(); victim.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client = from
			r.mu.Unlock()
			if r.spoof.CompareAndSwap(true, false) {
				r.spoofed.Add(int64(n))
				victim.Write(buf[:n])
				continue
			}
			out.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			c := r.client
			r.mu.Unlock()
			in.WriteToUDP(buf[:n], c)
		}
	}()
	go func() { // the victim never answers
		buf := make([]byte, 2048)
		for {
			n, err := victim.Read(buf)
			if err != nil {
				return
			}
			r.victimGot.Add(int64(n))
		}
	}()
	return r
}

// A user downloads, then sends one of its own packets from a forged source
// (review of quic-cid-route-v1, F1). Without path validation the server
// moved its whole send stream there at once: some 700 KB in 3 s at the
// victim for one packet of 36 bytes, with labels or after an Initial
// pinned the victim's address. Now the victim gets one PATH_CHALLENGE (1200
// bytes), and the download goes on to the user. Without labels in the front
// the forger first pins the victim's address with a forged Initial for the
// name: the victim also gets the server's answer to that Initial, three
// times its size at most, as from any QUIC server.
func TestNekoServerHysteriaSpoofedSource(t *testing.T) {
	for _, c := range []struct {
		name               string
		frontCID           bool
		serverName, obfsPW string
	}{
		{"hy2-masq, labels", true, "h.example.com", ""},
		{"hy2-masq, pinned by a forged Initial", false, "h.example.com", ""},
		{"hy2-obfs, labels", true, "x.invalid", "salamander"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server, salamander := hysteriaNode(t, ctx, true, c.frontCID)
			relay := newSpoofRelay(t, server)
			src, err := net.Listen("tcp", "127.0.0.1:0") // sends without end
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			go func() {
				for {
					c, err := src.Accept()
					if err != nil {
						return
					}
					go func() {
						b := make([]byte, 64<<10)
						for {
							if _, err := c.Write(b); err != nil {
								return
							}
						}
					}()
				}
			}()
			obfs := ""
			if c.obfsPW != "" {
				obfs = salamander
			}
			client := hysteriaClient(t, ctx, c.serverName, obfs, hysteria2.ClientOptions{
				ServerAddress: M.SocksaddrFromNet(relay.in.LocalAddr()), ReceiveBPS: 100 * 1000 * 1000 / 8})
			conn, err := client.DialConn(ctx, M.SocksaddrFromNet(src.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write([]byte("go"))
			var got atomic.Int64
			go func() {
				b := make([]byte, 64<<10)
				for {
					n, err := conn.Read(b)
					got.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
			time.Sleep(time.Second)
			pin := 0
			if !c.frontCID {
				// The front pins the victim's address by a forged Initial
				// for the name; the server answers it there.
				for _, d := range initials(t, c.serverName, quic.Version1) {
					pin += len(d)
					relay.victim.Write(d)
				}
				time.Sleep(time.Second)
			}
			relay.spoof.Store(true)
			time.Sleep(300 * time.Millisecond)
			before := got.Load()
			time.Sleep(1500 * time.Millisecond)
			after := got.Load()
			if relay.spoofed.Load() == 0 {
				t.Fatal("no packet went from the forged source")
			}
			if v := relay.victimGot.Load(); v > int64(3*pin+1300) {
				t.Fatalf("a forged Initial of %d bytes and a forged packet of %d: the victim got %d bytes", pin, relay.spoofed.Load(), v)
			}
			if after-before < 64<<10 {
				t.Fatalf("the download stopped after the forged packet: %d bytes in 1.5 s", after-before)
			}
		})
	}
}

// Whoever has a label's key reads the counter in its IDs, and so knows the
// IDs to come; a stateless reset's token is a function of the ID, and a
// packet for an ID not issued yet used to get one: its token, collected
// now, ended that connection later (review of quic-cid-route-v1, F2). Now
// hy2-masq (the Hysteria2 backend with stateless resets) drops a packet
// for an ID of its own it will issue, and answers one it never will (a
// process before it) with a reset, as before.
func TestNekoServerHysteriaNoResetAhead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo, _ := echoPair(t)
	server, _ := hysteriaNode(t, ctx, true, true)
	relay := newNATRelay(t, server)
	codec := labelCodec(cidSecret, 31) // hy2-masq's label
	var mu sync.Mutex
	var counter uint64
	seen := false
	relay.mu.Lock()
	relay.up = func(d []byte) {
		if len(d) < minCIDPacket || d[0]&0xc0 != 0x40 {
			return
		}
		x, y := codec.decrypt(binary.BigEndian.Uint32(d[1:5]), binary.BigEndian.Uint32(d[5:9]))
		mu.Lock()
		defer mu.Unlock()
		if c := uint64(x&0xff)<<32 | uint64(y); uint16(x>>16) == 31 && (!seen || c > counter) {
			counter, seen = c, true
		}
	}
	relay.mu.Unlock()
	client := hysteriaClient(t, ctx, "h.example.com", "", hysteria2.ClientOptions{ServerAddress: M.SocksaddrFromNet(relay.addr())})
	conn, err := client.DialConn(ctx, M.SocksaddrFromNet(echo.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("x"))
	io.ReadFull(conn, make([]byte, 1))
	mu.Lock()
	last, ok := counter, seen
	mu.Unlock()
	if !ok {
		t.Fatal("no short header of the client's")
	}
	// The server has issued a few IDs past the one the client uses.
	answered := func(c uint64) bool {
		s, err := net.DialUDP("udp4", nil, server)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		s.Write(shortPacket(codec.encode(31, c&(1<<cidCounterBits-1)), 100))
		s.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err = s.Read(make([]byte, 200))
		return err == nil
	}
	for k := uint64(8); k < 24; k++ {
		if answered(last + k) {
			t.Fatalf("a stateless reset for counter +%d, an ID the server will issue", k)
		}
	}
	if !answered(last - 1000) {
		t.Fatal("no stateless reset for an ID the server never issued: resets are off, the test proves nothing")
	}
}
