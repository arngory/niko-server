//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestNekoServerLoad is SPEC §6.6: 200 concurrent flows through each
// multiplexer for NIKO_LOAD (10m in the spec; CI runs a short one), then no
// goroutines or memory left behind once the clients stop and the flows
// expire. Set NIKO_LOAD=10m to run it.
func TestNekoServerLoad(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("NIKO_LOAD"))
	if err != nil || d <= 0 {
		t.Skip("set NIKO_LOAD to a duration, like 10m")
	}
	const flows = 200
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	log := NewLogger("error", io.Discard)
	cert := selfSigned(t, "r.example.com", "n.example.com")

	// Backends: TLS echo behind fd and proxy-v2, datagram echo behind packet.
	fdl, err := ListenFD(filepath.Join(dir, "fd.sock"), uid, log)
	if err != nil {
		t.Fatal(err)
	}
	defer fdl.Close()
	go echoTLS(fdl, cert)
	pxl, err := net.Listen("unix", filepath.Join(dir, "px.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer pxl.Close()
	go echoTLS(proxyListener{pxl}, cert)
	for _, name := range []string{"quic", "dns"} {
		pc := packetBackend(t, filepath.Join(dir, name+".sock"))
		go func() {
			b := make([]byte, 2048)
			for {
				n, from, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				pc.WriteTo(b[:n], from)
			}
		}()
	}
	backends := map[string]BackendRef{
		"fd":   {Socket: filepath.Join(dir, "fd.sock"), Mode: "fd", UID: uid},
		"px":   {Socket: filepath.Join(dir, "px.sock"), Mode: "proxy-v2", UID: uid},
		"quic": {Socket: filepath.Join(dir, "quic.sock"), Mode: "packet", UID: uid},
		"dns":  {Socket: filepath.Join(dir, "dns.sock"), Mode: "packet", UID: uid},
	}
	c := &FrontConfig{Schema: 1, Role: "front", Backends: backends,
		TCP: &FrontTCP{Listen: []string{"127.0.0.1:0"}, Default: "px", Routes: []TCPRoute{{SNI: []string{"n.example.com"}, Backend: "fd"}}},
		UDP: &FrontUDP{Listen: []string{"127.0.0.1:0"}, Idle: "5s", Routes: []UDPRoute{{SNI: []string{"h.example.com"}, Backend: "quic"}}},
	}
	tcp := newTCPFront(c.TCP, backends, log)
	if err := tcp.listen(c.TCP.Listen); err != nil {
		t.Fatal(err)
	}
	udp, err := newUDPFront(c.UDP, backends, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := udp.listen(c.UDP.Listen); err != nil {
		t.Fatal(err)
	}
	tcpAddr := tcp.listeners[0].Addr().String()
	var udpAddr *net.UDPAddr
	for _, s := range udp.sockets {
		udpAddr = s.LocalAddr().(*net.UDPAddr)
	}
	go tcp.run(ctx)
	go udp.run(ctx)
	// The DNS front binds what it is given: a port found free first.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr := probe.LocalAddr().(*net.UDPAddr)
	probe.Close()
	c.DNS = &FrontDNS{Listen: []string{dnsAddr.String()}, Zones: []DNSZone{{Zone: "t.example.com", Backend: "dns"}}}
	go runDNSFront(ctx, c, log)
	hello := initials(t, "h.example.com", quic.Version1)
	time.Sleep(300 * time.Millisecond)

	settle := func() (int, uint64) {
		runtime.GC()
		time.Sleep(500 * time.Millisecond)
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return runtime.NumGoroutine(), m.HeapInuse
	}
	g0, h0 := settle()

	var ok, failed atomic.Int64
	var failedBy [3]atomic.Int64 // tcp, dns, udp
	work, stop := context.WithTimeout(ctx, d)
	defer stop()
	var wg sync.WaitGroup
	for i := range flows {
		name := "n.example.com"
		if i%2 == 1 {
			name = "r.example.com"
		}
		wg.Go(func() { // TLS through tcpmux, both modes
			for work.Err() == nil {
				if tlsRound(work, tcpAddr, name) {
					ok.Add(1)
				} else if work.Err() == nil {
					failed.Add(1)
					failedBy[0].Add(1)
				}
			}
		})
		wg.Go(func() { // DNS queries through dnsmux
			for work.Err() == nil {
				if dnsRound(dnsAddr) {
					ok.Add(1)
				} else if work.Err() == nil {
					failed.Add(1)
					failedBy[1].Add(1)
				}
			}
		})
		wg.Go(func() { // a QUIC flow through udpmux, new port each round
			for work.Err() == nil {
				if udpRound(udpAddr, hello) {
					ok.Add(1)
				} else if work.Err() == nil {
					failed.Add(1)
					failedBy[2].Add(1)
				}
			}
		})
	}
	wg.Wait()
	udp.expire(time.Now().Add(time.Minute))
	g1, h1 := settle()
	t.Logf("failed: tcp %d, dns %d, udp %d", failedBy[0].Load(), failedBy[1].Load(), failedBy[2].Load())
	t.Logf("%v: %d rounds, %d failed; goroutines %d -> %d, heap %d -> %d KiB", d, ok.Load(), failed.Load(), g0, g1, h0>>10, h1>>10)
	if total := ok.Load() + failed.Load(); total == 0 || failed.Load()*100 > total {
		t.Errorf("%d of %d rounds failed", failed.Load(), total)
	}
	if g1 > g0+20 {
		t.Errorf("goroutines left behind: %d -> %d", g0, g1)
	}
	if h1 > h0+64<<20 {
		t.Errorf("heap grew: %d -> %d KiB", h0>>10, h1>>10)
	}
	udp.access.Lock()
	left := len(udp.flows) + len(udp.pending)
	udp.access.Unlock()
	if left != 0 {
		t.Errorf("%d UDP flows left after expiry", left)
	}
}

func echoTLS(ln net.Listener, cert tls.Certificate) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			s.SetDeadline(time.Now().Add(10 * time.Second))
			io.Copy(s, s)
		}()
	}
}

// tlsRound: a handshake, 32 KiB each way, close.
func tlsRound(ctx context.Context, addr, name string) bool {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	// Closed with a reset: thousands of rounds a minute would otherwise
	// run the test host out of ports in TIME_WAIT.
	c.(*net.TCPConn).SetLinger(0)
	defer c.Close()
	s := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
	s.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 32<<10)
	for i := range payload {
		payload[i] = byte(rand.IntN(256))
	}
	go s.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(s, got); err != nil {
		return false
	}
	return bytes.Equal(got, payload)
}

// udpRound: an Initial for a routed name, then datagrams, each echoed.
func udpRound(addr *net.UDPAddr, hello [][]byte) bool {
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 2048)
	// The first flight at once, as a client sends it: the ClientHello with
	// X25519MLKEM768 takes two Initials, and the flow is pinned only once
	// both are in.
	for _, h := range hello {
		c.Write(h)
	}
	for range hello {
		if _, err := c.Read(b); err != nil {
			return false
		}
	}
	for range 20 {
		p := make([]byte, 1200)
		p[0] = 0x40 // short header
		c.Write(p)
		if n, err := c.Read(b); err != nil || n != len(p) {
			return false
		}
	}
	return true
}

// dnsRound: queries for names in the zone, each answered (echoed).
func dnsRound(addr *net.UDPAddr) bool {
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 2048)
	for range 20 {
		q := []byte{byte(rand.IntN(256)), byte(rand.IntN(256)), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		label := make([]byte, 16)
		for i := range label {
			label[i] = "abcdefghijklmnopqrstuvwxyz"[rand.IntN(26)]
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
		q = append(q, 1, 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 16, 0, 1)
		c.Write(q)
		n, err := c.Read(b)
		if err != nil || !bytes.Equal(b[:n], q) {
			return false
		}
	}
	return true
}
