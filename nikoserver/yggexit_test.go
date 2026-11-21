package nikoserver

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
)

// pktPipe is one side of two netstacks wired to each other: a packet
// written on one is read on the other.
type pktPipe struct {
	in  <-chan []byte
	out chan<- []byte
}

func (p pktPipe) Read(b []byte) (int, error) {
	pkt, ok := <-p.in
	if !ok {
		return 0, io.EOF
	}
	return copy(b, pkt), nil
}

func (p pktPipe) Write(b []byte) (int, error) {
	p.out <- append([]byte(nil), b...)
	return len(b), nil
}

// exitPair is a node's exits on one netstack, a client on another, and
// inner as serve says, on a unix socket.
func exitPair(t *testing.T, serve func(net.Conn)) (dial func() *gonet.TCPConn, open *yggExitCount) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	node, client := netip.MustParseAddr("200::1"), netip.MustParseAddr("201::2")
	ns, err := yggNetstack(ctx, pktPipe{in: a, out: b}, node, 65535)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ns.Close)
	cs, err := yggNetstack(ctx, pktPipe{in: b, out: a}, client, 65535)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	inner := filepath.Join(t.TempDir(), "inner.sock")
	ln, err := net.Listen("unix", inner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	open = newYggExitCount()
	who := yggExitSource{key: [32]byte{1}, user: "u1"}
	serveExits(ns, map[uint16]bool{443: true}, inner, func(src netip.Addr) (yggExitSource, bool) { return who, src == client },
		open, NewLogger("error", io.Discard))
	return func() *gonet.TCPConn {
		t.Helper()
		c, err := gonet.DialTCP(cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(node.As16()), Port: 443}, ipv6.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}, open
}

// A client's half-close leaves inner's way to it alone, however long that
// lasts (second review: the 5 s linger began with either way's end, and a
// download after the client's FIN ended short at 5 s, as a clean end).
func TestYggExitHalfClose(t *testing.T) {
	const chunks = 35 // 1 KiB every 200 ms: 7 s
	dial, open := exitPair(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // the request, to the client's FIN
		chunk := make([]byte, 1024)
		for range chunks {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	c := dial()
	if _, err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	n, err := io.Copy(io.Discard, c)
	if err != nil || n != chunks*1024 {
		t.Fatalf("%d of %d bytes in %v: %v", n, chunks*1024, time.Since(start), err)
	}
	if !waitFor(2*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return open.total == 0 }) {
		t.Fatal("the exit's place not freed")
	}
}

// Once inner has ended its way, a client that says nothing more loses the
// exit within yggExitLinger: it holds no place.
func TestYggExitLinger(t *testing.T) {
	dial, open := exitPair(t, func(c net.Conn) {
		_, _ = c.Write([]byte("bye"))
		c.Close()
	})
	c := dial()
	b := make([]byte, 3)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(b); err != io.EOF {
		t.Fatalf("after inner closed: %v", err)
	}
	start := time.Now()
	if !waitFor(yggExitLinger+2*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return open.total == 0 }) {
		t.Fatal("a silent client kept its exit")
	}
	if d := time.Since(start); d < yggExitLinger-time.Second {
		t.Fatalf("closed after %v, before the linger", d)
	}
}
