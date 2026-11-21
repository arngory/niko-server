package nikoserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	gvh "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
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

// exitRig is a node's exits on one netstack (ns), a client on another
// (cs), and inner as serve says, on a unix socket; into carries packets to
// the node, from any source.
type exitRig struct {
	ns, cs       *stack.Stack
	into         chan<- []byte
	node, client netip.Addr
	open         *yggExitCount
}

func newExitRig(t *testing.T, serve func(net.Conn), allowed func(src netip.Addr) (yggExitSource, bool)) *exitRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	r := &exitRig{into: a, node: netip.MustParseAddr("200::1"), client: netip.MustParseAddr("201::2"), open: newYggExitCount()}
	var err error
	if r.ns, err = yggNetstack(ctx, pktPipe{in: a, out: b}, r.node, 65535); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.ns.Close)
	if r.cs, err = yggNetstack(ctx, pktPipe{in: b, out: a}, r.client, 65535); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.cs.Close)
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
	if allowed == nil {
		who := yggExitSource{key: [32]byte{1}, user: "u1"}
		allowed = func(src netip.Addr) (yggExitSource, bool) { return who, src == r.client }
	}
	t.Cleanup(func() { r.open.drop(func([32]byte) bool { return false }) })
	serveExits(r.ns, map[uint16]bool{443: true}, inner, allowed, r.open, NewLogger("error", io.Discard))
	return r
}

func (r *exitRig) dial(t *testing.T) *gonet.TCPConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, r.cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(r.node.As16()), Port: 443}, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// total is the exits counted.
func (r *exitRig) total() int {
	r.open.mu.Lock()
	defer r.open.mu.Unlock()
	return r.open.total
}

// sending is how many of the node's endpoints may still have data of an
// exit to send: none closed, nor in FIN-WAIT-2 or TIME-WAIT.
func (r *exitRig) sending() int {
	n := 0
	for _, ep := range r.ns.RegisteredEndpoints() {
		e, ok := ep.(*tcp.Endpoint)
		if !ok {
			continue
		}
		switch e.EndpointState() {
		case tcp.StateClose, tcp.StateError, tcp.StateFinWait2, tcp.StateTimeWait, tcp.StateListen:
		default:
			n++
		}
	}
	return n
}

// exitPair is an exitRig's dial and count, the client its one user's.
func exitPair(t *testing.T, serve func(net.Conn)) (dial func() *gonet.TCPConn, open *yggExitCount) {
	t.Helper()
	r := newExitRig(t, serve, nil)
	return func() *gonet.TCPConn { t.Helper(); return r.dial(t) }, r.open
}

// setVar sets *v to x for the test.
func setVar[T any](t *testing.T, v *T, x T) {
	was := *v
	*v = x
	t.Cleanup(func() { *v = was })
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

// An exit dropped (its key gone from the users file) ends at once, though
// inner says nothing and closes nothing (third review: a closed gonet conn
// reads as the client's FIN, and inner's way waited on inner).
func TestYggExitDropSilentInner(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	dial, open := exitPair(t, func(c net.Conn) {
		defer c.Close()
		<-hold // reads nothing, writes nothing
	})
	c := dial()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return open.total == 1 }) {
		t.Fatal("no exit")
	}
	if !waitFor(2*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return len(open.conns) == 1 }) {
		t.Fatal("the exit not held")
	}
	start := time.Now()
	open.drop(func([32]byte) bool { return false })
	if !waitFor(2*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return open.total == 0 }) {
		t.Fatal("a dropped exit stayed, inner silent")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("dropped after %v", d)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("a dropped exit reads as %v, not a reset", err)
	}
}

// After the client's FIN, inner's way ends once inner is silent
// yggExitHalfIdle: the node bounds it, whatever inner's timers.
// The client learns the cut from a reset, where a FIN would read as the
// reply's end (fourth review).
func TestYggExitHalfCloseIdle(t *testing.T) {
	setVar(t, &yggExitHalfIdle, 500*time.Millisecond)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	dial, open := exitPair(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
		_, _ = c.Write([]byte("part"))
		<-hold // silent after a part of the reply, open
	})
	c := dial()
	if _, err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	b, err := io.ReadAll(c)
	if string(b) != "part" || err == nil {
		t.Fatalf("read %q, %v: not the part and a reset", b, err)
	}
	if d := time.Since(start); d < yggExitHalfIdle {
		t.Fatalf("cut after %v, before the idle", d)
	}
	if !waitFor(5*time.Second, func() bool { open.mu.Lock(); defer open.mu.Unlock(); return open.total == 0 }) {
		t.Fatal("a half-closed exit stayed with inner silent")
	}
}

// writeAll is an inner that reads the request, writes n bytes and closes.
func writeAll(n int) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		b := make([]byte, 64<<10)
		if _, err := c.Read(b); err != nil {
			return
		}
		for ; n > 0; n -= len(b) {
			if _, err := c.Write(b[:min(n, len(b))]); err != nil {
				return
			}
		}
	}
}

// smallWindow gives the rig's client a receive buffer of 64 KiB.
func smallWindow(t *testing.T, r *exitRig) {
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 64 << 10, Max: 64 << 10}
	if err := r.cs.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		t.Fatal(err)
	}
}

// A client that takes nothing of what waits for it loses its exit once
// yggExitStall passes, its place and the node's endpoint with it (fourth
// review: such an exit stayed, inner's end unseen, with its send buffer).
func TestYggExitStalledClient(t *testing.T) {
	setVar(t, &yggExitStall, time.Second)
	r := newExitRig(t, writeAll(8<<20), nil)
	c := r.dial(t)
	if _, err := c.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*time.Second, func() bool { return r.total() == 1 }) {
		t.Fatal("no exit")
	}
	start := time.Now() // the client reads nothing
	if !waitFor(yggExitStall+3*time.Second, func() bool { return r.total() == 0 && r.sending() == 0 }) {
		t.Fatalf("a stalled exit stayed: %d counted, %d endpoints sending", r.total(), r.sending())
	}
	if d := time.Since(start); d < yggExitStall/2 {
		t.Fatalf("ended after %v, before the stall", d)
	}
}

// An exit that has ended keeps its place while the node's endpoint has of
// it still to send (fourth review: the place freed at the linger, and the
// endpoint stayed in FIN-WAIT-1 with what the client had not taken; one
// user held 800 of them).
func TestYggExitDrains(t *testing.T) {
	setVar(t, &yggExitDrain, 2*time.Second)
	r := newExitRig(t, writeAll(512<<10), nil)
	smallWindow(t, r)
	c := r.dial(t)
	if _, err := c.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	// Inner has written it all and closed; past the linger the node has
	// closed its side, the client still reads nothing.
	time.Sleep(yggExitLinger + time.Second)
	if n, s := r.total(), r.sending(); n != 1 || s != 1 {
		t.Fatalf("past the linger: %d counted, %d endpoints sending; want 1 and 1", n, s)
	}
	if !waitFor(yggExitDrain+2*time.Second, func() bool { return r.total() == 0 && r.sending() == 0 }) {
		t.Fatalf("a drained exit stayed: %d counted, %d endpoints sending", r.total(), r.sending())
	}
}

// A slow client keeps its exit: each write has yggExitStall of its own.
func TestYggExitSlowClient(t *testing.T) {
	setVar(t, &yggExitStall, 3*time.Second)
	const size, pauses = 16 << 20, 4 // past the buffers (to 4 MiB): writes wait in the pauses
	r := newExitRig(t, writeAll(size), nil)
	smallWindow(t, r)
	c := r.dial(t)
	if _, err := c.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32<<10)
	got, paused := 0, 0
	for {
		n, err := c.Read(b)
		got += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("after %d of %d bytes: %v", got, size, err)
		}
		if paused < pauses && got >= (paused+1)*size/(pauses+1) {
			paused++
			// Under the stall, with room for the wait for half the buffer
			// (three runs at once failed with 700 ms against 1 s).
			time.Sleep(time.Second)
		}
	}
	if got != size || paused != pauses {
		t.Fatalf("%d of %d bytes, %d pauses", got, size, paused)
	}
}

// rawSYN is a SYN from src to the node's exit port.
func rawSYN(src, dst netip.Addr, port uint16) []byte {
	b := make([]byte, gvh.IPv6MinimumSize+gvh.TCPMinimumSize)
	ip := gvh.IPv6(b)
	ip.Encode(&gvh.IPv6Fields{
		PayloadLength: gvh.TCPMinimumSize, TransportProtocol: gvh.TCPProtocolNumber, HopLimit: 64,
		SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16()),
	})
	h := gvh.TCP(b[gvh.IPv6MinimumSize:])
	h.Encode(&gvh.TCPFields{SrcPort: port, DstPort: 443, SeqNum: 1, DataOffset: gvh.TCPMinimumSize, Flags: gvh.TCPFlagSyn, WindowSize: 65535})
	h.SetChecksum(^h.CalculateChecksum(gvh.PseudoHeaderChecksum(gvh.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), gvh.TCPMinimumSize)))
	return b
}

// Users whose handshakes all hang hold no other's exit: each has 64 in
// flight, past them RST, and the forwarder has room for every one (third
// review: 16 users' handshakes held a new user's dial 5 s).
func TestYggExitHandshakesHeld(t *testing.T) {
	const users = 16
	var r *exitRig
	r = newExitRig(t, func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }, func(src netip.Addr) (yggExitSource, bool) {
		if src == r.client {
			return yggExitSource{key: [32]byte{1}, user: "new"}, true
		}
		b := src.As16()
		return yggExitSource{key: [32]byte{2, b[15]}, user: fmt.Sprint("u", b[15])}, b[0] == 2 && b[1] == 2
	})
	// From 202::u, whose SYN-ACKs reach no stack: the handshakes hang.
	for u := range users {
		src := netip.AddrFrom16([16]byte{0: 2, 1: 2, 15: byte(u)})
		for port := range yggExitsShaking + 8 {
			r.into <- rawSYN(src, r.node, uint16(10000+port))
		}
	}
	shaking := func() int {
		r.open.mu.Lock()
		defer r.open.mu.Unlock()
		n := 0
		for _, k := range r.open.shaking {
			n += k
		}
		return n
	}
	if !waitFor(5*time.Second, func() bool { return shaking() == users*yggExitsShaking }) {
		t.Fatalf("%d handshakes in flight, want %d", shaking(), users*yggExitsShaking)
	}
	start := time.Now()
	c := r.dial(t)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("echo %q: %v", b, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a new user's exit after %v", d)
	}
}
