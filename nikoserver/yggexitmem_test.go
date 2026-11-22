package nikoserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

// syncBuf is a log a test reads while exits write it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// usersRig is an exitRig whose client has an address for each of users,
// 201::100+u, each address a user of its own; the node logs to log.
func usersRig(t *testing.T, users int, serve func(net.Conn)) (*exitRig, *syncBuf) {
	t.Helper()
	log := &syncBuf{}
	setVar(t, &exitRigLog, NewLogger("info", log))
	r := newExitRig(t, serve, func(src netip.Addr) (yggExitSource, bool) {
		b := src.As16()
		return yggExitSource{key: [32]byte{3, b[15]}, user: fmt.Sprint("u", b[15])}, b[0] == 2 && b[1] == 1 && b[15] >= 100
	})
	for u := range users {
		if err := r.cs.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom16(userAddr(u).As16()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	return r, log
}

func userAddr(u int) netip.Addr { return netip.AddrFrom16([16]byte{0: 2, 1: 1, 15: byte(100 + u)}) }

// dialAs dials the node's exit from user u's address.
func (r *exitRig) dialAs(t *testing.T, u int) *gonet.TCPConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := gonet.DialTCPWithBind(ctx, r.cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(userAddr(u).As16())},
		tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(r.node.As16()), Port: 443}, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// buffers is the sum of the node's established endpoints' send and
// receive buffers past their floors, and the most of one's send buffer.
func (r *exitRig) buffers() (past, maxSend int64) {
	for _, ep := range r.ns.RegisteredEndpoints() {
		e, ok := ep.(*tcp.Endpoint)
		if !ok || e.EndpointState() != tcp.StateEstablished {
			continue
		}
		snd, rcv := e.SocketOptions().GetSendBufferSize(), e.SocketOptions().GetReceiveBufferSize()
		past += snd - yggExitSendFloor + rcv - yggExitRecvFloor
		maxSend = max(maxSend, snd)
	}
	return past, maxSend
}

func (r *exitRig) grown() (all int64, most int64) {
	r.open.mu.Lock()
	defer r.open.mu.Unlock()
	for _, n := range r.open.grownBy {
		most = max(most, n)
	}
	return r.open.grown, most
}

// writeN writes n bytes to c.
func writeN(c net.Conn, n int) error {
	b := make([]byte, 64<<10)
	for ; n > 0; n -= len(b) {
		if _, err := c.Write(b[:min(n, len(b))]); err != nil {
			return err
		}
	}
	return nil
}

func heapInUse() int64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse)
}

// Exits whose clients stopped reading hold no more than the node's budget
// past their floors, nor a user more than its share; the node warns once
// (protocol review: each held up to 4 MiB, a user 2 GiB, the node 16 GiB).
func TestYggExitBuffersBounded(t *testing.T) {
	const users, each, budget = 10, 8, 32 << 20 // more users than shares
	r, log := usersRig(t, users, writeAll(64<<20))
	smallWindow(t, r)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	before := heapInUse()
	for u := range users {
		for range each {
			c := r.dialAs(t, u)
			if _, err := c.Write([]byte("GET")); err != nil {
				t.Fatal(err)
			}
			// A fast start, the window grown, then nothing read.
			if _, err := io.CopyN(io.Discard, c, 2<<20); err != nil {
				t.Fatal(err)
			}
		}
	}
	time.Sleep(time.Second) // what is sent waits
	after := heapInUse()
	all, most := r.grown()
	past, maxSend := r.buffers()
	n := users * each
	t.Logf("%d exits: grown %d KiB (most of a user %d KiB), buffers past the floors %d KiB, largest send buffer %d KiB, heap +%d KiB",
		n, all>>10, most>>10, past>>10, maxSend>>10, (after-before)>>10)
	if all > budget || most > budget/yggExitShares || past > budget {
		t.Fatalf("past the budget: grown %d, a user %d, buffers %d; budget %d", all, most, past, budget)
	}
	// What waits in the exits, theirs and the clients' 64 KiB unread
	// each, inner's 64 KiB buffers, the copy buffers and the endpoints.
	if bound := int64(budget + n*(yggExitSendFloor+yggExitRecvFloor+512<<10)); after-before > bound {
		t.Fatalf("heap +%d KiB, past %d KiB", (after-before)>>10, bound>>10)
	}
	// Once each: the users' shares, then the node's budget.
	if out := log.String(); strings.Count(out, "logged once") != 2 || strings.Count(out, "at its share") != 1 ||
		strings.Count(out, "at the node's budget") != 1 {
		t.Fatalf("logged:\n%s", out)
	}
}

// With the node idle one exit grows its buffers as gVisor's tuning would,
// to 4 MiB of send buffer; the receive buffer grows with an upload.
func TestYggExitBuffersGrow(t *testing.T) {
	setVar(t, &exitRigDelay, 5*time.Millisecond)
	var up sync.WaitGroup
	up.Add(1)
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		b := make([]byte, 1)
		if _, err := c.Read(b); err != nil {
			return
		}
		if b[0] == 'u' {
			_, _ = io.Copy(io.Discard, c)
			up.Done()
			return
		}
		_ = writeN(c, 32<<20)
	}, nil)
	c := r.dial(t)
	if _, err := c.Write([]byte("d")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64<<10)
	var got, maxSend int64
	for got < 32<<20 {
		n, err := c.Read(b)
		got += int64(n)
		if err != nil {
			t.Fatalf("after %d bytes: %v", got, err)
		}
		_, s := r.buffers()
		maxSend = max(maxSend, s)
	}
	if maxSend != yggExitBufMax {
		t.Fatalf("send buffer to %d, not %d", maxSend, yggExitBufMax)
	}
	u := r.dial(t)
	if _, err := u.Write([]byte("u")); err != nil {
		t.Fatal(err)
	}
	var maxRecv int64
	for range 256 { // 16 MiB
		if _, err := u.Write(b); err != nil {
			t.Fatal(err)
		}
		for _, ep := range r.ns.RegisteredEndpoints() {
			if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == tcp.StateEstablished {
				maxRecv = max(maxRecv, e.SocketOptions().GetReceiveBufferSize())
			}
		}
	}
	u.CloseWrite()
	up.Wait()
	if maxRecv < 1<<20 {
		t.Fatalf("receive buffer to %d", maxRecv)
	}
	t.Logf("send buffer to %d KiB, receive buffer to %d KiB", maxSend>>10, maxRecv>>10)
}

// An exit idle past yggExitIdle gives back what it grew when another needs
// it: the budget is not held by exits that once were fast.
func TestYggExitBuffersGiveBack(t *testing.T) {
	const budget = 16 << 20 // a user's share: 2 MiB
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		if _, err := c.Read(make([]byte, 3)); err != nil {
			return
		}
		_ = writeN(c, 16<<20)
		<-hold // open, silent
	}, nil)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	first := r.dial(t)
	if _, err := first.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, first, 16<<20); err != nil {
		t.Fatal(err)
	}
	if _, most := r.grown(); most < budget/yggExitShares-yggExitBufMax/4 {
		t.Fatalf("the first exit grew %d", most)
	}
	time.Sleep(yggExitIdle + 100*time.Millisecond) // the first idle
	second := r.dial(t)
	if _, err := second.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, second, 16<<20); err != nil {
		t.Fatal(err)
	}
	_, maxSend := r.buffers()
	all, _ := r.grown()
	if maxSend < budget/yggExitShares || all > budget/yggExitShares {
		t.Fatalf("the second exit's send buffer %d, grown %d in all", maxSend, all)
	}
}

// An exit whose writer has ended keeps what its buffer grew while it still
// has of it to send: after the write side's close the endpoint reads as
// writable whatever waits, so giveBack must not go by it.
func TestYggExitBuffersKeptWhileSent(t *testing.T) {
	const budget = 16 << 20 // a user's share: 2 MiB
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		b := make([]byte, 3)
		if _, err := c.Read(b); err != nil {
			return
		}
		if string(b) == "one" {
			_ = writeN(c, 2<<20+512<<10) // what fits, and the client stops
		} else {
			_ = writeN(c, 16<<20)
		}
		_ = c.(*net.UnixConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	}, nil)
	smallWindow(t, r)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	first := r.dial(t)
	if _, err := first.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, first, 2<<20); err != nil {
		t.Fatal(err)
	}
	// The first's writer ends, the rest waiting in its buffer; it idles.
	sent := func() (n int64) {
		for _, ep := range r.ns.RegisteredEndpoints() {
			if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == tcp.StateFinWait1 {
				n = e.SocketOptions().GetSendBufferSize()
			}
		}
		return n
	}
	if !waitFor(2*time.Second, func() bool { return sent() > 0 }) {
		t.Fatal("the first exit's write side not closed")
	}
	time.Sleep(yggExitIdle + 100*time.Millisecond)
	second := r.dial(t)
	if _, err := second.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, second, 16<<20); err != nil {
		t.Fatal(err)
	}
	if n := sent(); n < 256<<10 {
		t.Fatalf("the first exit's send buffer %d, with 448 KiB to send", n)
	}
}

// Exits the node closes first leave their endpoints in TIME-WAIT for
// yggTimeWait, at most yggExitsClosing of them (protocol review: 60 s each,
// outside every count; and a client picking a port again waited it out).
func TestYggExitTimeWait(t *testing.T) {
	setVar(t, &yggExitsClosing, 16)
	r := newExitRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte("bye"))
		c.Close()
	}, nil)
	waiting := func() int {
		n := 0
		for _, ep := range r.ns.RegisteredEndpoints() {
			if e, ok := ep.(*tcp.Endpoint); ok && (e.EndpointState() == tcp.StateTimeWait || e.EndpointState() == tcp.StateFinWait2) {
				n++
			}
		}
		return n
	}
	most := 0
	for range 200 {
		c := r.dial(t)
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Fatal(err)
		}
		c.Close()
		most = max(most, waiting())
	}
	if most > yggExitsClosing+2 { // and the last ones, on their way to the ring
		t.Fatalf("%d endpoints in TIME-WAIT or FIN-WAIT-2", most)
	}
	if !waitFor(3*time.Second, func() bool { return waiting() == 0 }) { // yggTimeWait, 1 s
		t.Fatalf("%d endpoints still waiting after 3 s", waiting())
	}
}

// The budget comes from the cgroup's memory.max, the least up the tree,
// else MemTotal.
func TestHostMemory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	meminfo := write("meminfo", "MemTotal:        2048000 kB\nMemFree:  1 kB\n")
	self := write("cgroup", "0::/system.slice/niko.service\n")
	root := filepath.Join(dir, "fs")
	if got := hostMemory(self, root, meminfo); got != 2048000<<10 {
		t.Fatalf("no cgroup files: %d", got)
	}
	write("fs/system.slice/niko.service/memory.max", "max\n")
	write("fs/system.slice/memory.max", "536870912\n")
	if got := hostMemory(self, root, meminfo); got != 512<<20 {
		t.Fatalf("a parent's memory.max: %d", got)
	}
	if got := hostMemory(filepath.Join(dir, "none"), root, filepath.Join(dir, "none")); got != 0 {
		t.Fatalf("nothing known: %d", got)
	}
	for mem, want := range map[int64]int64{0: 64 << 20, 1 << 30: 256 << 20, 64 << 30: 4 << 30} {
		if got := exitBudgetFor(mem); got != want {
			t.Fatalf("budget for %d: %d, want %d", mem, got, want)
		}
	}
}
