package nikoserver

import (
	"bytes"
	"context"
	"encoding/binary"
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

// waiting is how many of the node's endpoints wait in TIME-WAIT or
// FIN-WAIT-2, and their remote ports.
func (r *exitRig) waiting() (int, map[uint16]bool) {
	ports := map[uint16]bool{}
	for _, ep := range r.ns.RegisteredEndpoints() {
		if e, ok := ep.(*tcp.Endpoint); ok && (e.EndpointState() == tcp.StateTimeWait || e.EndpointState() == tcp.StateFinWait2) {
			ports[e.Info().(*stack.TransportEndpointInfo).ID.RemotePort] = true
		}
	}
	return len(ports), ports
}

// Exits the node closes first leave their endpoints in TIME-WAIT for
// yggTimeWait, at most yggExitsClosing of them (protocol review: 60 s each,
// outside every count; and a client picking a port again waited it out).
// An endpoint waits in the ring or with its exit still counted, on its way
// there: the bound is the ring's and the exits' (protocol review, B2: a
// margin of 2 failed 7 of 40 runs under load).
func TestYggExitTimeWait(t *testing.T) {
	setVar(t, &yggExitsClosing, 16)
	r := newExitRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte("bye"))
		c.Close()
	}, nil)
	for range 200 {
		c := r.dial(t)
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Fatal(err)
		}
		c.Close()
		counted := r.total() // first: it only falls, no exit coming now
		if n, _ := r.waiting(); n > yggExitsClosing+counted {
			t.Fatalf("%d endpoints in TIME-WAIT or FIN-WAIT-2, %d exits counted", n, counted)
		}
		r.open.mu.Lock()
		ring := len(r.open.ending)
		r.open.mu.Unlock()
		if ring > yggExitsClosing {
			t.Fatalf("%d in the ring", ring)
		}
	}
	if !waitFor(3*time.Second, func() bool { n, _ := r.waiting(); return n == 0 }) { // yggTimeWait, 1 s
		n, _ := r.waiting()
		t.Fatalf("%d endpoints still waiting after 3 s", n)
	}
}

// Exits whose clients keep their way open once the node has closed both
// wait in FIN-WAIT-2 for yggFinWait2, in the ring: past its bound the
// oldest is reset, not the newest.
func TestYggExitFinWait2(t *testing.T) {
	setVar(t, &yggExitsClosing, 4)
	setVar(t, &yggExitLinger, 100*time.Millisecond)
	setVar(t, &yggFinWait2, 4*time.Second)
	r := newExitRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte("bye"))
		c.Close()
	}, nil)
	var ports []uint16
	for range 10 {
		c := r.dial(t)
		if b, err := io.ReadAll(c); err != nil || string(b) != "bye" {
			t.Fatalf("read %q: %v", b, err)
		}
		ports = append(ports, uint16(c.LocalAddr().(*net.TCPAddr).Port)) // and no FIN
		if !waitFor(2*time.Second, func() bool { return r.total() == 0 }) {
			t.Fatal("the exit stayed")
		}
	}
	start := time.Now()
	n, waits := r.waiting()
	if n != yggExitsClosing {
		t.Fatalf("%d endpoints in FIN-WAIT-2, want %d", n, yggExitsClosing)
	}
	for _, p := range ports[len(ports)-yggExitsClosing:] {
		if !waits[p] {
			t.Fatalf("the newest %v not all waiting: %v", ports[len(ports)-yggExitsClosing:], waits)
		}
	}
	if !waitFor(yggFinWait2+2*time.Second, func() bool { n, _ := r.waiting(); return n == 0 }) {
		t.Fatal("FIN-WAIT-2 past yggFinWait2")
	}
	if d := time.Since(start); d < yggFinWait2/4 {
		t.Fatalf("closed after %v", d)
	}
}

// The budget comes from the cgroup's limit, the least up the tree, v2's
// memory.max or v1's memory.limit_in_bytes, else MemTotal.
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
	// cgroup v1: the memory hierarchy's limit, "unlimited" above MemTotal;
	// a container's own cgroup mounted as the root.
	v1 := write("cgroup1", "4:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n0::/\n")
	write("fs/memory/memory.limit_in_bytes", "9223372036854771712\n")
	if got := hostMemory(v1, root, meminfo); got != 2048000<<10 {
		t.Fatalf("v1, unlimited: %d", got)
	}
	write("fs/memory/memory.limit_in_bytes", "1073741824\n")
	if got := hostMemory(v1, root, meminfo); got != 1<<30 {
		t.Fatalf("v1, the container's root: %d", got)
	}
	write("fs/memory/docker/abc/memory.limit_in_bytes", "268435456\n")
	if got := hostMemory(v1, root, meminfo); got != 256<<20 {
		t.Fatalf("v1, its own cgroup: %d", got)
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

// holer drops, for each client port armed, its first data segment to the
// node from then on, and every retransmission of it until the hole's
// deadline: a hole the node waits on, segments past it held.
type holer struct {
	mu    sync.Mutex
	armed map[uint16]time.Time
	hole  map[uint16]uint32
}

func newHoler() *holer { return &holer{armed: map[uint16]time.Time{}, hole: map[uint16]uint32{}} }

func (h *holer) arm(c net.Conn, until time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.armed[uint16(c.LocalAddr().(*net.TCPAddr).Port)] = until
}

// patient lets r's client retransmit a hole's segment past gVisor's 15
// times: SACKs at the rig's RTT had it lose the hole and the connection
// in 0.25 s, in one run of four.
func (r *exitRig) patient(t *testing.T) {
	retries := tcpip.TCPMaxRetriesOption(1 << 20)
	if err := r.cs.SetTransportProtocolOption(tcp.ProtocolNumber, &retries); err != nil {
		t.Fatal(err)
	}
}

func (h *holer) wrap(out chan<- []byte) chan<- []byte {
	in := make(chan []byte, 1<<14)
	go func() {
		for pkt := range in {
			// IPv6, TCP, to the node 200::1, with data.
			if len(pkt) >= 60 && pkt[6] == 6 && pkt[24] == 2 && pkt[39] == 1 && len(pkt) > 40+int(pkt[52]>>4)*4 {
				port, seq := binary.BigEndian.Uint16(pkt[40:]), binary.BigEndian.Uint32(pkt[44:])
				h.mu.Lock()
				until, armed := h.armed[port]
				s, holed := h.hole[port]
				if armed && !holed {
					h.hole[port], s, holed = seq, seq, true
				}
				drop := holed && seq == s && time.Now().Before(until)
				h.mu.Unlock()
				if drop {
					continue
				}
			}
			out <- pkt
		}
	}()
	return in
}

// The node's receive buffers past their floors, and the most any holds
// past its buffer (gVisor's own count, as giveBack reads it).
func (r *exitRig) heldPast() (most int64) {
	for _, ep := range r.ns.RegisteredEndpoints() {
		if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == tcp.StateEstablished {
			held, _ := rcvMemUsed(e)
			most = max(most, int64(held)-e.SocketOptions().GetReceiveBufferSize())
		}
	}
	return most
}

// An exit whose upload has a hole keeps its receive buffer while it holds
// segments past the hole (protocol review, B1: given back by its in-order
// queue alone, 8 such exits held 9.7 MiB against 2 MiB charged).
func TestYggExitBuffersHeldPastHole(t *testing.T) {
	const budget, n = 16 << 20, 6 // a user's share: 2 MiB
	setVar(t, &exitRigMTU, 1280)
	h := newHoler()
	setVar(t, &exitRigMangle, h.wrap)
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}, nil)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	r.patient(t)
	b := make([]byte, 64<<10)
	for range n {
		c := r.dial(t)
		for range 64 { // 4 MiB fast: the receive buffer grows
			if _, err := c.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		h.arm(c, time.Now().Add(time.Hour))
		go func() {
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			for {
				if _, err := c.Write(b); err != nil {
					return
				}
			}
		}()
		time.Sleep(yggExitIdle + 300*time.Millisecond) // idle: the next exit's sweep finds it
	}
	all, _ := r.grown()
	if most := r.heldPast(); most > 64<<10 {
		t.Fatalf("an exit holds %d KiB past its receive buffer; %d KiB charged in all", most>>10, all>>10)
	}
}

// A hole filled after the exit has idled is let in: a receive buffer given
// back below what is held past a hole would drop the hole's segment for
// ever.
func TestYggExitBuffersHoleFills(t *testing.T) {
	const budget = 16 << 20 // a user's share: 2 MiB
	setVar(t, &exitRigMTU, 1280)
	h := newHoler()
	setVar(t, &exitRigMangle, h.wrap)
	got := make(chan int64, 2)
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		got <- n
	}, nil)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	r.patient(t)
	b := make([]byte, 64<<10)
	first := r.dial(t)
	for range 64 {
		if _, err := first.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	h.arm(first, time.Now().Add(2*yggExitIdle+time.Second))
	for range 8 { // 512 KiB past the hole
		if _, err := first.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(yggExitIdle + 300*time.Millisecond)
	second := r.dial(t) // its growth short: a sweep
	for range 64 {
		if _, err := second.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case n := <-got:
		if n != 72*64<<10 {
			t.Fatalf("inner got %d of %d", n, 72*64<<10)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("the holed upload never ended; it holds %d KiB past its buffer", r.heldPast()>>10)
	}
}

// What exits grew comes back whole once they have ended, however they
// end: closed, dropped with their key, reset by the client, given back,
// reset out of the ring.
func TestYggExitBuffersAllBack(t *testing.T) {
	const budget = 16 << 20 // a user's share: 2 MiB
	setVar(t, &yggExitsClosing, 2)
	hold := make(chan struct{})
	r, _ := usersRig(t, 2, func(c net.Conn) {
		defer c.Close()
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		switch string(b) {
		case "bye.": // the node closes first: TIME-WAIT, the ring
			_, _ = c.Write([]byte("bye"))
			return
		case "idle":
			_ = writeN(c, 8<<20)
			<-hold
		default: // and upload, to the client's end
			_ = writeN(c, 8<<20)
			_, _ = io.Copy(io.Discard, c)
		}
	})
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	open := func(u int, req string) *gonet.TCPConn {
		c := r.dialAs(t, u)
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	idle := open(0, "idle") // grows, then idles: given back
	if _, err := io.CopyN(io.Discard, idle, 8<<20); err != nil {
		t.Fatal(err)
	}
	time.Sleep(yggExitIdle + 200*time.Millisecond)
	normal := open(0, "norm")
	if _, err := io.CopyN(io.Discard, normal, 8<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Write(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	normal.Close()
	reset := open(0, "rset")
	if _, err := io.CopyN(io.Discard, reset, 1<<20); err != nil {
		t.Fatal(err)
	}
	reset.Close() // what is unread resets
	dropped := open(1, "drop")
	if _, err := io.CopyN(io.Discard, dropped, 2<<20); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		c := open(0, "bye.")
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	r.open.drop(func(key [32]byte) bool { return key != [32]byte{3, 101} })
	close(hold)
	idle.Close()
	if !waitFor(5*time.Second, func() bool {
		all, _ := r.grown()
		return r.total() == 0 && all == 0
	}) {
		all, _ := r.grown()
		t.Fatalf("%d exits, %d bytes grown, after all ended", r.total(), all)
	}
	r.open.mu.Lock()
	defer r.open.mu.Unlock()
	if len(r.open.grownBy) != 0 {
		t.Fatalf("grown by user: %v", r.open.grownBy)
	}
}

// rcvMemUsed reads gVisor's count on the version go.mod pins: what an
// upload inner does not read holds, up to the buffer and a segment.
func TestYggRcvMemUsed(t *testing.T) {
	if rcvMemOffset == 0 {
		t.Fatal("gVisor's Endpoint has no rcvMemUsed: receive buffers are never given back")
	}
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	r := newExitRig(t, func(c net.Conn) { <-hold; c.Close() }, nil)
	c := r.dial(t)
	go func() { _, _ = c.Write(make([]byte, 8<<20)) }()
	var held, size int64
	waitFor(2*time.Second, func() bool {
		for _, ep := range r.ns.RegisteredEndpoints() {
			if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == tcp.StateEstablished {
				h, _ := rcvMemUsed(e)
				held, size = int64(h), e.SocketOptions().GetReceiveBufferSize()
			}
		}
		return held >= size/2
	})
	if held < size/2 || held > size+65536+4096 {
		t.Fatalf("held %d with a receive buffer of %d", held, size)
	}
}

// endpointOf is the node's endpoint of the client's c.
func (r *exitRig) endpointOf(c net.Conn) *tcp.Endpoint {
	port := uint16(c.LocalAddr().(*net.TCPAddr).Port)
	for _, ep := range r.ns.RegisteredEndpoints() {
		if e, ok := ep.(*tcp.Endpoint); ok && e.Info().(*stack.TransportEndpointInfo).ID.RemotePort == port {
			return e
		}
	}
	return nil
}

// A user short of its share sweeps its own exits, at most each 100 ms; a
// user short of the node's budget sweeps all, on a throttle of its own
// (protocol review: one throttle for both let a user at its share take
// the node's sweeps from another).
func TestYggExitSweepsApart(t *testing.T) {
	c := newYggExitCount()
	c.budget = 8 << 20 // a share: 1 MiB
	a := &yggExit{who: yggExitSource{user: "a"}, open: c}
	b := &yggExit{who: yggExitSource{user: "b"}, open: c}
	if got := c.grow(a, 1<<20); got != 1<<20 {
		t.Fatalf("a grew %d", got)
	}
	c.grow(a, 1) // short of a's share: a's sweep
	c.mu.Lock()
	c.grown = c.budget // the others' exits hold the rest
	c.mu.Unlock()
	mark := time.Now()
	c.grow(b, 1) // short of the node's: a node sweep, a's just before
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.reclaimed.After(mark) || !c.reclaimedBy["a"].Before(mark) {
		t.Fatalf("node sweep at %v, a's at %v, b asked at %v", c.reclaimed, c.reclaimedBy["a"], mark)
	}
}

// A user short of the node's budget, held by other users' idle exits,
// has them give back: the sweep is the node's, not the user's own.
func TestYggExitBuffersNodeSweep(t *testing.T) {
	const users, budget = 9, 16 << 20 // a share: 2 MiB; 8 users fill it
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	r, _ := usersRig(t, users, func(c net.Conn) {
		defer c.Close()
		if _, err := c.Read(make([]byte, 3)); err != nil {
			return
		}
		_ = writeN(c, 16<<20)
		<-hold
	})
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	for u := range users - 1 {
		c := r.dialAs(t, u)
		if _, err := c.Write([]byte("GET")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, c, 16<<20); err != nil {
			t.Fatal(err)
		}
	}
	if all, _ := r.grown(); all < budget*7/8 {
		t.Fatalf("the 8 grew %d of %d", all, budget)
	}
	time.Sleep(yggExitIdle + 200*time.Millisecond) // all idle
	last := r.dialAs(t, users-1)
	if _, err := last.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, last, 16<<20); err != nil {
		t.Fatal(err)
	}
	if e := r.endpointOf(last); e == nil || e.SocketOptions().GetSendBufferSize() < 1<<20 {
		t.Fatalf("the last user's send buffer %d", e.SocketOptions().GetSendBufferSize())
	}
}

// An upload and a download that go on, in bursts, keep what they grew
// through another exit's sweeps: idle is a second without a read for the
// receive buffer, without a write for the send one.
func TestYggExitBuffersActiveKept(t *testing.T) {
	const budget = 32 << 20 // a user's share: 4 MiB
	stop := make(chan struct{})
	r := newExitRig(t, func(c net.Conn) {
		defer c.Close()
		b := make([]byte, 1)
		if _, err := c.Read(b); err != nil {
			return
		}
		switch b[0] {
		case 'd': // in bursts, until stop
			for {
				select {
				case <-stop:
					return
				case <-time.After(100 * time.Millisecond):
				}
				if writeN(c, 256<<10) != nil {
					return
				}
			}
		case 'x':
			_ = writeN(c, 32<<20)
		}
		_, _ = io.Copy(io.Discard, c)
	}, nil)
	r.open.mu.Lock()
	r.open.budget = budget
	r.open.mu.Unlock()
	t.Cleanup(func() { close(stop) })
	down, up := r.dial(t), r.dial(t)
	go func() { _, _ = io.Copy(io.Discard, down) }()
	if _, err := down.Write([]byte("d")); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Write([]byte("u")); err != nil {
		t.Fatal(err)
	}
	go func() { // in bursts, until stop
		b := make([]byte, 256<<10)
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := up.Write(b); err != nil {
				return
			}
		}
	}()
	time.Sleep(time.Second) // both grown
	d, u := r.endpointOf(down), r.endpointOf(up)
	snd, rcv := d.SocketOptions().GetSendBufferSize(), u.SocketOptions().GetReceiveBufferSize()
	if snd <= yggExitSendFloor || rcv <= yggExitRecvFloor {
		t.Fatalf("grown to %d to send, %d to receive", snd, rcv)
	}
	other := r.dial(t)
	if _, err := other.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, other, 32<<20); done <- err }()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if s, v := d.SocketOptions().GetSendBufferSize(), u.SocketOptions().GetReceiveBufferSize(); s < snd || v < rcv {
			t.Fatalf("given back while active: send %d of %d, receive %d of %d", s, snd, v, rcv)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	all, _ := r.grown()
	if all < budget/yggExitShares-yggExitBufMax/4 {
		t.Fatalf("no sweep pressure: grown %d", all)
	}
}

// Ended endpoints the ring holds go once closed: when as many have come
// as the ring's least compaction, those gone are dropped, not kept to its
// bound.
func TestYggExitRingCompacts(t *testing.T) {
	r := newExitRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte("bye"))
		c.Close()
	}, nil)
	short := func() {
		c := r.dial(t)
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Fatal(err)
		}
		c.Close()
		if !waitFor(2*time.Second, func() bool { return r.total() == 0 }) {
			t.Fatal("the exit stayed")
		}
	}
	for range 64 { // the ring at its least compaction, 64: the next compacts
		short()
	}
	time.Sleep(yggTimeWait + 500*time.Millisecond) // all closed
	short()
	r.open.mu.Lock()
	defer r.open.mu.Unlock()
	if n := len(r.open.ending); n != 1 {
		t.Fatalf("%d in the ring, 1 waiting", n)
	}
}
