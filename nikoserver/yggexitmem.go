package nikoserver

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/atomicbitops"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// The exits' buffers. Left to itself gVisor grows an endpoint's send
// buffer with its congestion window, which it grows whether or not the
// client reads, and its receive buffer with what the reader takes, each
// to 4 MiB: 8 MiB an exit, 4 GiB a user, 32 GiB the node (protocol
// review). Here an exit's buffers start at their floors and grow as
// gVisor's own tuning would grow them (growSend, received), each byte
// past a floor taken from the node's budget (yggExitBudget) within its
// user's share of it, yggExitShares-th. When either is short the exits
// idle yggExitIdle give back what they grew (giveBack). So gVisor counts
// the exits' buffers at most at the budget plus their floors, yggExitsMax
// of them at most (the heap under received segments up to twice that,
// their pool chunks), and a node with few exits open has its windows.
const (
	// The send floor is above where gVisor's tuning starts at the mesh's
	// MTU (10 segments of 1220 bytes, twice); the receive floor is the
	// most a SYN-ACK offers, unscaled.
	yggExitSendFloor = 32 << 10
	yggExitRecvFloor = 64 << 10
	yggExitRecvStart = tcp.DefaultReceiveBufferSize // 1 MiB (received)
	yggExitBufMax    = tcp.MaxBufferSize            // 4 MiB, gVisor's own bound
	yggExitShares    = 8                            // as 8 users fill the exits
	yggExitIdle      = time.Second
)

// yggExitBudget is the default budget: a quarter of the memory the
// process may have (its cgroup's limit, else the host's MemTotal), within
// 64 MiB and 4 GiB.
var yggExitBudget = sync.OnceValue(func() int64 {
	return exitBudgetFor(hostMemory("/proc/self/cgroup", "/sys/fs/cgroup", "/proc/meminfo"))
})

func exitBudgetFor(mem int64) int64 { return min(max(mem/4, 64<<20), 4<<30) }

// hostMemory is the least of MemTotal and the limits of the cgroup the
// process is in and of its parents: memory.max in v2 (root), and
// memory.limit_in_bytes in v1's memory hierarchy (root/memory), whose
// "unlimited" is above any MemTotal. 0 when none is known. A container's
// own cgroup mounted as the hierarchy's root is read there, its path
// from /proc/self/cgroup not found under the mount.
func hostMemory(self, root, meminfo string) int64 {
	var mem int64
	least := func(n int64) {
		if n > 0 && (mem == 0 || n < mem) {
			mem = n
		}
	}
	limits := func(dir, mount, file string) {
		for dir = path.Clean("/" + dir); ; dir = path.Dir(dir) {
			if b, err := os.ReadFile(path.Join(mount, dir, file)); err == nil {
				n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64) // "max": 0
				least(n)
			}
			if dir == "/" {
				return
			}
		}
	}
	if b, err := os.ReadFile(self); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.SplitN(line, ":", 3)
			switch {
			case len(f) < 3:
			case f[0] == "0" && f[1] == "":
				limits(f[2], root, "memory.max")
			case slices.Contains(strings.Split(f[1], ","), "memory"):
				limits(f[2], path.Join(root, "memory"), "memory.limit_in_bytes")
			}
		}
	}
	if f, err := os.Open(meminfo); err == nil {
		defer f.Close()
		for s := bufio.NewScanner(f); s.Scan(); {
			if v, ok := strings.CutPrefix(s.Text(), "MemTotal:"); ok {
				kb, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
				least(kb << 10)
			}
		}
	}
	return mem
}

// grow gives e up to want more bytes of buffer, as much as the budget and
// its user's share leave.
func (c *yggExitCount) grow(e *yggExit, want int64) int64 {
	c.mu.Lock()
	node := c.budget - c.grown
	user := c.budget/yggExitShares - c.grownBy[e.who.user]
	got := max(min(want, node, user), 0)
	c.grown += got
	if got > 0 {
		c.grownBy[e.who.user] += got
	}
	var warn string
	if got < want && node < want && !c.warnedNode {
		c.warnedNode = true
		warn = fmt.Sprintf("exits' buffers at the node's budget, %d MiB: exits grow no further until others give back (logged once)", c.budget>>20)
	} else if got < want && node >= want && !c.warnedUser {
		c.warnedUser = true
		warn = fmt.Sprintf("a user's exits' buffers at its share of the budget, %d MiB: its exits grow no further until others give back (logged once)", c.budget/yggExitShares>>20)
	}
	var idle []*yggExit
	now := time.Now()
	if got < want && now.Sub(c.reclaimed) >= 100*time.Millisecond {
		// Short of the user's share only, only its exits' help.
		mine := node >= want
		c.reclaimed = now
		for _, conns := range c.conns {
			for conn := range conns {
				if x, ok := conn.(*yggExit); ok && x != e && (!mine || x.who.user == e.who.user) {
					idle = append(idle, x)
				}
			}
		}
	}
	log := c.log
	c.mu.Unlock()
	if warn != "" && log != nil {
		log.Warnf("%s", warn)
	}
	for _, x := range idle {
		x.giveBack(now)
	}
	return got
}

// release gives n bytes of user's back to the budget.
func (c *yggExitCount) release(user string, n int64) {
	if n == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grown -= n
	if c.grownBy[user] -= n; c.grownBy[user] <= 0 {
		delete(c.grownBy, user)
	}
}

// yggExitsClosing bounds the endpoints of exits ended that wait in
// FIN-WAIT-2 or TIME-WAIT, outside every count: past it the oldest is
// reset (closing). TIME-WAIT itself lasts yggTimeWait.
var yggExitsClosing = yggExitsMax // a var for the tests, read by serveExits

// closing keeps ep, an exit's endpoint drained, while it waits to close.
func (c *yggExitCount) closing(ep tcpip.Endpoint) {
	waits := func(ep tcpip.Endpoint) bool {
		s := tcp.EndpointState(ep.State())
		return s == tcp.StateFinWait2 || s == tcp.StateTimeWait
	}
	if !waits(ep) {
		return
	}
	c.mu.Lock()
	// Those closed go when as many again have come as were left the last
	// time, or at the bound: they hold no more than the waiting.
	if len(c.ending) >= min(max(64, 2*c.endingLeft), c.closingMax) {
		keep := c.ending[:0]
		for _, x := range c.ending {
			if waits(x) {
				keep = append(keep, x)
			}
		}
		clear(c.ending[len(keep):])
		c.ending, c.endingLeft = keep, len(keep)
	}
	var oldest tcpip.Endpoint
	if len(c.ending) >= c.closingMax {
		oldest = c.ending[0]
		copy(c.ending, c.ending[1:])
		c.ending[len(c.ending)-1] = nil
		c.ending = c.ending[:len(c.ending)-1]
	}
	c.ending = append(c.ending, ep)
	c.mu.Unlock()
	if oldest != nil {
		oldest.Abort()
	}
}

// buffers sets e's buffers to their floors, gVisor's tuning off.
func (e *yggExit) buffers(mtu uint32) {
	e.mss = int64(mtu) - 60 // IPv6 and TCP headers
	ops := e.ep.SocketOptions()
	ops.SetSendBufferSize(yggExitSendFloor, true)
	ops.SetReceiveBufferSize(yggExitRecvFloor, true)
	e.snd, e.rcv = yggExitSendFloor, yggExitRecvFloor
	e.prevCopied = e.firstCopied()
	now := time.Now()
	e.measured, e.rtt = now, e.srtt()
	e.lastRead.Store(now.UnixNano())
	e.lastWrite.Store(now.UnixNano())
}

// firstCopied is what received grows past from the floor: gVisor starts
// from the window its SYN-ACK offered, under its buffer of 1 MiB, but the
// floor's memory holds less than that in segments (under -race no upload
// grew it), so a quarter of it, or an initial window.
func (e *yggExit) firstCopied() int64 { return min(tcp.InitialCwnd*e.mss, yggExitRecvFloor/4) }

// rcvMemOffset is where gVisor's Endpoint keeps rcvMemUsed, the memory of
// every received segment it holds, queued, in order or out of it, which
// its enqueue admits against the receive buffer. gVisor exports no
// out-of-order size, so rcvMemUsed reads it in place, for the version
// go.mod pins (TestYggRcvMemUsed); 0, the field gone: never read.
var rcvMemOffset = func() uintptr {
	f, ok := reflect.TypeFor[tcp.Endpoint]().FieldByName("rcvMemUsed")
	if !ok || f.Type != reflect.TypeFor[atomicbitops.Int32]() {
		return 0
	}
	return f.Offset
}()

// rcvMemUsed is the memory ep's received segments hold; false when it
// cannot be read, and then the receive buffer is never given back.
func rcvMemUsed(ep tcpip.Endpoint) (int32, bool) {
	e, ok := ep.(*tcp.Endpoint)
	if !ok || rcvMemOffset == 0 {
		return 0, false
	}
	return (*atomicbitops.Int32)(unsafe.Add(unsafe.Pointer(e), rcvMemOffset)).Load(), true
}

// srtt is the endpoint's smoothed RTT, or a second when it has none: a
// longer interval only grows the receive buffer sooner.
func (e *yggExit) srtt() time.Duration {
	var info tcpip.TCPInfoOption
	if e.ep.GetSockOpt(&info) == nil && info.RTT > 0 {
		return info.RTT
	}
	return time.Second
}

// ended gives back what e's buffers grew: its endpoint holds nothing now.
func (e *yggExit) ended() {
	e.bmu.Lock()
	n := e.snd - yggExitSendFloor + e.rcv - yggExitRecvFloor
	e.snd, e.rcv, e.done = yggExitSendFloor, yggExitRecvFloor, true
	e.bmu.Unlock()
	e.open.release(e.who.user, n)
}

// growSend grows the send buffer, the endpoint's full, to what gVisor's
// tuning would make it, the congestion window twice; true when it grew.
// Four times in slow start: a blocked writer gets room at half the
// buffer, and by then the window has doubled (twice cost a 1 MiB reply
// an RTT, 8 MiB two, against gVisor's buffer of 1 MiB from the start).
func (e *yggExit) growSend() bool {
	var info tcpip.TCPInfoOption
	if e.ep.GetSockOpt(&info) != nil {
		return false
	}
	times := int64(2)
	if info.SndCwnd < info.SndSsthresh {
		times = 4
	}
	want := min(int64(max(info.SndCwnd, tcp.InitialCwnd))*e.mss*times, yggExitBufMax)
	e.bmu.Lock()
	defer e.bmu.Unlock()
	if e.done || want <= e.snd {
		return false
	}
	got := e.open.grow(e, want-e.snd)
	if got == 0 {
		return false
	}
	e.snd += got
	e.ep.SocketOptions().SetSendBufferSize(e.snd, true)
	return true
}

// received counts n bytes read from the client. The first read since the
// floor grows the receive buffer to gVisor's start, yggExitRecvStart: ACKs
// go out as segments come, before they are read, and from the floor their
// windows held an upload back for RTTs (8 MiB took 584 ms against 447 at
// a 40 ms RTT). Then, once an RTT has passed, as gVisor's ModerateRecvBuf
// would: twice what was read in it, more while that grows.
func (e *yggExit) received(n int) {
	now := time.Now()
	e.lastRead.Store(now.UnixNano())
	e.bmu.Lock()
	defer e.bmu.Unlock()
	e.copied += int64(n)
	if !e.reading {
		e.reading = true
		e.growRecv(yggExitRecvStart)
	}
	if now.Sub(e.measured) < e.rtt {
		return
	}
	copied, prev := e.copied, e.prevCopied
	e.measured, e.copied, e.rtt = now, 0, e.srtt()
	if copied <= prev {
		return
	}
	e.prevCopied = copied
	want := copied*2 + 16*e.mss
	want += 2 * (want * (copied - prev) / prev)
	e.growRecv(min(max(want, e.mss*tcp.InitialCwnd*2), yggExitBufMax))
}

// growRecv grows the receive buffer to want, as far as grow lets it.
func (e *yggExit) growRecv(want int64) {
	if e.done || want <= e.rcv {
		return
	}
	if got := e.open.grow(e, want-e.rcv); got > 0 {
		e.rcv += got
		e.ep.SocketOptions().SetReceiveBufferSize(e.rcv, true)
	}
}

// giveBack, when e has been idle yggExitIdle each way, brings its
// buffers back to their floors: the receive one when the endpoint holds
// nothing received, the send one when what waits to be acked fits in its
// floor. Only what neither its reader nor its writer holds. Not the
// receive one by its in-order queue alone (protocol review, B1): segments
// past a hole stay held, up to 3/4 of the size they came in under
// (rcv.go:504), and below them the hole's own segment is not let in.
func (e *yggExit) giveBack(now time.Time) {
	if !e.bmu.TryLock() {
		return
	}
	defer e.bmu.Unlock()
	if e.done {
		return
	}
	idle := now.Add(-yggExitIdle).UnixNano()
	ops := e.ep.SocketOptions()
	var n int64
	if held, ok := rcvMemUsed(e.ep); ok && held == 0 && e.rcv > yggExitRecvFloor && e.lastRead.Load() <= idle {
		// Nothing received held, in order or not: past the floor gVisor
		// then admits nothing more (segment_queue.go:49-57), and a segment
		// let in as the size changed shows here after.
		ops.SetReceiveBufferSize(yggExitRecvFloor, true)
		if held, _ := rcvMemUsed(e.ep); held <= yggExitRecvFloor {
			n += e.rcv - yggExitRecvFloor
			e.rcv, e.copied, e.reading = yggExitRecvFloor, 0, false
			e.prevCopied = e.firstCopied()
		} else {
			ops.SetReceiveBufferSize(e.rcv, true)
		}
	}
	if e.snd > yggExitSendFloor && e.lastWrite.Load() <= idle && e.wmu.TryLock() {
		// The endpoint is writable at the floor when less than it waits
		// to be acked; after the writer's end (sendDone) it is writable
		// whatever waits, so not then.
		ops.SetSendBufferSize(yggExitSendFloor, true)
		if !e.sendDone && e.ep.Readiness(waiter.WritableEvents)&waiter.WritableEvents != 0 {
			n += e.snd - yggExitSendFloor
			e.snd = yggExitSendFloor
		} else {
			ops.SetSendBufferSize(e.snd, true)
		}
		e.wmu.Unlock()
	}
	e.open.release(e.who.user, n)
}

var errExitStalled = errors.New("the client took nothing for yggExitStall")

// Write writes inner's way to the client, as gonet's Write does, but grows
// the send buffer when it is full (growSend). Each call has yggExitStall
// from its first wait for room to finish (a call is 16 KiB at most, the
// copy's buffer): a blocked write gets room once the client has acked
// half the buffer (up to 2 MiB). A client that takes nothing ends the exit,
// once more waits for it than the buffer holds; one that takes 2.3 KiB/s
// does not (fifth review: 5 min cut audio paced at 32-48 kbit/s). Not
// TCP's user timeout: gVisor's runs from the first retransmission until
// all sent is acked, and it cut a download that went on through a path's
// losses (the fourth review's fix, tried here).
func (e *yggExit) Write(b []byte) (int, error) {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	defer func() { e.lastWrite.Store(time.Now().UnixNano()) }()
	var (
		r     bytes.Reader
		n     int
		entry waiter.Entry
		ch    <-chan struct{}
		stall *time.Timer
	)
	for n < len(b) {
		r.Reset(b[n:])
		k, err := e.ep.Write(&r, tcpip.WriteOptions{})
		n += int(k)
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if e.growSend() {
				continue
			}
			if ch == nil { // and try once more: room may have come
				entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
				e.wq.EventRegister(&entry)
				defer e.wq.EventUnregister(&entry)
				continue
			}
			if stall == nil {
				stall = time.NewTimer(yggExitStall)
				defer stall.Stop()
			}
			select {
			case <-ch:
			case <-stall.C:
				return n, errExitStalled
			}
		default:
			return n, fmt.Errorf("write: %s", err)
		}
	}
	return n, nil
}

// Read reads the client's way, for received.
func (e *yggExit) Read(b []byte) (int, error) {
	n, err := e.c.Read(b)
	if n > 0 {
		e.received(n)
	}
	return n, err
}

// writerDone marks e's writer ended, before its endpoint's write side
// closes (giveBack).
func (e *yggExit) writerDone() {
	e.wmu.Lock()
	e.sendDone = true
	e.wmu.Unlock()
}
