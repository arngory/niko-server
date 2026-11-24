//go:build linux

package nikoserver

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arngory/niko-server/nikoserver/memlimit"
	squic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
)

// The memory of a Hysteria2 backend's connections (protocol review
// 2026-11-21, M2). quic-go keeps what a client sent until the server reads
// it, up to the receive windows, and what the server sent until the client
// acknowledges it, up to the congestion window. Before v0.19.3 the windows
// started at Hysteria's maximum, 8 MiB a stream and 20 MiB a connection,
// and Brutal's window is the client's rate times its smoothed RTT, which a
// client inflates by holding its ACKs, up to quic-go's 40000 packets
// outstanding (some 56 MiB): an upload to a destination that does not read,
// or a download whose ACKs come late, held 20 to 56 MiB a connection, with
// no bound on a user's connections. Now:
//
//   - the receive windows start at quic-go's own, 512 KiB a stream and 768
//     KiB a connection (hyStreamWindow, hyConnWindow), and grow as quic-go's
//     tuning grows them while the reader keeps up, to Hysteria's 8 and 20
//     MiB; every byte a connection's window grows by is taken from the
//     node's budget (hyMemBudget) within its user's share of it,
//     hyMemShares-th, and given back when the connection ends (quic-go
//     never shrinks a window it gave); the windows take half the budget
//     and half a share at most, so that a long upload leaves the flights
//     theirs;
//   - what the server has in flight on an authenticated connection is
//     bounded by hySendFloor plus what it took from the same budget, to
//     what Brutal or BBR allow; a connection whose congestion window wants
//     more takes it in steps (hySendStep), and when the budget or the
//     user's share runs short, the others give back what they hold past
//     their windows and their flights, past their flights once idle for
//     hyMemIdle (giveBack): a flight its client does not acknowledge is
//     memory held, and stays counted;
//   - a user has at most hy2ConnsPerUser connections at once (hyusers.go)
//     and hy2PendingPerUser streams waiting for their request (hylimits.go),
//     a connection hy2PendingStreams streams read before they are known,
//     and a UDP session a bounded queue and few fragments (the vendored
//     sing-quic's udpQueueBytes, udpDefragPackets).
//
// So the windows and the flight of all connections are at most the budget
// plus the floors of the unauthenticated, hyConnWindow a connection, as
// many as the front lets through: an authenticated connection's floor
// (hyFloor, 1.75 MiB) is taken from the budget, and one the budget has no
// floor for is closed (takeFloor). Before v0.19.3 the floors were outside
// it, hy2ConnsPerUser × hyFloor, some 28 MiB a user. quic-go holds a
// STREAM frame of 128 bytes or more in a packet buffer of its own (1452
// bytes), so the heap under a full receive window is up to 11 times the
// window for a client that sends 128-byte frames, about the window for one
// that fills its packets: the budget bounds the windows, not that ratio.
// The unauthenticated count as one user, "". Half a share for the windows
// (a sixteenth of the budget; quic-go doubles a window) stops a
// connection's at 1.5 MiB on a budget of 32 MiB (a host of 256 MiB or
// less without a cgroup limit, a unit limited to 85 MiB), its upload at
// that over the round trip (some 27 MiB/s at 40 ms, measured), and at 6
// MiB on a host of 1 GiB without a limit; in a unit, at 6 MiB in 256 MiB,
// 12 MiB in 512 MiB, Hysteria's 20 MiB from some 822 MiB.
const (
	hyStreamWindow = 512 << 10 // quic-go's InitialStreamReceiveWindow
	hyConnWindow   = 768 << 10 // and InitialConnectionReceiveWindow
	hySendFloor    = 1 << 20   // in flight without asking the budget
	// hyFloor is an authenticated connection's floor, its flight's and its
	// connection window's start: taken from the node's budget when it
	// authenticates (takeFloor).
	hyFloor       = hySendFloor + hyConnWindow
	hySendStep    = 256 << 10 // the least a sender takes at a time
	hyMemShares   = 8         // as 8 users fill the budget
	hyMemIdle     = time.Second
	hyMemSweepGap = 100 * time.Millisecond
	// hyMemShortFor: a sender short of the budget asks again this later.
	hyMemShortFor = 20 * time.Millisecond
)

// hyMemBudget is the default budget, of the memory the process may have
// (procMemory): 3/8 of its cgroup's limit when it has one below the host
// (memlimit.Limits.Limit), each Hysteria2 backend its own unit and its
// own limit (raycontrol memory-v1), 2 GiB at most; else an eighth of the
// host's MemTotal as before, within 32 MiB and 2 GiB (an eighth: a node
// has two Hysteria2 backends, each its own process, and the heap under a
// receive window can be more than the window); 32 MiB when neither is
// known. The connections' floors are in it (hyFloor).
var hyMemBudget = sync.OnceValue(func() int64 { return hyBudgetFor(procMemory()) })

func hyBudgetFor(l memlimit.Limits) int64 {
	if n := l.Limit(); n > 0 {
		return min(n/8*3, 2<<30)
	}
	return min(max(l.MemTotal/8, 32<<20), 2<<30)
}

// hyMem is a backend's budget and what its connections took of it.
type hyMem struct {
	budget int64
	log    *Logger

	mu          sync.Mutex
	grown       int64            // all connections'
	grownBy     map[string]int64 // by base name
	conns       map[<-chan struct{}]*hyMemConn
	warnedNode  bool
	warnedUser  bool
	reclaimed   time.Time
	reclaimedBy map[string]time.Time
	// recvAll and recvBy are what the receive windows took, of all and of
	// each user: within half the budget and half a share (growRecv), the
	// rest of each is the flights'. A window gives nothing back while its
	// connection lives.
	recvAll int64
	recvBy  map[string]int64
	// floors are the authenticated connections' floors, hyFloor each
	// (takeFloor): of the budget, of no user's share.
	floors      int64
	warnedFloor bool

	takes atomic.Int64 // asks of the budget, for the tests

	overReleased atomic.Int64 // releases past what was taken: a bug, for the tests
}

func newHyMem(budget int64, log *Logger) *hyMem {
	return &hyMem{budget: budget, log: log, grownBy: map[string]int64{}, conns: map[<-chan struct{}]*hyMemConn{},
		reclaimedBy: map[string]time.Time{}, recvBy: map[string]int64{}}
}

// hyMemConn is what one QUIC connection took: of its receive window, and
// of its flight (send, the sender's). Under hyMem.mu but sender.
type hyMemConn struct {
	user   string // base name; "" until authenticated
	recv   int64
	send   int64
	floor  bool // its hyFloor taken from the budget
	ended  bool
	sender *hyMemSender
}

// conn is the record of the connection that done is the end of, made at
// first sight: it ends with the connection.
func (m *hyMem) conn(done <-chan struct{}) *hyMemConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connLocked(done)
}

func (m *hyMem) connLocked(done <-chan struct{}) *hyMemConn {
	c := m.conns[done]
	if c == nil {
		c = &hyMemConn{}
		m.conns[done] = c
		go func() {
			<-done
			m.end(done)
		}()
	}
	return c
}

// end gives back what a connection took.
func (m *hyMem) end(done <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.conns[done]
	if c == nil {
		return
	}
	delete(m.conns, done)
	c.ended = true
	if c.floor {
		m.floors -= hyFloor
		c.floor = false
	}
	m.recvLocked(c.user, -c.recv)
	m.releaseLocked(c.user, c.recv+c.send)
	c.recv, c.send = 0, 0
	if c.sender != nil {
		c.sender.limit.Store(hySendFloor)
	}
}

// setUser makes the connection the user's (its base name): what it took
// before it authenticated moves from "" to the user.
func (m *hyMem) setUser(done <-chan struct{}, user string) *hyMemConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.connLocked(done)
	if c.user != user && !c.ended {
		if n := c.recv + c.send; n > 0 {
			m.releaseLocked(c.user, n)
			m.grown += n
			m.grownBy[user] += n
		}
		m.recvLocked(c.user, -c.recv)
		c.user = user
		m.recvLocked(c.user, c.recv)
	}
	return c
}

// recvLocked counts n more bytes of user's receive windows.
func (m *hyMem) recvLocked(user string, n int64) {
	if n == 0 {
		return
	}
	m.recvAll += n
	if m.recvBy[user] += n; m.recvBy[user] <= 0 {
		if m.recvBy[user] < 0 || m.recvAll < 0 {
			m.overReleased.Add(1)
		}
		delete(m.recvBy, user)
	}
}

func (m *hyMem) releaseLocked(user string, n int64) {
	if n == 0 {
		return
	}
	m.grown -= n
	if m.grownBy[user] -= n; m.grownBy[user] <= 0 {
		if m.grownBy[user] < 0 || m.grown < 0 {
			m.overReleased.Add(1)
		}
		delete(m.grownBy, user)
		delete(m.reclaimedBy, user)
	}
}

// takeLocked takes up to want for c (all of it, or nothing, when whole),
// within the budget and its user's share. Short, it warns once of either,
// and returns the connections that may give back.
func (m *hyMem) takeLocked(c *hyMemConn, want int64, whole bool) (got int64, idle []*hyMemSender, warn string) {
	if c.ended || want <= 0 {
		return 0, nil, ""
	}
	m.takes.Add(1)
	node := m.budget - m.grown - m.floors
	user := m.budget/hyMemShares - m.grownBy[c.user]
	got = max(min(want, node, user), 0)
	if whole && got < want {
		got = 0
	}
	if got > 0 {
		m.grown += got
		m.grownBy[c.user] += got
	}
	if got == want {
		return got, nil, ""
	}
	mine := node >= want
	switch {
	case !mine && !m.warnedNode:
		m.warnedNode = true
		warn = fmt.Sprintf("Hysteria2 connections' windows at the node's budget, %d MiB: they grow no further until others give back (logged once)", m.budget>>20)
	case mine && !m.warnedUser:
		m.warnedUser = true
		warn = fmt.Sprintf("a user's Hysteria2 connections' windows at its share of the budget, %d MiB: they grow no further until others give back (logged once)", m.budget/hyMemShares>>20)
	}
	return got, m.sweepLocked(c, mine), warn
}

// sweepLocked is the senders that may give back for c: short of its
// user's share only (mine), only its user's, at most each hyMemSweepGap a
// user; short of the node's budget, all of them, at most each
// hyMemSweepGap in all (as yggExitCount.grow).
func (m *hyMem) sweepLocked(c *hyMemConn, mine bool) (idle []*hyMemSender) {
	now := time.Now()
	last := m.reclaimed
	if mine {
		last = m.reclaimedBy[c.user]
	}
	if now.Sub(last) < hyMemSweepGap {
		return nil
	}
	if mine {
		m.reclaimedBy[c.user] = now
	} else {
		m.reclaimed = now
	}
	for _, x := range m.conns {
		if x != c && x.sender != nil && x.send > 0 && (!mine || x.user == c.user) {
			idle = append(idle, x.sender)
		}
	}
	return idle
}

// takeFloor takes an authenticated connection's floor, hyFloor, from the
// node's budget (not from its user's share), and says whether it has it.
// Short, the other connections give back what they hold past their
// windows and flights (giveBack, at most each hyMemSweepGap) and the
// budget is asked once more; still short, the node warns once and the
// connection is refused (connectionHook closes it, and its client dials
// again). So the floors of all connections are in the budget: a user's
// floors are no longer guaranteed (before v0.19.3 they were outside it,
// some 28 MiB a user), and a node whose budget its connections hold takes
// none more, of anyone's, until some end or give back.
func (m *hyMem) takeFloor(done <-chan struct{}) bool {
	for asked := false; ; asked = true {
		m.mu.Lock()
		c := m.connLocked(done)
		if !c.ended && !c.floor && m.budget-m.grown-m.floors >= hyFloor {
			m.floors += hyFloor
			c.floor = true
		}
		if c.floor || c.ended {
			m.mu.Unlock()
			return c.floor
		}
		var idle []*hyMemSender
		if !asked {
			idle = m.sweepLocked(c, false)
		}
		var warn string
		if (asked || len(idle) == 0) && !m.warnedFloor {
			m.warnedFloor = true
			warn = fmt.Sprintf("Hysteria2 connections' floors and windows at the node's budget, %d MiB: new connections are closed until others end or give back (logged once)", m.budget>>20)
		}
		m.mu.Unlock()
		m.after(idle, warn)
		if asked || len(idle) == 0 {
			return false
		}
	}
}

// allowRecv is quic-go's AllowConnectionWindowIncrease: a connection's
// receive window grows by delta only if the budget and its user's share
// have it all. A window cannot shrink: the bytes stay taken until the
// connection ends.
func (m *hyMem) allowRecv(conn *squic.Conn, delta uint64) bool {
	return m.growRecv(conn.Context().Done(), int64(delta)) // Context is a field: allowed in the callback
}

// growRecv is allowRecv by the connection's end.
func (m *hyMem) growRecv(done <-chan struct{}, delta int64) bool {
	m.mu.Lock()
	c := m.connLocked(done)
	// Windows take half the budget and half a share at most: a long upload
	// does not hold what downloads need for the connection's life.
	if m.recvAll+delta > m.budget/2 || m.recvBy[c.user]+delta > m.budget/hyMemShares/2 {
		m.mu.Unlock()
		return false
	}
	got, idle, warn := m.takeLocked(c, delta, true)
	c.recv += got
	m.recvLocked(c.user, got)
	m.mu.Unlock()
	m.after(idle, warn)
	return got > 0
}

func (m *hyMem) after(idle []*hyMemSender, warn string) {
	if warn != "" && m.log != nil {
		m.log.Warnf("%s", warn)
	}
	now := monotime.Now()
	for _, s := range idle {
		s.giveBack(now)
	}
}

// hyMemSender bounds what an authenticated connection's congestion
// controller may have in flight: at most limit (hySendFloor plus what the
// connection took), whatever the controller's own window. quic-go calls it
// from the connection's loop; limit is read there without a lock and
// changed under hyMem.mu, always hySendFloor plus the connection's send.
// inFlight and cwnd are the flight and the controller's window as the loop
// last saw them, for a give back from another connection's loop.
type hyMemSender struct {
	congestion.CongestionControl
	m          *hyMem
	c          *hyMemConn
	limit      atomic.Int64
	inFlight   atomic.Int64
	cwnd       atomic.Int64
	lastSent   atomic.Int64 // monotime of the last ack-eliciting packet sent
	shortUntil atomic.Int64 // monotime: the budget was short, no asking before
}

// hyMemSenderEx is hyMemSender for a controller that takes quic-go's
// extended calls (Brutal): quic-go asks for the interface.
type hyMemSenderEx struct {
	*hyMemSender
	ex congestion.CongestionControlEx
}

func (s hyMemSenderEx) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time,
	acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	left := int64(priorInFlight)
	for _, a := range acked {
		left -= int64(a.BytesAcked)
	}
	for _, l := range lost {
		left -= int64(l.BytesLost)
	}
	s.inFlight.Store(max(left, 0))
	s.ex.OnCongestionEventEx(priorInFlight, eventTime, acked, lost)
}
func (s hyMemSenderEx) OnPacketNeutered(n congestion.PacketNumber)  { s.ex.OnPacketNeutered(n) }
func (s hyMemSenderEx) OnPacketsLost(least congestion.PacketNumber) { s.ex.OnPacketsLost(least) }
func (s hyMemSenderEx) OnAppLimited(bytesInFlight congestion.ByteCount) {
	s.ex.OnAppLimited(bytesInFlight)
}

// wrapSender is the service's WrapCongestionControl: the connection is the
// user's from here, and its flight within the budget.
func (m *hyMem) wrapSender(conn *squic.Conn, user any, cc congestion.CongestionControl) congestion.CongestionControl {
	name := "-"
	if u, _ := user.(*hy2User); u != nil {
		name = baseName(u.name)
	}
	s := m.sender(conn.Context().Done(), name, cc)
	if ex, ok := cc.(congestion.CongestionControlEx); ok {
		return hyMemSenderEx{s, ex}
	}
	return s
}

// sender makes the connection that done ends the user's, and its sender.
func (m *hyMem) sender(done <-chan struct{}, user string, cc congestion.CongestionControl) *hyMemSender {
	c := m.setUser(done, user)
	s := &hyMemSender{CongestionControl: cc, m: m, c: c}
	s.limit.Store(hySendFloor)
	s.lastSent.Store(int64(monotime.Now()))
	m.mu.Lock()
	c.sender = s
	m.mu.Unlock()
	return s
}

// OnPacketSent notes the flight, and the time of a packet that asks for an
// ACK: one that carries only ACKs says nothing of what the connection
// sends, and an idle connection keeps acknowledging its client's.
func (s *hyMemSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount, number congestion.PacketNumber,
	bytes congestion.ByteCount, retransmittable bool) {
	if retransmittable {
		s.lastSent.Store(int64(sentTime))
		s.inFlight.Store(int64(bytesInFlight + bytes))
	} else {
		s.inFlight.Store(int64(bytesInFlight))
	}
	s.CongestionControl.OnPacketSent(sentTime, bytesInFlight, number, bytes, retransmittable)
}

func (s *hyMemSender) OnPacketAcked(number congestion.PacketNumber, acked, priorInFlight congestion.ByteCount, t monotime.Time) {
	s.inFlight.Store(max(int64(priorInFlight)-int64(acked), 0))
	s.CongestionControl.OnPacketAcked(number, acked, priorInFlight, t)
}

func (s *hyMemSender) OnCongestionEvent(number congestion.PacketNumber, lost, priorInFlight congestion.ByteCount) {
	s.inFlight.Store(max(int64(priorInFlight)-int64(lost), 0))
	s.CongestionControl.OnCongestionEvent(number, lost, priorInFlight)
}

// CanSend lets a packet go while the flight is under the limit; at it, a
// controller whose window is above takes more of the budget first, unless
// the budget was short a moment ago (hyMemShortFor): a sender at its limit
// asks at each packet, and the lock is the backend's.
func (s *hyMemSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	cwnd := int64(s.CongestionControl.GetCongestionWindow())
	s.cwnd.Store(cwnd)
	s.inFlight.Store(int64(bytesInFlight))
	if int64(bytesInFlight) >= s.limit.Load() {
		if now := monotime.Now(); int64(now) >= s.shortUntil.Load() {
			s.grow(cwnd, now)
		}
		if int64(bytesInFlight) >= s.limit.Load() {
			return false
		}
	}
	return s.CongestionControl.CanSend(bytesInFlight)
}

// GetCongestionWindow is the controller's, within the limit.
func (s *hyMemSender) GetCongestionWindow() congestion.ByteCount {
	return min(s.CongestionControl.GetCongestionWindow(), congestion.ByteCount(s.limit.Load()))
}

// grow takes budget towards the controller's window cwnd, by hySendStep at
// least, a quarter of the limit for a big one. Short, the sender asks no
// more for hyMemShortFor.
func (s *hyMemSender) grow(cwnd int64, now monotime.Time) {
	limit := s.limit.Load()
	if cwnd <= limit {
		return
	}
	want := min(cwnd-limit, max(hySendStep, limit/4))
	m := s.m
	m.mu.Lock()
	got, idle, warn := m.takeLocked(s.c, want, false)
	if got > 0 {
		s.c.send += got
		s.limit.Add(got)
	}
	m.mu.Unlock()
	if got < want {
		s.shortUntil.Store(int64(now.Add(hyMemShortFor)))
	}
	m.after(idle, warn)
}

// giveBack returns what the connection took for its flight past what it
// needs, when another is short: past its window and its flight, and once
// it sent nothing that asks for an ACK for hyMemIdle, past its flight. A
// flight that its client does not acknowledge is memory held: it stays
// counted however long the sender has been blocked.
func (s *hyMemSender) giveBack(now monotime.Time) {
	keep := max(hySendFloor, s.inFlight.Load())
	if now.Sub(monotime.Time(s.lastSent.Load())) < hyMemIdle {
		keep = max(keep, s.cwnd.Load())
	}
	m := s.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.c.ended {
		return
	}
	n := min(s.limit.Load()-keep, s.c.send)
	if n <= 0 {
		return
	}
	m.releaseLocked(s.c.user, n)
	s.c.send -= n
	s.limit.Add(-n)
}

// hysteriaWindows are the backend's receive windows: quic-go's to start
// with, Hysteria's at most, growing within m.
func hysteriaWindows(o *qtls.QUICOptions, m *hyMem) {
	o.StreamReceiveWindow, o.ConnectionReceiveWindow = hysteria.DefaultStreamReceiveWindow, hysteria.DefaultConnReceiveWindow
	o.InitialStreamReceiveWindow, o.InitialConnectionReceiveWindow = hyStreamWindow, hyConnWindow
	o.AllowConnectionWindowIncrease = m.allowRecv
}
