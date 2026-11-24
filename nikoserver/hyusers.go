//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/auth"
)

// A Hysteria2 backend's users (raycontrol docs/spec/traffic-limit-v1.md
// §2.2, §3.2): the service's table, the connections open under each
// password, and each name's bytes. The service checks a password once per
// connection, so a name gone from the users file (disabled, expired, over
// its limit) or given another password loses its connections here, as
// Yggdrasil's removed keys lose their links.
//
// The counters are by name only, up and down since the process started:
// nothing of destinations, addresses, ports or times. Neither they nor
// destinations go to the log. A name gone from the users file keeps its
// counters while it has a connection, a stream or a datagram session, and
// trafficStale after the last one ends (prune, v0.16.0).

// hy2User is the service's user: one per name and password. A reload keeps
// it while the users file gives that password to that name; otherwise it
// is revoked and its connections closed. The service's user type is this
// and not the name alone (as in sing-box): a connection's user then tells
// which password it came in with, without the password, and brings the
// name's counters along in the context, without a lookup.
type hy2User struct {
	name    string
	traffic *hy2Traffic
	revoked bool // under hy2Users.mu
}

// hy2Traffic are a name's bytes at the destinations' side: up sent to
// them, down received from them (and passed on to the client). A stream or
// a datagram session looks them up once; a buffer costs an atomic add.
// live and gone tell when the counters of a name the users file no longer
// has may go (prune): nothing of the name's left, and gone trafficStale
// ago.
type hy2Traffic struct {
	up, down atomic.Int64
	live     atomic.Int64 // the name's connections, streams and datagram sessions
	gone     time.Time    // under hy2Users.mu: when prune first saw it out and idle
}

// trafficStale is how long the counters of a name gone from the users file
// stay readable once nothing of it is left (raycontrol's naive keeps them
// as long, its prune): rayd reads them every 15 s, so it has their last
// bytes long before. Without it a process running for months would keep a
// name for each credential that ever rotated (raycontrol v0.23.0 names
// each credential for life) and answer traffic with more names than rayd
// reads (4 MiB, 65536 names), and limits would go unenforced.
const trafficStale = 5 * time.Minute

// hy2Conn is an authenticated QUIC connection: close ends it, its streams
// and datagram sessions with it. packets are those it has received (QUIC's
// count; nil: none known), by which the watch's looks tell when the client
// was last heard; the fields after it are hy2Users'.
type hy2Conn struct {
	close   func()
	packets func() uint64
	done    <-chan struct{} // its end, by which hyMem knows it; nil: none (tests)

	base  string    // its user's base name (baseName)
	at    time.Time // admitted
	heard time.Time // the last look that saw its count of packets grow
	seen  uint64    // the count then
}

// hy2ConnsPerUser bounds a user's QUIC connections at once in a backend,
// by base name, all its credentials and devices together (hyLimitNumbers
// conns). Each connection holds windows of its own (hymem.go), and before
// v0.19.3 one user could open as many as the front let through.
const hy2ConnsPerUser = 16

// hy2UnheardAfter is how long a connection of another credential of the
// user must have been unheard to give way to a new one: a live client is
// heard at least each keepalive (its own 25 s, or its answer to the
// server's PING at hysteriaKeepAlive), and the watch counts each
// usersLookEvery; past both and a margin it is gone (tests: hyLimitNumbers'
// unheard).
const hy2UnheardAfter = hysteriaKeepAlive + 7*time.Second

type hy2Users struct {
	mu     sync.Mutex
	byPass map[string]*hy2User // the service's table
	conns  map[*hy2User]map[*hy2Conn]bool
	// byBase are the connections of each base name, for its limit.
	byBase map[string]map[*hy2Conn]*hy2User
	// traffic is by name, the names gone from the users file too until
	// prune drops them: raycontrol counts by name.
	traffic map[string]*hy2Traffic
	names   map[string]bool // the users file's names
	boot    string
	stale   time.Duration    // trafficStale when 0 (tests make it short)
	now     func() time.Time // time.Now when nil (tests)
	// limits are the backend's per-user connection limits, whose refusals
	// the traffic line gives too; set before the stats socket serves.
	limits *hyLimits
	// mem is the backend's budget, whose floors admit takes; nil: none
	// (tests).
	mem *hyMem
}

func (u *hy2Users) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

func newHy2Users() *hy2Users {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails (Go 1.24)
	return &hy2Users{boot: hex.EncodeToString(b[:])}
}

// set takes the users file's names and passwords: update gives the service
// its new table, and the users it no longer has are revoked and their
// connections closed. A connection authenticated against the old table
// meets a reload under this lock in admit: either it was admitted before
// and is closed here, or it comes after and finds its user revoked. The
// connections close after the lock: QUIC's close waits for the
// connection's loop.
func (u *hy2Users) set(names, passwords []string, update func([]*hy2User, []string)) (closed int) {
	u.mu.Lock()
	next := make(map[string]*hy2User, len(names))
	u.names = make(map[string]bool, len(names))
	for i, name := range names {
		u.names[name] = true
		user := u.byPass[passwords[i]]
		if user == nil || user.name != name {
			user = &hy2User{name: name, traffic: u.trafficOf(name)}
		}
		next[passwords[i]] = user
	}
	list, pass := make([]*hy2User, 0, len(next)), make([]string, 0, len(next))
	for p, user := range next {
		list, pass = append(list, user), append(pass, p)
	}
	update(list, pass)
	var doomed []*hy2Conn
	for p, user := range u.byPass {
		if next[p] == user {
			continue
		}
		user.revoked = true
		for c := range u.conns[user] {
			doomed = append(doomed, c)
			u.dropLocked(user, c) // deleting while ranging is allowed
		}
	}
	u.byPass = next
	u.prune(u.clock())
	u.mu.Unlock()
	for _, c := range doomed {
		c.close()
	}
	return len(doomed)
}

// check is the watch's look every few seconds, whether the users file
// changed or not: prune, and each connection whose count of packets grew
// since the last look was heard from now.
func (u *hy2Users) check() {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.clock()
	u.prune(now)
	for _, conns := range u.conns {
		for c := range conns {
			c.look(now)
		}
	}
}

// look notes when c was last heard from; under hy2Users.mu.
func (c *hy2Conn) look(now time.Time) {
	if c.packets == nil {
		return
	}
	if n := c.packets(); n != c.seen {
		c.seen, c.heard = n, now
	}
}

// prune drops the counters of the names the users file no longer has,
// nothing of them left (no connection, stream or datagram session) for
// trafficStale or longer, from the first look that saw both. A name back
// in the file keeps its counters; one dropped and back starts from 0,
// which rayd takes as a name it has not seen. As raycontrol's naive does.
// Under u.mu.
func (u *hy2Users) prune(now time.Time) {
	stale := u.stale
	if stale <= 0 {
		stale = trafficStale
	}
	for name, t := range u.traffic {
		switch {
		case u.names[name] || t.live.Load() > 0:
			t.gone = time.Time{}
		case t.gone.IsZero():
			t.gone = now
		case now.Sub(t.gone) >= stale:
			delete(u.traffic, name)
		}
	}
}

// trafficOf is a name's counters, made at its first sight; under u.mu.
func (u *hy2Users) trafficOf(name string) *hy2Traffic {
	if u.traffic == nil {
		u.traffic = map[string]*hy2Traffic{}
	}
	t := u.traffic[name]
	if t == nil {
		t = new(hy2Traffic)
		u.traffic[name] = t
	}
	return t
}

// admit lets an authenticated connection in unless its user was revoked
// meanwhile; leave takes it out when it ends. With the per-user limits on
// (hyLimits), at the user's limit of connections one gives way, closed,
// the one heard from longest ago among:
//  1. the newcomer's own credential's (a device that reconnects, its phone
//     on another network, leaves its old connection behind until the idle
//     timeout);
//  2. else the user's unheard for hy2UnheardAfter (gone);
//  3. else those of the credential that holds the most, if that is more
//     than its fair share: the limit over the credentials with
//     connections, the newcomer's counted, one at least. Each credential
//     is a device (raycontrol names one for each), so a leaked one with
//     the limit's worth of live connections loses places to the owner's
//     other devices, down to an equal share, and takes nothing from them;
//  4. else none, and the newcomer is refused: every credential is at its
//     fair share or under, all heard. The service closes it before the
//     auth's answer (the hook's false), with no error code; Hysteria
//     clients dial again.
//
// Then the newcomer takes its floor of the budget (hyMem.takeFloor),
// whatever the limits say: the floor of the connection it replaces, if
// one gives way, else the budget's. Short, it is refused (memory) and the
// one chosen to give way stays. Else each is counted (conns). Live connections of different credentials do not
// take each other's places in turn: a newcomer of a credential at its share
// replaces its own. Two clients of one credential (a shared link) cut down
// below their number by (3) do: each one's redial replaces the other's.
func (u *hy2Users) admit(user *hy2User, c *hy2Conn) bool {
	u.mu.Lock()
	if user == nil || user.revoked {
		u.mu.Unlock()
		return false
	}
	now := u.clock()
	c.base, c.at, c.heard = baseName(user.name), now, now
	if c.packets != nil {
		c.seen = c.packets()
	}
	var gone *hy2Conn
	l := u.limits
	if l != nil && l.limited(c.base) && len(u.byBase[c.base]) >= max(1, l.n.conns) {
		quieter := func(x, y *hy2Conn) bool {
			return y == nil || x.heard.Before(y.heard) || x.heard.Equal(y.heard) && x.at.Before(y.at)
		}
		for x := range u.conns[user] {
			if x.look(now); quieter(x, gone) {
				gone = x
			}
		}
		if gone == nil {
			for x := range u.byBase[c.base] {
				if x.look(now); now.Sub(x.heard) >= l.n.unheard && quieter(x, gone) {
					gone = x
				}
			}
		}
		if gone == nil {
			held := map[*hy2User]int{}
			for _, y := range u.byBase[c.base] {
				held[y]++
			}
			var most *hy2User
			for y, n := range held {
				if most == nil || n > held[most] {
					most = y
				}
			}
			fair := max(1, max(1, l.n.conns)/(len(held)+1)) // the newcomer's holds none
			if most != nil && held[most] > fair {
				for x := range u.conns[most] {
					if quieter(x, gone) {
						gone = x
					}
				}
			}
		}
		if gone == nil {
			l.refuse(c.base, refusedConns)
			u.mu.Unlock()
			return false
		}
	}
	if u.mem != nil {
		var from <-chan struct{}
		if gone != nil {
			from = gone.done
		}
		if !u.mem.takeFloor(c.done, from) {
			if l != nil {
				l.refuse(c.base, refusedMemory)
			}
			u.mu.Unlock()
			return false
		}
	}
	if gone != nil {
		l.refuse(c.base, refusedConns)
		u.dropLocked(u.byBase[c.base][gone], gone)
	}
	if u.conns == nil {
		u.conns = map[*hy2User]map[*hy2Conn]bool{}
		u.byBase = map[string]map[*hy2Conn]*hy2User{}
	}
	if u.conns[user] == nil {
		u.conns[user] = map[*hy2Conn]bool{}
	}
	if u.byBase[c.base] == nil {
		u.byBase[c.base] = map[*hy2Conn]*hy2User{}
	}
	u.conns[user][c] = true
	u.byBase[c.base][c] = user
	user.traffic.live.Add(1)
	u.mu.Unlock()
	if gone != nil {
		gone.close() // QUIC's close waits for the connection's loop: not under the lock
	}
	return true
}

// dropLocked takes a connection out of the tables; under u.mu. Its
// counter of what is live goes when it ends (leave).
func (u *hy2Users) dropLocked(user *hy2User, c *hy2Conn) {
	delete(u.conns[user], c)
	if len(u.conns[user]) == 0 {
		delete(u.conns, user)
	}
	delete(u.byBase[c.base], c)
	if len(u.byBase[c.base]) == 0 {
		delete(u.byBase, c.base)
	}
}

// leave takes out a connection that admit let in, once, whether it gave
// way or was revoked before it ended or not.
func (u *hy2Users) leave(user *hy2User, c *hy2Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	user.traffic.live.Add(-1)
	u.dropLocked(user, c)
}

// connectionHook is the service's ConnectionHook: a connection is admitted
// with its floor of the budget (admit), and counted in its address's stats
// until it ends; or refused (its limit, the budget short of its floor,
// counted as memory whatever conn_limit says, or its user revoked between
// its password check and now), and the service closes it before the
// auth's answer.
func connectionHook(users *hy2Users, live *sessions) func(net.Addr, any, func() hysteria2.ConnectionStats, func(), <-chan struct{}) bool {
	return func(remote net.Addr, user any, stats func() hysteria2.ConnectionStats, closeConnection func(), done <-chan struct{}) bool {
		u, _ := user.(*hy2User)
		c := &hy2Conn{close: closeConnection, packets: func() uint64 { return stats().PacketsReceived }, done: done}
		if !users.admit(u, c) {
			return false
		}
		forget := live.add(remote, u.name, stats)
		go func() {
			<-done
			forget()
			users.leave(u, c)
		}()
		return true
	}
}

// trafficFrom is the counters of the user a stream or a datagram session
// came with. Without one (the outbound driven directly) they count for
// nobody.
func trafficFrom(ctx context.Context) *hy2Traffic {
	_, t := userFrom(ctx)
	return t
}

// userFrom is whose limits a stream or a datagram session takes (the base
// name of the user it came with: u5 for each of u5's credentials,
// raycontrol conn-limit-v1 §2) and the counters of its name. Without a
// user the name is "": limited by nothing, counted for nobody.
func userFrom(ctx context.Context) (base string, t *hy2Traffic) {
	if user, _ := auth.UserFromContext[*hy2User](ctx); user != nil {
		return baseName(user.name), user.traffic
	}
	return "", new(hy2Traffic)
}

// open counts a stream or a datagram session as the name's until the
// returned func: prune keeps the counters meanwhile.
func (t *hy2Traffic) open() (done func()) {
	t.live.Add(1)
	return func() { t.live.Add(-1) }
}

// HysteriaTraffic answers the stats socket's traffic query: each name's
// bytes since the process started (or since it came back, prune having
// dropped it), as raycontrol's rayd reads them (traffic-limit-v1 §2.2).
// Reading resets nothing; Boot is random at each start, so a new one means
// the counters began again. The Yggdrasil backend answers in it too, by
// LAN group (yggRelay.traffic).
type HysteriaTraffic struct {
	V     int                    `json:"v"`
	Boot  string                 `json:"boot"`
	Users map[string]UserTraffic `json:"users"`
	// Limit (v0.17.0, Hysteria2) are the refusals of the per-user
	// connection limits by base name (u5 for each of u5's credentials: the
	// limits are a user's, the bytes a credential's) and kind (tcp, rate,
	// failed, udp, evicted, dest, live, lookup; conns and pending since
	// v0.19.3), since the process started
	// (raycontrol conn-limit-v1 §2, §7); only names and kinds with some,
	// and absent with none. As rayd naive answers (raycontrol v0.24.0): a
	// field a rayd before that does not read.
	Limit map[string]map[string]int64 `json:"limit,omitempty"`
	// Uptime (v0.17.0) is how long the process has run, in whole seconds:
	// by it rayd tells a process started since its last round, whose
	// refusals are all new, from one it reads for the first time.
	Uptime int64 `json:"uptime"`
}

// uptime is how long the process has run, in whole seconds.
func uptime() int64 { return int64(time.Since(procStart) / time.Second) }

// UserTraffic are a name's bytes at the destinations' side.
type UserTraffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (u *hy2Users) trafficSnapshot() HysteriaTraffic {
	u.mu.Lock()
	st := HysteriaTraffic{V: 1, Boot: u.boot, Users: make(map[string]UserTraffic, len(u.traffic)), Uptime: uptime()}
	for name, t := range u.traffic {
		st.Users[name] = UserTraffic{Up: t.up.Load(), Down: t.down.Load()}
	}
	u.mu.Unlock()
	if u.limits != nil {
		st.Limit = u.limits.Refused() // none: left out of the answer
	}
	return st
}
