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
// and datagram sessions with it.
type hy2Conn struct{ close func() }

type hy2Users struct {
	mu     sync.Mutex
	byPass map[string]*hy2User // the service's table
	conns  map[*hy2User]map[*hy2Conn]bool
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
		}
		delete(u.conns, user)
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
// changed or not: prune.
func (u *hy2Users) check() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.prune(u.clock())
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
// meanwhile; leave takes it out when it ends.
func (u *hy2Users) admit(user *hy2User, c *hy2Conn) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if user == nil || user.revoked {
		return false
	}
	if u.conns == nil {
		u.conns = map[*hy2User]map[*hy2Conn]bool{}
	}
	if u.conns[user] == nil {
		u.conns[user] = map[*hy2Conn]bool{}
	}
	u.conns[user][c] = true
	user.traffic.live.Add(1)
	return true
}

// leave takes out a connection that admit let in.
func (u *hy2Users) leave(user *hy2User, c *hy2Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	user.traffic.live.Add(-1)
	delete(u.conns[user], c)
	if len(u.conns[user]) == 0 {
		delete(u.conns, user)
	}
}

// connectionHook is the service's ConnectionHook: a connection is admitted
// (or closed at once, its user revoked between its password check and
// now) and counted in its address's stats until it ends.
func connectionHook(users *hy2Users, live *sessions) func(net.Addr, any, func() hysteria2.ConnectionStats, func(), <-chan struct{}) {
	return func(remote net.Addr, user any, stats func() hysteria2.ConnectionStats, closeConnection func(), done <-chan struct{}) {
		u, _ := user.(*hy2User)
		c := &hy2Conn{close: closeConnection}
		if !users.admit(u, c) {
			closeConnection()
			return
		}
		forget := live.add(remote, u.name, stats)
		go func() {
			<-done
			forget()
			users.leave(u, c)
		}()
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
	// failed, udp, evicted, dest, live, lookup), since the process started
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
