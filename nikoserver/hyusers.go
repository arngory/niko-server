//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"

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
// destinations go to the log.

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
type hy2Traffic struct{ up, down atomic.Int64 }

// hy2Conn is an authenticated QUIC connection: close ends it, its streams
// and datagram sessions with it.
type hy2Conn struct{ close func() }

type hy2Users struct {
	mu     sync.Mutex
	byPass map[string]*hy2User // the service's table
	conns  map[*hy2User]map[*hy2Conn]bool
	// traffic is by name and kept until the process ends, the names gone
	// from the users file too: raycontrol counts by name.
	traffic map[string]*hy2Traffic
	boot    string
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
	for i, name := range names {
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
	u.mu.Unlock()
	for _, c := range doomed {
		c.close()
	}
	return len(doomed)
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
	return true
}

func (u *hy2Users) leave(user *hy2User, c *hy2Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
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
	if user, _ := auth.UserFromContext[*hy2User](ctx); user != nil {
		return user.traffic
	}
	return new(hy2Traffic)
}

// HysteriaTraffic answers the stats socket's traffic query: each name's
// bytes since the process started, as raycontrol's rayd reads them
// (traffic-limit-v1 §2.2). Reading resets nothing; Boot is random at each
// start, so a new one means the counters began again.
type HysteriaTraffic struct {
	V     int                    `json:"v"`
	Boot  string                 `json:"boot"`
	Users map[string]UserTraffic `json:"users"`
}

// UserTraffic are a name's bytes at the destinations' side.
type UserTraffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (u *hy2Users) trafficSnapshot() HysteriaTraffic {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := HysteriaTraffic{V: 1, Boot: u.boot, Users: make(map[string]UserTraffic, len(u.traffic))}
	for name, t := range u.traffic {
		st.Users[name] = UserTraffic{Up: t.up.Load(), Down: t.down.Load()}
	}
	return st
}
