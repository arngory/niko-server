//go:build linux

package nikoserver

import (
	"net"
	"sync"

	"github.com/sagernet/sing-quic/hysteria2"
)

// A Hysteria2 backend's users (raycontrol docs/spec/traffic-limit-v1.md
// §3.2): the service's table and the connections open under each password.
// The service checks a password once per connection, so a name gone from
// the users file (disabled, expired, over its limit) or given another
// password loses its connections here, as Yggdrasil's removed keys lose
// their links.

// hy2User is the service's user: one per name and password. A reload keeps
// it while the users file gives that password to that name; otherwise it
// is revoked and its connections closed. The service's user type is this
// and not the name alone (as in sing-box): a connection's user then tells
// which password it came in with, without the password.
type hy2User struct {
	name    string
	revoked bool // under hy2Users.mu
}

// hy2Conn is an authenticated QUIC connection: close ends it, its streams
// and datagram sessions with it.
type hy2Conn struct{ close func() }

type hy2Users struct {
	mu     sync.Mutex
	byPass map[string]*hy2User // the service's table
	conns  map[*hy2User]map[*hy2Conn]bool
}

func newHy2Users() *hy2Users { return &hy2Users{} }

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
			user = &hy2User{name: name}
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
