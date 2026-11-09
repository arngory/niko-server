//go:build linux

package nikoserver

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// LAN over Yggdrasil (raycontrol docs/spec/lan-v1.md, v0.16.0): a user's
// devices reach each other through the node. A key of the users file may
// carry a group, its user's base name ("yggdrasil": {"lan": "u5"}); on a
// client's link the filter passes the frames between two keys of one
// group (yggRule), and charges those the node relays between them, neither
// end the node, to the group's bucket (lan-v1 §4.4): lan_relay_mbps a
// group, a second's worth of burst. Over it a frame is dropped and TCP
// inside slows down; at 0 nothing is relayed. What passed counts for
// raycontrol's traffic limits (traffic-limit-v1 §2.2) by group, on the
// stats socket's traffic line, as Hysteria2's names do: the relay goes
// past inner, where Xray counts everything else. A group gone from the
// users file is dropped once it has relayed nothing for trafficStale
// (prune). Nothing of it goes to the log: no keys, no groups, no frames
// (§4.3).

// yggLANRelayDefault is a group's ceiling without lan_relay_mbps, Mbit/s.
const yggLANRelayDefault = 20

// yggLANName is a group as raycontrol writes it, its user's base name
// u<id>.
var yggLANName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// yggRelay is the backend's groups by name, and the relay's totals for the
// stats snapshot. A group gone from the users file is kept (raycontrol
// counts by name; one that comes back keeps its count and its bucket)
// until it has relayed nothing for trafficStale since it left, as
// Hysteria2's names (prune).
type yggRelay struct {
	rate  float64 // a group's bytes a second, its burst too; 0: nothing relayed
	boot  string  // random at each start, as Hysteria2's
	now   func() time.Time
	stale time.Duration // trafficStale when 0 (tests make it short)

	mu     sync.Mutex
	byName map[string]*yggLAN
	in     map[string]bool // the users file's groups

	frames, bytes, dropped atomic.Uint64 // relayed, and dropped over a group's rate
}

func newYggRelay(mbps int) *yggRelay {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails (Go 1.24)
	return &yggRelay{rate: float64(mbps) * 1e6 / 8, boot: hex.EncodeToString(b[:]), now: time.Now}
}

// group is the group of a name, its bucket full at its first sight.
func (r *yggRelay) group(name string) *yggLAN {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.groupOf(name)
}

// groupOf is group under r.mu.
func (r *yggRelay) groupOf(name string) *yggLAN {
	g := r.byName[name]
	if g == nil {
		if r.byName == nil {
			r.byName = map[string]*yggLAN{}
		}
		g = &yggLAN{relay: r, tokens: r.rate, last: r.now()}
		r.byName[name] = g
	}
	return g
}

// take is a reading of the users file's groups: the group of each name,
// and those it no longer has pruned. Under r.mu, so that prune never drops
// a group the reading has.
func (r *yggRelay) take(names map[string]bool) map[string]*yggLAN {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.in = names
	groups := make(map[string]*yggLAN, len(names))
	for name := range names {
		groups[name] = r.groupOf(name)
	}
	r.prune(r.now())
	return groups
}

// check is the watch's look every few seconds: prune.
func (r *yggRelay) check() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(r.now())
}

// prune drops the groups the users file no longer has, nothing relayed
// for them for trafficStale or longer since the first look that saw them
// gone. A group back in the file keeps its count; one dropped and back
// starts from 0, which rayd takes as a name it has not seen. Under r.mu.
func (r *yggRelay) prune(now time.Time) {
	stale := r.stale
	if stale <= 0 {
		stale = trafficStale
	}
	for name, g := range r.byName {
		switch {
		case r.in[name]:
			g.gone = time.Time{}
		case g.gone.IsZero():
			g.gone = now
		case now.Sub(g.gone) >= stale && now.Sub(g.charged()) >= stale:
			delete(r.byName, name)
		}
	}
}

// traffic answers the stats socket's traffic line as Hysteria2's does:
// each group's bytes relayed since the process started (or since it came
// back after prune dropped it), up as they came in from its devices; down
// is always 0 (a relayed frame counts once, where it comes in). The groups
// of the users file are there from their first reading, 0 or not.
func (r *yggRelay) traffic() HysteriaTraffic {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := HysteriaTraffic{V: 1, Boot: r.boot, Users: make(map[string]UserTraffic, len(r.byName))}
	for name, g := range r.byName {
		t.Users[name] = UserTraffic{Up: g.up.Load()}
	}
	return t
}

// yggLAN is a group: its token bucket and the bytes it let through.
type yggLAN struct {
	relay *yggRelay

	mu     sync.Mutex
	tokens float64   // bytes; up to a second's worth
	last   time.Time // the bucket's last fill: the last frame charged

	up   atomic.Int64
	gone time.Time // under relay.mu: when prune first saw it out of the file
}

// charged is when the group was last charged a frame (made, if never).
func (g *yggLAN) charged() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

// pass charges a relayed frame of size bytes to the group: true when the
// bucket holds that many, which it then loses. Counted either way.
func (g *yggLAN) pass(size int) bool {
	r := g.relay
	ok := false
	if r.rate > 0 {
		g.mu.Lock()
		now := r.now()
		g.tokens = min(r.rate, g.tokens+now.Sub(g.last).Seconds()*r.rate)
		g.last = now
		if ok = g.tokens >= float64(size); ok {
			g.tokens -= float64(size)
		}
		g.mu.Unlock()
	}
	if !ok {
		r.dropped.Add(1)
		return false
	}
	g.up.Add(int64(size))
	r.frames.Add(1)
	r.bytes.Add(uint64(size))
	return true
}
