package nikoserver

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// serveStats gives snapshot() on a unix socket: to each connection one
// JSON line, then the close; nothing is read. The socket's directory keeps
// it to the service's group (raycontrol's rayd): a dnstt backend's
// counters (stats_socket), the DNS front's (dns.stats_socket).
func serveStats(path string, snapshot func() any, log *Logger) (func(), error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		var backoff acceptBackoff
		for {
			c, err := ln.Accept()
			if err != nil {
				if !backoff.again(err, log) {
					return
				}
				continue
			}
			backoff.ok()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(c).Encode(snapshot())
			c.Close()
		}
	}()
	log.Infof("stats on %s", path)
	return func() { ln.Close() }, nil
}

// acceptBackoff paces a stats socket's accept loop: an Accept error
// leaves the socket serving, only its close ends it. Out of descriptors
// (EMFILE under a flood of the front's own connections) waits and goes on
// (review 12: one EMFILE ended the stats for good, without a word): 5 ms
// at first, twice as long each time up to 1 s, from the start again after
// an accept that works; each error said once in an episode, until another
// comes or an accept works (review 13: 20 lines a second while the
// descriptors ran out).
type acceptBackoff struct {
	delay time.Duration
	said  string
}

func (b *acceptBackoff) again(err error, log *Logger) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if msg := err.Error(); msg != b.said {
		b.said = msg
		log.Warnf("stats socket: %v", err)
	}
	time.Sleep(b.next())
	return true
}

// ok is an accept that worked: the next error waits from the start and is
// said again, once (review 14: after a first episode the later ones were
// silent for the life of the process).
func (b *acceptBackoff) ok() { b.delay, b.said = 0, "" }

// next is the wait after one more error.
func (b *acceptBackoff) next() time.Duration {
	b.delay = min(max(2*b.delay, 5*time.Millisecond), time.Second)
	return b.delay
}

// startStats serves snapshot on path when path is set; a socket that
// cannot be made is said and left out: the counters are not worth the
// service (review 12: the front's TCP and UDP 443 went down with it).
func startStats(path string, snapshot func() any, log *Logger) func() {
	if path == "" {
		return func() {}
	}
	stop, err := serveStats(path, snapshot, log)
	if err != nil {
		log.Warnf("stats socket %s: %v; no counters", path, err)
		return func() {}
	}
	return stop
}

// dnsFrontStats counts what the DNS front did since it started, for the
// node's metrics (raycontrol: rayctl metrics, and which zone of a tunnel
// its clients still reach, dnszones-v1). Safe for concurrent use.
type dnsFrontStats struct {
	started time.Time
	// Queries in a zone, by zone: the map is made before the front serves
	// and only read after.
	queries map[string]*atomic.Uint64

	malformed, refused, apex, probes, probesOverRate, forwarded, backendAway, answers, unmatched, truncated, dropped, untagged atomic.Uint64
}

func newDNSFrontStats(zones []string) *dnsFrontStats {
	s := &dnsFrontStats{started: time.Now(), queries: make(map[string]*atomic.Uint64, len(zones))}
	for _, z := range zones {
		s.queries[z] = new(atomic.Uint64)
	}
	return s
}

// DNSFrontSnapshot is what the DNS front gives on dns.stats_socket (v0.11.0).
// Its queries by zone are load, not reach: anyone can send a zone's name to
// UDP 53. Which zone clients reach is dnstt's count of its zones' queries
// that passed dnsauth (StatsSnapshot.Zones).
type DNSFrontSnapshot struct {
	Started        int64             `json:"started"`          // the front's start, Unix seconds
	Queries        map[string]uint64 `json:"queries"`          // queries in a zone, by zone
	Malformed      uint64            `json:"malformed"`        // datagrams that are no query the front reads, or too large
	Refused        uint64            `json:"refused"`          // queries outside the zones: REFUSED
	Apex           uint64            `json:"apex"`             // answered at a zone's apex (SOA, NS)
	Probes         uint64            `json:"probes"`           // dnsprobe-v1 probes answered
	ProbesOverRate uint64            `json:"probes_over_rate"` // probes over the rate: no answer
	Forwarded      uint64            `json:"forwarded"`        // queries put in a backend's queue (a lost connection drops what waits there)
	BackendAway    uint64            `json:"backend_away"`     // not queued: the backend away, or its queue full
	Answers        uint64            `json:"answers"`          // the backends' answers sent on
	Unmatched      uint64            `json:"unmatched"`        // the backends' answers no query waited for: dropped
	Truncated      uint64            `json:"truncated"`        // answers over the requester's size: sent with TC, no records (in answers)
	Dropped        uint64            `json:"dropped"`          // the backends' messages not sent on: unreadable, no question to truncate to, a failed write
	Untagged       uint64            `json:"untagged"`         // queries of a tagged zone (slipstream) without a device's tag: NOERROR, the backend sees none (v0.13.0)
}

func (s *dnsFrontStats) snapshot() DNSFrontSnapshot {
	out := DNSFrontSnapshot{
		Started: s.started.Unix(), Queries: make(map[string]uint64, len(s.queries)),
		Malformed: s.malformed.Load(), Refused: s.refused.Load(), Apex: s.apex.Load(),
		Probes: s.probes.Load(), ProbesOverRate: s.probesOverRate.Load(),
		Forwarded: s.forwarded.Load(), BackendAway: s.backendAway.Load(),
		Answers: s.answers.Load(), Unmatched: s.unmatched.Load(), Truncated: s.truncated.Load(), Dropped: s.dropped.Load(), Untagged: s.untagged.Load(),
	}
	for z, n := range s.queries {
		out.Queries[z] = n.Load()
	}
	return out
}
