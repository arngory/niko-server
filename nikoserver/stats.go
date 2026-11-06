package nikoserver

import (
	"encoding/json"
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
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(c).Encode(snapshot())
			c.Close()
		}
	}()
	log.Infof("stats on %s", path)
	return func() { ln.Close() }, nil
}

// dnsFrontStats counts what the DNS front did since it started, for the
// node's metrics (raycontrol: rayctl metrics, and which zone of a tunnel
// its clients still reach, dnszones-v1). Safe for concurrent use.
type dnsFrontStats struct {
	started time.Time
	// Queries in a zone, by zone: the map is made before the front serves
	// and only read after.
	queries map[string]*atomic.Uint64

	malformed, refused, apex, probes, probesOverRate, forwarded, backendAway, answers, unmatched, truncated atomic.Uint64
}

func newDNSFrontStats(zones []string) *dnsFrontStats {
	s := &dnsFrontStats{started: time.Now(), queries: make(map[string]*atomic.Uint64, len(zones))}
	for _, z := range zones {
		s.queries[z] = new(atomic.Uint64)
	}
	return s
}

// DNSFrontSnapshot is what the DNS front gives on dns.stats_socket (v0.11.0).
type DNSFrontSnapshot struct {
	Started        int64             `json:"started"`          // the front's start, Unix seconds
	Queries        map[string]uint64 `json:"queries"`          // queries in a zone, by zone
	Malformed      uint64            `json:"malformed"`        // datagrams that are no query the front reads, or too large
	Refused        uint64            `json:"refused"`          // queries outside the zones: REFUSED
	Apex           uint64            `json:"apex"`             // answered at a zone's apex (SOA, NS)
	Probes         uint64            `json:"probes"`           // dnsprobe-v1 probes answered
	ProbesOverRate uint64            `json:"probes_over_rate"` // probes over the rate: no answer
	Forwarded      uint64            `json:"forwarded"`        // queries passed to a backend
	BackendAway    uint64            `json:"backend_away"`     // not passed: the backend away, or its queue full
	Answers        uint64            `json:"answers"`          // the backends' answers sent on
	Unmatched      uint64            `json:"unmatched"`        // the backends' answers no query waited for: dropped
	Truncated      uint64            `json:"truncated"`        // answers over the requester's size: sent with TC, no records
}

func (s *dnsFrontStats) snapshot() DNSFrontSnapshot {
	out := DNSFrontSnapshot{
		Started: s.started.Unix(), Queries: make(map[string]uint64, len(s.queries)),
		Malformed: s.malformed.Load(), Refused: s.refused.Load(), Apex: s.apex.Load(),
		Probes: s.probes.Load(), ProbesOverRate: s.probesOverRate.Load(),
		Forwarded: s.forwarded.Load(), BackendAway: s.backendAway.Load(),
		Answers: s.answers.Load(), Unmatched: s.unmatched.Load(), Truncated: s.truncated.Load(),
	}
	for z, n := range s.queries {
		out.Queries[z] = n.Load()
	}
	return out
}
