package dnsttserver

import (
	"sync/atomic"
	"time"
)

// Stats counts what the dnstt backend did since it started (neko), for the
// node's metrics (raycontrol: rayctl metrics, the status's events). Safe for
// concurrent use; the zero value counts.
type Stats struct {
	Queries  atomic.Uint64 // DNS queries parsed
	MemoHits atomic.Uint64 // retries answered from the memo

	SessionsAdmitted atomic.Uint64 // new ClientIDs let in
	// Session starts refused: start packets of a ClientID not let in, so a
	// client's retries (KCP's, a resolver's) count again.
	RefusedFull       atomic.Uint64 // MaxSessions or MaxHandshakes reached
	RefusedRate       atomic.Uint64 // over NewSessionsPerSecond
	RefusedDevice     atomic.Uint64 // the device's MaxSessionsPerDevice
	SessionsEvicted   atomic.Uint64 // a device's silent session closed for its new one
	HandshakeTimeouts atomic.Uint64 // closed with the Noise handshake undone
	StreamsRefused    atomic.Uint64 // over MaxStreams

	// Started is when the backend started (zero: not said): a reader tells
	// a restart, whose counters start again from 0, by it.
	Started time.Time

	// The current sessions and handshakes, from the session table, which
	// comes after the stats socket may already read (review 11: a race).
	current atomic.Pointer[func() (sessions, handshakes int)]
	// Each zone's queries that carried a device's valid tag, set up by run
	// as current is.
	zones atomic.Pointer[zoneCounts]
}

// zoneCounts are the tagged queries of each zone, in the order of run's
// domains (the main zone first).
type zoneCounts struct {
	names  []string
	tagged []atomic.Uint64
}

// setZones starts the zones' counts.
func (s *Stats) setZones(names []string) {
	s.zones.Store(&zoneCounts{names: names, tagged: make([]atomic.Uint64, len(names))})
}

// tagged counts a query of zone i (run's domains) with a device's valid tag.
func (s *Stats) tagged(i int) {
	if z := s.zones.Load(); z != nil && i >= 0 && i < len(z.tagged) {
		z.tagged[i].Add(1)
	}
}

// StatsSnapshot is Stats at one moment, as the stats socket gives it (JSON),
// with the dnsauth-v1 and dnsseal-v1 counters of the service.
type StatsSnapshot struct {
	Started           int64  `json:"started,omitempty"` // Unix seconds
	Queries           uint64 `json:"queries"`
	MemoHits          uint64 `json:"memo_hits"`
	Sessions          int    `json:"sessions"`
	Handshakes        int    `json:"handshakes"`
	SessionsAdmitted  uint64 `json:"sessions_admitted"`
	RefusedFull       uint64 `json:"starts_refused_full"`
	RefusedRate       uint64 `json:"starts_refused_rate"`
	RefusedDevice     uint64 `json:"starts_refused_device"`
	SessionsEvicted   uint64 `json:"sessions_evicted"`
	HandshakeTimeouts uint64 `json:"handshake_timeouts"`
	StreamsRefused    uint64 `json:"streams_refused"`
	AuthValid         uint64 `json:"auth_valid"`
	AuthUntagged      uint64 `json:"auth_untagged"`
	AuthRefused       uint64 `json:"auth_refused"`
	AuthThrottled     uint64 `json:"auth_throttled"`
	SealOpened        uint64 `json:"seal_opened"`
	SealUnsealed      uint64 `json:"seal_unsealed"`
	SealRefused       uint64 `json:"seal_refused"`
	// Zones are each zone's queries with a device's valid dnsauth tag:
	// which zone of the tunnel clients reach (raycontrol dnszones-v1),
	// which no one without a device's key can make up; none with auth off.
	Zones map[string]uint64 `json:"zones,omitempty"`
}

// Snapshot reads the counters, those of auth and seal too (either may be
// nil).
func (s *Stats) Snapshot(auth *Auth, seal *Seal) StatsSnapshot {
	out := StatsSnapshot{
		Queries: s.Queries.Load(), MemoHits: s.MemoHits.Load(),
		SessionsAdmitted: s.SessionsAdmitted.Load(), RefusedFull: s.RefusedFull.Load(), RefusedRate: s.RefusedRate.Load(),
		RefusedDevice: s.RefusedDevice.Load(), SessionsEvicted: s.SessionsEvicted.Load(),
		HandshakeTimeouts: s.HandshakeTimeouts.Load(), StreamsRefused: s.StreamsRefused.Load(),
	}
	if !s.Started.IsZero() {
		out.Started = s.Started.Unix()
	}
	if f := s.current.Load(); f != nil {
		out.Sessions, out.Handshakes = (*f)()
	}
	if z := s.zones.Load(); z != nil && auth != nil && auth.Mode != AuthOff {
		out.Zones = make(map[string]uint64, len(z.names))
		for i, name := range z.names {
			out.Zones[name] = z.tagged[i].Load()
		}
	}
	if auth != nil {
		out.AuthValid, out.AuthUntagged = auth.Valid.Load(), auth.Untagged.Load()
		out.AuthRefused, out.AuthThrottled = auth.Refused.Load(), auth.Throttled.Load()
	}
	if seal != nil {
		out.SealOpened, out.SealUnsealed, out.SealRefused = seal.Opened.Load(), seal.Unsealed.Load(), seal.Refused.Load()
	}
	return out
}
