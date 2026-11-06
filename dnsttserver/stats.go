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

	SessionsAdmitted  atomic.Uint64 // new ClientIDs let in
	RefusedFull       atomic.Uint64 // not admitted: MaxSessions or MaxHandshakes reached
	RefusedRate       atomic.Uint64 // not admitted: NewSessionsPerSecond
	RefusedDevice     atomic.Uint64 // not admitted: the device's MaxSessionsPerDevice
	SessionsEvicted   atomic.Uint64 // a device's silent session closed for its new one
	HandshakeTimeouts atomic.Uint64 // closed with the Noise handshake undone
	StreamsRefused    atomic.Uint64 // over MaxStreams

	// Started is when the backend started (zero: not said): a reader tells
	// a restart, whose counters start again from 0, by it.
	Started time.Time

	// The current sessions and handshakes, from the session table.
	current func() (sessions, handshakes int)
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
	RefusedFull       uint64 `json:"sessions_refused_full"`
	RefusedRate       uint64 `json:"sessions_refused_rate"`
	RefusedDevice     uint64 `json:"sessions_refused_device"`
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
	if f := s.current; f != nil {
		out.Sessions, out.Handshakes = f()
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
