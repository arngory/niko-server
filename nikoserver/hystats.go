//go:build linux

package nikoserver

import (
	"bufio"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
)

// Stats of the Hysteria2 sessions of a backend, for raycontrol's channel
// probes (its probe-v1, "link"): what the server knows of the connections
// from one client address. Aggregates only, since several people may share
// an address behind carrier-grade NAT; asked with a user's name, the
// sessions of that user from the address one by one as well (own).

// HysteriaStats answers a stats query.
type HysteriaStats struct {
	Connections int     `json:"connections"`
	RTTus       Spread  `json:"rtt_us"`     // smoothed RTT
	MinRTTus    uint64  `json:"min_rtt_us"` // the least of the connections' minimum RTT
	PacketsSent uint64  `json:"packets_sent"`
	PacketsLost uint64  `json:"packets_lost"`
	LossRate    float64 `json:"loss_rate"`
	// Brutal: the connections whose client gave its rate; the server sends
	// at it and paces by the acknowledged share.
	Brutal struct {
		Connections int         `json:"connections"`
		RateBps     Spread      `json:"rate_bps"`
		AckRate     FloatSpread `json:"ack_rate"`
	} `json:"brutal"`
	// Own are the sessions of the user named in the query (and of its
	// rotating variants, name-*), one by one; absent without a name.
	Own []SessionStats `json:"own,omitempty"`
}

// SessionStats is one session of the asking user.
type SessionStats struct {
	RTTus       uint64 `json:"rtt_us"`
	MinRTTus    uint64 `json:"min_rtt_us"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsLost uint64 `json:"packets_lost"`
	// Brutal: the rate the server sends at and its acknowledged share;
	// absent when the client left the rate to the server (BBR).
	Brutal *struct {
		RateBps uint64  `json:"rate_bps"`
		AckRate float64 `json:"ack_rate"`
	} `json:"brutal,omitempty"`
}

// Spread is the minimum, median and maximum over the connections.
type Spread struct {
	Min    uint64 `json:"min"`
	Median uint64 `json:"median"`
	Max    uint64 `json:"max"`
}

// FloatSpread is Spread for shares.
type FloatSpread struct {
	Min    float64 `json:"min"`
	Median float64 `json:"median"`
	Max    float64 `json:"max"`
}

func spreadOf(v []uint64) Spread {
	if len(v) == 0 {
		return Spread{}
	}
	slices.Sort(v)
	return Spread{Min: v[0], Median: v[len(v)/2], Max: v[len(v)-1]}
}

func floatSpreadOf(v []float64) FloatSpread {
	if len(v) == 0 {
		return FloatSpread{}
	}
	slices.Sort(v)
	return FloatSpread{Min: v[0], Median: v[len(v)/2], Max: v[len(v)-1]}
}

// sessions are the live Hysteria2 connections by client address.
type sessions struct {
	mu   sync.Mutex
	byIP map[netip.Addr]map[*session]bool
}

type session struct {
	user  string
	stats func() hysteria2.ConnectionStats
}

// hook is the service's ConnectionHook.
func (t *sessions) hook(remote net.Addr, user any, stats func() hysteria2.ConnectionStats, done <-chan struct{}) {
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return
	}
	ip := ap.Addr().Unmap()
	name, _ := user.(string)
	s := &session{user: name, stats: stats}
	t.mu.Lock()
	if t.byIP == nil {
		t.byIP = map[netip.Addr]map[*session]bool{}
	}
	if t.byIP[ip] == nil {
		t.byIP[ip] = map[*session]bool{}
	}
	t.byIP[ip][s] = true
	t.mu.Unlock()
	go func() {
		<-done
		t.mu.Lock()
		delete(t.byIP[ip], s)
		if len(t.byIP[ip]) == 0 {
			delete(t.byIP, ip)
		}
		t.mu.Unlock()
	}()
}

// owns reports whether a session's user is name or one of its variants
// (name-n, name-p while a credential rotates).
func owns(user, name string) bool {
	return name != "" && (user == name || strings.HasPrefix(user, name+"-"))
}

func (t *sessions) stats(ip netip.Addr, name string) HysteriaStats {
	t.mu.Lock()
	var list []*session
	for s := range t.byIP[ip.Unmap()] {
		list = append(list, s)
	}
	t.mu.Unlock()
	var st HysteriaStats
	var rtts, rates []uint64
	var acks []float64
	for _, s := range list {
		c := s.stats()
		if owns(s.user, name) {
			own := SessionStats{RTTus: uint64(c.SmoothedRTT.Microseconds()), MinRTTus: uint64(c.MinRTT.Microseconds()),
				PacketsSent: c.PacketsSent, PacketsLost: c.PacketsLost}
			if c.Brutal {
				own.Brutal = &struct {
					RateBps uint64  `json:"rate_bps"`
					AckRate float64 `json:"ack_rate"`
				}{c.RateBPS * 8, c.AckRate}
			}
			st.Own = append(st.Own, own)
		}
		st.Connections++
		rtts = append(rtts, uint64(c.SmoothedRTT.Microseconds()))
		if m := uint64(c.MinRTT.Microseconds()); m > 0 && (st.MinRTTus == 0 || m < st.MinRTTus) {
			st.MinRTTus = m
		}
		st.PacketsSent += c.PacketsSent
		st.PacketsLost += c.PacketsLost
		if c.Brutal {
			st.Brutal.Connections++
			rates = append(rates, c.RateBPS*8)
			acks = append(acks, c.AckRate)
		}
	}
	st.RTTus = spreadOf(rtts)
	st.Brutal.RateBps, st.Brutal.AckRate = spreadOf(rates), floatSpreadOf(acks)
	if st.PacketsSent > 0 {
		st.LossRate = float64(st.PacketsLost) / float64(st.PacketsSent)
	}
	return st
}

// serveStats answers on a unix socket: a client address on one line in,
// optionally followed by a space and a user's name, HysteriaStats as JSON
// out. The socket's directory keeps it to the service's group (raycontrol's
// rayd).
func (t *sessions) serveStats(path string, log *Logger) (func(), error) {
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
				if !acceptAgain(err, log) {
					return
				}
				continue
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				line, err := bufio.NewReader(&limitedReader{c, 192}).ReadString('\n')
				addr, name, _ := strings.Cut(strings.TrimSpace(line), " ")
				ip, perr := netip.ParseAddr(addr)
				if err != nil || perr != nil {
					return
				}
				_ = json.NewEncoder(c).Encode(t.stats(ip, strings.TrimSpace(name)))
			}()
		}
	}()
	log.Infof("stats on %s", path)
	return func() { ln.Close() }, nil
}

type limitedReader struct {
	c net.Conn
	n int
}

func (r *limitedReader) Read(b []byte) (int, error) {
	if r.n <= 0 {
		return 0, net.ErrClosed
	}
	if len(b) > r.n {
		b = b[:r.n]
	}
	n, err := r.c.Read(b)
	r.n -= n
	return n, err
}
