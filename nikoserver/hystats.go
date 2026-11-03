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
// from one client address. Aggregates only: several people may share an
// address behind carrier-grade NAT.

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
	stats func() hysteria2.ConnectionStats
}

// hook is the service's ConnectionHook.
func (t *sessions) hook(remote net.Addr, stats func() hysteria2.ConnectionStats, done <-chan struct{}) {
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return
	}
	ip := ap.Addr().Unmap()
	s := &session{stats: stats}
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

func (t *sessions) stats(ip netip.Addr) HysteriaStats {
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
// HysteriaStats as JSON out. The socket's directory keeps it to the
// service's group (raycontrol's rayd).
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
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				line, err := bufio.NewReader(&limitedReader{c, 64}).ReadString('\n')
				ip, perr := netip.ParseAddr(strings.TrimSpace(line))
				if err != nil || perr != nil {
					return
				}
				_ = json.NewEncoder(c).Encode(t.stats(ip))
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
