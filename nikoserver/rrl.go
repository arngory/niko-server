//go:build linux

package nikoserver

import (
	"net/netip"
	"sync"
	"time"
)

// frontRRL (v0.19.3, review 2026-11-21 item 7) limits what the DNS front
// sends to one address block (its /24, or /48), the address an answer goes
// to being one anyone can forge as a query's source:
//
//   - the front's own answers, REFUSED (about the query's size) and the
//     apex's (SOA and NS, about 2.5 times), rrlRate a second (rrlBurst at
//     once); past that none: a resolver asks again, and the apex's answers
//     are kept 300 s. No TC to call it over TCP, as RRL does elsewhere: the
//     node has no TCP 53. Probes keep their own limits (dnsprobe.go);
//   - the SOA of a NODATA below the apex (some 60 bytes): the same rate,
//     past it the NODATA goes without it. A NODATA is never held back: a
//     resolver minimising QNAMEs asks for the names above a tunnel's
//     query (RFC 9156), a few for each, and a NODATA is no larger than the
//     query;
//   - the backends' answers, tunnel data among them, rrlDataRate bytes a
//     second (rrlDataBurst at once); past that they are dropped, counted:
//     whoever has a device's key can have its session's data, up to 1232
//     bytes for a query of 100, sent to an address of their choice. The
//     budget is far over what DNS tunnels carry through one resolver's
//     block (a dnstt or slipstream session takes some tens to hundreds of
//     KB/s through a resolver): it only cuts a reflection. A tunnel over it
//     slows, it does not break (its queries go on, KCP and QUIC send again).
//
// Each block's buckets live two generations of rrlLife (rrlMax blocks a
// generation, a flood of blocks swaps them sooner): a block forgotten
// starts full again.
type frontRRL struct {
	dataRate  float64 // bytes a second to a block, 0: rrlDataRate; < 0: no limit (dns.rrl_data_kib)
	mu        sync.Mutex
	cur, prev map[netip.Prefix]*rrlBlock
	swapped   time.Time
	now       func() time.Time // time.Now when nil (tests)
}

type rrlBlock struct{ own, soa, data tokenBucket }

const (
	rrlRate, rrlBurst         = 20, 40
	rrlDataRate, rrlDataBurst = 4 << 20, 8 << 20
	rrlLife                   = time.Minute
	rrlMax                    = 1 << 14
)

// block is addr's block's buckets, now; the caller holds mu.
func (r *frontRRL) block(addr netip.Addr, now time.Time) *rrlBlock {
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	prefix, _ := addr.Prefix(bits)
	if r.cur == nil || now.Sub(r.swapped) > rrlLife || len(r.cur) >= rrlMax {
		r.prev, r.cur, r.swapped = r.cur, make(map[netip.Prefix]*rrlBlock), now
	}
	b := r.cur[prefix]
	if b == nil {
		if b = r.prev[prefix]; b == nil {
			b = &rrlBlock{}
		}
		r.cur[prefix] = b
	}
	return b
}

func (r *frontRRL) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// own reports whether one of the front's own answers (REFUSED, the apex's)
// may go to addr now.
func (r *frontRRL) own(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	return r.block(addr, now).own.take(1, rrlRate, rrlBurst, now)
}

// soa reports whether a NODATA to addr may carry its zone's SOA now.
func (r *frontRRL) soa(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	return r.block(addr, now).soa.take(1, rrlRate, rrlBurst, now)
}

// data reports whether a backend's answer of n bytes may go to addr now.
func (r *frontRRL) data(addr netip.Addr, n int) bool {
	rate, burst := float64(rrlDataRate), float64(rrlDataBurst)
	switch {
	case r.dataRate < 0:
		return true
	case r.dataRate > 0:
		rate, burst = r.dataRate, 2*r.dataRate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	return r.block(addr, now).data.take(float64(n), rate, burst, now)
}
