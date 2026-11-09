//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TCP's dial for a user (raycontrol docs/spec/conn-limit-v1.md §2, §3.2): a
// name's addresses come from the process's cache; each address tried is an
// attempt, the first paid when the stream was admitted (tcpStart) and each
// next one a token of its own; an attempt that sent a SYN and got no
// connection charges the failed dials. IPv4 and IPv6 race as Go's dialer
// has them (a fallback after 300 ms): before, Go's dialer did all of it
// inside one Dial, where nothing could be counted.
const (
	fallbackDelay = 300 * time.Millisecond
	// minAttempt is the least time one address of several gets, as Go's.
	minAttempt = 2 * time.Second
)

// dialUser reaches destination for the user: the probe name's address on
// the node, or the destination's addresses through o.dial, which refuses
// those that are not public.
func (o *outbound) dialUser(ctx context.Context, user string, destination M.Socksaddr) (net.Conn, error) {
	lim := o.limits()
	if o.isProbe(destination) {
		// The probe name leads to its address on the node, and only it.
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", o.probe.Address)
		lim.failedDial(user, err)
		return c, err
	}
	addrs := []netip.Addr{destination.Addr}
	if !destination.Addr.IsValid() {
		// A name, or what is none: "no such host" then, without a lookup.
		var err error
		if addrs, err = lim.lookupName(ctx, user, destination.Fqdn); err != nil {
			return nil, err
		}
	}
	list := make([]netip.AddrPort, len(addrs))
	for i, a := range addrs {
		list[i] = netip.AddrPortFrom(a.Unmap(), destination.Port)
	}
	return o.dialRace(ctx, user, list)
}

// dialRace dials the addresses of the first one's family in turn, and
// those of the other family from fallbackDelay on (or once the first
// family failed), as Go's dialer does: the first connection wins.
func (o *outbound) dialRace(ctx context.Context, user string, addrs []netip.AddrPort) (net.Conn, error) {
	var primary, fallback []netip.AddrPort
	for _, a := range addrs {
		if a.Addr().Is4() == addrs[0].Addr().Is4() {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	var paid atomic.Bool // the first attempt was paid when the stream was admitted
	paid.Store(true)
	if len(fallback) == 0 {
		return o.dialSerial(ctx, user, primary, &paid)
	}
	type result struct {
		c       net.Conn
		err     error
		primary bool
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	start := func(list []netip.AddrPort, primary bool) {
		go func() {
			c, err := o.dialSerial(ctx, user, list, &paid)
			results <- result{c, err, primary}
		}()
	}
	start(primary, true)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var firstErr error
	started, done := 1, 0
	for {
		select {
		case <-timer.C:
			if started == 1 {
				start(fallback, false)
				started++
			}
		case r := <-results:
			done++
			if r.err == nil {
				// The other one, if it comes, is closed.
				go func(left int) {
					for range left {
						if r := <-results; r.c != nil {
							_ = r.c.Close()
						}
					}
				}(started - done)
				return r.c, nil
			}
			if firstErr == nil || r.primary {
				firstErr = r.err
			}
			if started == 1 {
				timer.Stop()
				start(fallback, false)
				started++
			} else if done == started {
				return nil, firstErr
			}
		}
	}
}

// dialSerial tries the addresses in turn, each within its share of the
// time left. An attempt takes the token paid at the stream's admission if
// it is still there, or a new one now, or ends the dial.
func (o *outbound) dialSerial(ctx context.Context, user string, addrs []netip.AddrPort, paid *atomic.Bool) (net.Conn, error) {
	lim := o.limits()
	var firstErr error
	for i, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		if !paid.CompareAndSwap(true, false) && !lim.attempt(user) {
			if firstErr == nil {
				firstErr = errTooMany
			}
			break
		}
		actx := ctx
		if d, ok := ctx.Deadline(); ok {
			share := time.Until(d) / time.Duration(len(addrs)-i)
			if share < minAttempt {
				share = min(minAttempt, time.Until(d))
			}
			var cancel context.CancelFunc
			actx, cancel = context.WithTimeout(ctx, share)
			defer cancel()
		}
		c, err := o.dial(actx, "tcp", a.String())
		if err == nil {
			return c, nil
		}
		switch {
		case errors.Is(err, errNotPublic):
			// No SYN went: the token is the next attempt's.
			paid.Store(true)
		case !errors.Is(ctx.Err(), context.Canceled):
			// A race lost, or a backend stopping, sent its SYN for nothing
			// of the user's doing: not charged.
			lim.failedDial(user, err)
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return nil, firstErr
}
