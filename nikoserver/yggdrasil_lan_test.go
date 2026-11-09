//go:build linux

package nikoserver

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// LAN over Yggdrasil on real cores (raycontrol lan-v1): devices as Niko's,
// each a yggdrasil-go core (ironwood inside) with a netstack, linked to a
// Yggdrasil backend behind tcpmux, as on a node.

// lanDevice is a device: its core, its netstack and its key. It answers
// TCP on port 7 with "reached", and takes in whatever comes on port 9,
// counted.
type lanDevice struct {
	core *core.Core
	net  *stack.Stack
	key  ed25519.PublicKey
	sunk atomic.Int64
}

func newLANDevice(t *testing.T, ctx context.Context, n *yggNode, mtu ...uint32) *lanDevice {
	t.Helper()
	c, s, key := yggClientMTU(t, ctx, n.peer, append(mtu, 0)[0])
	d := &lanDevice{core: c, net: s, key: key}
	serve := func(port uint16, conn func(*gonet.TCPConn)) {
		ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Port: port}, ipv6.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go conn(c.(*gonet.TCPConn))
			}
		}()
	}
	serve(7, func(c *gonet.TCPConn) {
		c.Write([]byte("reached"))
		c.Close()
	})
	serve(9, func(c *gonet.TCPConn) {
		defer c.Close()
		b := make([]byte, 64<<10)
		for {
			n, err := c.Read(b)
			d.sunk.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	return d
}

func (d *lanDevice) up(t *testing.T) {
	t.Helper()
	d.core.RetryPeersNow()
	if !waitFor(10*time.Second, func() bool { return peerUp(d.core) }) {
		t.Fatalf("a device's link is not up: %+v", d.core.GetPeers())
	}
}

// reaches: TCP from d to e's port 7 gets "reached" within wait.
func (d *lanDevice) reaches(ctx context.Context, e *lanDevice, wait time.Duration) bool {
	c, err := yggDial(ctx, d.net, e.key, 7, wait)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(wait))
	b := make([]byte, 7)
	_, err = io.ReadFull(c, b)
	return err == nil && string(b) == "reached"
}

// exits: d reaches the node's exit port (inner, an echo here).
func (d *lanDevice) exits(ctx context.Context, n *yggNode) bool {
	c, err := yggDial(ctx, d.net, n.key, 4433, 10*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, 5)
	if _, err := c.Write([]byte("hello")); err != nil {
		return false
	}
	_, err = io.ReadFull(c, got)
	return err == nil && string(got) == "hello"
}

// uptime is how long d's link to the node has been up; 0 when down.
func (d *lanDevice) uptime() time.Duration {
	for _, p := range d.core.GetPeers() {
		if p.Up {
			return p.Uptime
		}
	}
	return 0
}

// bulk has d send to e's port 9 as fast as it goes for dur: what e took
// in, in what time.
func (d *lanDevice) bulk(t *testing.T, ctx context.Context, e *lanDevice, dur time.Duration) (int64, time.Duration) {
	t.Helper()
	c, err := yggDial(ctx, d.net, e.key, 9, 15*time.Second)
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	defer c.Close()
	before := e.sunk.Load()
	start := time.Now()
	c.SetWriteDeadline(start.Add(dur))
	b := make([]byte, 64<<10)
	for {
		if _, err := c.Write(b); err != nil {
			break
		}
	}
	took := time.Since(start)
	return e.sunk.Load() - before, took
}

func TestNekoServerYggdrasilLAN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // after the parallel subtests

	// The isolation first, its two nodes side by side, and only then the
	// rates: those saturate the CPU (under -race, on 4 cores, a link of
	// "groups" once missed ironwood's 3 s while they ran).
	t.Run("isolation", func(t *testing.T) { lanIsolation(ctx, t) })
	lanRates(ctx, t)
}

func lanIsolation(ctx context.Context, t *testing.T) {
	// Two devices of u5 reach each other through the node, both ways; a
	// device of u6 and one in no group reach neither, nor are reached; all
	// reach the node. What the node relayed counts for u5 on the traffic
	// line. A device whose group changes keeps its link and reaches its new
	// group at once; one taken out of its group keeps its link and reaches
	// no one but the node; one taken out of the users file loses its link.
	t.Run("groups", func(t *testing.T) {
		t.Parallel()
		n := startYggNode(t, ctx)
		a, b, c, d := newLANDevice(t, ctx, n), newLANDevice(t, ctx, n), newLANDevice(t, ctx, n), newLANDevice(t, ctx, n)
		n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{b.key, "u5"}, yggDevice{c.key, "u6"}, yggDevice{d.key, ""})
		for _, x := range []*lanDevice{a, b, c, d} {
			x.up(t)
		}
		if !a.reaches(ctx, b, 15*time.Second) || !b.reaches(ctx, a, 15*time.Second) {
			t.Fatal("two devices of one group do not reach each other")
		}
		type try struct {
			name     string
			from, to *lanDevice
		}
		tries := []try{{"u6 to u5", c, a}, {"u5 to u6", a, c}, {"none to u5", d, b}, {"u5 to none", b, d}, {"u6 to none", c, d}}
		reached := make([]bool, len(tries))
		var wg sync.WaitGroup
		for i, x := range tries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				reached[i] = x.from.reaches(ctx, x.to, 6*time.Second)
			}()
		}
		wg.Wait()
		for i, x := range tries {
			if reached[i] {
				t.Errorf("%s: reached", x.name)
			}
		}
		for _, x := range []*lanDevice{a, b, c, d} {
			if !peerUp(x.core) || !x.exits(ctx, n) {
				t.Fatal("a device's link went, or it does not reach the node")
			}
		}
		tr := n.traffic(t)
		if tr.V != 1 || len(tr.Boot) != 16 || len(tr.Users) != 2 || tr.Users["u5"].Up == 0 || tr.Users["u5"].Down != 0 {
			t.Fatalf("traffic %+v", tr)
		}
		// The totals of the snapshot are the groups' bytes.
		if !waitFor(5*time.Second, func() bool {
			tr, s := n.traffic(t), n.snapshot(t)
			return s.RelayedFrames > 0 && s.RelayedBytes == uint64(tr.Users["u5"].Up+tr.Users["u6"].Up)
		}) {
			t.Errorf("snapshot %+v, traffic %+v", n.snapshot(t), n.traffic(t))
		}
		t.Logf("u5 relayed %d bytes, u6 %d (its lookups); %+v", tr.Users["u5"].Up, tr.Users["u6"].Up, n.snapshot(t))

		// c joins u5: no cut, and it reaches a.
		was := c.uptime()
		n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{b.key, "u5"}, yggDevice{c.key, "u5"}, yggDevice{d.key, ""})
		if !c.reaches(ctx, a, 15*time.Second) || !a.reaches(ctx, c, 15*time.Second) {
			t.Fatal("c, moved to u5, does not reach a")
		}
		if up := c.uptime(); up <= was {
			t.Fatalf("c's link was cut: up %v, before the change %v", up, was)
		}
		// c leaves its group: no cut, and it reaches no one but the node.
		was = c.uptime()
		n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{b.key, "u5"}, yggDevice{c.key, ""}, yggDevice{d.key, ""})
		if c.reaches(ctx, a, 6*time.Second) || a.reaches(ctx, c, 6*time.Second) {
			t.Error("c, out of its group, still reaches a")
		}
		if up := c.uptime(); up <= was || !c.exits(ctx, n) {
			t.Fatalf("c's link was cut, or c does not reach the node: up %v, before %v", up, was)
		}
		// b leaves the users file: its link goes, a's stays.
		n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{c.key, ""}, yggDevice{d.key, ""})
		if !waitFor(5*time.Second, func() bool { return !peerUp(b.core) }) {
			t.Fatal("b was removed, yet its link stays")
		}
		if !peerUp(a.core) {
			t.Fatal("a's link went with b's")
		}
	})

	// lan_relay_mbps 0: two devices of one group do not reach each other
	// through the node; both reach the node.
	t.Run("relay 0", func(t *testing.T) {
		t.Parallel()
		n := startYggNode(t, ctx, func(c *BackendConfig) { c.Options.LANRelayMbps = new(int) })
		a, b := newLANDevice(t, ctx, n), newLANDevice(t, ctx, n)
		n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{b.key, "u5"})
		a.up(t)
		b.up(t)
		if !a.exits(ctx, n) || !b.exits(ctx, n) {
			t.Fatal("a device does not reach the node")
		}
		if a.reaches(ctx, b, 6*time.Second) || b.reaches(ctx, a, 6*time.Second) {
			t.Fatal("relay 0, yet a reaches b")
		}
		if !peerUp(a.core) || !peerUp(b.core) {
			t.Fatal("a link went")
		}
		s, tr := n.snapshot(t), n.traffic(t)
		if s.RelayDroppedFrames == 0 || s.RelayedFrames != 0 || tr.Users["u5"] != (UserTraffic{}) {
			t.Fatalf("snapshot %+v, traffic %+v", s, tr)
		}
	})
}

func lanRates(ctx context.Context, t *testing.T) {
	// lan_relay_mbps limits what the node relays for a group: a bulk TCP
	// transfer from a to b, both of u5, for 8 s, at 8 Mbit/s, at the
	// default (20) and with no bound to speak of; each link to the node 12
	// ms each way (a to b and back about 50 ms), or none; the devices'
	// netstacks at the core's MTU (65535: a TCP segment of 64 KiB a frame)
	// or at 1280. The bucket's bound holds on the relayed bytes (a's data
	// and b's acknowledgements, framed and encrypted): a second's worth more
	// than the rate over the time, at most. With a round trip TCP gets most
	// of the rate; with none it overruns the bucket in a moment, loses
	// whole windows and backs off: there only the bound is held.
	var mu sync.Mutex
	var rates []string
	t.Run("rate", func(t *testing.T) {
		t.Parallel()
		for _, c := range []struct {
			mbps  int // -1: lan_relay_mbps absent
			mtu   uint32
			delay time.Duration
		}{{8, 0, 12 * time.Millisecond}, {8, 1280, 12 * time.Millisecond}, {-1, 1280, 12 * time.Millisecond},
			{10000, 0, 12 * time.Millisecond}, {8, 0, 0}} {
			mbps := c.mbps
			t.Run(fmt.Sprintf("%d Mbit/s, MTU %d, %v", mbps, c.mtu, c.delay), func(t *testing.T) {
				t.Parallel()
				n := startYggNode(t, ctx, func(c *BackendConfig) {
					if mbps >= 0 {
						c.Options.LANRelayMbps = &mbps
					}
				})
				if mbps < 0 {
					mbps = yggLANRelayDefault
				}
				if c.delay > 0 {
					n.peer = strings.Replace(n.peer, n.front, delayProxy(t, n.front, c.delay), 1)
				}
				a, b := newLANDevice(t, ctx, n, c.mtu), newLANDevice(t, ctx, n, c.mtu)
				n.setLAN(t, yggDevice{a.key, "u5"}, yggDevice{b.key, "u5"})
				a.up(t)
				b.up(t)
				if !a.reaches(ctx, b, 15*time.Second) {
					t.Fatal("a does not reach b")
				}
				time.Sleep(time.Second) // the bucket full again
				before := n.traffic(t).Users["u5"].Up
				start := time.Now()
				got, took := a.bulk(t, ctx, b, 8*time.Second)
				relayed := n.traffic(t).Users["u5"].Up - before
				window := time.Since(start)
				goodput := float64(got) * 8 / took.Seconds() / 1e6
				line := fmt.Sprintf("lan_relay_mbps %d, MTU %d, %v each way: %d bytes in %v, %.2f Mbit/s of TCP; relayed %d bytes in %v, %.2f Mbit/s with the burst; %+v",
					mbps, c.mtu, c.delay, got, took.Round(time.Millisecond), goodput, relayed, window.Round(time.Millisecond),
					float64(relayed)*8/window.Seconds()/1e6, n.snapshot(t))
				t.Log(line)
				mu.Lock()
				rates = append(rates, line)
				mu.Unlock()
				bound := float64(mbps) * 1e6 / 8 * (window.Seconds() + 1)
				if float64(relayed) > bound+2*yggFrameMax {
					t.Errorf("relayed %d bytes in %v, over %d Mbit/s and a second's burst (%.0f)", relayed, window, mbps, bound)
				}
				if got == 0 || relayed < got {
					t.Errorf("b got %d bytes, %d relayed", got, relayed)
				}
				// TCP's share is logged, not held: under -race the stack
				// itself runs at about 9 Mbit/s. Without it, 12 ms each way:
				// at 20 Mbit/s about 87 % in every run; at 8 about 90 % in
				// some, and in others, the slow start's overshoot of the
				// burst lost whole windows and their retransmissions, about
				// 20 % (a burst of 100 ms did far worse: 3-6 %); with no
				// bound about 30 Mbit/s.
				if c.delay > 0 || mbps > 100 {
					return
				}
				// The bucket itself: a's core floods b with packets of 1200
				// bytes for 4 s, no TCP to slow down. The node relays the
				// rate and the burst, never above; below by 30 % at most
				// (alone it relays 99.5-100 %; under -race beside the other
				// rates a sender's pause once lost 11 % of the refill).
				time.Sleep(time.Second)
				before = n.traffic(t).Users["u5"].Up
				dropped := n.snapshot(t).RelayDroppedFrames
				start = time.Now()
				p := make([]byte, 1200)
				for time.Since(start) < 4*time.Second {
					_, _ = a.core.WriteTo(p, iwt.Addr(b.key))
				}
				time.Sleep(200 * time.Millisecond) // what is on its way
				relayed = n.traffic(t).Users["u5"].Up - before
				window = time.Since(start)
				rate := float64(mbps) * 1e6 / 8
				line = fmt.Sprintf("lan_relay_mbps %d, a flood of 1200-byte packets: relayed %d bytes in %v, %.2f Mbit/s with the burst; %d frames dropped over the rate",
					mbps, relayed, window.Round(time.Millisecond), float64(relayed)*8/window.Seconds()/1e6, n.snapshot(t).RelayDroppedFrames-dropped)
				t.Log(line)
				mu.Lock()
				rates = append(rates, line)
				mu.Unlock()
				if float64(relayed) > rate*(window.Seconds()+1)+2*yggFrameMax || float64(relayed) < 0.7*rate*(4+1) {
					t.Errorf("a flood: relayed %d bytes in %v at %d Mbit/s and a second's burst", relayed, window, mbps)
				}
			})
		}
	})
	t.Cleanup(func() {
		for _, r := range rates {
			t.Log(r)
		}
	})
}

// delayProxy is a TCP proxy to target that holds what it passes for d,
// each way: a link with a round trip.
func delayProxy(t *testing.T, target string, d time.Duration) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	type chunk struct {
		due time.Time
		b   []byte
	}
	pipe := func(src, dst net.Conn) {
		q := make(chan chunk, 4096) // full: the reader waits, as a window would
		go func() {
			defer dst.Close()
			for c := range q {
				time.Sleep(time.Until(c.due))
				if _, err := dst.Write(c.b); err != nil {
					return
				}
			}
		}()
		defer close(q)
		b := make([]byte, 64<<10)
		for {
			n, err := src.Read(b)
			if n > 0 {
				q <- chunk{time.Now().Add(d), append([]byte(nil), b[:n]...)}
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			mu.Lock()
			conns = append(conns, c, o)
			mu.Unlock()
			go pipe(c, o)
			go pipe(o, c)
		}
	}()
	return ln.Addr().String()
}
