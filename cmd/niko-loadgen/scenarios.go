//go:build linux

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

var flagSources = flag.Int("sources", 1, "distinct source addresses 127.0.x.y for the senders")
var flagIdle = flag.Bool("idle", false, "legit: sessions open a stream and stay idle (the inner sends nothing)")
var flagUpload = flag.Bool("upload", false, "legit: clients upload, the inner never reads (a stalled inner stage)")
var flagJunk = flag.Int("junk", 1, "junk: bytes after the query")
var flagSealPad = flag.String("sealpad", "spec", "legit, sealed: padding frame spec (random 0..31) or none")
var flagSocks = flag.Int("socks", 8, "UDP sockets per sender")

var innerBytes, innerConns, debugShim atomic.Int64

// startInner: the inner stage, a download source: each connection gets
// random data until it closes.
func startInner(path string) {
	l, err := net.Listen("unix", path)
	must(err)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			innerConns.Add(1)
			if *flagIdle || *flagUpload {
				return // holds the connection: sends nothing, reads nothing
			}
			go func() {
				defer c.Close()
				go func() { io.Copy(io.Discard, c); c.Close() }()
				buf := make([]byte, 32<<10)
				crand.Read(buf)
				for {
					n, err := c.Write(buf)
					innerBytes.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
}

func runScenario(n *node, stop <-chan struct{}) {
	switch *flagScenario {
	case "legit":
		legit(n, stop)
	case "flood":
		flood(n, stop)
	case "garbage":
		garbage(n, stop)
	case "probe":
		probe(n, stop)
	case "apex":
		apex(n, stop)
	case "refused":
		blast(n, stop, func(rng *rand.Rand, dst []byte) []byte {
			return plainQuery(dst, uint16(rng.Uint32()), fmt.Sprintf("x%d.example.org", rng.IntN(1000)), 1, *flagEDNS)
		}, nil)
	case "junk":
		// a tunnel-looking query (random base32 payload, TXT, OPT) with
		// -junk bytes after it: the front forwards it, dnstt cannot parse it.
		blast(n, stop, func(rng *rand.Rand, dst []byte) []byte {
			body := make([]byte, 96)
			for i := range body {
				body[i] = byte(rng.Uint32())
			}
			dst = wireQuery(dst, uint16(rng.Uint32()), body, zone, 16, *flagEDNS, true, rng)
			for range *flagJunk {
				dst = append(dst, byte(rng.Uint32()))
			}
			return dst
		}, nil)
	case "idle":
		select {
		case <-time.After(*flagDur):
		case <-stop:
		}
	default:
		must(fmt.Errorf("unknown scenario %q", *flagScenario))
	}
}

// blast sends queries from gen as fast as the rate allows, from several
// sockets (several source addresses), and counts the answers.
func blast(n *node, stop <-chan struct{}, gen func(*rand.Rand, []byte) []byte, done func() bool) {
	up, err := net.ResolveUDPAddr("udp4", n.dnsAddr)
	must(err)
	quit := make(chan struct{})
	var wg sync.WaitGroup
	var conns []*net.UDPConn
	finished := make(chan struct{})
	var finishOnce sync.Once
	for s := range *flagSenders {
		var socks []*net.UDPConn
		for k := range *flagSocks {
			src := (s*(*flagSocks) + k) % *flagSources
			laddr := &net.UDPAddr{IP: net.IPv4(127, byte(src>>8), byte(src&0xff), 1)} // one /24 per source
			c, err := net.DialUDP("udp4", laddr, up)
			must(err)
			c.SetReadBuffer(4 << 20)
			c.SetWriteBuffer(4 << 20)
			socks = append(socks, c)
			conns = append(conns, c)
			go func() {
				buf := make([]byte, 65536)
				for {
					if _, err := c.Read(buf); err != nil {
						if strings.Contains(err.Error(), "refused") {
							continue
						}
						return
					}
					answered.Add(1)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(s)+1, uint64(time.Now().UnixNano())))
			var buf []byte
			perSender := *flagRate / float64(*flagSenders)
			next := time.Now()
			const batch = 16
			for i := 0; ; i++ {
				select {
				case <-quit:
					return
				default:
				}
				if done != nil && done() {
					finishOnce.Do(func() { close(finished) })
					return
				}
				for range batch {
					buf = gen(rng, buf)
					socks[i%len(socks)].Write(buf)
					sent.Add(1)
				}
				if perSender > 0 {
					next = next.Add(time.Duration(float64(batch) / perSender * 1e9))
					if d := time.Until(next); d > 0 {
						time.Sleep(d)
					}
				}
			}
		}()
	}
	select {
	case <-time.After(*flagDur):
	case <-stop:
	case <-finished:
	}
	close(quit)
	wg.Wait()
	time.Sleep(1500 * time.Millisecond) // late answers
	for _, c := range conns {
		c.Close()
	}
}

// flood: fresh random ClientIDs, each query a new one, carrying what the
// variant says: poll (padding only), ack (a 24-byte KCP ACK: a session),
// push64k (a PUSH whose 2 bytes are a Noise length of 65535), pushbad (a
// PUSH with a whole bad Noise message). Tagged with a random tag when auth
// is required (no device key), untagged otherwise; sealed with the zone
// key when the zone seals (the key is in every link).
func flood(n *node, stop <-chan struct{}) {
	var sl *sealer
	if *flagSeal != "off" {
		sl = newSealer(n.sealKey)
	}
	var ids atomic.Int64
	gen := func(rng *rand.Rand, dst []byte) []byte {
		body := make([]byte, 8, 128)
		binary.LittleEndian.PutUint64(body, rng.Uint64())
		ids.Add(1)
		pad := func(k int) {
			body = append(body, byte(224+k))
			for range k {
				body = append(body, byte(rng.Uint32()))
			}
		}
		conv := rng.Uint32()
		var seg []byte
		switch *flagVariant {
		case "poll":
			pad(8)
		case "ack":
			pad(3)
			seg = kcpSegment(conv, kcpAck, 128, 0, nil)
		case "push64k":
			pad(3)
			seg = kcpSegment(conv, kcpPush, 128, 0, []byte{0xff, 0xff})
		case "pushbad":
			pad(3)
			msg := make([]byte, 50)
			msg[1] = 48
			for i := 2; i < len(msg); i++ {
				msg[i] = byte(rng.Uint32())
			}
			seg = kcpSegment(conv, kcpPush, 128, 0, msg)
		default:
			must(fmt.Errorf("variant %q", *flagVariant))
		}
		if seg != nil {
			body = append(body, byte(len(seg)))
			body = append(body, seg...)
		}
		if *flagAuth == "required" {
			var t [8]byte
			binary.LittleEndian.PutUint64(t[:], rng.Uint64())
			body = append(t[:], body...)
		}
		if sl != nil {
			body = sl.seal(body, rng)
		}
		return wireQuery(dst, uint16(rng.Uint32()), body, zone, 16, *flagEDNS, sl != nil, rng)
	}
	var done func() bool
	if *flagIDs > 0 {
		done = func() bool { return ids.Load() >= int64(*flagIDs) }
	}
	blast(n, stop, gen, done)
	fmt.Printf("   distinct ClientIDs sent: %d\n", ids.Load())
}

// garbage: random payloads of a tunnel query's size; -sealed seals them
// with the zone key (they pass the seal and cost an auth scan).
func garbage(n *node, stop <-chan struct{}) {
	sl := newSealer(n.sealKey)
	blast(n, stop, func(rng *rand.Rand, dst []byte) []byte {
		body := make([]byte, 96)
		for i := range body {
			body[i] = byte(rng.Uint32())
		}
		if *flagSealed {
			body = sl.seal(body, rng)
		}
		return wireQuery(dst, uint16(rng.Uint32()), body, zone, 16, *flagEDNS, true, rng)
	}, nil)
}

// probe: dnsprobe-v1 queries with the key (-valid) or a wrong MAC.
func probe(n *node, stop <-chan struct{}) {
	key := n.probeKey
	if !*flagValid {
		key = randKey()
	}
	blast(n, stop, func(rng *rand.Rand, dst []byte) []byte {
		label := probeLabel(key, zone, *flagLarge, uint32(time.Now().Unix()/60), rng.Uint64())
		return plainQuery(dst, uint16(rng.Uint32()), label+"."+zone, 16, *flagEDNS)
	}, nil)
}

func apex(n *node, stop <-chan struct{}) {
	blast(n, stop, func(rng *rand.Rand, dst []byte) []byte {
		return plainQuery(dst, uint16(rng.Uint32()), zone, uint16(*flagQType), *flagEDNS)
	}, nil)
}

type udpDialer struct{}

func (udpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.Dial(network, destination.String())
}

func (udpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

// legit: N sessions of the stock dnstt client, each through a resolver of
// its own that tags (dnsauth-v1, its device's key) and seals (dnsseal-v1)
// its queries, each session downloading from the inner stage.
func legit(n *node, stop <-chan struct{}) {
	clientZone := strings.Repeat("p", 40) + "." + zone
	pub := hex.EncodeToString(noise.PubkeyFromPrivkey(n.privkey))
	var down atomic.Int64
	var connected, failed atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var clients []*dnstt.Client
	var mu sync.Mutex
	for i := range *flagN {
		shim := startShim(n, i, clientZone, ctx)
		parsed, err := dnstt.ParseResolver("udp://" + shim)
		must(err)
		client, err := dnstt.NewClient(dnstt.ClientOptions{Context: ctx, Logger: logger.NOP(), Dialer: udpDialer{},
			Domain: clientZone, PubKey: pub, Resolver: parsed})
		must(err)
		mu.Lock()
		clients = append(clients, client)
		mu.Unlock()
		go func() {
			dctx, dcancel := context.WithTimeout(ctx, 60*time.Second)
			defer dcancel()
			conn, err := client.DialConn(dctx)
			if err != nil {
				failed.Add(1)
				fmt.Println("dial:", err)
				return
			}
			connected.Add(1)
			defer conn.Close()
			if *flagUpload {
				chunk := make([]byte, 16<<10)
				for {
					k, err := conn.Write(chunk)
					down.Add(int64(k)) // bytes up, here
					if err != nil {
						return
					}
				}
			}
			buf := make([]byte, 64<<10)
			for {
				k, err := conn.Read(buf)
				down.Add(int64(k))
				if err != nil {
					return
				}
			}
		}()
		time.Sleep(10 * time.Millisecond)
	}
	// Warm up: the sessions open; then the window that is measured.
	warm := time.Now()
	for connected.Load()+failed.Load() < int64(*flagN) && time.Since(warm) < 60*time.Second {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("   %d sessions connected, %d failed, in %s\n", connected.Load(), failed.Load(), time.Since(warm).Round(time.Millisecond))
	time.Sleep(2 * time.Second)
	b, _ := n.backend.stats()
	f, _ := n.front.stats()
	d0, q0, a0, t0 := down.Load(), sent.Load(), answered.Load(), time.Now()
	select {
	case <-time.After(*flagDur):
	case <-stop:
	}
	d := time.Since(t0)
	b2, _ := n.backend.stats()
	f2, _ := n.front.stats()
	mb := float64(down.Load()-d0) / 1e6
	cpuB, cpuF := b2.cpu()-b.cpu(), f2.cpu()-f.cpu()
	fmt.Printf("   measured window %s: %.1f MB down (%.2f MB/s, %.1f KB/s per session), %d queries (%.0f/s), %d answers\n",
		d.Round(time.Second), mb, mb/d.Seconds(), mb*1e3/d.Seconds()/float64(max(1, connected.Load())), sent.Load()-q0, float64(sent.Load()-q0)/d.Seconds(), answered.Load()-a0)
	fmt.Printf("   server cpu: backend %.2fs (%.0f%%), front %.2fs (%.0f%%); %.3f cpu-s per MB (backend %.3f, front %.3f); %.1f us per query\n",
		cpuB, 100*cpuB/d.Seconds(), cpuF, 100*cpuF/d.Seconds(), (cpuB+cpuF)/max(mb, 1e-9), cpuB/max(mb, 1e-9), cpuF/max(mb, 1e-9),
		(cpuB+cpuF)/float64(max(1, sent.Load()-q0))*1e6)
	fmt.Printf("   backend now: RSS %.1f MiB, heap inuse %.1f MiB, stack %.1f MiB, goroutines %d, KCP sessions %d\n",
		mib(b2.VmRSS), mib(b2.HeapInuse), mib(b2.StackInuse), b2.Goroutines, b2.KCPCurrEstab)
	cancel()
	for _, c := range clients {
		c.Close()
	}
}

// startShim: a resolver for one client: tags and seals its queries on the
// way to the node, takes the seal off the answers on the way back.
func startShim(n *node, i int, clientZone string, ctx context.Context) string {
	cs, err := net.ListenPacket("udp4", "127.0.0.1:0")
	must(err)
	up, err := net.ResolveUDPAddr("udp4", n.dnsAddr)
	must(err)
	us, err := net.DialUDP("udp4", nil, up)
	must(err)
	go func() { <-ctx.Done(); cs.Close(); us.Close() }()
	dev := n.devices[i%len(n.devices)]
	var sl *sealer
	if *flagSeal != "off" {
		sl = newSealer(n.sealKey)
	}
	cz, _ := dns.ParseName(clientZone)
	var client atomic.Value
	type pending struct {
		wire  []byte
		tries int
	}
	var pmu sync.Mutex
	inflight := map[uint16]*pending{}
	go func() {
		buf := make([]byte, 4096)
		rng := rand.New(rand.NewPCG(uint64(i), uint64(time.Now().UnixNano())))
		var out []byte
		for {
			k, from, err := cs.ReadFrom(buf)
			if err != nil {
				return
			}
			client.Store(from)
			q, err := dns.MessageFromWireFormat(buf[:k])
			if err != nil || len(q.Question) != 1 {
				continue
			}
			prefix, ok := q.Question[0].Name.TrimSuffix(cz)
			if !ok {
				continue
			}
			payload, err := b32.DecodeString(strings.ToUpper(string(bytes.Join(prefix, nil))))
			if err != nil || len(payload) < 8 {
				continue
			}
			if sl != nil && len(payload) > 8 && payload[8] >= 224 {
				// dnsseal-v1 §3: dnstt's padding goes (N makes the name
				// unique); a padding frame of a random length 0..31, as
				// much as fits (-sealpad spec), or none (-sealpad none,
				// as the repo's sealingResolver).
				rest := payload[min(len(payload), 9+int(payload[8]-224)):]
				payload = payload[:8:8]
				if *flagSealPad == "spec" {
					room := 140 - 10 - 8 - 8 - 1 - len(rest)
					k := min(rng.IntN(32), max(room, 0))
					payload = append(payload, byte(224+k))
					for range k {
						payload = append(payload, byte(rng.Uint32()))
					}
				}
				payload = append(payload, rest...)
			}
			if *flagAuth != "off" {
				payload = tag(&dev, payload)
			}
			if sl != nil {
				payload = sl.seal(payload, rng)
			}
			out = wireQuery(out, q.ID, payload, zone, 16, *flagEDNS, sl != nil, rng)
			if len(out) > 512 {
				fmt.Println("shim: query too long", len(out))
			}
			us.Write(out)
			sent.Add(1)
			if *flagRetry > 0 {
				p := &pending{wire: append([]byte(nil), out...)}
				id := q.ID
				pmu.Lock()
				inflight[id] = p
				pmu.Unlock()
				var resend func()
				resend = func() {
					pmu.Lock()
					cur := inflight[id]
					pmu.Unlock()
					if cur != p || p.tries >= 2 {
						return
					}
					p.tries++
					us.Write(p.wire)
					sent.Add(1)
					time.AfterFunc(*flagRetry, resend)
				}
				time.AfterFunc(*flagRetry, resend)
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			k, err := us.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			answered.Add(1)
			m, err := dns.MessageFromWireFormat(buf[:k])
			if err != nil {
				continue
			}
			if *flagRetry > 0 {
				pmu.Lock()
				_, first := inflight[m.ID]
				delete(inflight, m.ID)
				pmu.Unlock()
				if !first {
					continue // the resolver passes on the first answer only
				}
			}
			resp := dns.Message{ID: m.ID, Flags: m.Flags, Question: []dns.Question{{Name: cz, Type: dns.RRTypeTXT, Class: dns.ClassIN}}}
			if len(m.Answer) == 1 {
				data, err := dns.DecodeRDataTXT(m.Answer[0].Data)
				if err != nil {
					continue
				}
				if sl != nil {
					data = sl.open(data)
				}
				resp.Answer = []dns.RR{{Name: cz, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 60, Data: dns.EncodeRDataTXT(data)}}
			}
			wire, err := resp.WireFormat()
			if err != nil {
				continue
			}
			if addr, ok := client.Load().(net.Addr); ok {
				cs.WriteTo(wire, addr)
			}
		}
	}()
	return cs.LocalAddr().String()
}
