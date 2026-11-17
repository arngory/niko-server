package nikoserver

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// firstFlights dials n QUIC connections to name and returns each one's
// first flight: the Initials whose CRYPTO frames make up its ClientHello,
// in the order the client sent them (no retransmissions).
func firstFlights(t *testing.T, name string, n int) [][][]byte {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range n {
		go quic.DialAddr(ctx, ln.LocalAddr().String(),
			&tls.Config{ServerName: name, NextProtos: []string{"h3"}, InsecureSkipVerify: true},
			&quic.Config{Versions: []quic.Version{quic.Version1}})
	}
	type flight struct {
		asm     helloAssembler
		packets [][]byte
		done    bool
	}
	byID := map[string]*flight{}
	var order []string
	buf := make([]byte, 2048)
	ln.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	for {
		k, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			break
		}
		d := append([]byte(nil), buf[:k]...)
		p, err := parseQUICInitial(d)
		if err != nil {
			continue
		}
		f := byID[string(p.dcid)]
		if f == nil {
			f = &flight{}
			byID[string(p.dcid)] = f
			order = append(order, string(p.dcid))
		}
		if f.done {
			continue
		}
		f.packets = append(f.packets, d)
		if _, done, err := f.asm.add(p.crypto); err != nil {
			t.Fatal(err)
		} else {
			f.done = done
		}
	}
	var out [][][]byte
	for _, id := range order {
		if byID[id].done {
			out = append(out, byID[id].packets)
		}
	}
	if len(out) < n {
		t.Fatalf("%d whole first flights of %d", len(out), n)
	}
	return out[:n]
}

// desyncFront is a UDP front with one QUIC backend by name, as naive-quic,
// hy2-masq and DoH3 are routed: classify is called directly.
func desyncFront(t *testing.T) (*udpFront, *backendLink) {
	t.Helper()
	dir := t.TempDir()
	packetBackend(t, filepath.Join(dir, "naive.sock"))
	c := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{
		{SNI: []string{"n.example.com"}, Backend: "naive-quic"},
	}}
	backends := map[string]BackendRef{
		"naive-quic": {Socket: filepath.Join(dir, "naive.sock"), Mode: "packet", UID: os.Getuid()},
	}
	var e configErrors
	c.validate(&e, backends)
	if len(e) > 0 {
		t.Fatal(e)
	}
	front, err := newUDPFront(c, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	link := front.byName["n.example.com"]
	if link == nil {
		t.Fatal("no route by name")
	}
	return front, link
}

// prelude is what a client's prelude sends without a name: 100 to 1200
// random bytes whose first byte is neither a long nor a short header.
func prelude(t *testing.T) []byte {
	t.Helper()
	n, _ := rand.Int(rand.Reader, big.NewInt(1101))
	b := make([]byte, 100+n.Int64())
	rand.Read(b)
	b[0] &= 0x3f
	return b
}

// TestUDPFrontDesync: a client's udp_desync before its first flight (fakes
// on the same 4-tuple: noise, Initials for another name, whole or cut
// short) and that flight's two Initials in reverse order. The fakes pin
// nothing, and the real ClientHello is put together from its packets in
// either order; the backend gets the packets as they came.
func TestUDPFrontDesync(t *testing.T) {
	real := firstFlights(t, "n.example.com", 2)
	fakes := firstFlights(t, "allowed.example", 8)
	for i, f := range fakes {
		if len(f) < 2 {
			t.Fatalf("fake %d: its ClientHello fits one packet, the cut case would not be cut", i)
		}
	}
	if len(real[0]) < 2 {
		t.Logf("the first flight is %d packet(s): reverse order not exercised", len(real[0]))
	}
	reversed := func(f [][]byte) [][]byte {
		out := make([][]byte, len(f))
		for i, d := range f {
			out[len(f)-1-i] = d
		}
		return out
	}
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.7:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	now := time.Now()
	for _, c := range []struct {
		name          string
		prelude       [][]byte
		flight        [][]byte
		leavesNothing bool // the prelude alone leaves no state
	}{
		{"in order", nil, real[0], true},
		{"reversed", nil, reversed(real[0]), true},
		{"8 noise, reversed", func() (p [][]byte) {
			for range 8 {
				p = append(p, prelude(t))
			}
			return
		}(), reversed(real[0]), true},
		{"8 whole Initials for another name, reversed", func() (p [][]byte) {
			for _, f := range fakes {
				p = append(p, f...)
			}
			return
		}(), reversed(real[1]), true},
		{"8 cut Initials for another name, reversed", func() (p [][]byte) {
			for _, f := range fakes {
				p = append(p, f[0])
			}
			return
		}(), reversed(real[1]), false},
		// The oldest goes, not the newest: with 4 places taken (3 fakes and
		// the real flight's first packet) a fifth ID takes a fake's place,
		// and the real flight's second packet still completes it.
		{"3 cut, real 1, a cut fake, real 2", [][]byte{fakes[0][0], fakes[1][0], fakes[2][0]},
			[][]byte{real[1][0], fakes[3][0], real[1][1]}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			front, want := desyncFront(t)
			for i, d := range c.prelude {
				if link, out := classifyChecked(t, front, key, d, now); link != nil || out != nil {
					t.Fatalf("fake %d routed (%v, %d packets)", i, link != nil, len(out))
				}
			}
			if c.leavesNothing && (front.pendingBytes != 0 || len(front.pending) != 0) {
				t.Fatalf("the fakes left %d bytes, %d flows pending", front.pendingBytes, len(front.pending))
			}
			var got *backendLink
			var out [][]byte
			var sent [][]byte // the real flight's packets as they came
			for i, d := range c.flight {
				if p, err := parseQUICInitial(d); err == nil && string(p.dcid) == dcidOf(t, c.flight[0]) {
					sent = append(sent, d)
				}
				link, o := classifyChecked(t, front, key, d, now)
				if link != nil {
					if i != len(c.flight)-1 {
						t.Fatalf("routed at packet %d of %d", i+1, len(c.flight))
					}
					got, out = link, o
				}
			}
			if got != want {
				t.Fatalf("the real flight went to %v, want naive-quic", got)
			}
			if len(out) != len(sent) {
				t.Fatalf("%d packets to the backend, want %d", len(out), len(sent))
			}
			for i := range out {
				if string(out[i]) != string(sent[i]) {
					t.Fatalf("packet %d to the backend is not the %d-th that came", i, i+1)
				}
			}
			// The routed flow holds nothing pending, fakes included.
			if front.pendingBytes != 0 || len(front.pending) != 0 {
				t.Fatalf("pending after routing: %d bytes, %d flows", front.pendingBytes, len(front.pending))
			}
		})
	}
}

// dcidOf is an Initial's Destination Connection ID.
func dcidOf(t *testing.T, d []byte) string {
	t.Helper()
	p, err := parseQUICInitial(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(p.dcid)
}

// sealInitial makes a QUIC v1 client Initial for dcid with this payload of
// frames, padded with PADDING to a datagram of size bytes at least.
func sealInitial(dcid, frames []byte, size int) []byte {
	key, iv, hp := initialKeys(quicV1, dcid)
	head := func(payload []byte) []byte {
		h := []byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}
		h = append(h, dcid...)
		h = append(h, 0, 0) // no SCID, no token
		l := 4 + len(payload) + 16
		return append(h, 0x40|byte(l>>8), byte(l))
	}
	payload := append([]byte(nil), frames...)
	for len(head(payload))+4+len(payload)+16 < size {
		payload = append(payload, 0)
	}
	h := head(payload)
	pn := len(h)
	h = append(h, 0, 0, 0, 0)
	b, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(b)
	pkt := aead.Seal(append([]byte(nil), h...), iv, payload, h)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pn+4:pn+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := range 4 {
		pkt[pn+i] ^= mask[1+i]
	}
	return pkt
}

// cryptoFrame16383 is a CRYPTO frame of one byte at offset 16383, the
// highest a ClientHello may reach.
var cryptoFrame16383 = []byte{0x06, 0x7f, 0xff, 0x01, 0xab}

func randomDCID() []byte {
	d := make([]byte, 8)
	rand.Read(d)
	return d
}

// TestUDPFrontPendingBudget: Initials whose ClientHellos never complete,
// from more 4-tuples than the front keeps (anyone can make them: their
// keys come from the packet), hold no more than maxPendingBytes together,
// and a real first flight gets through while they are there, the oldest
// going for it; expiry gives every byte back.
func TestUDPFrontPendingBudget(t *testing.T) {
	cut := firstFlights(t, "allowed.example", 2)
	real := firstFlights(t, "n.example.com", 1)[0]
	front, want := desyncFront(t)
	now := time.Now()
	key := func(i int) flowKey {
		return flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 40000),
			local: netip.MustParseAddrPort("127.0.0.1:443")}
	}
	for i := range 2 * maxPendingFlows {
		for _, f := range cut {
			front.classify(key(i), f[0], now)
		}
		if front.pendingBytes > maxPendingBytes {
			t.Fatalf("%d flows: %d bytes pending, over %d", i+1, front.pendingBytes, maxPendingBytes)
		}
		if len(front.pending) > maxPendingFlows {
			t.Fatalf("%d flows pending, over %d", len(front.pending), maxPendingFlows)
		}
	}
	if front.pendingBytes < maxPendingBytes*3/4 {
		t.Fatalf("only %d bytes pending: the budget was not reached", front.pendingBytes)
	}
	// While the budget is full: the real flight gets through.
	var got *backendLink
	for _, d := range real {
		if link, _ := front.classify(flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}, d, now); link != nil {
			got = link
		}
	}
	if got != want {
		t.Fatal("a real first flight did not get through a full budget")
	}
	front.expire(now.Add(pendingFor + time.Second))
	if front.pendingBytes != 0 || len(front.pending) != 0 || front.pendingOrder.Len() != 0 {
		t.Fatalf("after expiry: %d bytes, %d flows, %d in order", front.pendingBytes, len(front.pending), front.pendingOrder.Len())
	}
}

// TestUDPFrontSparseCrypto: a CRYPTO frame far ahead holds what it sent,
// not a buffer up to its offset, and an Initial in a datagram under 1200
// bytes is dropped at once (RFC 9000 §14.1): a flood of the smallest
// Initials neither fills the budget cheaply nor keeps a real flight out.
func TestUDPFrontSparseCrypto(t *testing.T) {
	front, want := desyncFront(t)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.7:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	if link, _ := front.classify(key, sealInitial(randomDCID(), cryptoFrame16383, 0), now); link != nil || len(front.pending) != 0 {
		t.Fatalf("a %d-byte Initial was kept", len(sealInitial(randomDCID(), cryptoFrame16383, 0)))
	}
	d := sealInitial(randomDCID(), cryptoFrame16383, minInitialDatagram)
	if len(d) < minInitialDatagram {
		t.Fatalf("%d bytes", len(d))
	}
	front.classify(key, d, now)
	if front.pendingBytes > len(d)+pendingHelloCost+pendingPacketCost+pendingFrameCost+16 {
		t.Fatalf("one byte at offset 16383 counts %d bytes for a %d-byte datagram", front.pendingBytes, len(d))
	}
	real := firstFlights(t, "n.example.com", 1)[0]
	var got *backendLink
	for _, p := range real {
		if link, _ := front.classify(key, p, now); link != nil {
			got = link
		}
	}
	if got != want || front.pendingBytes != 0 {
		t.Fatalf("real flight: %v, %d bytes left pending", got != nil, front.pendingBytes)
	}
}

// TestUDPFrontPendingPackets: a ClientHello that never completes under
// one ID is given up at maxPendingPackets, every byte back; one whose
// flow's window is over starts afresh, whether the sweep came or not.
func TestUDPFrontPendingPackets(t *testing.T) {
	cut := firstFlights(t, "allowed.example", 1)[0][0]
	front, _ := desyncFront(t)
	now := time.Now()
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.7:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	for range maxPendingPackets {
		classifyChecked(t, front, key, cut, now)
	}
	if front.pendingBytes == 0 {
		t.Fatal("nothing pending after 16 packets")
	}
	classifyChecked(t, front, key, cut, now)
	if front.pendingBytes != 0 || len(front.pending) != 0 {
		t.Fatalf("after packet %d: %d bytes, %d flows", maxPendingPackets+1, front.pendingBytes, len(front.pending))
	}
	front.classify(key, cut, now)
	held := front.pendingBytes
	front.classify(key, cut, now.Add(pendingFor+time.Second))
	if front.pendingBytes != held || len(front.pending[key].hellos[dcidOf(t, cut)].packets) != 1 {
		t.Fatalf("a flow past its window: %d bytes (was %d)", front.pendingBytes, held)
	}
}

// TestUDPFrontPendingFlows: more 4-tuples with a pending ClientHello than
// the front keeps (maxPendingFlows, well within the byte budget): the
// oldest flows go, not the newcomer, and a real first flight gets through.
func TestUDPFrontPendingFlows(t *testing.T) {
	front, want := desyncFront(t)
	now := time.Now()
	for i := range maxPendingFlows + 100 {
		key := flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 40000),
			local: netip.MustParseAddrPort("127.0.0.1:443")}
		front.classify(key, sealInitial(randomDCID(), cryptoFrame16383, minInitialDatagram), now)
	}
	if len(front.pending) != maxPendingFlows || front.pendingBytes > maxPendingBytes {
		t.Fatalf("%d flows, %d bytes pending", len(front.pending), front.pendingBytes)
	}
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	var got *backendLink
	for _, d := range firstFlights(t, "n.example.com", 1)[0] {
		if link, _ := front.classify(key, d, now); link != nil {
			got = link
		}
	}
	if got != want {
		t.Fatal("a real first flight did not get through a full table of pending flows")
	}
}

// checkPending recounts what the pending ClientHellos hold from what they
// hold, and checks the flow list against the flow map.
func checkPending(t *testing.T, f *udpFront) {
	t.Helper()
	total := 0
	for key, pf := range f.pending {
		if len(pf.hellos) == 0 {
			t.Fatalf("flow %v pending with no hello", key)
		}
		if pf.elem == nil || pf.elem.Value.(flowKey) != key {
			t.Fatalf("flow %v not in the list as itself", key)
		}
		for id, ph := range pf.hellos {
			n := pendingHelloCost + len(ph.asm.frames)*pendingFrameCost
			for _, fr := range ph.asm.frames {
				n += len(fr.data)
			}
			for _, d := range ph.packets {
				n += len(d) + pendingPacketCost
			}
			if n != ph.bytes {
				t.Fatalf("hello %x counts %d bytes, holds %d", id, ph.bytes, n)
			}
			total += n
		}
	}
	if total != f.pendingBytes {
		t.Fatalf("pendingBytes %d, the hellos hold %d", f.pendingBytes, total)
	}
	if f.pendingOrder.Len() != len(f.pending) {
		t.Fatalf("%d flows listed, %d pending", f.pendingOrder.Len(), len(f.pending))
	}
}

func classifyChecked(t *testing.T, f *udpFront, key flowKey, d []byte, now time.Time) (*backendLink, [][]byte) {
	t.Helper()
	link, out := f.classify(key, d, now)
	checkPending(t, f)
	return link, out
}

// TestUDPFrontEvictsOldestFlow: of the flows waiting for a ClientHello the
// oldest go, never the newest: with the table full, a real client's first
// packet takes a place, and a flood packet right after it takes the
// oldest one, not the client's, whose second packet then completes the
// flight. A flood must bring maxPendingFlows new flows between the two
// packets to keep it out.
func TestUDPFrontEvictsOldestFlow(t *testing.T) {
	real := firstFlights(t, "n.example.com", 1)[0]
	if len(real) < 2 {
		t.Skip("a first flight of one packet")
	}
	flood := func(f *udpFront, from, n int, now time.Time) {
		for i := range n {
			k := flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte((from + i) >> 8), byte(from + i)}), 40000),
				local: netip.MustParseAddrPort("127.0.0.1:443")}
			f.classify(k, sealInitial(randomDCID(), cryptoFrame16383, minInitialDatagram), now)
		}
	}
	client := flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	now := time.Now()
	t.Run("full table, the client, one flood flow", func(t *testing.T) {
		front, want := desyncFront(t)
		flood(front, 0, maxPendingFlows, now)
		classifyChecked(t, front, client, real[0], now)
		flood(front, maxPendingFlows, 1, now)
		if link, _ := classifyChecked(t, front, client, real[1], now); link != want {
			t.Fatal("one flood packet after the client's first evicted it")
		}
	})
	for _, c := range []struct {
		n      int
		routed bool
	}{{maxPendingFlows - 1, true}, {maxPendingFlows, false}} {
		t.Run(fmt.Sprintf("the client, %d flood flows", c.n), func(t *testing.T) {
			front, want := desyncFront(t)
			classifyChecked(t, front, client, real[0], now)
			flood(front, 0, c.n, now)
			checkPending(t, front)
			if link, _ := classifyChecked(t, front, client, real[1], now); (link == want) != c.routed {
				t.Fatalf("routed %v, want %v", link == want, c.routed)
			}
		})
	}
}

// TestUDPFrontEvictsOldestBytes: the same for the byte bound, with flood
// flows of 16 packets each, so that the bound binds before the table: a
// flood flow right after the client's first packet pushes out the oldest
// flows, not the client's.
func TestUDPFrontEvictsOldestBytes(t *testing.T) {
	real := firstFlights(t, "n.example.com", 1)[0]
	cut := firstFlights(t, "allowed.example", 1)[0][0]
	if len(real) < 2 {
		t.Skip("a first flight of one packet")
	}
	front, want := desyncFront(t)
	now := time.Now()
	heavy := func(i int) {
		k := flowKey{client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 19, byte(i >> 8), byte(i)}), 40000),
			local: netip.MustParseAddrPort("127.0.0.1:443")}
		for range maxPendingPackets {
			front.classify(k, cut, now)
		}
	}
	i := 0
	for ; front.pendingBytes < maxPendingBytes-64<<10 && i < maxPendingFlows; i++ {
		heavy(i)
	}
	checkPending(t, front)
	if len(front.pending) >= maxPendingFlows {
		t.Fatalf("%d flows: the table, not the byte bound, binds", len(front.pending))
	}
	checkPending(t, front)
	client := flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	classifyChecked(t, front, client, real[0], now)
	heavy(i)
	heavy(i + 1)
	checkPending(t, front)
	if front.pendingBytes > maxPendingBytes {
		t.Fatalf("%d bytes pending", front.pendingBytes)
	}
	if link, _ := classifyChecked(t, front, client, real[1], now); link != want {
		t.Fatal("flood flows after the client's first packet pushed it out")
	}
}
