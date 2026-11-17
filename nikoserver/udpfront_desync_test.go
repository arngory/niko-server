package nikoserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
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
		name    string
		prelude [][]byte
		flight  [][]byte
	}{
		{"in order", nil, real[0]},
		{"reversed", nil, reversed(real[0])},
		{"8 noise, reversed", func() (p [][]byte) {
			for range 8 {
				p = append(p, prelude(t))
			}
			return
		}(), reversed(real[0])},
		{"8 whole Initials for another name, reversed", func() (p [][]byte) {
			for _, f := range fakes {
				p = append(p, f...)
			}
			return
		}(), reversed(real[1])},
		{"8 cut Initials for another name, reversed", func() (p [][]byte) {
			for _, f := range fakes {
				p = append(p, f[0])
			}
			return
		}(), reversed(real[1])},
	} {
		t.Run(c.name, func(t *testing.T) {
			front, want := desyncFront(t)
			for i, d := range c.prelude {
				if link, out := front.classify(key, d, now); link != nil || out != nil {
					t.Fatalf("fake %d routed (%v, %d packets)", i, link != nil, len(out))
				}
			}
			var got *backendLink
			var out [][]byte
			for i, d := range c.flight {
				link, o := front.classify(key, d, now)
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
			if len(out) != len(c.flight) {
				t.Fatalf("%d packets to the backend, want %d", len(out), len(c.flight))
			}
			for i := range out {
				if string(out[i]) != string(c.flight[i]) {
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

// TestUDPFrontPendingBudget: Initials whose ClientHellos never complete,
// from many 4-tuples (anyone can make them: their keys come from the
// packet), hold no more than maxPendingBytes together; a real first flight
// still gets through once they expire, and expiry gives every byte back.
func TestUDPFrontPendingBudget(t *testing.T) {
	cut := firstFlights(t, "allowed.example", 2)
	real := firstFlights(t, "n.example.com", 1)[0]
	front, want := desyncFront(t)
	now := time.Now()
	for port := range maxPendingFlows {
		key := flowKey{client: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.9"), uint16(10000+port)),
			local: netip.MustParseAddrPort("127.0.0.1:443")}
		for _, f := range cut {
			front.classify(key, f[0], now)
		}
		if front.pendingBytes > maxPendingBytes+64<<10 {
			t.Fatalf("%d flows: %d bytes pending, over %d", port+1, front.pendingBytes, maxPendingBytes)
		}
	}
	if front.pendingBytes < maxPendingBytes/2 {
		t.Fatalf("only %d bytes pending: the budget was not reached", front.pendingBytes)
	}
	front.expire(now.Add(pendingFor + time.Second))
	if front.pendingBytes != 0 || len(front.pending) != 0 {
		t.Fatalf("after expiry: %d bytes, %d flows", front.pendingBytes, len(front.pending))
	}
	key := flowKey{client: netip.MustParseAddrPort("192.0.2.10:40000"), local: netip.MustParseAddrPort("127.0.0.1:443")}
	var got *backendLink
	for _, d := range real {
		if link, _ := front.classify(key, d, now.Add(pendingFor+time.Second)); link != nil {
			got = link
		}
	}
	if got != want {
		t.Fatal("a real first flight did not get through after the fakes expired")
	}
}
