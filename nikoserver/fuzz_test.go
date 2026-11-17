//go:build linux

package nikoserver

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

// Fuzz targets for what the front reads off the internet: the DNS query
// path (name, zone, apex, probe), the IPC header between front and
// backends, ClientHello over TCP, QUIC Initial and its CRYPTO frames, and
// salamander, and the labels of connection IDs. No input may panic, and
// what is sent back must stay a valid answer within its bounds. Run one
// with
//
//	go test ./nikoserver -run '^$' -fuzz '^FuzzDNSQuery$' -fuzztime 60s
//
// `go test` runs the seeds of each.

func FuzzDNSQuery(f *testing.F) {
	key := bytes.Repeat([]byte{7}, 32)
	zone := "t.example.com"
	probe := newDNSProbe(key)
	probe.now = func() time.Time { return time.Unix(1_740_000_000, 0) }
	apex := newApexZone(zone, []string{"ns1.example.com"}, 1)
	minute := uint32(1_740_000_000 / 60)
	for _, q := range [][]byte{
		probeQuery(probeLabel(key, zone, false, minute, [8]byte{1})+"."+zone, 16, 1232),
		probeQuery(probeLabel(key, zone, true, minute, [8]byte{2})+"."+zone, 16, 0),
		probeQuery(zone, 6, 1232),
		probeQuery(zone, 2, 0),
		probeQuery("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbb."+zone, 16, 4096),
		probeQuery("other.example.org", 1, 0),
	} {
		f.Add(q, false)
		f.Add(q, true)
	}
	f.Fuzz(func(t *testing.T, query []byte, pad bool) {
		name, end, ok := queryName(query)
		if !ok {
			return
		}
		if end > len(query) || end < 12 {
			t.Fatalf("question end %d of %d bytes", end, len(query))
		}
		z := zoneOf(name, []string{zone})
		if z == "" {
			if r := refused(query, end); len(r) != end+len(frontOPT(query, end)) || r[3]&0x0f != 5 {
				t.Fatalf("refused: %x", r)
			}
			return
		}
		if name == z {
			if reply, ok := apex.answer(query); ok {
				checkReply(t, "apex", reply, 4096)
			}
		}
		if reply, isProbe := probe.answer(query, name, end, z, netip.MustParseAddr("192.0.2.1"), pad); isProbe && reply != nil {
			checkReply(t, "probe", reply, 1232)
		}
	})
}

// checkReply: an answer parses and fits.
func checkReply(t *testing.T, what string, reply []byte, limit int) {
	t.Helper()
	if len(reply) > limit {
		t.Fatalf("%s: %d bytes", what, len(reply))
	}
	if m, err := dns.MessageFromWireFormat(reply); err != nil || m.Flags&0x8000 == 0 {
		t.Fatalf("%s: %+v %v", what, m, err)
	}
}

func FuzzIPC(f *testing.F) {
	f.Add(encodePacket(nil, netip.MustParseAddrPort("198.51.100.7:53000"), netip.MustParseAddrPort("203.0.113.1:53"), []byte("query")))
	f.Add(encodePacket(nil, netip.MustParseAddrPort("[2001:db8::1]:443"), netip.MustParseAddrPort("[2001:db8::2]:443"), nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		client, local, payload, err := decodePacket(msg)
		if err == nil {
			// What decodes encodes to a message that decodes the same.
			again := encodePacket(nil, client, local, payload)
			c2, l2, p2, err := decodePacket(again)
			if err != nil || c2 != client || l2 != local || !bytes.Equal(p2, payload) {
				t.Fatalf("round trip: %v", err)
			}
		}
		decodeHandoff(msg)
	})
}

func FuzzClientHello(f *testing.F) {
	for _, name := range []string{"a.example.com", "", "xn--80ak6aa92e.example"} {
		c, s := net.Pipe()
		go func() {
			tls.Client(c, &tls.Config{ServerName: name, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}).Handshake()
		}()
		_, raw, err := readClientHello(s)
		s.Close()
		c.Close()
		if err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		readClientHello(bytes.NewReader(raw))
		if len(raw) > 9 {
			parseClientHello(raw[9:])
		}
		parseClientHello(raw)
	})
}

func FuzzQUICInitial(f *testing.F) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		for _, d := range initialsOrNil(f, "q.example.com", v) {
			f.Add(d)
		}
	}
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x41, 0})
	f.Fuzz(func(t *testing.T, d []byte) {
		if isQUICInitial(d) {
			parseQUICInitial(d)
		}
		salamanderInitial([]byte("cxNlY3JldC1zYWxhbWFuZGVy"), d)
		// The CRYPTO frames of a decrypted Initial, and their assembly.
		if frames, err := cryptoFrames(d); err == nil {
			var a helloAssembler
			a.add(frames)
			if a.size > maxQUICHello*maxHelloFrames || len(a.frames) > maxHelloFrames {
				t.Fatalf("assembler holds %d bytes in %d frames", a.size, len(a.frames))
			}
			held := 0
			for _, f := range a.frames {
				held += len(f.data)
			}
			if held != a.size {
				t.Fatalf("assembler counts %d bytes, holds %d", a.size, held)
			}
		}
	})
}

// FuzzCIDRoute is the front's path for a datagram no flow explains, with
// routing by connection ID (quic-cid-route-v1): the short header or
// Handshake, salamander's start, the ID's label and the backend it names.
// Nothing panics, and a datagram goes to a backend only as it came and
// only by a label of that backend's, read under its own obfuscation.
func FuzzCIDRoute(f *testing.F) {
	front, password := cidFront(f, true)
	for _, label := range []uint16{1, 2, 3, 9} {
		id := cidID(cidSecret, label, uint64(label)<<20)
		f.Add(shortPacket(id, 64))
		f.Add(handshakePacket(id, 64))
		f.Add(obfuscate(password, shortPacket(id, 64)))
		f.Add(obfuscate(password, handshakePacket(id, 64)))
	}
	f.Add(shortPacket(cidID(cidSecret, 1, 0), minCIDPacket))
	f.Add([]byte{0x40, 1, 2, 3})
	labelOf := map[string]uint16{"a": 1, "b": 2, "s": 3}
	var n uint32
	now := time.Now()
	f.Fuzz(func(t *testing.T, d []byte) {
		// A source of its own each time: the per-source bound aside.
		n++
		src := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
		link, packets := front.classify(flowKey{netip.AddrPortFrom(src, 1), netip.MustParseAddrPort("127.0.0.1:443")}, d, now)
		if link == nil || isQUICInitial(d) { // an Initial goes by its name (FuzzQUICInitial)
			return
		}
		if len(packets) != 1 || !bytes.Equal(packets[0], d) {
			t.Fatalf("to %s: %d packets, not the datagram as it came", link.name, len(packets))
		}
		if link.name == "s" {
			head, ok := salamanderHead([]byte(password), d)
			id := clientCID(head[:min(len(d)-8, cidHead)], len(d)-8)
			if label, lok := labelCodec(cidSecret, labelOf["s"]).label(id); !ok || !isQUICInitial(head[:7]) && (id == nil || !lok || label != labelOf["s"]) {
				t.Fatalf("to s without its Initial or label: %x", d[:min(len(d), 24)])
			}
			return
		}
		id := clientCID(d[:min(len(d), cidHead)], len(d))
		if label, ok := labelCodec(cidSecret, labelOf[link.name]).label(id); id == nil || !ok || label != labelOf[link.name] {
			t.Fatalf("to %s by label %d %v: %x", link.name, label, ok, d[:min(len(d), 24)])
		}
	})
}

// FuzzCIDCodec: an ID reads back as its label, and Speck's two ways undo
// each other.
func FuzzCIDCodec(f *testing.F) {
	f.Add(uint16(1), uint64(0), uint32(0), uint32(0))
	f.Add(uint16(MaxCIDLabel), uint64(1<<40-1), uint32(0xffffffff), uint32(1))
	codec := labelCodec(cidSecret, 1)
	f.Fuzz(func(t *testing.T, label uint16, counter uint64, x, y uint32) {
		id := codec.encode(label, counter)
		got, ok := codec.label(id[:])
		if got != label || ok != (label != 0) {
			t.Fatalf("label %d read as %d %v", label, got, ok)
		}
		if a, b := codec.decrypt(codec.encrypt(x, y)); a != x || b != y {
			t.Fatalf("%08x %08x came back %08x %08x", x, y, a, b)
		}
	})
}

// initialsOrNil is initials for a fuzz seed; no seeds when no client can
// be run.
func initialsOrNil(f *testing.F, name string, v quic.Version) [][]byte {
	defer func() { recover() }()
	t := &testing.T{}
	_ = t
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil
	}
	defer ln.Close()
	go quic.DialAddr(f.Context(), ln.LocalAddr().String(),
		&tls.Config{ServerName: name, NextProtos: []string{"h3"}, InsecureSkipVerify: true},
		&quic.Config{Versions: []quic.Version{v}})
	var out [][]byte
	buf := make([]byte, 2048)
	ln.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	for {
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	return out
}
