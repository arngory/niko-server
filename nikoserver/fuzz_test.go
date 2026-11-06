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
// salamander. No input may panic, and what is sent back must stay a valid
// answer within its bounds. Run one with
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
			if len(a.buf) > maxQUICHello {
				t.Fatalf("assembler grew to %d", len(a.buf))
			}
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
