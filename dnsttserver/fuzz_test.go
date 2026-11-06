package dnsttserver

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// Fuzz targets for what a dnstt backend reads off the internet: a query
// (responseFor, then the packets of its payload as recvLoop takes them),
// the seal of a query (dnsseal-v1) and the tag of dnsauth-v1, and the
// sealed answer built for what comes back. No input may panic, and every
// answer must be a message that parses. Run one with
//
//	go test ./dnsttserver -run '^$' -fuzz '^FuzzResponseFor$' -fuzztime 60s
//
// `go test` runs the seeds of each.

var (
	fuzzNow     = time.Unix(1_800_000_000, 0)
	fuzzDevKey  = [32]byte{1, 2, 3}
	fuzzSealKey = bytes.Repeat([]byte{9}, 32)
	fuzzOldKey  = bytes.Repeat([]byte{8}, 32)
)

func fuzzAuth(mode AuthMode) *Auth {
	a := &Auth{Mode: mode, Now: func() time.Time { return fuzzNow }}
	if err := a.SetKeys([]byte("d-1 " + hex.EncodeToString(fuzzDevKey[:]) + "\n")); err != nil {
		panic(err)
	}
	return a
}

// fuzzWire is a TXT query (or another type) for a payload in the zone, as
// a client sends it: base32 in labels of up to 63 before the zone.
func fuzzWire(tb testing.TB, payload []byte, qtype uint16, edns uint16) []byte {
	enc := []byte(strings.ToLower(base32Encoding.EncodeToString(payload)))
	var labels [][]byte
	for len(enc) > 0 {
		n := min(len(enc), 63)
		labels, enc = append(labels, enc[:n]), enc[n:]
	}
	zone, _ := dns.ParseName("t.example.com")
	name, err := dns.NewName(append(labels, zone...))
	if err != nil {
		tb.Fatal(err)
	}
	q := dns.Message{ID: 0x4242, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}}}
	if edns != 0 {
		q.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: edns, Data: []byte{}}}
	}
	b, err := q.WireFormat()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func FuzzResponseFor(f *testing.F) {
	s, err := NewSeal(SealRequired, fuzzSealKey, fuzzOldKey)
	if err != nil {
		f.Fatal(err)
	}
	inner := append([]byte("CLIENTID"), 0xe3, 1, 2, 3, 5, 'h', 'e', 'l', 'l', 'o')
	tag := Tag(&fuzzDevKey, EpochOf(fuzzNow), inner)
	tagged := append(tag[:], inner...)
	for _, p := range [][]byte{
		inner,
		tagged,
		sealQuery(s.list()[0], seq(0xa0, 8), inner),
		sealQuery(s.list()[1], seq(0xa0, 8), tagged),
		sealQuery(s.list()[0], seq(0xa0, 8), append([]byte("CLIENTID"), 0xff)),
		[]byte("short"),
		bytes.Repeat([]byte{0xdf}, 140),
	} {
		for _, mode := range []uint8{0, 4, 8} {
			f.Add(fuzzWire(f, p, dns.RRTypeTXT, 1232), mode)
		}
		f.Add(fuzzWire(f, p, dns.RRTypeTXT, 0), uint8(5))
	}
	f.Add(fuzzWire(f, inner, 1, 4096), uint8(0))
	f.Add([]byte("\x42\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02!!\x01t\x07example\x03com\x00\x00\x10\x00\x01"), uint8(2))

	domain, _ := dns.ParseName("t.example.com")
	f.Fuzz(func(t *testing.T, wire []byte, modes uint8) {
		query, err := dns.MessageFromWireFormat(wire)
		if err != nil {
			return
		}
		sealMode, authMode := SealMode(modes%3), AuthMode(modes/3%3)
		seal, err := NewSeal(sealMode, fuzzSealKey, fuzzOldKey)
		if err != nil {
			t.Fatal(err)
		}
		resp, payload, sealed, key := responseFor(&query, domain, fuzzAuth(authMode), seal)
		if resp == nil {
			if query.Flags&0x8000 == 0 {
				t.Fatal("no answer to a query")
			}
			return
		}
		if resp.ID != query.ID {
			t.Fatalf("answer ID %d to query %d", resp.ID, query.ID)
		}
		if sealed != nil && (sealMode == SealOff || payload == nil) {
			t.Fatalf("sealed with mode %d, payload %x", sealMode, payload)
		}
		if payload != nil {
			if key == "" {
				t.Fatal("a payload without a memo key")
			}
			if resp.Rcode() != dns.RcodeNoError || !carriesData(resp) {
				t.Fatalf("a payload with rcode %d, carries data %v", resp.Rcode(), carriesData(resp))
			}
			if sealMode == SealRequired && sealed == nil {
				t.Fatal("required seal took an open query")
			}
		}
		if _, err := resp.WireFormat(); err != nil {
			t.Fatalf("answer: %v", err)
		}
		size := requesterSize(&query)
		if size < 512 || size > maxUDPPayload || encodedPayload(size) <= sealNonceLen+2 {
			t.Fatalf("requester size %d, payload %d", size, encodedPayload(size))
		}
		// The packets, as recvLoop takes them.
		var id turbotunnel.ClientID
		if copy(id[:], payload) < len(id) {
			return
		}
		r := bytes.NewReader(payload[len(id):])
		total := 0
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			if len(p) >= 224 {
				t.Fatalf("a packet of %d bytes", len(p))
			}
			total += 1 + len(p)
		}
		if total > len(payload)-len(id) {
			t.Fatalf("%d bytes of packets from a payload of %d", total, len(payload)-len(id))
		}
	})
}

// FuzzSealOpen: whatever a query brings, open either fails or gives back
// what sealing the result with the same nonce turns into that query.
func FuzzSealOpen(f *testing.F) {
	s, err := NewSeal(SealOptional, fuzzSealKey, fuzzOldKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealQuery(s.list()[0], seq(0xa0, 8), []byte("CLIENTID\x01\xff")))
	f.Add(sealQuery(s.list()[1], seq(0xa0, 8), nil))
	f.Add(seq(0, 10))
	f.Add([]byte("CLIENTID"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		inner, key := s.open(payload)
		if key == nil {
			if inner != nil {
				t.Fatal("no key, but a payload")
			}
			return
		}
		if again := sealQuery(key, payload[:sealNonceLen], inner); !bytes.Equal(again, payload) {
			t.Fatalf("opened %x to %x, which seals to %x", payload, inner, again)
		}
	})
}

// FuzzSealAnswer: a sealed answer opens to its frames, then a zero length
// and zeros; it is padded to a multiple of sealBucket or to its room, and
// never longer than the room unless the frames alone are.
func FuzzSealAnswer(f *testing.F) {
	s, err := NewSeal(SealRequired, fuzzSealKey)
	if err != nil {
		f.Fatal(err)
	}
	k := s.list()[0]
	f.Add([]byte{0, 2, 0xaa, 0xbb}, uint16(1000))
	f.Add([]byte{}, uint16(64))
	f.Add([]byte{}, uint16(9))
	f.Add(bytes.Repeat([]byte{1}, 900), uint16(908))
	f.Add(bytes.Repeat([]byte{1}, 899), uint16(908))
	f.Add(bytes.Repeat([]byte{1}, 54), uint16(1000))
	f.Fuzz(func(t *testing.T, frames []byte, room uint16) {
		out := k.answer(frames, int(room))
		n := sealNonceLen + len(frames)
		if len(out) < n || len(out) > max(int(room), n) {
			t.Fatalf("%d bytes for %d of frames, room %d", len(out), len(frames), room)
		}
		if int(room)-n >= 2 && len(out)%sealBucket != 0 && len(out) != int(room) {
			t.Fatalf("%d bytes, room %d: not padded", len(out), room)
		}
		if int(room)-n < 2 && len(out) != n {
			t.Fatalf("%d bytes, room %d: padded without room", len(out), room)
		}
		plain := append([]byte(nil), out...)
		sealXOR(&k.down, plain[:sealNonceLen], plain[sealNonceLen:])
		if !bytes.Equal(plain[sealNonceLen:n], frames) {
			t.Fatal("frames do not open")
		}
		if bytes.ContainsFunc(plain[n:], func(r rune) bool { return r != 0 }) {
			t.Fatalf("padding %x", plain[n:])
		}
	})
}

// FuzzAuthCheck: a payload is refused, taken as it is (untagged, optional
// mode), or taken after a valid tag.
func FuzzAuthCheck(f *testing.F) {
	body := append([]byte("CLIENTID"), 0xe0)
	tag := Tag(&fuzzDevKey, EpochOf(fuzzNow), body)
	f.Add(append(tag[:], body...), uint8(1))
	f.Add(append(tag[:], body...), uint8(2))
	f.Add(body, uint8(1))
	f.Add(body, uint8(2))
	f.Add([]byte("x"), uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, mode uint8) {
		a := fuzzAuth(AuthMode(mode % 3))
		rest, ok := a.Check(payload)
		switch {
		case !ok:
			if rest != nil {
				t.Fatal("refused, but a payload")
			}
		case bytes.Equal(rest, payload):
			if a.Mode == AuthRequired {
				t.Fatal("required mode took an untagged payload")
			}
		case len(payload) >= AuthTagLen && bytes.Equal(rest, payload[AuthTagLen:]):
			tag := Tag(&fuzzDevKey, EpochOf(fuzzNow), rest)
			if !bytes.Equal(tag[:], payload[:AuthTagLen]) {
				// The epochs either side are valid too.
				before, after := Tag(&fuzzDevKey, EpochOf(fuzzNow)-1, rest), Tag(&fuzzDevKey, EpochOf(fuzzNow)+1, rest)
				if !bytes.Equal(before[:], payload[:AuthTagLen]) && !bytes.Equal(after[:], payload[:AuthTagLen]) {
					t.Fatalf("took %x as tagged", payload)
				}
			}
		default:
			t.Fatalf("rest %x of %x", rest, payload)
		}
	})
}
