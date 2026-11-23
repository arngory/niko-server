//go:build linux

package nikoserver

import (
	"encoding/binary"
	"strings"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// The zone apex (zones[].ns): the DNS front answers SOA and NS for the zone
// itself, and NODATA with the SOA for any other type there, as an
// authoritative server does. Some resolvers gave SERVFAIL for a delegated
// zone whose apex had neither (raycontrol docs/research/dns-resolvers.md). The
// answers are built as dnstt builds its own: QR and AA, the question as
// asked, an OPT of 4096 when the query had one. Only for dnstt zones:
// masterdns answers otherwise.
const (
	apexType     = 6 // SOA
	apexNS       = 2
	apexANY      = 255
	apexTTL      = 300
	apexNegative = 60 // SOA minimum: how long resolvers keep a NODATA
)

type apexZone struct {
	ns  []string
	soa []byte // SOA RDATA
	// For the SOA of a NODATA below the apex (negative): the zone's name
	// on the wire, its labels, and the SOA's RDATA with RNAME's zone
	// to point at the question.
	zone      []byte
	labels    int
	soaMName  []byte
	soaFixed  []byte // serial, refresh, retry, expire, minimum
	negativeN int    // the SOA record's length there
}

func newApexZone(zone string, ns []string, serial uint32) *apexZone {
	names := make([]string, len(ns))
	for i, n := range ns {
		names[i] = canonicalName(n)
	}
	soa := wireName(names[0])
	soa = append(soa, wireName("hostmaster."+zone)...)
	// serial, refresh, retry, expire, minimum
	var fixed []byte
	for _, v := range []uint32{serial, 7200, 3600, 1209600, apexNegative} {
		fixed = binary.BigEndian.AppendUint32(fixed, v)
	}
	soa = append(soa, fixed...)
	a := &apexZone{ns: names, soa: soa, zone: wireName(zone), soaMName: wireName(names[0]), soaFixed: fixed}
	a.labels = strings.Count(strings.TrimSuffix(zone, "."), ".") + 1
	// owner (a pointer), type, class, TTL, length; MNAME, "hostmaster"
	// and a pointer, the five numbers
	a.negativeN = 2 + 10 + len(a.soaMName) + 1 + len("hostmaster") + 2 + len(fixed)
	return a
}

// negative adds the zone's SOA to the authority section of a NODATA below
// the apex (RFC 2308 §3: how long a resolver keeps it, and the zone's own
// mark, as at the apex), its TTL the SOA's minimum: answer is NOERROR with
// AA and without TC, the one question ending at questionEnd and in the zone, no answer
// and no authority records. The SOA's name and RNAME's zone point at the
// zone's labels in the question (some 60 bytes in all). Nil when the
// answer is not such a NODATA or would grow past limit.
func (a *apexZone) negative(answer []byte, questionEnd, limit int) []byte {
	if len(answer) < 12 || answer[2]&0x86 != 0x84 || answer[3]&0x0f != 0 || answer[2]&0x78 != 0 ||
		binary.BigEndian.Uint16(answer[4:6]) != 1 || binary.BigEndian.Uint16(answer[6:8]) != 0 ||
		binary.BigEndian.Uint16(answer[8:10]) != 0 || len(answer)+a.negativeN > limit || questionEnd > len(answer) {
		return nil
	}
	// Where the zone's labels start in the question.
	var starts [128]int
	n := 0
	for i := 12; ; {
		if i >= questionEnd || n == len(starts) {
			return nil
		}
		l := int(answer[i])
		if l == 0 {
			break
		}
		if l > 63 {
			return nil
		}
		starts[n] = i
		n++
		i += 1 + l
	}
	if n <= a.labels {
		return nil // the apex, or not the zone
	}
	at := starts[n-a.labels]
	if !sameNameFold(answer[at:questionEnd-4], a.zone) {
		return nil
	}
	ptr := []byte{0xc0 | byte(at>>8), byte(at)}
	out := make([]byte, 0, len(answer)+a.negativeN)
	out = append(out, answer[:questionEnd]...)
	out = append(out, ptr...)
	out = binary.BigEndian.AppendUint16(out, apexType)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, apexNegative)
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.soaMName)+1+len("hostmaster")+2+len(a.soaFixed)))
	out = append(out, a.soaMName...)
	out = append(out, byte(len("hostmaster")))
	out = append(out, "hostmaster"...)
	out = append(out, ptr...)
	out = append(out, a.soaFixed...)
	out = append(out, answer[questionEnd:]...)
	binary.BigEndian.PutUint16(out[8:10], 1)
	return out
}

func apexSerial() uint32 { return uint32(time.Now().Unix()) }

// wireName is a name in wire format, uncompressed.
func wireName(name string) []byte {
	var b []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// answer answers a query for the apex; ok is false for one it leaves to
// the backend (not a plain query of class IN, a second question or OPT, an
// EDNS version but 0), which answers it as before.
func (a *apexZone) answer(query []byte) (reply []byte, ok bool) {
	q, err := dns.MessageFromWireFormat(query)
	if err != nil || q.Flags&0x8000 != 0 || q.Opcode() != 0 || len(q.Question) != 1 || q.Question[0].Class != dns.ClassIN {
		return nil, false
	}
	resp := dns.Message{ID: q.ID, Flags: 0x8400, Question: q.Question}
	limit := 512 // the requester's size: 512 without OPT (RFC 1035, 6891)
	for _, rr := range q.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 || (rr.TTL>>16)&0xff != 0 {
			return nil, false
		}
		// The query's DO bit, as dnstt's answers (RFC 3225 §3).
		resp.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: rr.TTL & optDO, Data: []byte{}}}
		limit = max(limit, int(rr.Class))
	}
	name, question := q.Question[0].Name, q.Question[0]
	soa := dns.RR{Name: name, Type: apexType, Class: dns.ClassIN, TTL: apexTTL, Data: a.soa}
	switch question.Type {
	case apexType, apexANY:
		resp.Answer = []dns.RR{soa}
	case apexNS:
		for _, ns := range a.ns {
			resp.Answer = append(resp.Answer, dns.RR{Name: name, Type: apexNS, Class: dns.ClassIN, TTL: apexTTL, Data: wireName(ns)})
		}
	default:
		// NODATA, with the SOA for how long to keep it (RFC 2308 §3).
		soa.TTL = apexNegative
		resp.Authority = []dns.RR{soa}
	}
	wire, err := resp.WireFormat()
	if err != nil {
		return nil, false
	}
	if len(wire) > limit {
		// Long names that do not fit: TC and no records, for the
		// resolver to ask again over TCP. Never more than was asked for.
		resp.Answer, resp.Authority = nil, nil
		resp.Flags |= 0x0200
		if wire, err = resp.WireFormat(); err != nil {
			return nil, false
		}
	}
	return wire, true
}
