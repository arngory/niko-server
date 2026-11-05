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
// zone whose apex had neither (raycontrol docs/13-dns-resolvers.md). The
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
}

func newApexZone(zone string, ns []string, serial uint32) *apexZone {
	names := make([]string, len(ns))
	for i, n := range ns {
		names[i] = strings.ToLower(strings.TrimSuffix(n, "."))
	}
	soa := wireName(names[0])
	soa = append(soa, wireName("hostmaster."+zone)...)
	// serial, refresh, retry, expire, minimum
	for _, v := range []uint32{serial, 7200, 3600, 1209600, apexNegative} {
		soa = binary.BigEndian.AppendUint32(soa, v)
	}
	return &apexZone{ns: names, soa: soa}
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
	for _, rr := range q.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 || (rr.TTL>>16)&0xff != 0 {
			return nil, false
		}
		resp.Additional = []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}}}
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
	return wire, true
}
