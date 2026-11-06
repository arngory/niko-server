package nikoserver

import (
	"encoding/base32"
	"encoding/binary"
	"strings"

	"github.com/arngory/niko-server/dnsttserver"
)

// taggedZone (v0.13.0) checks the device's tag a query of a slipstream zone
// carries before its backend sees the query (raycontrol slipstream-v1 §2):
// the name's labels before the zone are base32 (RFC 4648, any case, no
// padding) of the dnsauth-v2 field (8 bytes, dnsauth-v2 §2) and the QUIC
// packet it signs. The key is found by the hint, no scan (required): what
// is not a device's query costs a lookup and gets no further.
type taggedZone struct {
	zone string
	auth *dnsttserver.DeviceAuth
}

var slipBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// check returns the query as its backend gets it, or nil: one question, IN
// TXT, in the zone and below it, with a device's tag over the data. The
// backend gets it rebuilt, as its parser takes it: the header (ID, RD, CD),
// the question as it came (the case kept: resolvers check it in answers)
// and an OPT with the requester's size and DO when the query had one,
// without options.
func (t *taggedZone) check(query []byte, name string, questionEnd int) []byte {
	if len(query) < 12 || query[2]&0x78 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) > 1 {
		return nil
	}
	if binary.BigEndian.Uint16(query[questionEnd-4:]) != 16 || binary.BigEndian.Uint16(query[questionEnd-2:]) != 1 {
		return nil // TXT, IN
	}
	labels, ok := strings.CutSuffix(name, "."+t.zone)
	if !ok || labels == "" {
		return nil
	}
	raw, err := slipBase32.DecodeString(strings.ToUpper(strings.ReplaceAll(labels, ".", "")))
	if err != nil || len(raw) <= dnsttserver.AuthTagLen {
		return nil
	}
	if _, ok := t.auth.Scan(dnsttserver.ScanSession, [dnsttserver.AuthTagLen]byte(raw[:dnsttserver.AuthTagLen]), raw[dnsttserver.AuthTagLen:]); !ok {
		return nil
	}
	out := make([]byte, questionEnd, questionEnd+11)
	copy(out, query[:questionEnd])
	out[2] &= 0x01 // RD
	out[3] &= 0x10 // CD
	binary.BigEndian.PutUint16(out[10:12], 0)
	if i := optOffset(query, questionEnd); i >= 0 {
		binary.BigEndian.PutUint16(out[10:12], 1)
		// root, OPT, the requester's size, extended RCODE and version 0, DO, no data
		out = append(out, 0, 0, 41, query[i+2], query[i+3], 0, 0, query[i+6]&0x80, 0, 0, 0)
	}
	return out
}

// nodata answers a query with NOERROR and no records, as the zone would for
// a name without the type asked: the question echoed, AA set.
func nodata(query []byte, questionEnd int) []byte {
	answer := make([]byte, questionEnd)
	copy(answer, query[:questionEnd])
	answer[2] = 0x84 | query[2]&0x79 // QR, AA, opcode, RD
	answer[3] = query[3] & 0x10      // CD
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint16(answer[6:8], 0)
	binary.BigEndian.PutUint16(answer[8:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 0)
	return answer
}
