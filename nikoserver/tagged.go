package nikoserver

import (
	"encoding/base32"
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// taggedZone (v0.13.0) checks the device's tag a query of a slipstream zone
// carries before its backend sees the query (raycontrol slipstream-v1 §2):
// the name's labels before the zone are base32 (RFC 4648, any case, no
// padding) of the dnsauth-v2 field (8 bytes, dnsauth-v2 §2) and the QUIC
// packet it signs. The key is found by the hint, no scan (required): what
// is not a device's query costs a lookup and gets no further. A field seen
// before is a copy (review: anyone on the path could replay a query for
// the 20-30 minutes its tag holds, and the server sent the connection's
// next packet to the copy's address): it gets no further either.
type taggedZone struct {
	zone   string
	suffix string // "." + zone
	auth   *dnsttserver.DeviceAuth
	seen   seenFields
	now    func() time.Time // tests
}

func newTaggedZone(zone string, auth *dnsttserver.DeviceAuth) *taggedZone {
	return &taggedZone{zone: zone, suffix: "." + zone, auth: auth}
}

var slipBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// The verdicts of check.
const (
	tagPassed = iota
	tagRefused
	tagReplayed
)

// check returns the query as its backend gets it, built in buf, its field
// and tagPassed; or tagRefused, or tagReplayed for a field seen before. A
// query passed on that never reaches the backend gives its field back
// (forget): a retry of it is no copy. It
// takes one question, IN TXT, in the zone and below it, with a device's tag
// over the data. The backend gets it rebuilt, as its parser takes it: the
// header (ID, RD, CD), the question as it came (the case kept: resolvers
// check it in answers) and an OPT with the requester's size and DO when the
// query had one, without options.
func (t *taggedZone) check(query []byte, name string, questionEnd int, buf []byte) ([]byte, [dnsttserver.AuthTagLen]byte, int) {
	var field [dnsttserver.AuthTagLen]byte
	if len(query) < 12 || query[2]&0x78 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) > 1 {
		return nil, field, tagRefused
	}
	if binary.BigEndian.Uint16(query[questionEnd-4:]) != 16 || binary.BigEndian.Uint16(query[questionEnd-2:]) != 1 {
		return nil, field, tagRefused // TXT, IN
	}
	labels, ok := strings.CutSuffix(name, t.suffix)
	if !ok || labels == "" {
		return nil, field, tagRefused
	}
	var rawBuf [maxNameText]byte
	raw, ok := slipDecode(labels, rawBuf[:0])
	if !ok || len(raw) <= dnsttserver.AuthTagLen {
		return nil, field, tagRefused
	}
	field = [dnsttserver.AuthTagLen]byte(raw[:dnsttserver.AuthTagLen])
	if _, ok := t.auth.Scan(dnsttserver.ScanSession, field, raw[dnsttserver.AuthTagLen:]); !ok {
		return nil, field, tagRefused
	}
	now := time.Now
	if t.now != nil {
		now = t.now
	}
	if !t.seen.first(field, dnsttserver.EpochOf(now())) {
		return nil, field, tagReplayed
	}
	out := append(buf[:0], query[:questionEnd]...)
	out[2] &= 0x01 // RD
	out[3] &= 0x10 // CD
	binary.BigEndian.PutUint16(out[10:12], 0)
	if i := optOffset(query, questionEnd); i >= 0 {
		binary.BigEndian.PutUint16(out[10:12], 1)
		// root, OPT, the requester's size, extended RCODE and version 0, DO, no data
		out = append(out, 0, 0, 41, query[i+2], query[i+3], 0, 0, query[i+6]&0x80, 0, 0, 0)
	}
	return out, field, tagPassed
}

// slipDecode decodes the labels before a slipstream zone into dst: base32
// (lower case here, queryName folded it) with the dots taken out, and
// nothing the server's decoder could read otherwise (review): only a-z and
// 2-7, a length a whole number of bytes takes, and the unused bits of the
// last character zero. Go's decoder skips CR and LF and takes any last
// bits: the tag would be checked over other bytes than the server reads.
func slipDecode(labels string, dst []byte) ([]byte, bool) {
	var textBuf [maxNameText]byte
	text := textBuf[:0]
	if len(labels) > len(textBuf) {
		return nil, false
	}
	for i := 0; i < len(labels); i++ {
		switch c := labels[i]; {
		case c == '.':
		case 'a' <= c && c <= 'z':
			text = append(text, c-'a'+'A')
		case '2' <= c && c <= '7':
			text = append(text, c)
		default:
			return nil, false
		}
	}
	// The bits of the last character no byte takes: 5 per character, 8 per
	// byte. 1, 3 and 6 characters over a block of 8 make no whole byte.
	var spare uint
	switch len(text) % 8 {
	case 0:
	case 2:
		spare = 2
	case 4:
		spare = 4
	case 5:
		spare = 1
	case 7:
		spare = 3
	default:
		return nil, false
	}
	if len(text) == 0 {
		return nil, false
	}
	if spare > 0 {
		last := text[len(text)-1]
		v := last - 'A'
		if last <= '7' {
			v = last - '2' + 26
		}
		if v&(1<<spare-1) != 0 {
			return nil, false
		}
	}
	n := slipBase32.DecodedLen(len(text))
	if cap(dst) < n {
		dst = make([]byte, 0, n)
	}
	n, err := slipBase32.Decode(dst[:n], text)
	if err != nil {
		return nil, false
	}
	return dst[:n], true
}

// seenFields remembers the dnsauth-v2 fields of the queries passed on, for
// as long as a tag holds: a tag of epoch e is taken while the clock is in
// e-1, e or e+1, so a field first seen in epoch n is good until the end of
// n+2, and the fields stay four epochs (generations by the epoch they were
// seen in). A generation full (seenCap: a zone under a heavy load, ~220
// queries a second for 10 minutes) starts the next one early, the oldest
// going: copies older than that are no longer caught here, and the server
// still answers them empty (it binds no answer to a connection for a
// packet it already had).
type seenFields struct {
	mu    sync.Mutex
	epoch uint32 // of gens[0]
	gens  [4]map[[dnsttserver.AuthTagLen]byte]struct{}
}

const seenCap = 1 << 17

// first reports whether field is seen for the first time, and takes it in.
func (s *seenFields) first(field [dnsttserver.AuthTagLen]byte, epoch uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gens[0] == nil {
		s.gens[0], s.epoch = make(map[[dnsttserver.AuthTagLen]byte]struct{}), epoch
	}
	if d := epoch - s.epoch; d > 0 && d < 1<<31 {
		s.turn(min(d, uint32(len(s.gens))))
		s.epoch = epoch
	}
	for _, g := range s.gens {
		if _, ok := g[field]; ok {
			return false
		}
	}
	if len(s.gens[0]) >= seenCap {
		s.turn(1)
	}
	s.gens[0][field] = struct{}{}
	return true
}

// forget gives back a field taken in: its query never reached the backend.
func (s *seenFields) forget(field [dnsttserver.AuthTagLen]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.gens[0], field)
}

// turn starts n new generations, the oldest ones going.
func (s *seenFields) turn(n uint32) {
	for range n {
		copy(s.gens[1:], s.gens[:len(s.gens)-1])
		s.gens[0] = make(map[[dnsttserver.AuthTagLen]byte]struct{})
	}
}

// frontOPT is the OPT the front answers an EDNS query with when no backend
// does: the size every answer of the node says (4096: the front's apex and
// probe answers, dnstt's and the slipstream server's), the query's DO bit,
// no options; so the front's answers and the backends' read the same.
func frontOPT(query []byte, questionEnd int) []byte {
	i := optOffset(query, questionEnd)
	if i < 0 {
		return nil
	}
	return []byte{0, 0, 41, 0x10, 0x00, 0, 0, query[i+6] & 0x80, 0, 0, 0}
}

// nodata answers a query with NOERROR and no records, as the zone would for
// a name without the type asked: the question echoed, AA set, and an OPT
// when the query had one, as the server's empty answer (review: without it
// the front's answer told an untagged query apart, and an EDNS query must
// get one, RFC 6891 §7). Another opcode than QUERY gets NOTIMP without AA,
// as authoritative servers answer it.
func nodata(query []byte, questionEnd int) []byte {
	opt := frontOPT(query, questionEnd)
	answer := make([]byte, questionEnd, questionEnd+len(opt))
	copy(answer, query[:questionEnd])
	answer[2] = 0x84 | query[2]&0x79 // QR, AA, opcode, RD
	answer[3] = query[3] & 0x10      // CD
	if query[2]&0x78 != 0 {
		answer[2] &^= 0x04 // not authoritative
		answer[3] = 4      // NOTIMP
	}
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint16(answer[6:8], 0)
	binary.BigEndian.PutUint16(answer[8:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 0)
	if opt != nil {
		binary.BigEndian.PutUint16(answer[10:12], 1)
		answer = append(answer, opt...)
	}
	return answer
}
