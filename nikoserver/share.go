//go:build linux

package nikoserver

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// answerShare (v0.19.3, review 2026-11-21 item 3) gives the copies of a
// tagged zone's query the answer the first one got. The front passes on
// the first query with a field and holds back the others (seenFields); the
// server answered the one passed on only. So a copy that came first, from
// anyone on the path who is faster than the resolver, took the server's
// answer, and the resolver's own query got nothing: every packet of the
// connection went to the copier's address, and the client's queries were
// left unanswered. Now a copy of a field passed on lately waits for the
// answer to the first and gets it too, or gets it at once when it came:
// with its own ID, question (its name as it asked it: in another case, or
// in other labels, when the answer's names all point at the question) and
// EDNS, within its requester's size. A field's answer goes to shareAnswers
// queries in all, the first's included: a resolver's retries, from more
// than one of its addresses; the copies past them get nothing, so one
// query seen does not reflect its answer as often as it is sent. A copy
// never gets another answer than the first's: the server's next packet
// goes to the next query.
//
// Two generations of pendingGeneration bound it, as the queries waiting
// for their answers, each shareBytes at most: a copy later than 5 to 10
// s, or than a flood allows, is one as before (no answer within seenQuiet,
// then NOERROR).
type answerShare struct {
	mu        sync.Mutex
	cur, prev map[[dnsttserver.AuthTagLen]byte]*sharedAnswer
	curBytes  int
	swapped   time.Time
	now       func() time.Time // time.Now when nil (tests)
}

type sharedAnswer struct {
	answer  []byte // the backend's, nil until it comes
	given   int    // the queries it goes or went to, the first included
	waiting []shareWaiter
}

// shareWaiter is a copy that waits for the answer: where it came from and
// to, and the query.
type shareWaiter struct {
	client, local netip.AddrPort
	dst           netip.Addr
	query         []byte
	questionEnd   int
}

const (
	shareAnswers   = 4
	shareBytes     = 4 << 20 // a generation's: answers and queries waiting, and shareEntryCost each
	shareEntryCost = 160
)

func (s *answerShare) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// age turns the generations over; the caller holds mu.
func (s *answerShare) age(now time.Time) {
	switch since := now.Sub(s.swapped); {
	case s.cur == nil || since > 2*pendingGeneration:
		s.prev, s.cur, s.curBytes, s.swapped = nil, make(map[[dnsttserver.AuthTagLen]byte]*sharedAnswer), 0, now
	case since > pendingGeneration || s.curBytes >= shareBytes:
		s.prev, s.cur, s.curBytes, s.swapped = s.cur, make(map[[dnsttserver.AuthTagLen]byte]*sharedAnswer), 0, now
	}
}

// find is a field's entry; the caller holds mu.
func (s *answerShare) find(field [dnsttserver.AuthTagLen]byte) *sharedAnswer {
	if e := s.cur[field]; e != nil {
		return e
	}
	return s.prev[field]
}

// open notes a field whose query goes to the backend.
func (s *answerShare) open(field [dnsttserver.AuthTagLen]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.age(s.clock())
	s.cur[field] = &sharedAnswer{given: 1}
	s.curBytes += shareEntryCost
}

// forget drops a field whose query never reached the backend.
func (s *answerShare) forget(field [dnsttserver.AuthTagLen]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cur, field)
	delete(s.prev, field)
}

// copyOf takes a copy of a field: handled false when the field is not
// one passed on lately (the caller answers as before); else reply is the
// first's answer for it to send now, or nil: it waits for the answer, or
// gets none (the field's answers given).
func (s *answerShare) copyOf(field [dnsttserver.AuthTagLen]byte, query []byte, questionEnd int, client, local netip.AddrPort, dst netip.Addr) (reply []byte, handled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.age(s.clock())
	e := s.find(field)
	if e == nil {
		return nil, false
	}
	if e.given >= shareAnswers {
		return nil, true
	}
	if e.answer != nil {
		if reply = shareReply(e.answer, query, questionEnd); reply != nil {
			e.given++
		}
		return reply, true
	}
	e.given++
	e.waiting = append(e.waiting, shareWaiter{client: client, local: local, dst: dst, query: append([]byte(nil), query...), questionEnd: questionEnd})
	s.curBytes += len(query)
	return nil, true
}

// answered keeps the backend's answer to a field's query and returns the
// copies that wait for it.
func (s *answerShare) answered(field [dnsttserver.AuthTagLen]byte, answer []byte) []shareWaiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.age(s.clock())
	e := s.find(field)
	if e == nil || e.answer != nil {
		return nil
	}
	e.answer = append([]byte(nil), answer...)
	s.curBytes += len(answer)
	w := e.waiting
	e.waiting = nil
	return w
}

// shareReply is the answer to one query made the answer to another of the
// same field: its ID, RD and CD, its question, the answer's records but
// OPT, then an OPT as the front's (4096, its DO) when it has one, within
// its requester's size (truncated as a backend's answer, past it). The
// question goes in as it came when every name in the answer's records is
// the root or points at the question (the slipstream server's: SPCDNS
// compresses the TXT's name to it), and their data hold no names; else
// only when it is the answer's but for case. Nil when the answer does not
// read, or the question cannot go in.
func shareReply(answer, query []byte, questionEnd int) []byte {
	if len(answer) < 12 || binary.BigEndian.Uint16(answer[4:6]) != 1 {
		return nil
	}
	aEnd, ok := skipName(answer, 12)
	if !ok || aEnd+4 > len(answer) {
		return nil
	}
	aEnd += 4
	an := int(binary.BigEndian.Uint16(answer[6:8]))
	ns := int(binary.BigEndian.Uint16(answer[8:10]))
	ar := int(binary.BigEndian.Uint16(answer[10:12]))
	pointersOnly := true
	type span struct{ from, to, section int }
	var records []span
	i := aEnd
	for r := 0; r < an+ns+ar; r++ {
		from := i
		switch {
		case i < len(answer) && answer[i] == 0:
			i++
		case i+1 < len(answer) && answer[i] == 0xc0 && answer[i+1] == 12:
			i += 2
		default:
			pointersOnly = false
			if i, ok = skipName(answer, i); !ok {
				return nil
			}
		}
		if i+10 > len(answer) {
			return nil
		}
		typ := binary.BigEndian.Uint16(answer[i : i+2])
		switch typ {
		case 1, 16, 28, 41: // A, TXT, AAAA, OPT: no names in their data
		default:
			pointersOnly = false
		}
		i += 10 + int(binary.BigEndian.Uint16(answer[i+8:i+10]))
		if i > len(answer) {
			return nil
		}
		section := 0
		switch {
		case r >= an+ns:
			section = 2
		case r >= an:
			section = 1
		}
		if typ != 41 {
			records = append(records, span{from, i, section})
		}
	}
	if !pointersOnly && !sameNameFold(answer[12:aEnd], query[12:questionEnd]) {
		return nil
	}
	out := make([]byte, 0, questionEnd+len(answer)-aEnd+11)
	out = append(out, query[:2]...)
	out = append(out, answer[2]&^0x01|query[2]&0x01, answer[3]&^0x10|query[3]&0x10)
	out = append(out, 0, 1, 0, 0, 0, 0, 0, 0)
	out = append(out, query[12:questionEnd]...)
	var counts [3]uint16
	for _, r := range records {
		out = append(out, answer[r.from:r.to]...)
		counts[r.section]++
	}
	if opt := frontOPT(query, questionEnd); opt != nil {
		out = append(out, opt...)
		counts[2]++
	}
	binary.BigEndian.PutUint16(out[6:8], counts[0])
	binary.BigEndian.PutUint16(out[8:10], counts[1])
	binary.BigEndian.PutUint16(out[10:12], counts[2])
	if len(out) > min(requesterSize(query, questionEnd), maxBackendAnswer) {
		return truncated(out)
	}
	return out
}

// sameNameFold reports whether two questions are one but for the case of
// their names' letters (ASCII, RFC 4343).
func sameNameFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
