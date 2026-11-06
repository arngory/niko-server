package nikoserver

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// pendingQueries remembers, for each query the front passed to a backend,
// the most its requester takes (RFC 6891 §6.2.5: the OPT's size, never
// under 512; 512 without one). An answer from a backend never goes out
// larger: one that is gets TC and no records, as a server's that does not
// fit. A backend that does not size its answers itself (masterdns sends the
// kilobytes of its MTU probes to anyone) would otherwise make the node a
// reflector: a forged source, a hundred bytes in, kilobytes out to the
// victim. An answer no query waits for is dropped. Two generations of
// pendingGeneration bound it: an answer later than 5 to 10 seconds is
// dropped too, and a flood swaps them sooner.
type pendingQueries struct {
	mu        sync.Mutex
	cur, prev map[pendingKey]pendingEntry
	swapped   time.Time
	now       func() time.Time // time.Now when nil (tests)
}

type pendingKey struct {
	client netip.AddrPort
	id     uint16
}

type pendingEntry struct {
	size uint16 // the requester's
	n    uint16 // queries with this key still waiting (a resolver's retry has the same)
}

const (
	pendingGeneration = 5 * time.Second
	pendingMax        = 1 << 16 // queries in a generation
)

func (p *pendingQueries) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// age turns the generations over; the caller holds mu.
func (p *pendingQueries) age(now time.Time) {
	switch since := now.Sub(p.swapped); {
	case p.cur == nil || since > 2*pendingGeneration:
		p.prev, p.cur, p.swapped = nil, make(map[pendingKey]pendingEntry), now
	case since > pendingGeneration || len(p.cur) >= pendingMax:
		p.prev, p.cur, p.swapped = p.cur, make(map[pendingKey]pendingEntry), now
	}
}

// add notes a query from client that goes to a backend.
func (p *pendingQueries) add(client netip.AddrPort, query []byte, questionEnd int) {
	k := pendingKey{client, binary.BigEndian.Uint16(query)}
	size := uint16(requesterSize(query, questionEnd))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.age(p.clock())
	e, ok := p.cur[k]
	if !ok {
		if e, ok = p.prev[k]; ok {
			delete(p.prev, k)
		}
	}
	e.size = max(e.size, size)
	if e.n < 1<<16-1 {
		e.n++
	}
	p.cur[k] = e
}

// take finds the query an answer is for: the requester's size, and false
// when none waits.
func (p *pendingQueries) take(client netip.AddrPort, answer []byte) (int, bool) {
	if len(answer) < 12 {
		return 0, false
	}
	k := pendingKey{client, binary.BigEndian.Uint16(answer)}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.age(p.clock())
	gen := p.cur
	e, ok := gen[k]
	if !ok {
		gen = p.prev
		if e, ok = gen[k]; !ok {
			return 0, false
		}
	}
	if e.n--; e.n == 0 {
		delete(gen, k)
	} else {
		gen[k] = e
	}
	return int(e.size), true
}

// requesterSize is the UDP payload size a query's requester takes: its OPT
// record's (the first record of the additional section, right after the
// one question, with the root name), at least 512; 512 without one.
func requesterSize(query []byte, questionEnd int) int {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) == 0 {
		return 512
	}
	rr := query[questionEnd:]
	if len(rr) < 11 || rr[0] != 0 || binary.BigEndian.Uint16(rr[1:3]) != 41 {
		return 512
	}
	return min(max(int(binary.BigEndian.Uint16(rr[3:5])), 512), maxDatagram)
}

// truncated is an answer cut to its header and question, with TC set and
// no records: what a server sends that does not fit the requester. Nil
// when the answer has no question it can find.
func truncated(answer []byte) []byte {
	if len(answer) < 12 || binary.BigEndian.Uint16(answer[4:6]) != 1 {
		return nil
	}
	i := 12
	for {
		if i >= len(answer) {
			return nil
		}
		n := int(answer[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(answer) {
			return nil
		}
		i += n
	}
	if i+4 > len(answer) {
		return nil
	}
	out := append([]byte(nil), answer[:i+4]...)
	out[2] |= 0x02 // TC
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}
