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
// larger, nor over maxBackendAnswer: one that is gets TC and no records, as
// a server's that does not fit. An answer no query waits for is dropped.
// This bounds what a forged source gets out of a backend; it does not end
// it, as the forged query writes the requester's size itself: an answer of
// up to 1232 bytes still goes to the victim (masterdns's MTU probes sent 4
// to 6 KB, up to 136 times the query). The backends bound the rest:
// masterdns (arngory/sing-box 15c95f4) answers a probe with at most 4 times
// its query, dnstt sizes its answers and answers a query without a device's
// tag empty where dnsauth is required. Two generations of pendingGeneration
// bound the table: an answer later than 5 to 10 seconds is dropped too, and
// a flood swaps them sooner.
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

// maxBackendAnswer is the most a backend's answer may be over UDP whatever
// the requester's OPT says, since a forged query brings its own: with an
// OPT of 65535, masterdns's MTU probe answers (4 to 6 KB) still went to the
// victim (review 7). dnstt never answers more (maxUDPPayload), and 1232 is
// DNS's size that does not fragment (DNS Flag Day 2020): the most a forged
// query gets out is what any DNS server's EDNS answer is.
const maxBackendAnswer = 1232

// requesterSize is the UDP payload size a query's requester takes: its OPT
// record's, wherever it is in the additional section (as dnstt reads it),
// at least 512; 512 without one, or when the query cannot be walked.
func requesterSize(query []byte, questionEnd int) int {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return 512
	}
	an := int(binary.BigEndian.Uint16(query[6:8]))
	ns := int(binary.BigEndian.Uint16(query[8:10]))
	ar := int(binary.BigEndian.Uint16(query[10:12]))
	i := questionEnd
	for r := 0; r < an+ns+ar; r++ {
		var ok bool
		if i, ok = skipName(query, i); !ok || i+10 > len(query) {
			return 512
		}
		if r >= an+ns && binary.BigEndian.Uint16(query[i:i+2]) == 41 {
			return min(max(int(binary.BigEndian.Uint16(query[i+2:i+4])), 512), maxDatagram)
		}
		i += 10 + int(binary.BigEndian.Uint16(query[i+8:i+10]))
	}
	return 512
}

// skipName returns where the name at msg[i:] ends: after its root label or
// its compression pointer.
func skipName(msg []byte, i int) (int, bool) {
	for i < len(msg) {
		switch n := int(msg[i]); {
		case n == 0:
			return i + 1, true
		case n&0xc0 == 0xc0:
			return i + 2, i+2 <= len(msg)
		case n > 63:
			return 0, false
		default:
			i += 1 + n
		}
	}
	return 0, false
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
