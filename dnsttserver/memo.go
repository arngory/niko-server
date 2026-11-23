package dnsttserver

import (
	"hash/maphash"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// answerMemo keeps the data of recent answers by query payload (neko). A
// resolver that hears nothing in time asks again, the same query of the
// client's, and takes whichever answer comes first; the other is dropped.
// Answered with new data, the retry lost what it carried, and KCP had to
// send it again. Now it gets the first answer's data, and so does any
// copy of the query, however its name is cased or split: it takes nothing
// of the client's next data. The payload carries the client's random
// padding, or a sealed query's N, so the client never repeats one.
//
// Two generations of memoGeneration bound it, each memoBytes at most (v0.19.3;
// it was 4096 answers, whatever their size, and at ~800 answers a second a
// generation lasted less than its 5 s): an answer is kept 5 to 10 seconds,
// fewer under a flood. An answer goes out again memoRepeats times at most
// (a resolver's retries, from more than one of its addresses); copies past
// that get an empty answer (copyMemory), so one recorded query does not
// reflect its answer to an address as often as it is sent. Only sendLoop
// uses it, from one goroutine.
type answerMemo struct {
	cur, prev map[string]*memoEntry
	curBytes  int
	swapped   time.Time
	now       func() time.Time // time.Now when nil (tests)
}

type memoEntry struct {
	data []byte // TXT RDATA
	raw  int    // payload bytes in it
	hits uint8  // times it went out again
}

const (
	memoGeneration = 5 * time.Second
	memoBytes      = 8 << 20 // a generation's, keys and data and memoEntryCost each
	memoEntryCost  = 160     // the map's slot, the string and slice headers, the entry (measured: TestLoadMemoCapacity)
	memoRepeats    = 3       // an answer's repeats from the memo
)

func (m *answerMemo) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// age turns the generations over by the clock: what is older than two
// generations is gone even when no answer came meanwhile.
func (m *answerMemo) age(now time.Time) {
	switch since := now.Sub(m.swapped); {
	case m.cur == nil || since > 2*memoGeneration:
		m.prev, m.cur, m.curBytes, m.swapped = nil, make(map[string]*memoEntry), 0, now
	case since > memoGeneration || m.curBytes >= memoBytes:
		m.prev, m.cur, m.curBytes, m.swapped = m.cur, make(map[string]*memoEntry), 0, now
	}
}

// answer fills rec's answer from the memo, if its query was answered
// lately and not memoRepeats times since. Data that would not fit this
// requester (a retry through a smaller resolver) is not sent: the answer
// goes out empty.
func (m *answerMemo) answer(rec *record) bool {
	if rec.Key == "" {
		return false
	}
	m.age(m.clock())
	e, ok := m.cur[rec.Key]
	if !ok {
		e, ok = m.prev[rec.Key]
	}
	if !ok || e.hits >= memoRepeats {
		return false
	}
	e.hits++
	data := e.data
	if e.raw > encodedPayload(rec.Size) {
		var empty []byte
		if rec.Seal != nil {
			empty = rec.Seal.answer(nil, encodedPayload(rec.Size))
		}
		data = dns.EncodeRDataTXT(empty)
	}
	q := rec.Resp.Question[0]
	rec.Resp.Answer = []dns.RR{{Name: q.Name, Type: q.Type, Class: q.Class, TTL: responseTTL, Data: data}}
	return true
}

func (m *answerMemo) remember(rec *record, raw int) {
	if rec.Key == "" {
		return
	}
	m.age(m.clock())
	data := rec.Resp.Answer[0].Data
	cost := len(rec.Key) + len(data) + memoEntryCost
	if m.curBytes+cost > memoBytes && len(m.cur) > 0 {
		m.prev, m.cur, m.curBytes, m.swapped = m.cur, make(map[string]*memoEntry), 0, m.clock()
	}
	m.cur[rec.Key] = &memoEntry{data: data, raw: raw}
	m.curBytes += cost
}

// copyMemory remembers the payloads of the queries sendLoop answered with
// data (v0.19.3, review 2026-11-21 item 3) for as long as a dnsauth tag
// holds: a tag of epoch e is taken while the clock is in e-1, e or e+1, so
// a payload first seen in epoch n may come again until the end of n+2, and
// the payloads stay three epochs (generations by the epoch). A query whose
// payload it holds and the memo no longer answers is a copy (anyone on the
// path can send a recorded query again, from any address): it gets an empty
// answer, never the session's next data, which before went to the copy's
// address and was lost to the client until KCP sent it again.
//
// A generation is a Bloom filter of copyMemoryCap payloads, 1 MiB under a
// keyed hash (a map of their hashes took 36 bytes a payload): the whole
// window at ~870 data queries a second; under more, a full generation
// starts the next one early (counted), the oldest going. One query in
// about 2000 (in 700 with all three generations full) is taken for a copy
// it is not: its answer goes out empty, and the data waits for the
// client's next query; what the query carried reaches KCP all the same
// (recvLoop). Without dnsauth a payload never expires: a copy older than the
// memory takes data as before. A query sendLoop never got (its queue full)
// is not in it: a retry is no copy. Only sendLoop uses it.
type copyMemory struct {
	seed  maphash.Seed
	ready bool   // seed made
	epoch uint32 // of gens[0]
	gens  [3]copyFilter
	turns func() // a generation started early; nil: not counted
}

type copyFilter struct {
	bits []uint64
	n    int // payloads put in
}

const (
	copyMemoryCap = 1 << 19
	copyBits      = 16 * copyMemoryCap // a generation's: 1 MiB
	copyHashes    = 11                 // bits a payload sets: the fewest false copies at 16 bits a payload
)

// has reports whether all of h's bits are set, and with set, sets them.
func (f *copyFilter) has(h uint64, set bool) bool {
	if f.bits == nil {
		if !set {
			return false
		}
		f.bits = make([]uint64, copyBits/64)
	}
	// Two hashes make the others (Kirsch and Mitzenmacher).
	a, b := uint32(h), uint32(h>>32)|1
	all := true
	for i := range uint32(copyHashes) {
		bit := (a + i*b) % copyBits
		w, m := bit/64, uint64(1)<<(bit%64)
		if f.bits[w]&m == 0 {
			all = false
			if !set {
				return false
			}
			f.bits[w] |= m
		}
	}
	if set && !all {
		f.n++
	}
	return all
}

// sight takes a payload in, and reports whether it was there: a copy.
func (c *copyMemory) sight(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	epoch := EpochOf(now)
	if !c.ready {
		c.seed, c.epoch, c.ready = maphash.MakeSeed(), epoch, true
	}
	if d := epoch - c.epoch; d > 0 && d < 1<<31 {
		c.turn(min(d, uint32(len(c.gens))))
		c.epoch = epoch
	}
	h := maphash.String(c.seed, key)
	for i := range c.gens {
		if c.gens[i].has(h, false) {
			return true
		}
	}
	if c.gens[0].n >= copyMemoryCap {
		c.turn(1)
		if c.turns != nil {
			c.turns()
		}
	}
	c.gens[0].has(h, true)
	return false
}

// turn starts n new generations, the oldest ones going.
func (c *copyMemory) turn(n uint32) {
	for range n {
		old := c.gens[len(c.gens)-1].bits
		copy(c.gens[1:], c.gens[:len(c.gens)-1])
		clear(old) // its 1 MiB again, not a new one
		c.gens[0] = copyFilter{bits: old}
	}
}
