package dnsttserver

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// copyHarness is recvLoop and sendLoop over a feedConn, with one session
// in the table.
type copyHarness struct {
	t    *testing.T
	tt   *turbotunnel.QueuePacketConn
	conn feedConn
	id   turbotunnel.ClientID
}

func newCopyHarness(t *testing.T, stats *Stats) *copyHarness {
	t.Helper()
	domain, _ := dns.ParseName("t.example.com")
	h := &copyHarness{t: t, tt: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, time.Minute),
		conn: feedConn{in: make(chan []byte, 1<<14), out: make(chan []byte, 1<<14)}, id: turbotunnel.ClientID{1, 2, 3, 4, 5, 6, 7, 9}}
	t.Cleanup(func() { h.tt.Close(); close(h.conn.in) })
	if stats == nil {
		stats = &Stats{}
	}
	sessions := newSessionTableStats(stats)
	sessions.admit(h.id, startPacket(), nil)
	ch := make(chan *record, 1<<14)
	go recvLoop([]dns.Name{domain}, h.conn, h.tt, ch, nil, nil, &clientSizes{}, sessions)
	go sendLoop(h.conn, h.tt, ch, sessions)
	return h
}

// poll is the client's query number n: its ClientID and a padding frame
// that tells it from the others.
func (h *copyHarness) poll(n int) []byte {
	inner := append(h.id[:], 0xe2, byte(n>>8), byte(n))
	return pollQuery(h.t, inner, "t.example.com")
}

// data is an answer's TXT data.
func (h *copyHarness) data(w []byte) []byte {
	h.t.Helper()
	m, err := dns.MessageFromWireFormat(w)
	if err != nil || len(m.Answer) != 1 {
		h.t.Fatalf("answer %+v %v", m, err)
	}
	d, _ := dns.DecodeRDataTXT(m.Answer[0].Data)
	return d
}

func (h *copyHarness) ask(q []byte) []byte {
	h.t.Helper()
	h.conn.in <- q
	select {
	case w := <-h.conn.out:
		return h.data(w)
	case <-time.After(5 * time.Second):
		h.t.Fatal("no answer")
		return nil
	}
}

func framed(p []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...) }

// A copy of a client's query that comes after the memo has let it go (here
// pushed out by many other queries; or later than 10 s) gets an empty
// answer, never the session's next data (review 2026-11-21 item 3: anyone
// who recorded a query could replay it for as long as its tag held, and
// took the data queued for the client to the copy's address).
func TestCopyBeyondMemoTakesNoData(t *testing.T) {
	stats := &Stats{}
	h := newCopyHarness(t, stats)
	first := []byte("first packet")
	h.tt.WriteTo(first, h.id)
	original := h.poll(0)
	if got := h.ask(original); !bytes.Equal(got, framed(first)) {
		t.Fatalf("the first answer: %q", got)
	}
	// More queries than the memo kept in v0.19.2 (two generations of
	// 4096), sent at once: each answer ends when the next query comes.
	const others = 2*4096 + 64
	for n := 1; n <= others; n++ {
		h.conn.in <- h.poll(n)
	}
	for range others {
		select {
		case <-h.conn.out:
		case <-time.After(10 * time.Second):
			t.Fatal("an answer missing")
		}
	}
	next := []byte("the session's next packet")
	h.tt.WriteTo(next, h.id)
	if got := h.ask(original); bytes.Equal(got, framed(next)) {
		t.Fatal("a copy of an old query took the session's next packet")
	}
	// The packet is still the client's: its next query takes it.
	if got := h.ask(h.poll(others + 1)); !bytes.Equal(got, framed(next)) {
		t.Fatalf("the client's next query: %q, want the next packet", got)
	}
}

// Copies within the memo get the first answer's data, a few times: a
// resolver's retries, from more than one of its addresses. Past that they
// get an empty answer: one recorded query no longer reflects its answer
// to any address as often as it is sent.
func TestMemoRepeatsBounded(t *testing.T) {
	stats := &Stats{}
	h := newCopyHarness(t, stats)
	first := bytes.Repeat([]byte{7}, 900)
	h.tt.WriteTo(first, h.id)
	original := h.poll(0)
	if got := h.ask(original); !bytes.Equal(got, framed(first)) {
		t.Fatalf("the first answer: %d bytes", len(got))
	}
	repeated := 0
	for range 20 {
		switch got := h.ask(original); {
		case bytes.Equal(got, framed(first)):
			repeated++
		case len(got) != 0:
			t.Fatalf("a copy got %d other bytes", len(got))
		}
	}
	if repeated != memoRepeats {
		t.Fatalf("%d copies got the first answer's data, want %d", repeated, memoRepeats)
	}
	if c := stats.Snapshot(nil, nil).Copies; c != 20-memoRepeats {
		t.Fatalf("copies counted %d, want %d", c, 20-memoRepeats)
	}
}

// The memo is bounded in bytes, not answers: small answers (a poll's empty
// one, an ACK) stay their 5 to 10 s under a load where 4096 a generation
// lasted less than that.
func TestMemoBoundedInBytes(t *testing.T) {
	name, _ := dns.ParseName("x.t.example.com")
	rec := func(i int) *record {
		key := make([]byte, 40)
		binary.BigEndian.PutUint64(key, uint64(i))
		return &record{Key: string(key), Size: maxUDPPayload,
			Resp: &dns.Message{Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
				Answer: []dns.RR{{Data: dns.EncodeRDataTXT(make([]byte, 20))}}}}
	}
	var m answerMemo
	for i := range 3 * 4096 {
		m.remember(rec(i), 20)
	}
	if !m.answer(rec(0)) {
		t.Fatal("a small answer gone after 12288 others")
	}
	// Large ones fill a generation by their bytes.
	var big answerMemo
	data := dns.EncodeRDataTXT(make([]byte, encodedPayload(maxUDPPayload)))
	n := 0
	for ; big.prev == nil; n++ {
		r := rec(n)
		r.Resp.Answer[0].Data = data
		big.remember(r, len(data))
	}
	if n > memoBytes/len(data)+1 || n < memoBytes/(len(data)+200) {
		t.Fatalf("a generation of %d large answers", n-1)
	}
}

// The copies' memory holds a payload for three epochs (as long as its tag
// can hold), turns a full generation early, counted, and takes few
// payloads for copies they are not.
func TestCopyMemory(t *testing.T) {
	at := func(e uint32) time.Time { return time.Unix(int64(e)*int64(AuthEpoch/time.Second), 0) }
	var c copyMemory
	if c.sight("a", at(100)) || !c.sight("a", at(100)) || !c.sight("a", at(102)) {
		t.Fatal("a payload of epoch 100 not caught again by 102")
	}
	if c.sight("a", at(103)) {
		t.Fatal("a payload of epoch 100 still caught in 103")
	}
	if c.sight("", at(103)) || c.sight("", at(103)) {
		t.Fatal("no key, a copy")
	}
	turns := 0
	g := copyMemory{turns: func() { turns++ }}
	key := func(i int) string { return string(binary.BigEndian.AppendUint64(nil, uint64(i))) }
	last := 0
	for ; turns == 0; last++ {
		g.sight(key(last), at(7))
	}
	last--
	if turns != 1 || g.gens[0].n != 1 || g.gens[1].n != copyMemoryCap || last > copyMemoryCap+copyMemoryCap/1000 {
		t.Fatalf("a full generation: %d turns, %d and %d in the two, after %d", turns, g.gens[0].n, g.gens[1].n, last+1)
	}
	if !g.sight(key(0), at(7)) || !g.sight(key(last), at(7)) {
		t.Fatal("a payload of the turned generation, or of the new one, not caught")
	}
	false_ := 0
	const tries = 200000
	for i := range tries {
		if g.sight(key(1<<40+i), at(7)) {
			false_++
		}
	}
	// One full generation and the new one filling: under 1 in 1000.
	if false_ > tries/1000 {
		t.Fatalf("%d of %d fresh payloads taken for copies", false_, tries)
	}
	t.Logf("%d of %d fresh payloads taken for copies", false_, tries)
}
