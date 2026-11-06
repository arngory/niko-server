package dnsttserver

// Load measurements (not CI): NIKO_LOAD=1 go test ./dnsttserver -run Load -v

import (
	"crypto/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// The answer memo at capacity: two generations of memoMax answers, each the
// largest a requester of maxUDPPayload takes (sealed: every answer at least
// 64 bytes), keyed by the longest payload a query name carries.
func TestLoadMemoCapacity(t *testing.T) {
	if os.Getenv("NIKO_LOAD") == "" {
		t.Skip("NIKO_LOAD=1")
	}
	name, _ := dns.ParseName("x.t.example.com")
	for _, c := range []struct {
		what string
		data int
	}{{"largest answers", encodedPayload(maxUDPPayload)}, {"empty sealed answers", sealBucket}} {
		h0 := heapNow()
		var memo answerMemo
		for range 2 * memoMax {
			key := make([]byte, 150) // the longest payload in a name of 255 octets
			rand.Read(key)
			rec := &record{Key: string(key), Size: maxUDPPayload,
				Resp: &dns.Message{Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
					Answer: []dns.RR{{Data: dns.EncodeRDataTXT(make([]byte, c.data))}}}}
			memo.remember(rec, c.data)
		}
		h1 := heapNow()
		t.Logf("memo, %s (%d bytes of TXT data): %d + %d entries, %.2f MiB, %.0f B/entry", c.what, c.data,
			len(memo.cur), len(memo.prev), float64(h1-h0)/(1<<20), float64(h1-h0)/float64(len(memo.cur)+len(memo.prev)))
		runtime.KeepAlive(&memo)
	}
}

// What one distinct ClientID costs in the turbotunnel RemoteMap: sendLoop
// looks up its stash and send queue for every query that has a ClientID.
func TestLoadRemoteMapPerClient(t *testing.T) {
	if os.Getenv("NIKO_LOAD") == "" {
		t.Skip("NIKO_LOAD=1")
	}
	const n = 100000
	tt := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	defer tt.Close()
	h0 := heapNow()
	for i := range n {
		var id turbotunnel.ClientID
		id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
		tt.Unstash(id)
		tt.OutgoingQueue(id)
	}
	h1 := heapNow()
	t.Logf("RemoteMap: %d ClientIDs, %.1f MiB, %.0f B per ClientID (kept %s to %s after the last query)",
		n, float64(h1-h0)/(1<<20), float64(h1-h0)/n, idleTimeout*2, idleTimeout*3)
	runtime.KeepAlive(tt)
	_ = time.Second
}

// The first encodedPayload call builds the table for 512..maxUDPPayload: a
// binary search up to 32 KiB of TXT data for each of 721 sizes.
func TestLoadEncodedPayloadInit(t *testing.T) {
	if os.Getenv("NIKO_LOAD") == "" {
		t.Skip("NIKO_LOAD=1")
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	encodedPayload(512)
	d := time.Since(start)
	runtime.ReadMemStats(&m1)
	t.Logf("encodedPayload table: %s, %.0f MiB allocated, %d allocations", d.Round(time.Millisecond), float64(m1.TotalAlloc-m0.TotalAlloc)/(1<<20), m1.Mallocs-m0.Mallocs)
}
