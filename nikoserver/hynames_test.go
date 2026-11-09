//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDomainName(t *testing.T) {
	label := strings.Repeat("a", 63)
	long := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".") // 253 bytes
	for host, want := range map[string]bool{
		"example.com": true, "example.com.": true, "_dmarc.example.com": true, "a-b.c": true, "xn--d1acufc.xn--p1ai": true,
		long: true, long + ".": true, long + "b": false, strings.Repeat("a", 1<<20): false,
		label + "a.com": false, "": false, ".": false, "a..b": false, "-a.com": false, "a-.com": false, "a.com-": false,
		"123": false, "1.2.3": false, "a b.com": false, "a/b": false, "a\x00b": false, "exämple.com": false,
	} {
		if got := domainName(host); got != want {
			t.Errorf("%.40q (%d bytes): %v, want %v", host, len(host), got, want)
		}
	}
}

// The process's cache of names keeps answers and NXDOMAIN or NODATA, never
// a timeout, SERVFAIL or a refusal (EPERM from raycontrol's guard); a miss
// pays a lookup token of the user's.
func TestHyNameCache(t *testing.T) {
	asked := map[string]int{}
	answer := map[string]error{
		"nx.test":       &net.DNSError{Err: "no such host", IsNotFound: true},
		"slow.test":     &net.DNSError{Err: "i/o timeout", IsTimeout: true},
		"servfail.test": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		"guard.test":    &net.OpError{Op: "write", Err: os.NewSyscallError("sendto", syscall.EPERM)},
	}
	l, c := fakeHyLimits()
	l.resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		asked[name]++
		if err := answer[name]; err != nil {
			return nil, err
		}
		if name == "nodata.test" {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}
	for range 3 {
		for _, n := range []string{"ok.test", "nx.test", "nodata.test", "slow.test", "servfail.test", "guard.test"} {
			_, _ = l.lookupName(bg(), "u5", n)
		}
	}
	for n, want := range map[string]int{"ok.test": 1, "nx.test": 1, "nodata.test": 1, "slow.test": 3, "servfail.test": 3, "guard.test": 3} {
		if asked[n] != want {
			t.Errorf("%s asked %d times, want %d", n, asked[n], want)
		}
	}
	if _, err := l.lookupName(bg(), "u5", "nx.test"); !errors.Is(err, errNoName) {
		t.Errorf("a cached NXDOMAIN: %v", err)
	}
	// One entry a name, however it is spelt; another user has it too.
	if a, err := l.lookupName(bg(), "u6", "OK.Test."); err != nil || len(a) != 1 || asked["ok.test"] != 1 || len(asked) != 6 {
		t.Errorf("OK.Test.: %v %v, asked %v", a, err, asked)
	}
	// Answers for a minute, misses for 30 s.
	c.t = c.t.Add(31 * time.Second)
	_, _ = l.lookupName(bg(), "u5", "nx.test")
	_, _ = l.lookupName(bg(), "u5", "ok.test")
	if asked["nx.test"] != 2 || asked["ok.test"] != 1 {
		t.Errorf("after 31 s: nx %d, ok %d", asked["nx.test"], asked["ok.test"])
	}
	c.t = c.t.Add(30 * time.Second)
	_, _ = l.lookupName(bg(), "u5", "ok.test")
	if asked["ok.test"] != 2 {
		t.Errorf("after 61 s: ok %d", asked["ok.test"])
	}
	// Misses pay: 100 at once, then 20 a second; without a token no lookup.
	l.mu.Lock()
	tokens := l.users["u5"].lookups.level(c.t, 20, 100)
	l.mu.Unlock()
	// Full again after a minute, less the miss of ok.test just now.
	if tokens != 99 {
		t.Errorf("u5's lookup tokens %v", tokens)
	}
	for i := range 100 {
		if _, err := l.lookupName(bg(), "u7", fmt.Sprintf("n%d.test", i)); err != nil {
			t.Fatalf("lookup %d of the burst: %v", i, err)
		}
	}
	if _, err := l.lookupName(bg(), "u7", "other.test"); !errors.Is(err, errLookups) || asked["other.test"] != 0 {
		t.Errorf("no token: looked up (%v)", err)
	}
	if _, err := l.lookupName(bg(), "u7", "ok.test"); err != nil {
		t.Errorf("a cached name needs no token: %v", err)
	}
	if _, err := l.lookupName(bg(), "u8", "other.test"); err != nil {
		t.Errorf("another user's token: %v", err)
	}
	c.t = c.t.Add(time.Second / 20)
	if _, err := l.lookupName(bg(), "u7", "another.test"); err != nil {
		t.Errorf("a token 1/20 s later: %v", err)
	}
	if got := l.Refused()["u7"][refusedLookup]; got != 1 {
		t.Errorf("refused lookups: %d", got)
	}
	// Off, or without a user: no token is needed.
	l.SetConnLimit(false)
	if _, err := l.lookupName(bg(), "u7", "off.test"); err != nil {
		t.Errorf("off: %v", err)
	}
	l.SetConnLimit(true)
	if _, err := l.lookupName(bg(), "", "nouser.test"); err != nil {
		t.Errorf("no user: %v", err)
	}
}

// A host that is no domain name (too long, not a name) is refused before
// the cache, the user's token and the resolver: one user's megabyte names
// must not fill the process's memory.
func TestHyNameCacheBadNames(t *testing.T) {
	var asked atomic.Int32
	l, _ := fakeHyLimits()
	l.n.lookupBurst = 1
	l.resolve = func(context.Context, string) ([]netip.Addr, error) {
		asked.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}
	for _, n := range []string{strings.Repeat("a", 1<<20) + ".com", strings.Repeat("a.", 127) + "com", "a..b", "-x.test", "192.0.2.1", ""} {
		if _, err := l.lookupName(bg(), "u5", n); !errors.Is(err, errBadName) {
			t.Errorf("%.20q: %v", n, err)
		}
	}
	if asked.Load() != 0 || len(l.names.m) != 0 || len(l.names.flights) != 0 {
		t.Fatalf("bad names looked up %d times, %d kept", asked.Load(), len(l.names.m))
	}
	// No token went: the one there is still looks a good name up.
	if _, err := l.lookupName(bg(), "u5", "ok.test"); err != nil || asked.Load() != 1 {
		t.Fatalf("a good name after bad ones: %v, asked %d", err, asked.Load())
	}
}

// An answer keeps 16 addresses at most.
func TestHyNameCacheAddrs(t *testing.T) {
	var many []netip.Addr
	for i := range 200 {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	l, _ := fakeHyLimits()
	l.resolve = func(context.Context, string) ([]netip.Addr, error) { return many, nil }
	got, err := l.lookupName(bg(), "u5", "many.test")
	if err != nil || len(got) != nameAddrs {
		t.Fatalf("%d addresses, %v", len(got), err)
	}
	l.names.mu.Lock()
	kept := l.names.m["many.test"].addrs
	l.names.mu.Unlock()
	if len(kept) != nameAddrs || cap(kept) != nameAddrs {
		t.Fatalf("kept %d (cap %d)", len(kept), cap(kept))
	}
}

// What expired leaves the cache at the next answer kept, full or not; a
// full cache drops what expires first, not any name: it never holds more
// than nameCache names.
func TestHyNameCacheExpiry(t *testing.T) {
	var c hyNames
	t0 := time.Unix(1_700_000_000, 0)
	a := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	c.put("nx.test", nil, nil, t0)
	c.put("ok.test", a, nil, t0)
	c.put("new.test", a, nil, t0.Add(nameMiss))
	if _, ok := c.m["nx.test"]; ok || len(c.m) != 2 {
		t.Fatalf("an expired miss kept: %d names", len(c.m))
	}
	// Full: answers at one time each, misses later; the first answer, the
	// earliest to expire, goes for a new name.
	c = hyNames{}
	for i := range nameCache - 1 {
		c.put(fmt.Sprintf("h%d.test", i), a, nil, t0.Add(time.Duration(i)*time.Millisecond))
	}
	c.put("m.test", nil, nil, t0.Add(time.Duration(nameCache)*time.Millisecond)) // expires before every answer
	now := t0.Add(time.Duration(nameCache+1) * time.Millisecond)
	c.put("next.test", a, nil, now)
	if _, ok := c.m["m.test"]; ok || len(c.m) != nameCache {
		t.Fatalf("full: the miss expiring first kept, %d names", len(c.m))
	}
	c.put("next2.test", a, nil, now)
	if _, ok := c.m["h0.test"]; ok || len(c.m) != nameCache {
		t.Fatalf("full: the first answer kept, %d names", len(c.m))
	}
	if _, ok := c.m["h1.test"]; !ok {
		t.Fatal("full: more than one went")
	}
	// A name replaced keeps its place by its new time.
	c.put("h1.test", a, nil, now)
	c.put("next3.test", a, nil, now)
	if _, ok := c.m["h1.test"]; !ok {
		t.Fatal("a replaced name went by its old time")
	}
	if _, ok := c.m["h2.test"]; ok {
		t.Fatal("full: h2 should have gone")
	}
	// Many times the cache's names, all kept as misses: bounded, and the
	// queues with it.
	c = hyNames{}
	for i := range 5 * nameCache {
		c.put(fmt.Sprintf("x%d.test", i), nil, nil, t0.Add(time.Duration(i)*time.Microsecond))
	}
	if len(c.m) != nameCache || len(c.misses.q)-c.misses.head > 2*nameCache {
		t.Fatalf("%d names kept, %d in the queue", len(c.m), len(c.misses.q)-c.misses.head)
	}
}

// Misses of one name at once share one lookup: only the first pays a token
// (none left for the others, they are not refused), and the first one's
// stream ending does not end the others' wait.
func TestHyNameCacheInFlight(t *testing.T) {
	var asked atomic.Int32
	release := make(chan struct{})
	l := newHyLimits()
	l.n.lookupBurst = 1
	l.resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		asked.Add(1)
		select {
		case <-release:
		case <-ctx.Done(): // the first one's stream ended: not the lookup
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}
	lctx, leave := context.WithCancel(bg())
	first := make(chan error, 1)
	go func() {
		_, err := l.lookupName(lctx, "u5", "slow.test")
		first <- err
	}()
	if !waitFor(5*time.Second, func() bool { return asked.Load() == 1 }) {
		t.Fatal("not looked up")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 9)
	for range cap(errs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.lookupName(bg(), "u5", "Slow.Test")
			errs <- err
		}()
	}
	time.Sleep(50 * time.Millisecond) // the others wait
	leave()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("the first one, gone: %v", err)
	}
	close(release)
	wg.Wait()
	for range cap(errs) {
		if err := <-errs; err != nil {
			t.Fatalf("a miss under way: %v", err)
		}
	}
	if asked.Load() != 1 {
		t.Fatalf("looked up %d times", asked.Load())
	}
	if got := l.Refused()["u5"][refusedLookup]; got != 0 {
		t.Fatalf("refused %d lookups", got)
	}
	l.names.mu.Lock()
	flights := len(l.names.flights)
	l.names.mu.Unlock()
	if flights != 0 {
		t.Fatalf("%d lookups left under way", flights)
	}
}
