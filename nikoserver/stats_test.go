package nikoserver

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// A stats socket's accept loop after errors: its close ends it; another
// error waits, twice as long each time up to 1 s, and is said once until
// another comes (review 13).
func TestAcceptBackoff(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger("warn", &buf)
	var b acceptBackoff
	if b.again(net.ErrClosed, log) || buf.Len() != 0 {
		t.Fatalf("the socket's close: goes on, or said %q", buf.String())
	}
	emfile := errors.New("accept unix: too many open files")
	for i, want := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		if !b.again(emfile, log) || b.delay != want {
			t.Fatalf("error %d: delay %v, want %v", i, b.delay, want)
		}
	}
	if n := strings.Count(buf.String(), "too many open files"); n != 1 {
		t.Fatalf("the same error said %d times: %q", n, buf.String())
	}
	b.again(errors.New("accept unix: software caused connection abort"), log)
	if n := strings.Count(buf.String(), "stats socket:"); n != 2 {
		t.Fatalf("another error: %d lines: %q", n, buf.String())
	}
	b.delay = 600 * time.Millisecond
	if d := b.next(); d != time.Second {
		t.Fatalf("the cap: %v", d)
	}
	if b.ok(); b.next() != 5*time.Millisecond {
		t.Fatal("from the start after an accept that works")
	}
	// A later episode is said again.
	b.ok()
	b.again(emfile, log)
	if n := strings.Count(buf.String(), "too many open files"); n != 2 {
		t.Fatalf("a second episode: said %d times in all", n)
	}
}
