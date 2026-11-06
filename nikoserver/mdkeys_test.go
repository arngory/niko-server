package nikoserver

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// The watcher gives the file as it is at its first ticks, whatever the
// server started with: a key file replaced between the server's read and
// the watcher's start is not missed (review).
func TestWatchMasterdnsKeysFirstTick(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "service.keys")
	os.WriteFile(file, []byte("new\nold\n"), 0o600)
	var mu sync.Mutex
	var got [][]string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchMasterdnsKeys(ctx, file, 10*time.Millisecond, func(k []string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, k)
		return nil
	}, NewLogger("warn", io.Discard))
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // and not again for the same text
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !slices.Equal(got[0], []string{"new", "old"}) {
		t.Fatalf("given %q", got)
	}
	if _, err := masterdnsKeys([]byte("a\nb\nc\n")); err == nil {
		t.Fatal("three keys taken")
	}
	if k, err := masterdnsKeys([]byte("\r\na \r\n\n")); err != nil || !slices.Equal(k, []string{"a"}) {
		t.Fatalf("blank lines and CRLF: %q %v", k, err)
	}
}

// A text is given once it reads the same on two ticks in a row: a file
// caught while written in place ("new" of "new\nold") would close the old
// key's sessions at once (review).
func TestWatchMasterdnsKeysSettled(t *testing.T) {
	var got [][]string
	w := mdKeysWatch{file: "service.keys", log: NewLogger("warn", io.Discard), set: func(k []string) error {
		got = append(got, k)
		return nil
	}}
	w.read([]byte("a\n"), nil)
	w.read([]byte("a\n"), nil)
	w.read([]byte("new\n"), nil) // caught mid-write
	w.read([]byte("new\nold\n"), nil)
	w.read([]byte("new\nold\n"), nil)
	w.read([]byte("new\nold\n"), nil) // given once
	w.read(nil, os.ErrNotExist)       // keeps what it has
	w.read([]byte("new\nold\n"), nil)
	if want := [][]string{{"a"}, {"new", "old"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("given %q, want %q", got, want)
	}
}
