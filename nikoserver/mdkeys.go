package nikoserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// masterdnsKeys reads a masterdns key file (raycontrol
// docs/spec/masterdns-key-rotation.md §3): one key a line, the current
// first, then the previous one while it is still taken.
func masterdnsKeys(text []byte) ([]string, error) {
	var keys []string
	for _, line := range strings.Split(string(text), "\n") {
		if k := strings.TrimSpace(line); k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 || len(keys) > 2 {
		return nil, fmt.Errorf("%d keys: the current one, and the previous one at most", len(keys))
	}
	return keys, nil
}

// watchMasterdnsKeys rereads the key file every period until ctx ends and
// gives the server its keys when the text changes (by content: a key
// replaced at the same size within a tick is still seen) and reads the same
// on the next tick: a file caught while written in place ("NEW\n" of
// "NEW\nOLD\n") would close the previous key's sessions at once (review).
// A text that does not read or that the server refuses keeps the keys in
// force, said once. The server closes the sessions of a key no longer
// listed at once.
func watchMasterdnsKeys(ctx context.Context, file string, every time.Duration, set func([]string) error, log *Logger) {
	// No baseline of its own: the file read here could be newer than the
	// one the server started with (a rotation during the start), and would
	// then never be given. The first ticks give the file as it is; keys the
	// server has already keep their sessions (review).
	w := mdKeysWatch{file: file, set: set, log: log}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
		w.read(b, err)
	}
}

// mdKeysWatch is what the watcher knows between its ticks.
type mdKeysWatch struct {
	file              string
	set               func([]string) error
	log               *Logger
	cur, bad, pending []byte
	readErr           string
}

// read takes one tick's read of the file.
func (w *mdKeysWatch) read(b []byte, err error) {
	if err != nil {
		if err.Error() != w.readErr {
			w.readErr = err.Error()
			w.log.Warnf("masterdns keys %s not read, the keys in force stay: %v", w.file, err)
		}
		return
	}
	w.readErr = ""
	if bytes.Equal(b, w.cur) || (w.bad != nil && bytes.Equal(b, w.bad)) {
		w.pending = nil
		return
	}
	if !bytes.Equal(b, w.pending) {
		w.pending = b // taken when the next tick reads the same
		return
	}
	w.pending = nil
	keys, err := masterdnsKeys(b)
	if err == nil {
		err = w.set(keys)
	}
	if err != nil {
		w.bad = b
		w.log.Warnf("masterdns keys %s not taken, the keys in force stay: %v", w.file, err)
		return
	}
	first := w.cur == nil
	w.cur, w.bad = b, nil
	if !first {
		w.log.Infof("masterdns keys reloaded: %d (the sessions of a key gone are closed)", len(keys))
	}
}
