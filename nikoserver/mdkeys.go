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
// replaced at the same size within a tick is still seen). A text that does
// not read or that the server refuses keeps the keys in force, said once.
// The server closes the sessions of a key no longer listed at once.
func watchMasterdnsKeys(ctx context.Context, file string, every time.Duration, set func([]string) error, log *Logger) {
	cur, _ := os.ReadFile(file) //nolint:gosec // G304: the configured file
	var bad []byte
	var readErr string
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
		if err != nil {
			if err.Error() != readErr {
				readErr = err.Error()
				log.Warnf("masterdns keys %s not read, the keys in force stay: %v", file, err)
			}
			continue
		}
		readErr = ""
		if bytes.Equal(b, cur) || (bad != nil && bytes.Equal(b, bad)) {
			continue
		}
		keys, err := masterdnsKeys(b)
		if err == nil {
			err = set(keys)
		}
		if err != nil {
			bad = b
			log.Warnf("masterdns keys %s not taken, the keys in force stay: %v", file, err)
			continue
		}
		cur, bad = b, nil
		log.Infof("masterdns keys reloaded: %d (the sessions of a key gone are closed)", len(keys))
	}
}
