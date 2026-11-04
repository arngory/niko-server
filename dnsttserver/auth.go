package dnsttserver

// dnsauth-v1 (neko; raycontrol docs/spec/dnsauth-v1.md): every query carries
// an 8-byte tag before the ClientID, an HMAC of the rest with a key of the
// device that sent it. Without a valid tag the zone answers as an empty one
// (NXDOMAIN), so a leaked or old link opens no sessions and a probe of the
// zone finds nothing.

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// AuthTagLen is the tag's length in a query's payload.
	AuthTagLen = 8
	// AuthEpoch is the time step of the tag; the node takes the epochs
	// before and after too (resolver caches delay queries).
	AuthEpoch = 600 * time.Second
	authLabel = "dnsauth1"
	// authCacheMax bounds the ClientID -> key cache.
	authCacheMax = 4096
)

// AuthMode is how the tags are checked.
type AuthMode int

const (
	AuthOff      AuthMode = iota // no tags (dnstt as it was)
	AuthOptional                 // tagged queries and untagged ones (clients moving over)
	AuthRequired                 // tagged queries only
)

// ParseAuthMode reads "", "off", "optional" or "required".
func ParseAuthMode(s string) (AuthMode, error) {
	switch s {
	case "", "off":
		return AuthOff, nil
	case "optional":
		return AuthOptional, nil
	case "required":
		return AuthRequired, nil
	}
	return AuthOff, fmt.Errorf("auth %q: off, optional or required", s)
}

type authKey struct {
	id  string
	key [32]byte
}

// Auth checks the tags of queries against the keys of the devices allowed
// on the service. Safe for concurrent use; the keys can be replaced while it
// runs.
type Auth struct {
	Mode AuthMode
	Now  func() time.Time // time.Now when nil

	keys atomic.Pointer[[]authKey]

	mu    sync.Mutex
	cache map[turbotunnel.ClientID]string // ClientID -> device id of its last valid tag

	// Counters for the log: queries with a valid tag, untagged ones taken
	// (optional), refused ones.
	Valid, Untagged, Refused atomic.Uint64
}

// SetKeys replaces the keys: lines "<device id> <64 hex digits>"; empty lines
// and lines starting with # are skipped.
func (a *Auth) SetKeys(text []byte) error {
	var keys []authKey
	sc := bufio.NewScanner(bytes.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 2 {
			return fmt.Errorf("auth keys line %d: want \"<device id> <key hex>\"", line)
		}
		b, err := hex.DecodeString(f[1])
		if err != nil || len(b) != 32 {
			return fmt.Errorf("auth keys line %d: the key is not 32 bytes of hex", line)
		}
		k := authKey{id: f[0]}
		copy(k.key[:], b)
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	a.keys.Store(&keys)
	a.mu.Lock()
	a.cache = nil // a revoked device's sessions go with its key
	a.mu.Unlock()
	return nil
}

// LoadKeys reads the keys file.
func (a *Auth) LoadKeys(file string) error {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the configured file
	if err != nil {
		return err
	}
	return a.SetKeys(b)
}

// WatchKeys reloads the file when its modification time or size changes,
// until stop is closed. A file that does not parse keeps the keys in force.
func (a *Auth) WatchKeys(file string, every time.Duration, stop <-chan struct{}, logf func(string, ...any)) {
	stat := func() (time.Time, int64) {
		fi, err := os.Stat(file)
		if err != nil {
			return time.Time{}, -1
		}
		return fi.ModTime(), fi.Size()
	}
	mod, size := stat()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		m, s := stat()
		if m.Equal(mod) && s == size {
			continue
		}
		mod, size = m, s
		if err := a.LoadKeys(file); err != nil {
			logf("auth keys %s not reloaded: %v", file, err)
			continue
		}
		logf("auth keys reloaded: %d devices", len(*a.keys.Load()))
	}
}

// Tag computes the tag of a payload (ClientID and what follows) for a key and
// an epoch; clients do the same.
func Tag(key *[32]byte, epoch uint32, payload []byte) [AuthTagLen]byte {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(authLabel))
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	m.Write(e[:])
	m.Write(payload)
	var out [AuthTagLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// EpochOf is the tag epoch of a time.
func EpochOf(t time.Time) uint32 { return uint32(t.Unix() / int64(AuthEpoch/time.Second)) }

// Check takes a query's decoded payload. With a valid tag it returns the
// payload after the tag; without one, the payload as it is when the mode
// takes untagged queries; otherwise ok is false and the query is answered
// as by an empty zone.
func (a *Auth) Check(payload []byte) (rest []byte, ok bool) {
	if a == nil || a.Mode == AuthOff {
		return payload, true
	}
	if len(payload) >= AuthTagLen+len(turbotunnel.ClientID{}) && a.valid(payload) {
		a.Valid.Add(1)
		return payload[AuthTagLen:], true
	}
	if a.Mode == AuthOptional {
		a.Untagged.Add(1)
		return payload, true
	}
	a.Refused.Add(1)
	return nil, false
}

func (a *Auth) valid(payload []byte) bool {
	keys := a.keys.Load()
	if keys == nil || len(*keys) == 0 {
		return false
	}
	var tag [AuthTagLen]byte
	copy(tag[:], payload)
	body := payload[AuthTagLen:]
	var cid turbotunnel.ClientID
	copy(cid[:], body)
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	e := EpochOf(now)
	match := func(k *authKey) bool {
		for _, epoch := range []uint32{e, e - 1, e + 1} {
			t := Tag(&k.key, epoch, body)
			if hmac.Equal(t[:], tag[:]) {
				return true
			}
		}
		return false
	}
	// The key this session signed with last, then all of them.
	a.mu.Lock()
	id, cached := a.cache[cid]
	a.mu.Unlock()
	if cached {
		for i := range *keys {
			if (*keys)[i].id == id && match(&(*keys)[i]) {
				return true
			}
		}
	}
	for i := range *keys {
		k := &(*keys)[i]
		if k.id != id && match(k) {
			a.mu.Lock()
			if a.cache == nil || len(a.cache) >= authCacheMax {
				a.cache = map[turbotunnel.ClientID]string{}
			}
			a.cache[cid] = k.id
			a.mu.Unlock()
			return true
		}
	}
	return false
}
