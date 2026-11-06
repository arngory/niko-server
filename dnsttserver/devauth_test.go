package dnsttserver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// devKeys makes n devices' keys file: "d<i> <hex>".
func devKeys(t testing.TB, n int) ([][32]byte, []byte) {
	t.Helper()
	keys := make([][32]byte, n)
	var b strings.Builder
	for i := range keys {
		rand.Read(keys[i][:])
		fmt.Fprintf(&b, "d%d %s\n", i, hex.EncodeToString(keys[i][:]))
	}
	return keys, []byte(b.String())
}

// masterdns's tag (dnsauth-masterdns §2): the vector of the whole query,
// nonce 00..0b and frame 0c..17 at 1767268800, the device's tag through
// Device; the epochs next to it too, none further.
func TestDeviceAuthDevice(t *testing.T) {
	k, _ := hex.DecodeString("2f9bd5e6fc2ef3f56206998eee87f2d4b798a66c3c846ef34eff2f2647599bd5")
	now := time.Unix(1767268800, 0)
	a := &DeviceAuth{Now: func() time.Time { return now }}
	if err := a.SetKeys([]byte("dev1 " + hex.EncodeToString(k) + "\n")); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 0x18)
	for i := range msg {
		msg[i] = byte(i)
	}
	var tag [AuthTagLen]byte
	hex.Decode(tag[:], []byte("67e1435d89134138"))
	if !a.Device("dev1", tag, msg) {
		t.Fatal("the vector's tag")
	}
	if a.Device("dev2", tag, msg) || a.Device("dev1", tag, msg[1:]) {
		t.Fatal("another device, another message")
	}
	var key [32]byte
	copy(key[:], k)
	for d, want := range map[int]bool{-2: false, -1: true, 1: true, 2: false} {
		other := Tag(&key, uint32(int(EpochOf(now))+d), msg)
		if a.Device("dev1", other, msg) != want {
			t.Errorf("epoch %+d: want %v", d, want)
		}
	}
	// Revoked: gone from the file, its tags fail from then on.
	a.SetKeys([]byte("dev9 " + hex.EncodeToString(k) + "\n"))
	if a.Device("dev1", tag, msg) {
		t.Fatal("a revoked device")
	}
	if a.Valid.Load() != 3 || a.Refused.Load() != 5 {
		t.Fatalf("valid %d refused %d", a.Valid.Load(), a.Refused.Load())
	}
}

// Scan finds a device among many, the recent ones first; each kind spends
// its own budget, so probes over theirs leave the INITs theirs.
func TestDeviceAuthScan(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 300)
	a := &DeviceAuth{Now: func() time.Time { return now }}
	if err := a.SetKeys(text); err != nil {
		t.Fatal(err)
	}
	msg := []byte("nonce-12byteframe")
	tagOf := func(i int) [AuthTagLen]byte { return Tag(&keys[i], EpochOf(now), msg) }
	id, ok := a.Scan(ScanInit, tagOf(250), msg)
	if !ok || id != "d250" {
		t.Fatalf("scan: %q %v", id, ok)
	}
	// Again: the recent device first, one HMAC.
	before := a.tokens[ScanInit]
	if id, ok := a.Scan(ScanInit, tagOf(250), msg); !ok || id != "d250" || before-a.tokens[ScanInit] != 1 {
		t.Fatalf("recent: %q %v, %v HMACs", id, ok, before-a.tokens[ScanInit])
	}
	// A tag of nobody's costs a full scan and is refused.
	if _, ok := a.Scan(ScanSession, [AuthTagLen]byte{1}, msg); ok {
		t.Fatal("garbage found a device")
	}
	// The probes' budget spent: probes are refused unscanned, INITs not.
	a.ScanHMACs = 1 // two full scans a second of each kind at least
	for range 10 {
		a.Scan(ScanProbe, [AuthTagLen]byte{2}, msg)
	}
	if _, ok := a.Scan(ScanProbe, tagOf(7), msg); ok || a.Throttled.Load() == 0 {
		t.Fatalf("probes over the budget: throttled %d", a.Throttled.Load())
	}
	if id, ok := a.Scan(ScanInit, tagOf(7), msg); !ok || id != "d7" {
		t.Fatalf("an INIT while the probes' budget is spent: %q %v", id, ok)
	}
	// The budget comes back with time.
	now = now.Add(2 * time.Second)
	if id, ok := a.Scan(ScanProbe, tagOf(8), msg); !ok || id != "d8" {
		t.Fatalf("probes two seconds later: %q %v", id, ok)
	}
	// No keys: nothing found, nothing scanned.
	b := &DeviceAuth{}
	if _, ok := b.Scan(ScanProbe, tagOf(1), msg); ok || b.Device("d1", tagOf(1), msg) {
		t.Fatal("found without keys")
	}
}

// The recent devices stay at most recentMax, the latest first.
func TestDeviceAuthRecent(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, recentMax+10)
	a := &DeviceAuth{Now: func() time.Time { return now }, ScanHMACs: 1e9}
	a.SetKeys(text)
	msg := []byte("m")
	for i := range keys {
		if _, ok := a.Scan(ScanInit, Tag(&keys[i], EpochOf(now), msg), msg); !ok {
			t.Fatalf("device %d", i)
		}
	}
	if len(a.recent) != recentMax || a.recent[0] != fmt.Sprintf("d%d", len(keys)-1) {
		t.Fatalf("recent %d, first %s", len(a.recent), a.recent[0])
	}
}

// Device and Scan from many goroutines while the keys change (-race).
func TestDeviceAuthConcurrent(t *testing.T) {
	keys, text := devKeys(t, 50)
	a := &DeviceAuth{ScanHMACs: 1e9}
	a.SetKeys(text)
	msg := []byte("concurrent")
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				d := (g*31 + i) % len(keys)
				tag := Tag(&keys[d], EpochOf(time.Now()), msg)
				if g%2 == 0 {
					a.Device(fmt.Sprintf("d%d", d), tag, msg)
				} else {
					a.Scan(ScanKind(i%3), tag, msg)
				}
			}
		}()
	}
	for range 20 {
		a.SetKeys(text)
	}
	wg.Wait()
	if a.Valid.Load() == 0 {
		t.Fatal("nothing valid")
	}
}
