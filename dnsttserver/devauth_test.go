package dnsttserver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
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
	before := a.slots[ScanInit].tokens
	if id, ok := a.Scan(ScanInit, tagOf(250), msg); !ok || id != "d250" || before-a.slots[ScanInit].tokens != 1 {
		t.Fatalf("recent: %q %v, %v HMACs", id, ok, before-a.slots[ScanInit].tokens)
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

// A kind's scan under way refuses another of the kind at once, not after
// it (review 13: the workers waited behind a scan of garbage); the other
// kinds and Device go on.
func TestDeviceAuthScanBusy(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 20)
	a := &DeviceAuth{Now: func() time.Time { return now }}
	a.SetKeys(text)
	msg := []byte("busy")
	tagOf := func(i int) [AuthTagLen]byte { return Tag(&keys[i], EpochOf(now), msg) }
	a.slots[ScanProbe].mu.Lock() // a probe's scan under way
	done := make(chan bool)
	go func() {
		_, ok := a.Scan(ScanProbe, tagOf(3), msg)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok || a.Throttled.Load() != 1 {
			t.Fatalf("a probe beside a probe's scan: %v, throttled %d", ok, a.Throttled.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a probe waits for another probe's scan")
	}
	if id, ok := a.Scan(ScanInit, tagOf(3), msg); !ok || id != "d3" {
		t.Fatalf("an INIT beside a probe's scan: %q %v", id, ok)
	}
	if !a.Device("d4", tagOf(4), msg) {
		t.Fatal("a session's check beside a probe's scan")
	}
	a.slots[ScanProbe].mu.Unlock()
	if id, ok := a.Scan(ScanProbe, tagOf(3), msg); !ok || id != "d3" {
		t.Fatalf("a probe after the scan: %q %v", id, ok)
	}
}

// A device revoked is found by no scan from then on, though it is among
// the recent ones, and drops out of them; a device that comes back with
// another key is found by its new key only.
func TestDeviceAuthScanRevoked(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 10)
	a := &DeviceAuth{Now: func() time.Time { return now }, ScanHMACs: 1e9}
	a.SetKeys(text)
	msg := []byte("revoked")
	tagOf := func(k *[32]byte) [AuthTagLen]byte { return Tag(k, EpochOf(now), msg) }
	for _, i := range []int{5, 6} {
		if id, ok := a.Scan(ScanInit, tagOf(&keys[i]), msg); !ok || id != fmt.Sprintf("d%d", i) {
			t.Fatalf("d%d: %q %v", i, id, ok)
		}
	}
	// d5 gone; d6 with a new key.
	var b strings.Builder
	var fresh [32]byte
	rand.Read(fresh[:])
	for i := range keys {
		switch i {
		case 5:
		case 6:
			fmt.Fprintf(&b, "d6 %s\n", hex.EncodeToString(fresh[:]))
		default:
			fmt.Fprintf(&b, "d%d %s\n", i, hex.EncodeToString(keys[i][:]))
		}
	}
	if err := a.SetKeys([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []ScanKind{ScanProbe, ScanInit, ScanSession} {
		if id, ok := a.Scan(kind, tagOf(&keys[5]), msg); ok {
			t.Fatalf("kind %d: the revoked d5 found as %q", kind, id)
		}
		if id, ok := a.Scan(kind, tagOf(&keys[6]), msg); ok {
			t.Fatalf("kind %d: d6's old key found as %q", kind, id)
		}
	}
	if a.Device("d5", tagOf(&keys[5]), msg) || a.Device("d6", tagOf(&keys[6]), msg) {
		t.Fatal("Device: a revoked key")
	}
	if id, ok := a.Scan(ScanInit, tagOf(&fresh), msg); !ok || id != "d6" {
		t.Fatalf("d6's new key: %q %v", id, ok)
	}
	if id, ok := a.Scan(ScanInit, tagOf(&keys[2]), msg); !ok || id != "d2" {
		t.Fatalf("d2: %q %v", id, ok)
	}
	if slices.Contains(a.recent, "d5") || a.recent[0] != "d2" || a.recent[1] != "d6" {
		t.Fatalf("recent %v", a.recent)
	}
}

// A scan may start while the budget is above zero and leave it below; the
// debt is paid with time before the next scan of the kind starts.
func TestDeviceAuthScanDebt(t *testing.T) {
	now := time.Unix(1767268800, 0)
	_, text := devKeys(t, 300) // a scan of garbage: 900 HMACs
	a := &DeviceAuth{Now: func() time.Time { return now }, ScanHMACs: 1}
	a.SetKeys(text) // the floor: 1800 HMACs a second, 3600 at once
	msg := []byte("debt")
	garbage := [AuthTagLen]byte{9}
	for range 4 {
		a.Scan(ScanSession, garbage, msg)
	}
	if got := a.slots[ScanSession].tokens; got != 0 {
		t.Fatalf("after the burst: %v", got)
	}
	throttled := func() bool {
		before := a.Throttled.Load()
		a.Scan(ScanSession, garbage, msg)
		return a.Throttled.Load() != before
	}
	if !throttled() {
		t.Fatal("a scan with no budget")
	}
	now = now.Add(250 * time.Millisecond) // 450
	if throttled() {
		t.Fatal("a scan with 450 left")
	}
	if got := a.slots[ScanSession].tokens; got != -450 {
		t.Fatalf("the debt: %v", got)
	}
	now = now.Add(250 * time.Millisecond) // 0
	if !throttled() {
		t.Fatal("a scan while the debt is paid")
	}
	now = now.Add(250 * time.Millisecond) // 450
	if throttled() {
		t.Fatal("a scan after the debt")
	}
}

// Device and Scan from many goroutines while the keys are set again
// (-race): each answer right — a tag found is its device's, a session's
// check of a valid tag passes — and each query counted once.
func TestDeviceAuthConcurrent(t *testing.T) {
	keys, text := devKeys(t, 50)
	a := &DeviceAuth{ScanHMACs: 1e9}
	a.SetKeys(text)
	msg := []byte("concurrent")
	const goroutines, each = 8, 300
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				d := (g*31 + i) % len(keys)
				want := fmt.Sprintf("d%d", d)
				tag := Tag(&keys[d], EpochOf(time.Now()), msg)
				if g%2 == 0 {
					if !a.Device(want, tag, msg) {
						errs <- fmt.Errorf("Device %s refused", want)
						return
					}
				} else if id, ok := a.Scan(ScanKind(i%3), tag, msg); ok && id != want {
					errs <- fmt.Errorf("Scan found %s for %s", id, want)
					return
				}
			}
		}()
	}
	for range 50 {
		a.SetKeys(text)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	valid, refused, throttled := a.Valid.Load(), a.Refused.Load(), a.Throttled.Load()
	if refused != 0 || valid+throttled != goroutines*each || valid < goroutines/2*each {
		t.Fatalf("valid %d refused %d throttled %d", valid, refused, throttled)
	}
}
