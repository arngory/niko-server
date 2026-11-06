package dnsttserver

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// v2Payload is a dnstt payload with key's dnsauth-v2 tag at now: tag field,
// ClientID, data.
func v2Payload(key *[32]byte, now time.Time, cid byte, data string) []byte {
	body := append(bytes.Repeat([]byte{cid}, len(turbotunnel.ClientID{})), data...)
	field := Tag2(key, EpochOf(now), body)
	return append(field[:], body...)
}

func v1Payload(key *[32]byte, now time.Time, cid byte, data string) []byte {
	body := append(bytes.Repeat([]byte{cid}, len(turbotunnel.ClientID{})), data...)
	tag := Tag(key, EpochOf(now), body)
	return append(tag[:], body...)
}

// dnstt with dnsauth-v2 (raycontrol dnsauth-v2.md): a v2 tag is found by
// its hint while garbage has spent the scan budget; optional still takes v1
// by a scan; required takes no v1 tag and scans nothing; a key taken out is
// not found from the next SetKeys on.
func TestAuthHint(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 300)
	a := &Auth{Mode: AuthRequired, Hint: HintOptional, Now: func() time.Time { return now }, ScanHMACs: 1}
	if err := a.SetKeys(text); err != nil {
		t.Fatal(err)
	}
	// Garbage spends the scan budget (the floor: two full scans a second).
	for i := range 20 {
		a.CheckDevice(append(bytes.Repeat([]byte{byte(i), 0xee}, 8), "garbage"...))
	}
	if a.Throttled.Load() == 0 {
		t.Fatal("garbage did not spend the budget")
	}
	throttled := a.Throttled.Load()
	if rest, dev, ok := a.CheckDevice(v2Payload(&keys[123], now, 1, "v2")); !ok || dev != "d123" || string(rest[8:]) != "v2" {
		t.Fatalf("a v2 session with the budget spent: %q %q %v", rest, dev, ok)
	}
	if a.Throttled.Load() != throttled {
		t.Fatal("the v2 check was charged to the scan budget")
	}
	// The live session's next queries, by its cached key.
	if _, dev, ok := a.CheckDevice(v2Payload(&keys[123], now.Add(time.Minute), 1, "more")); !ok || dev != "d123" {
		t.Fatalf("the v2 session's next query: %q %v", dev, ok)
	}
	// optional: v1 still by a scan, once the budget is back.
	now = now.Add(5 * time.Second)
	if _, dev, ok := a.CheckDevice(v1Payload(&keys[7], now, 2, "v1")); !ok || dev != "d7" {
		t.Fatalf("a v1 session in optional: %q %v", dev, ok)
	}

	// required: no v1, no scan: garbage costs no HMAC and no budget.
	r := &Auth{Mode: AuthRequired, Hint: HintRequired, Now: func() time.Time { return now }, ScanHMACs: 1}
	r.SetKeys(text)
	if _, _, ok := r.CheckDevice(v1Payload(&keys[7], now, 3, "v1")); ok {
		t.Fatal("a v1 tag in required")
	}
	for i := range 1000 {
		r.CheckDevice(append(bytes.Repeat([]byte{byte(i), byte(i >> 8)}, 8), "garbage"...))
	}
	if r.Throttled.Load() != 0 || r.tokens != 0 {
		t.Fatalf("garbage in required: throttled %d, tokens %v", r.Throttled.Load(), r.tokens)
	}
	if _, dev, ok := r.CheckDevice(v2Payload(&keys[250], now, 4, "v2")); !ok || dev != "d250" {
		t.Fatalf("v2 in required: %q %v", dev, ok)
	}
	// Taken out: neither its live session nor a new one passes.
	var rest bytes.Buffer
	for i := range keys {
		if i != 250 {
			rest.WriteString(lineOf(t, text, i))
		}
	}
	if err := r.SetKeys(rest.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.CheckDevice(v2Payload(&keys[250], now, 4, "again")); ok {
		t.Fatal("a removed key's live session")
	}
	if _, _, ok := r.CheckDevice(v2Payload(&keys[250], now, 5, "new")); ok {
		t.Fatal("a removed key's new session")
	}
	// Epochs next to now pass, further ones do not.
	for d, want := range map[time.Duration]bool{-10 * time.Minute: true, 10 * time.Minute: true, 25 * time.Minute: false} {
		if _, _, ok := r.CheckDevice(v2Payload(&keys[9], now.Add(d), byte(0x40+d/time.Minute), "e")); ok != want {
			t.Errorf("a tag at %v: %v, want %v", d, ok, want)
		}
	}
}

// lineOf is key i's line in a devKeys text.
func lineOf(t *testing.T, text []byte, i int) string {
	t.Helper()
	return string(bytes.SplitAfter(text, []byte("\n"))[i])
}

// masterdns with dnsauth-v2: Scan finds a v2 tag by its hint with the
// kind's budget spent; Device checks a session's v2 tags; required takes no
// v1 tag; a device taken out is not found at once.
func TestDeviceAuthHint(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 300)
	a := &DeviceAuth{Now: func() time.Time { return now }, ScanHMACs: 1, Hint: HintOptional}
	a.SetKeys(text)
	msg := []byte("nonce-12byteframe")
	v2 := func(i int, at time.Time) [AuthTagLen]byte { return Tag2(&keys[i], EpochOf(at), msg) }
	for range 10 {
		a.Scan(ScanInit, [AuthTagLen]byte{9}, msg) // garbage: the INITs' budget spent
	}
	if a.slots[ScanInit].tokens > 0 {
		t.Fatalf("budget left: %v", a.slots[ScanInit].tokens)
	}
	if id, ok := a.Scan(ScanInit, v2(77, now), msg); !ok || id != "d77" {
		t.Fatalf("a v2 INIT with the budget spent: %q %v", id, ok)
	}
	if !a.Device("d77", v2(77, now.Add(time.Minute)), msg) || a.Device("d78", v2(77, now), msg) {
		t.Fatal("Device with v2 tags")
	}
	r := &DeviceAuth{Now: func() time.Time { return now }, Hint: HintRequired}
	r.SetKeys(text)
	if _, ok := r.Scan(ScanProbe, Tag(&keys[5], EpochOf(now), msg), msg); ok {
		t.Fatal("a v1 tag in required")
	}
	if r.Device("d5", Tag(&keys[5], EpochOf(now), msg), msg) {
		t.Fatal("Device: a v1 tag in required")
	}
	if r.Throttled.Load() != 0 || r.slots[ScanProbe].tokens != 0 {
		t.Fatal("required scanned")
	}
	var rest bytes.Buffer
	for i := range keys {
		if i != 5 {
			rest.WriteString(lineOf(t, text, i))
		}
	}
	r.SetKeys(rest.Bytes())
	if _, ok := r.Scan(ScanProbe, v2(5, now), msg); ok || r.Device("d5", v2(5, now), msg) {
		t.Fatal("a device taken out")
	}
	if id, ok := r.Scan(ScanProbe, v2(6, now), msg); !ok || id != "d6" {
		t.Fatalf("another device: %q %v", id, ok)
	}
}

// The index one epoch on is the previous one shifted with the new epoch's
// hints: the same as one built from scratch. A caller with older keys or a
// clock behind does not replace the index in force (review of a4e5342).
func TestHintIndexShiftAndStale(t *testing.T) {
	_, text := devKeys(t, 50)
	k, err := parseAuthKeys(text)
	if err != nil {
		t.Fatal(err)
	}
	e := EpochOf(time.Unix(1767268800, 0))
	var h hintIndexes
	x0 := h.get(k, e)
	x1 := h.get(k, e+1)
	full := buildHintIndex(k, e+1, nil)
	for i := range k.keys {
		if x1.hints[i] != full.hints[i] {
			t.Fatalf("key %d: shifted %v, built %v", i, x1.hints[i], full.hints[i])
		}
	}
	for s := range 3 {
		if len(x1.byHint[s]) != len(full.byHint[s]) {
			t.Fatalf("slot %d: %d hints shifted, %d built", s, len(x1.byHint[s]), len(full.byHint[s]))
		}
		for hint, ids := range full.byHint[s] {
			if !slices.Equal(x1.byHint[s][hint], ids) {
				t.Fatalf("slot %d hint %04x: %v, want %v", s, hint, x1.byHint[s][hint], ids)
			}
		}
	}
	if x0.byHint[2][x0.hints[0][2]] == nil || x1.byHint[1][x0.hints[0][2]] == nil {
		t.Fatal("the shifted slot lost its keys")
	}
	// A clock one epoch behind gets the index before the one in force (its
	// own window, review), not one built on every call.
	if back := h.get(k, e); back != x0 || h.cur.Load() != x1 {
		t.Fatal("a caller one epoch behind did not get the previous index")
	}
	// A clock stepped further back: its index is built once and kept
	// beside the one in force, and the clock coming back finds that.
	far := h.get(k, e-5)
	if far.middle != e-5 || h.get(k, e-5) != far || h.cur.Load() != x1 {
		t.Fatal("the index of a clock stepped back is not kept")
	}
	if h.get(k, e+1) != x1 {
		t.Fatal("the clock back: not the index in force")
	}
	// Keys read later win; a caller still holding the old ones does not
	// put them back.
	k2, _ := parseAuthKeys(text)
	x2 := h.get(k2, e+1)
	if h.cur.Load() != x2 {
		t.Fatal("newer keys not in force")
	}
	if h.get(k, e+1); h.cur.Load() != x2 {
		t.Fatal("a caller with older keys replaced the index of newer ones")
	}
}

// A v2 device found by its hint does not take a place among the recent
// ones: they are for the v1 pass.
func TestDeviceAuthHintNotRecent(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 10)
	a := &DeviceAuth{Now: func() time.Time { return now }, Hint: HintOptional}
	a.SetKeys(text)
	msg := []byte("nonce-12byteframe")
	if id, ok := a.Scan(ScanInit, Tag2(&keys[3], EpochOf(now), msg), msg); !ok || id != "d3" {
		t.Fatalf("v2 scan: %q %v", id, ok)
	}
	a.recentMu.Lock()
	n := len(a.recent)
	a.recentMu.Unlock()
	if n != 0 || a.Valid.Load() != 1 {
		t.Fatalf("recent %d, valid %d after a v2 scan", n, a.Valid.Load())
	}
}
