package dnsttserver

import (
	"testing"
	"time"
)

// The valid tags are counted by version, and the snapshot gives them apart
// (review 2026-11-21 item 4): an operator sees when no device signs v1
// any more and auth_hint can go to required; untagged queries taken in
// optional mode are their own count, as before.
func TestAuthCountsByVersion(t *testing.T) {
	now := time.Unix(1767268800, 0)
	keys, text := devKeys(t, 3)
	a := &Auth{Mode: AuthOptional, Hint: HintOptional, Now: func() time.Time { return now }}
	if err := a.SetKeys(text); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{v2Payload(&keys[0], now, 1, "a"), v2Payload(&keys[0], now, 1, "b"), v1Payload(&keys[1], now, 2, "c"),
		v1Payload(&keys[1], now, 2, "d"), v1Payload(&keys[2], now, 3, "e")} {
		if _, _, ok := a.CheckDevice(p); !ok {
			t.Fatal("a valid tag refused")
		}
	}
	a.CheckDevice([]byte("an untagged query of an old client"))
	s := (&Stats{}).Snapshot(a, nil)
	if s.AuthValid != 5 || s.AuthValidV1 != 3 || s.AuthValidV2 != 2 || s.AuthUntagged != 1 {
		t.Fatalf("valid %d (v1 %d, v2 %d), untagged %d", s.AuthValid, s.AuthValidV1, s.AuthValidV2, s.AuthUntagged)
	}

	// masterdns's: Device and Scan.
	d := &DeviceAuth{Hint: HintOptional, Now: func() time.Time { return now }}
	d.SetKeys(text)
	msg := []byte("nonce-12byteframe")
	e := EpochOf(now)
	if _, ok := d.Scan(ScanInit, Tag2(&keys[0], e, msg), msg); !ok {
		t.Fatal("v2 scan")
	}
	if _, ok := d.Scan(ScanInit, Tag(&keys[1], e, msg), msg); !ok {
		t.Fatal("v1 scan")
	}
	if !d.Device("d0", Tag2(&keys[0], e, msg), msg) || !d.Device("d1", Tag(&keys[1], e, msg), msg) || !d.Device("d1", Tag(&keys[1], e, msg), msg) {
		t.Fatal("Device")
	}
	if d.Valid.Load() != 5 || d.ValidV1.Load() != 3 || d.ValidV2.Load() != 2 {
		t.Fatalf("masterdns: valid %d (v1 %d, v2 %d)", d.Valid.Load(), d.ValidV1.Load(), d.ValidV2.Load())
	}
}
