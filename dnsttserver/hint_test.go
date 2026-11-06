package dnsttserver

import (
	"encoding/hex"
	"testing"
	"time"
)

// The vectors of raycontrol docs/spec/dnsauth-v2.md §6, computed apart from
// this code (and by the client): K of dnsauth-v1 §2, 1767268800,
// msg 00 01 … 17.
func TestHintVectors(t *testing.T) {
	var key [32]byte
	hex.Decode(key[:], []byte("0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c"))
	epoch := EpochOf(time.Unix(1767268800, 0))
	if epoch != 2945448 {
		t.Fatalf("epoch %d", epoch)
	}
	msg := make([]byte, 0x18)
	for i := range msg {
		msg[i] = byte(i)
	}
	if h := Hint(&key, epoch); hex.EncodeToString(h[:]) != "2d82" {
		t.Errorf("hint %x", h)
	}
	if f := Tag2(&key, epoch, msg); hex.EncodeToString(f[:]) != "2d82b1220002a927" {
		t.Errorf("field %x", f)
	}
	for d, want := range map[int]string{-1: "a5f9", 1: "e97f"} {
		if h := Hint(&key, uint32(int(epoch)+d)); hex.EncodeToString(h[:]) != want {
			t.Errorf("hint at epoch %+d: %x, want %s", d, h, want)
		}
	}
	// v1 and v2 tags of the same payload differ: the labels part them.
	if Tag(&key, epoch, msg) == Tag2(&key, epoch, msg) {
		t.Fatal("v1 and v2 tags alike")
	}
}
