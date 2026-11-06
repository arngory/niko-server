package dnsttserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
	"sync/atomic"
)

// dnsauth-v2 (raycontrol docs/spec/dnsauth-v2.md): the 8 bytes of a tag are
// hint (2) || tag (6). The hint is the device's for the epoch, so the node
// looks its key up instead of scanning every key: a flood of garbage from
// whoever holds the link no longer spends the scan budget that new sessions
// need.
const (
	// HintLen is the hint's length at the start of a v2 tag.
	HintLen   = 2
	hintLabel = "dnsauth2-hint"
	tag2Label = "dnsauth2-tag"
)

// HintMode is whether tags carry the key's hint (dnsauth-v2).
type HintMode int

const (
	HintOff      HintMode = iota // dnsauth-v1 only
	HintOptional                 // v2 by the hint, v1 by a scan within the budget
	HintRequired                 // v2 only: no scan at all
)

// ParseHintMode reads "", "off", "optional" or "required".
func ParseHintMode(s string) (HintMode, error) {
	switch s {
	case "", "off":
		return HintOff, nil
	case "optional":
		return HintOptional, nil
	case "required":
		return HintRequired, nil
	}
	return HintOff, fmt.Errorf("auth_hint %q: off, optional or required", s)
}

// Hint is a key's hint for an epoch: HMAC-SHA256(K, "dnsauth2-hint" ||
// uint32_be(epoch))[:2]. Clients compute the same.
func Hint(key *[32]byte, epoch uint32) [HintLen]byte {
	m := hmac.New(sha256.New, key[:])
	var head [len(hintLabel) + 4]byte
	copy(head[:], hintLabel)
	binary.BigEndian.PutUint32(head[len(hintLabel):], epoch)
	m.Write(head[:])
	var out [HintLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// Tag2 is a payload's v2 tag field for a key and an epoch: the hint, then
// HMAC-SHA256(K, "dnsauth2-tag" || uint32_be(epoch) || payload)[:6].
// Clients compute the same.
func Tag2(key *[32]byte, epoch uint32, payload []byte) [AuthTagLen]byte {
	var out [AuthTagLen]byte
	h := Hint(key, epoch)
	copy(out[:], h[:])
	var t [AuthTagLen]byte
	tagWithLabel(hmac.New(sha256.New, key[:]), tag2Label, epoch, payload, new(tagScratch), &t)
	copy(out[HintLen:], t[:AuthTagLen-HintLen])
	return out
}

// match2 reports whether field is the v2 tag of payload under the key m
// holds for epoch; the hint was already matched against the key's.
func match2(m hash.Hash, epoch uint32, field *[AuthTagLen]byte, payload []byte, sc *tagScratch) bool {
	var t [AuthTagLen]byte
	tagWithLabel(m, tag2Label, epoch, payload, sc, &t)
	return hmac.Equal(t[:AuthTagLen-HintLen], field[HintLen:])
}

// hintIndex is the hints of one generation of keys for the epochs a tag may
// be in: middle-1, middle, middle+1.
type hintIndex struct {
	keys   *authKeys
	middle uint32
	hints  [][3]uint16           // by key, by epoch slot
	byHint [3]map[uint16][]int32 // by epoch slot: the keys with that hint
}

// epochSlots are the slots a tag is looked up in, the current epoch first.
var epochSlots = [3]int{1, 0, 2}

func (x *hintIndex) epoch(slot int) uint32 { return x.middle + uint32(slot) - 1 }

func hintValue(h [HintLen]byte) uint16 { return binary.BigEndian.Uint16(h[:]) }

// buildHintIndex builds the index of keys k around the epoch middle. From
// the index of the same keys one epoch before, it only computes the new
// epoch's hints (n HMACs every 10 minutes, raycontrol dnsauth-v2.md §3);
// otherwise all three.
func buildHintIndex(k *authKeys, middle uint32, prev *hintIndex) *hintIndex {
	x := &hintIndex{keys: k, middle: middle, hints: make([][3]uint16, len(k.keys))}
	from := 0
	if prev != nil && prev.keys == k && middle == prev.middle+1 {
		// The maps are never written once built: shared with prev.
		x.byHint[0], x.byHint[1] = prev.byHint[1], prev.byHint[2]
		for i := range x.hints {
			x.hints[i][0], x.hints[i][1] = prev.hints[i][1], prev.hints[i][2]
		}
		from = 2
	}
	for s := from; s < 3; s++ {
		x.byHint[s] = make(map[uint16][]int32, len(k.keys))
	}
	var head [len(hintLabel) + 4]byte
	copy(head[:], hintLabel)
	var sum [sha256.Size]byte
	for i := range k.keys {
		m := hmac.New(sha256.New, k.keys[i].key[:])
		for s := from; s < 3; s++ {
			m.Reset()
			binary.BigEndian.PutUint32(head[len(hintLabel):], x.epoch(s))
			m.Write(head[:])
			h := binary.BigEndian.Uint16(m.Sum(sum[:0]))
			x.hints[i][s] = h
			x.byHint[s][h] = append(x.byHint[s][h], int32(i))
		}
	}
	return x
}

// hintIndexes holds the index in force: built again at once when the keys
// change (a device revoked is not found from then on) and when the epoch
// moves on; and the one before it, for a clock behind.
type hintIndexes struct {
	mu   sync.Mutex
	cur  atomic.Pointer[hintIndex]
	prev atomic.Pointer[hintIndex]
}

// get is the index of the keys k for the epoch now. A clock one epoch behind
// the index in force (a caller that read the time just before the epoch
// moved on, or a step back) gets the one before it, and a clock further back
// an index built once and kept there: building one per call stalled every
// lookup after a step back (review: 3 ms a query with 2000 keys). A caller
// with keys older than those in force gets its own index without keeping it.
func (h *hintIndexes) get(k *authKeys, now uint32) *hintIndex {
	if x := h.cur.Load(); x != nil && x.keys == k && x.middle == now {
		return x
	}
	if x := h.prev.Load(); x != nil && x.keys == k && x.middle == now {
		return x
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cur, prev := h.cur.Load(), h.prev.Load()
	if cur != nil && cur.keys == k && cur.middle == now {
		return cur
	}
	if prev != nil && prev.keys == k && prev.middle == now {
		return prev
	}
	x := buildHintIndex(k, now, cur)
	switch {
	case cur == nil || k.gen > cur.keys.gen || (k.gen == cur.keys.gen && now > cur.middle):
		h.prev.Store(cur)
		h.cur.Store(x)
	case k.gen == cur.keys.gen:
		h.prev.Store(x) // a clock behind
	}
	return x
}

// find looks a v2 field up: the keys its hint names in each epoch, the
// current one first, checked with match (which holds the key's HMAC). It
// returns the key's index, or -1.
func (x *hintIndex) find(field *[AuthTagLen]byte, match func(i int, epoch uint32) bool) int {
	h := binary.BigEndian.Uint16(field[:HintLen])
	for _, s := range epochSlots {
		for _, i := range x.byHint[s][h] {
			if match(int(i), x.epoch(s)) {
				return int(i)
			}
		}
	}
	return -1
}

// keyMatches reports whether field is key i's v2 tag in some epoch: the
// hint compared first, so a key whose hint differs costs no HMAC.
func (x *hintIndex) keyMatches(i int, field *[AuthTagLen]byte, match func(epoch uint32) bool) bool {
	h := binary.BigEndian.Uint16(field[:HintLen])
	for _, s := range epochSlots {
		if x.hints[i][s] == h && match(x.epoch(s)) {
			return true
		}
	}
	return false
}
