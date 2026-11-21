package nikoserver

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Routable connection IDs (raycontrol docs/spec/quic-cid-route-v1.md): a
// QUIC backend gives its server connection IDs a label, its number, and
// the front reads the label of a client's packet from an address it does
// not know yet, so a connection outlives a change of the client's address
// (NAT rebinding, a client that moves to a new socket). An ID is 8 bytes:
// Speck64/128 of
//
//	label (16 bits) | 0 (8 bits) | counter (40 bits)
//
// under the label's key, HMAC-SHA256(node secret, "quic-cid-route-v1" ||
// BE16(label)), 16 bytes, which raycontrol derives. A backend has only its
// own label's key, the front those of its backends' labels; the secret
// stays with raycontrol. To anyone without the key the IDs are random and
// distinct, the label included; the zero byte and the label make a random
// 8 bytes pass for one of k labels in about k·2^-24.

const (
	// cidLen is the length of a routable connection ID.
	cidLen = 8
	// cidRounds: Speck64/128.
	cidRounds = 27
	// cidCounterBits is the counter's part of an ID.
	cidCounterBits = 40
	// MaxCIDLabel is the largest label; 0 is none.
	MaxCIDLabel = 1<<16 - 1
	// cidKeyContext derives the Speck key from the node's secret.
	cidKeyContext = "quic-cid-route-v1"
	// minCIDPacket: the shortest packet with a header of a routable ID
	// worth reading. A short header, 8 bytes of ID, the packet number's 4
	// bytes the header protection's sample is taken after, and that sample
	// (RFC 9001 §5.4.2); nothing shorter can be opened.
	minCIDPacket = 1 + cidLen + 4 + 16
	// cidHead is what a packet's header is read for: a long header's
	// first byte, version, ID length and the ID itself.
	cidHead = 1 + 4 + 1 + cidLen
)

// cidCodec is Speck64/128 with the round keys of a node's secret.
type cidCodec struct {
	rk [cidRounds]uint32
}

// newSpeck expands a Speck64/128 key given as the paper prints it: the
// words l2, l1, l0, k0 in that order, each big-endian.
func newSpeck(key []byte) *cidCodec {
	c := &cidCodec{}
	l := [cidRounds + 2]uint32{binary.BigEndian.Uint32(key[8:12]), binary.BigEndian.Uint32(key[4:8]), binary.BigEndian.Uint32(key[0:4])}
	c.rk[0] = binary.BigEndian.Uint32(key[12:16])
	for i := range cidRounds - 1 {
		l[i+3] = (c.rk[i] + bits.RotateLeft32(l[i], -8)) ^ uint32(i)
		c.rk[i+1] = bits.RotateLeft32(c.rk[i], 3) ^ l[i+3]
	}
	return c
}

func (c *cidCodec) encrypt(x, y uint32) (uint32, uint32) {
	for _, k := range c.rk {
		x = (bits.RotateLeft32(x, -8) + y) ^ k
		y = bits.RotateLeft32(y, 3) ^ x
	}
	return x, y
}

func (c *cidCodec) decrypt(x, y uint32) (uint32, uint32) {
	for i := cidRounds - 1; i >= 0; i-- {
		y = bits.RotateLeft32(y^x, -3)
		x = bits.RotateLeft32((x^c.rk[i])-y, 8)
	}
	return x, y
}

// encode is the ID of a label and a counter (its low 40 bits).
func (c *cidCodec) encode(label uint16, counter uint64) [cidLen]byte {
	x := uint32(label)<<16 | uint32(counter>>32)&0xff
	x, y := c.encrypt(x, uint32(counter))
	var id [cidLen]byte
	binary.BigEndian.PutUint32(id[0:4], x)
	binary.BigEndian.PutUint32(id[4:8], y)
	return id
}

// label reads the label of an ID (its first 8 bytes); false when it holds
// none: the byte after the label is not 0, or the label is.
func (c *cidCodec) label(id []byte) (uint16, bool) {
	if len(id) < cidLen {
		return 0, false
	}
	x, _ := c.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	label := uint16(x >> 16)
	return label, x&0xff00 == 0 && label != 0
}

// clientCID is where a client's packet names a server's connection ID
// that may carry a label, nil if it does not: a short header (form 0,
// fixed bit 1), or a long header of a Handshake packet of QUIC v1 or v2,
// with an ID of cidLen. head is the packet's start (cidHead bytes, fewer
// for a short one), size its whole length. Initial packets are not read
// here: a client's first carry an ID of its own, and the front routes
// them by name. 0-RTT packets carry the client's ID as well.
func clientCID(head []byte, size int) []byte {
	if size < minCIDPacket || len(head) < 1+cidLen {
		return nil
	}
	switch head[0] & 0xc0 {
	case 0x40:
		return head[1 : 1+cidLen]
	case 0xc0:
		if len(head) < cidHead || head[5] != cidLen {
			return nil
		}
		typ := head[0] >> 4 & 3
		switch binary.BigEndian.Uint32(head[1:5]) {
		case quicV1:
			if typ != 2 {
				return nil
			}
		case quicV2:
			if typ != 3 {
				return nil
			}
		default:
			return nil
		}
		return head[6 : 6+cidLen]
	}
	return nil
}

// cidGenerator makes a backend's connection IDs: its label and a counter
// that starts from the clock (cidStart), one step per ID. IDs of one
// generator never repeat before 2^40 of them; those of two labels never
// meet.
type cidGenerator struct {
	codec *cidCodec
	label uint16
	next  atomic.Uint64
}

func newCIDGenerator(codec *cidCodec, label uint16) (*cidGenerator, error) {
	return newCIDGeneratorAt(codec, label, time.Now())
}

// newCIDGeneratorAt is newCIDGenerator started at now.
func newCIDGeneratorAt(codec *cidCodec, label uint16, now time.Time) (*cidGenerator, error) {
	if label == 0 {
		return nil, errors.New("label 0 is none")
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	g := &cidGenerator{codec: codec, label: label}
	g.next.Store(cidStart(now, binary.BigEndian.Uint16(b[:])))
	return g, nil
}

// cidStart is a generator's counter at its start: 4096 a second of the
// clock since 1970, and a random offset within the second, modulo 2^40
// (the counter wraps every 2^28 s, 8.5 years). A process after another
// starts past the IDs the one before issued, as long as that one issued
// fewer than 4096 a second on average since its own start: its IDs are
// behind the new window of ahead, and the new IDs are not the old ones.
// Without the label's key the counter is not seen: the IDs stay random. A
// clock set back by more than the old process lived puts the old IDs in
// the window: their clients wait out their idle time instead of a reset,
// and nothing else.
func cidStart(now time.Time, random uint16) uint64 {
	return (uint64(now.Unix())<<12 + uint64(random&0xfff)) & (1<<cidCounterBits - 1) //nolint:gosec // G115: the seconds since 1970
}

// generate returns the next ID.
func (g *cidGenerator) generate() [cidLen]byte {
	return g.codec.encode(g.label, g.next.Add(1)&(1<<cidCounterBits-1))
}

// cidAheadWindow is how far past the last ID issued an ID of the
// generator's own counts as one it will issue: 2^32 IDs, years at any rate
// a node issues them.
const cidAheadWindow = 1 << 32

// ahead reports whether id is one of the generator's own, its label under
// its key, that it has not issued yet and will within cidAheadWindow. A
// server must not answer a packet for such an ID with a stateless reset:
// its token is a function of the ID, and whoever has the label's key
// could collect the tokens of IDs to come and end those connections later
// (review of quic-cid-route-v1, F2). The IDs of a process before this one
// are behind the window (cidStart): they still get their resets.
func (g *cidGenerator) ahead(id []byte) bool {
	if len(id) < cidLen {
		return false
	}
	x, y := g.codec.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	if uint16(x>>16) != g.label || x&0xff00 != 0 {
		return false
	}
	const mask = 1<<cidCounterBits - 1
	counter := uint64(x&0xff)<<32 | uint64(y)
	d := (counter - g.next.Load()) & mask
	return d >= 1 && d <= cidAheadWindow
}

// behind reports whether id is one of the generator's own, its label under
// its key, issued already or by a process before (not ahead).
func (g *cidGenerator) behind(id []byte) bool {
	if len(id) < cidLen {
		return false
	}
	x, _ := g.codec.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	return uint16(x>>16) == g.label && x&0xff00 == 0 && !g.ahead(id)
}

// dropUnlabelled reports whether a server under an obfuscation drops a
// client's packet: a short header whose destination ID is not one of the
// generator's own it issued (behind). There the server sends stateless
// resets (hysteriaResetKey), and a reset to anything else would answer a
// prober's packet, which the obfuscation reads as random QUIC, whatever
// the front passes; one of 2^24 random IDs passes the label's check.
func (g *cidGenerator) dropUnlabelled(p []byte) bool {
	if len(p) < 1 || p[0]&0xc0 != 0x40 {
		return false
	}
	return len(p) < minCIDPacket || !g.behind(p[1:1+cidLen])
}

// dropAhead reports whether a server drops a client's packet: a short
// header whose destination ID is one the generator will issue (ahead).
// Long headers are not read: their ID is elsewhere, and a client's
// Initial carries its own.
func (g *cidGenerator) dropAhead(p []byte) bool {
	return len(p) >= minCIDPacket && p[0]&0xc0 == 0x40 && g.ahead(p[1:1+cidLen])
}

// maxCIDKeys bounds the keys of the front's file: a node has a few QUIC
// backends.
const maxCIDKeys = 256

// readCIDKeys reads the front's keys of its backends' labels: a line
// "<label> <16 bytes in hex>" each, a label once. Its errors say what is
// wrong with the file, never what it holds.
func readCIDKeys(path string) (map[uint16]*cidCodec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[uint16]*cidCodec{}
	for i, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		label, err := strconv.ParseUint(fields[0], 10, 16)
		if len(fields) != 2 || err != nil || label == 0 {
			return nil, fmt.Errorf("line %d: want a label (1-%d) and its key", i+1, MaxCIDLabel)
		}
		key, err := hex.DecodeString(fields[1])
		if err != nil || len(key) != 16 {
			return nil, fmt.Errorf("line %d: want a key of 16 bytes in hex", i+1)
		}
		if keys[uint16(label)] != nil {
			return nil, fmt.Errorf("line %d: label %d twice", i+1, label)
		}
		if len(keys) == maxCIDKeys {
			return nil, fmt.Errorf("more than %d keys", maxCIDKeys)
		}
		keys[uint16(label)] = newSpeck(key)
	}
	return keys, nil
}

// readCIDLabelKey reads a backend's key of its label (16 bytes in hex):
// a backend has its own label's key and no other.
func readCIDLabelKey(path string) (*cidCodec, error) {
	key, err := readHexKey(path, 16)
	if err != nil {
		return nil, err
	}
	return newSpeck(key), nil
}

func readHexKey(path string, size int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != size {
		return nil, fmt.Errorf("want %d bytes in hex", size)
	}
	return key, nil
}
