package nikoserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"strings"
	"sync/atomic"
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
// BE16(label)), 16 bytes. A backend has only its own label's key; the front
// has the secret, and so every label's. To anyone without the key the IDs
// are random and distinct, the label included; the zero byte and the label
// make a random 8 bytes pass for one of k labels in about k·2^-24.

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

// cidLabelKey is a label's Speck key: HMAC-SHA256(secret,
// "quic-cid-route-v1" || BE16(label)), its first 16 bytes.
func cidLabelKey(secret []byte, label uint16) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(cidKeyContext))
	mac.Write([]byte{byte(label >> 8), byte(label)})
	return mac.Sum(nil)[:16]
}

// labelCodec is the codec of a label under the node's 32-byte secret: the
// label's key read as the paper's key words l2 l1 l0 k0 (big-endian).
func labelCodec(secret []byte, label uint16) *cidCodec {
	return newSpeck(cidLabelKey(secret, label))
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
// that starts at random, one step per ID. IDs of one generator never
// repeat before 2^40 of them; those of two labels never meet.
type cidGenerator struct {
	codec *cidCodec
	label uint16
	next  atomic.Uint64
}

func newCIDGenerator(codec *cidCodec, label uint16) (*cidGenerator, error) {
	if label == 0 {
		return nil, errors.New("label 0 is none")
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	g := &cidGenerator{codec: codec, label: label}
	g.next.Store(binary.BigEndian.Uint64(b[:]))
	return g, nil
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
// (review of quic-cid-route-v1, F2). An ID of a process before this one
// falls in the window by chance only, cidAheadWindow/2^40 of the time.
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

// dropAhead reports whether a server drops a client's packet: a short
// header whose destination ID is one the generator will issue (ahead).
// Long headers are not read: their ID is elsewhere, and a client's
// Initial carries its own.
func (g *cidGenerator) dropAhead(p []byte) bool {
	return len(p) >= minCIDPacket && p[0]&0xc0 == 0x40 && g.ahead(p[1:1+cidLen])
}

// readCIDSecret reads the node's secret of routable connection IDs (the
// front's): 32 bytes in hex, as the other keys.
func readCIDSecret(path string) ([]byte, error) {
	return readHexKey(path, 32)
}

// readCIDLabelKey reads a backend's key of its label (16 bytes in hex,
// cidLabelKey): a backend has its own label's key, not the node's secret.
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
