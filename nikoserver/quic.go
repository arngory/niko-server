package nikoserver

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"sort"

	"github.com/sagernet/sing-quic/hysteria2"
	"golang.org/x/crypto/blake2b"
)

// udpmux reads what a QUIC client says in the clear (SPEC §3.2): the
// Initial packets are encrypted with keys anyone can derive from the
// Destination Connection ID (RFC 9001 §5.2), so the front can take the
// ClientHello's server name from them without being part of the session.

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf // RFC 9369
)

var (
	quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicV2Salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	errNotInitial = errors.New("not a QUIC Initial of a known version")
)

// quicInitial is one decrypted client Initial packet.
type quicInitial struct {
	dcid   []byte
	crypto []cryptoFrame
}

type cryptoFrame struct {
	offset uint64
	data   []byte
}

// isQUICInitial tells whether a datagram starts with a long-header Initial
// packet of a QUIC version the front knows, without decrypting it.
func isQUICInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	switch binary.BigEndian.Uint32(b[1:5]) {
	case quicV1:
		return (b[0]>>4)&3 == 0
	case quicV2:
		return (b[0]>>4)&3 == 1
	}
	return false
}

// parseQUICInitial decrypts the first packet of a datagram if it is a
// client Initial and returns its CRYPTO frames.
func parseQUICInitial(datagram []byte) (quicInitial, error) {
	var p quicInitial
	if !isQUICInitial(datagram) {
		return p, errNotInitial
	}
	version := binary.BigEndian.Uint32(datagram[1:5])
	r := helloReader(datagram[5:])
	dcid, ok := r.vector(1)
	if !ok || len(dcid) > 20 {
		return p, errNotInitial
	}
	if _, ok = r.vector(1); !ok { // SCID
		return p, errNotInitial
	}
	tokenLen, ok := readVarint(&r)
	if !ok || !r.skip(int(tokenLen)) {
		return p, errNotInitial
	}
	length, ok := readVarint(&r)
	if !ok || length > uint64(len(r)) || length < 20 {
		return p, errNotInitial
	}
	pnOffset := len(datagram) - len(r)
	packet := append([]byte(nil), datagram[:pnOffset+int(length)]...)

	key, iv, hp := initialKeys(version, dcid)
	// Header protection (RFC 9001 §5.4): a mask from 16 bytes of sample.
	block, err := aes.NewCipher(hp)
	if err != nil {
		return p, err
	}
	if pnOffset+4+16 > len(packet) {
		return p, errNotInitial
	}
	var mask [16]byte
	block.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+16])
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&3) + 1
	var pn uint64
	for i := range pnLen {
		packet[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(packet[pnOffset+i])
	}
	header := packet[:pnOffset+pnLen]
	aesKey, err := aes.NewCipher(key)
	if err != nil {
		return p, err
	}
	aead, err := cipher.NewGCM(aesKey)
	if err != nil {
		return p, err
	}
	nonce := append([]byte(nil), iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	payload, err := aead.Open(nil, nonce, packet[pnOffset+pnLen:], header)
	if err != nil {
		return p, errNotInitial
	}
	p.dcid = append([]byte(nil), dcid...)
	p.crypto, err = cryptoFrames(payload)
	return p, err
}

// initialKeys derives the client's Initial key, IV and header protection key.
func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt, prefix := quicV1Salt, "quic "
	if version == quicV2 {
		salt, prefix = quicV2Salt, "quicv2 "
	}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	client := expandLabel(initial, "client in", 32)
	return expandLabel(client, prefix+"key", 16), expandLabel(client, prefix+"iv", 12), expandLabel(client, prefix+"hp", 16)
}

// expandLabel is TLS 1.3 HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), length)
	return out
}

func readVarint(r *helloReader) (uint64, bool) {
	if len(*r) == 0 {
		return 0, false
	}
	n := 1 << ((*r)[0] >> 6)
	b, ok := r.bytes(n)
	if !ok {
		return 0, false
	}
	v := uint64(b[0] & 0x3f)
	for _, x := range b[1:] {
		v = v<<8 | uint64(x)
	}
	return v, true
}

// cryptoFrames reads the frames an Initial may carry and keeps CRYPTO.
func cryptoFrames(payload []byte) ([]cryptoFrame, error) {
	var out []cryptoFrame
	r := helloReader(payload)
	for len(r) > 0 {
		typ, ok := readVarint(&r)
		if !ok {
			return nil, errNotInitial
		}
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK: largest, delay, range count, first range, ranges, ECN
			var count uint64
			fields := []*uint64{nil, nil, &count, nil}
			for _, f := range fields {
				v, ok := readVarint(&r)
				if !ok {
					return nil, errNotInitial
				}
				if f != nil {
					*f = v
				}
			}
			if count > 256 {
				return nil, errNotInitial
			}
			n := 2 * count
			if typ == 0x03 {
				n += 3
			}
			for range n {
				if _, ok := readVarint(&r); !ok {
					return nil, errNotInitial
				}
			}
		case 0x06: // CRYPTO
			offset, ok1 := readVarint(&r)
			length, ok2 := readVarint(&r)
			if !ok1 || !ok2 {
				return nil, errNotInitial
			}
			data, ok := r.bytes(int(length))
			if !ok {
				return nil, errNotInitial
			}
			if len(data) == 0 {
				continue
			}
			if len(out) == maxPacketFrames {
				return nil, errNotTLS // only work for the front (helloAssembler)
			}
			out = append(out, cryptoFrame{offset: offset, data: data})
		case 0x1c: // CONNECTION_CLOSE
			return out, nil
		default:
			return nil, errNotInitial
		}
	}
	return out, nil
}

// helloAssembler puts CRYPTO frames back in order until they hold a
// whole ClientHello. It holds the bytes that came, as pieces sorted by
// offset that do not overlap, not a buffer up to the highest offset: what
// it holds is what was sent once (a byte at offset 16383 holds one byte,
// not 16 KB; a retransmission adds nothing), and that is what the front
// counts against its budget of pending hellos. A frame must agree with
// what is held where they overlap: the backend gets the packets as they
// came, and the name the front routes by is the one it will read.
type helloAssembler struct {
	frames []cryptoFrame // held pieces, by offset, not overlapping
	size   int           // their bytes
}

const (
	maxQUICHello = 16 << 10
	// maxPacketFrames and maxHelloFrames: Chromium's chaos protection
	// splits its ClientHello into a few CRYPTO frames a packet (2 to 10
	// added), quic-go into two; a packet of hundreds of one-byte frames is
	// only work for the front. maxHelloFrames bounds the pieces held.
	maxPacketFrames = 32
	maxHelloFrames  = 256
)

// add takes a packet's frames and returns the ClientHello once it is
// complete.
func (a *helloAssembler) add(frames []cryptoFrame) (clientHello, bool, error) {
	n := 0
	for _, f := range frames {
		if f.offset+uint64(len(f.data)) > maxQUICHello {
			return clientHello{}, false, errNotTLS
		}
		if len(f.data) > 0 {
			n++
		}
	}
	if n > maxPacketFrames {
		return clientHello{}, false, errNotTLS
	}
	// The parts of this packet's frames that nothing held covers, each
	// checked against what is held; then against one another, in order of
	// offset, the overlaps among them dropped.
	var parts []cryptoFrame
	for _, f := range frames {
		if len(f.data) == 0 {
			continue
		}
		var ok bool
		if parts, ok = gaps(a.frames, f, parts); !ok || len(a.frames)+len(parts) > 2*maxHelloFrames {
			return clientHello{}, false, errNotTLS
		}
	}
	// In order of offset a part goes past the end of those before it or
	// adds nothing: a hole among them ends before its offset. What it
	// overlaps must agree.
	slices.SortFunc(parts, func(x, y cryptoFrame) int { return cmp.Compare(x.offset, y.offset) })
	added := make([]cryptoFrame, 0, len(parts))
	for _, p := range parts {
		var ok bool
		if added, ok = gaps(added, p, added); !ok {
			return clientHello{}, false, errNotTLS
		}
	}
	if len(a.frames)+len(added) > maxHelloFrames {
		return clientHello{}, false, errNotTLS
	}
	if len(added) > 0 {
		total := 0
		for _, p := range added {
			total += len(p.data)
		}
		buf := make([]byte, 0, total) // one copy of the new bytes
		for i := range added {
			start := len(buf)
			buf = append(buf, added[i].data...)
			added[i].data = buf[start:len(buf):len(buf)]
		}
		a.frames = mergePieces(a.frames, added)
		a.size += total
	}
	have := a.prefix()
	if have < 4 {
		return clientHello{}, false, nil
	}
	var head [4]byte
	a.fill(head[:])
	if head[0] != 1 {
		return clientHello{}, false, errNotTLS
	}
	size := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if 4+size > maxQUICHello {
		return clientHello{}, false, errNotTLS
	}
	if have < 4+size {
		return clientHello{}, false, nil
	}
	buf := make([]byte, 4+size)
	a.fill(buf)
	h, err := parseClientHello(buf[4:])
	return h, err == nil, err
}

// gaps checks frame f against held, pieces sorted by offset that do not
// overlap: where they overlap the bytes must agree (false if not). It
// appends to out the parts of f that held does not cover, in order, and
// returns it.
func gaps(held []cryptoFrame, f cryptoFrame, out []cryptoFrame) ([]cryptoFrame, bool) {
	end := f.offset + uint64(len(f.data))
	i := sort.Search(len(held), func(i int) bool { return held[i].offset+uint64(len(held[i].data)) > f.offset })
	pos := f.offset
	for ; i < len(held) && held[i].offset < end; i++ {
		h := held[i]
		hEnd := h.offset + uint64(len(h.data))
		if h.offset > pos {
			out = append(out, cryptoFrame{offset: pos, data: f.data[pos-f.offset : h.offset-f.offset]})
		}
		lo, hi := max(h.offset, f.offset), min(hEnd, end)
		if !bytes.Equal(f.data[lo-f.offset:hi-f.offset], h.data[lo-h.offset:hi-h.offset]) {
			return out, false
		}
		pos = max(pos, hEnd)
	}
	if pos < end {
		out = append(out, cryptoFrame{offset: pos, data: f.data[pos-f.offset:]})
	}
	return out, true
}

// mergePieces merges two lists of pieces sorted by offset that do not
// overlap one another.
func mergePieces(a, b []cryptoFrame) []cryptoFrame {
	out := make([]cryptoFrame, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0].offset < b[0].offset {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	out = append(out, a...)
	return append(out, b...)
}

// prefix is how many bytes from offset 0 the pieces hold without a gap.
func (a *helloAssembler) prefix() int {
	var have uint64
	for _, f := range a.frames {
		if f.offset != have {
			break
		}
		have += uint64(len(f.data))
	}
	return int(have)
}

// fill copies the pieces into dst from offset 0, as far as dst goes.
func (a *helloAssembler) fill(dst []byte) {
	for _, f := range a.frames {
		if f.offset >= uint64(len(dst)) {
			break
		}
		copy(dst[f.offset:], f.data)
	}
}

// salamanderOpen removes Hysteria2's salamander obfuscation: 8 bytes of
// salt, then the packet XOR BLAKE2b-256(password || salt), repeated.
func salamanderOpen(password, datagram []byte) ([]byte, bool) {
	if len(datagram) <= 8 {
		return nil, false
	}
	key := salamanderKey(password, datagram[:8])
	out := make([]byte, len(datagram)-8)
	hysteria2.SalamanderXOR(out, datagram[8:], &key, 0)
	return out, true
}

// salamanderInitial reports whether a datagram is a QUIC Initial under
// salamander with this password.
func salamanderInitial(password, datagram []byte) bool {
	head, ok := salamanderHead(password, datagram)
	return ok && isQUICInitial(head[:7])
}

// salamanderSalt is the salt ahead of a salamander datagram.
const salamanderSalt = 8

// salamanderHead opens the start of a datagram under salamander with this
// password: the bytes of a QUIC header that tell what it is (cidHead, those
// there are; the rest zero). Only they are opened, on the stack, so a
// garbage datagram costs one key and no copy. false: too short for an
// Initial's 7 bytes.
func salamanderHead(password, datagram []byte) (head [cidHead]byte, ok bool) {
	if len(datagram) < salamanderSalt+7 {
		return head, false
	}
	key := salamanderKey(password, datagram[:8])
	for i := range min(len(head), len(datagram)-8) {
		head[i] = datagram[8+i] ^ key[i]
	}
	return head, true
}

// salamanderKey is BLAKE2b-256(password || salt), without an allocation for
// a password of up to 120 bytes.
func salamanderKey(password, salt []byte) [blake2b.Size256]byte {
	var in [128]byte
	if len(password)+len(salt) <= len(in) {
		n := copy(in[:], password)
		n += copy(in[n:], salt)
		return blake2b.Sum256(in[:n])
	}
	return blake2b.Sum256(append(password[:len(password):len(password)], salt...))
}
