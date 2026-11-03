package nikoserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

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
// whole ClientHello.
type helloAssembler struct {
	buf    []byte
	filled []bool
}

const maxQUICHello = 16 << 10

// add takes frames and returns the ClientHello once it is complete.
func (a *helloAssembler) add(frames []cryptoFrame) (clientHello, bool, error) {
	for _, f := range frames {
		end := f.offset + uint64(len(f.data))
		if end > maxQUICHello {
			return clientHello{}, false, errNotTLS
		}
		if int(end) > len(a.buf) {
			a.buf = append(a.buf, make([]byte, int(end)-len(a.buf))...)
			a.filled = append(a.filled, make([]bool, int(end)-len(a.filled))...)
		}
		copy(a.buf[f.offset:], f.data)
		for i := f.offset; i < end; i++ {
			a.filled[i] = true
		}
	}
	have := 0
	for have < len(a.filled) && a.filled[have] {
		have++
	}
	if have < 4 {
		return clientHello{}, false, nil
	}
	if a.buf[0] != 1 {
		return clientHello{}, false, errNotTLS
	}
	size := int(a.buf[1])<<16 | int(a.buf[2])<<8 | int(a.buf[3])
	if 4+size > maxQUICHello {
		return clientHello{}, false, errNotTLS
	}
	if have < 4+size {
		return clientHello{}, false, nil
	}
	h, err := parseClientHello(a.buf[4 : 4+size])
	return h, err == nil, err
}

// salamanderOpen removes Hysteria2's salamander obfuscation: 8 bytes of
// salt, then the packet XOR BLAKE2b-256(password || salt), repeated.
func salamanderOpen(password, datagram []byte) ([]byte, bool) {
	if len(datagram) <= 8 {
		return nil, false
	}
	key := blake2b.Sum256(append(append([]byte(nil), password...), datagram[:8]...))
	out := make([]byte, len(datagram)-8)
	for i := range out {
		out[i] = datagram[8+i] ^ key[i%32]
	}
	return out, true
}
