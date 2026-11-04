package hysteria2

import (
	"encoding/binary"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/blake2b"
)

const salamanderSaltLen = 8

// neko: the key without an allocation per packet, and the XOR word by word,
// instead of a byte loop with a modulo: about 17 times faster on a full
// packet (niko-server review, P-1, and the review after v0.8.0).

// salamanderKey is BLAKE2b-256(password || salt).
func salamanderKey(password, salt []byte) [blake2b.Size256]byte {
	var in [128]byte
	if len(password)+len(salt) <= len(in) {
		n := copy(in[:], password)
		n += copy(in[n:], salt)
		return blake2b.Sum256(in[:n])
	}
	return blake2b.Sum256(append(password[:len(password):len(password)], salt...))
}

// SalamanderXOR sets dst to src XOR the key repeated, starting at byte off
// of the key stream; dst and src are the same slice or do not overlap, and
// dst is at least as long as src. The key goes as four 64-bit words over
// each 32-byte block, with no key stream built per packet.
func SalamanderXOR(dst, src []byte, key *[blake2b.Size256]byte, off int) {
	if len(src) == 0 {
		return
	}
	dst = dst[:len(src)]
	i := 0
	if off %= blake2b.Size256; off != 0 {
		// Up to where the key starts again.
		i = min(blake2b.Size256-off, len(src))
		for j := range i {
			dst[j] = src[j] ^ key[off+j]
		}
	}
	k0 := binary.LittleEndian.Uint64(key[0:])
	k1 := binary.LittleEndian.Uint64(key[8:])
	k2 := binary.LittleEndian.Uint64(key[16:])
	k3 := binary.LittleEndian.Uint64(key[24:])
	for ; len(src)-i >= blake2b.Size256; i += blake2b.Size256 {
		s, d := src[i:i+32:i+32], dst[i:i+32:i+32]
		w0 := binary.LittleEndian.Uint64(s[0:]) ^ k0
		w1 := binary.LittleEndian.Uint64(s[8:]) ^ k1
		w2 := binary.LittleEndian.Uint64(s[16:]) ^ k2
		w3 := binary.LittleEndian.Uint64(s[24:]) ^ k3
		binary.LittleEndian.PutUint64(d[0:], w0)
		binary.LittleEndian.PutUint64(d[8:], w1)
		binary.LittleEndian.PutUint64(d[16:], w2)
		binary.LittleEndian.PutUint64(d[24:], w3)
	}
	for j := 0; i < len(src); i, j = i+1, j+1 {
		dst[i] = src[i] ^ key[j]
	}
}

// salamanderBuf holds a datagram with its salt while it is read: quic-go
// reads into 1452 bytes, and a full packet is 8 more on the wire (P-6). A
// reader with a larger buffer grows the one it gets.
var salamanderBuf = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}

const ObfsTypeSalamander = "salamander"

type SalamanderPacketConn struct {
	net.PacketConn
	password []byte
}

func NewSalamanderConn(conn net.PacketConn, password []byte) net.PacketConn {
	writer, isVectorised := bufio.CreateVectorisedPacketWriter(conn)
	if isVectorised {
		return &VectorisedSalamanderPacketConn{
			SalamanderPacketConn: SalamanderPacketConn{
				PacketConn: conn,
				password:   password[:len(password):len(password)],
			},
			writer: writer,
		}
	} else {
		return &SalamanderPacketConn{
			PacketConn: conn,
			password:   password[:len(password):len(password)],
		}
	}
}

// neko: read with room for the salt, so that a packet as large as p fits
// after it is taken off (P-6: the reader's 1452 bytes cut clients' packets
// to 1444).
func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bp := salamanderBuf.Get().(*[]byte)
	defer salamanderBuf.Put(bp)
	if want := min(len(p)+salamanderSaltLen, 65536); cap(*bp) < want {
		*bp = make([]byte, want)
	}
	b := (*bp)[:min(len(p)+salamanderSaltLen, cap(*bp))]
	n, addr, err = s.PacketConn.ReadFrom(b)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return copy(p, b[:n]), addr, nil
	}
	key := salamanderKey(s.password, b[:salamanderSaltLen])
	n = min(n-salamanderSaltLen, len(p))
	SalamanderXOR(p[:n], b[salamanderSaltLen:salamanderSaltLen+n], &key, 0)
	return n, addr, nil
}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := salamanderKey(s.password, buffer.Bytes())
	SalamanderXOR(buffer.Extend(len(p)), p, &key, 0)
	_, err = s.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderPacketConn) Upstream() any {
	return s.PacketConn
}

type VectorisedSalamanderPacketConn struct {
	SalamanderPacketConn
	writer N.VectorisedPacketWriter
}

func (s *VectorisedSalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(salamanderSaltLen)
	buffer.WriteRandom(salamanderSaltLen)
	key := salamanderKey(s.password, buffer.Bytes())
	SalamanderXOR(p, p, &key, 0)
	err = s.writer.WriteVectorisedPacket([]*buf.Buffer{buffer, buf.As(p)}, M.SocksaddrFromNet(addr))
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *VectorisedSalamanderPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(salamanderSaltLen)
	defer header.Release()
	header.WriteRandom(salamanderSaltLen)
	key := salamanderKey(s.password, header.Bytes())
	var index int
	for _, buffer := range buffers {
		content := buffer.Bytes()
		SalamanderXOR(content, content, &key, index)
		index += len(content)
	}
	return s.writer.WriteVectorisedPacket(append([]*buf.Buffer{header}, buffers...), destination)
}

type SalamanderConn struct {
	net.Conn
	password []byte
}

func NewSalamanderClientConn(conn net.Conn, password []byte) net.Conn {
	writer, isVectorised := bufio.CreateVectorisedWriter(conn)
	if isVectorised {
		return &VectorisedSalamanderConn{
			SalamanderConn: SalamanderConn{
				Conn:     conn,
				password: password[:len(password):len(password)],
			},
			writer: writer,
		}
	} else {
		return &SalamanderConn{
			Conn:     conn,
			password: password[:len(password):len(password)],
		}
	}
}

func (s *SalamanderConn) Read(p []byte) (n int, err error) {
	n, err = s.Conn.Read(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return
	}
	key := salamanderKey(s.password, p[:salamanderSaltLen])
	// In place, then moved over the salt: XORBytes takes no shifted overlap.
	SalamanderXOR(p[salamanderSaltLen:n], p[salamanderSaltLen:n], &key, 0)
	copy(p, p[salamanderSaltLen:n])
	return n - salamanderSaltLen, nil
}

func (s *SalamanderConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := salamanderKey(s.password, buffer.Bytes())
	SalamanderXOR(buffer.Extend(len(p)), p, &key, 0)
	_, err = s.Conn.Write(buffer.Bytes())
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderConn) Upstream() any {
	return s.Conn
}

type VectorisedSalamanderConn struct {
	SalamanderConn
	writer N.VectorisedWriter
}

func (s *VectorisedSalamanderConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := salamanderKey(s.password, buffer.Bytes())
	SalamanderXOR(p, p, &key, 0)
	_, err = bufio.WriteVectorised(s.writer, [][]byte{buffer.Bytes(), p})
	if err != nil {
		return
	}
	return len(p), nil
}
