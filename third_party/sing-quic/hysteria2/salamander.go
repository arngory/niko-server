package hysteria2

import (
	"crypto/subtle"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/blake2b"
)

const salamanderSaltLen = 8

// neko: the key without an allocation per packet, and the XOR word by word
// (crypto/subtle) over the key tiled once, instead of a byte loop with a
// modulo: about 9 times faster on a full packet (niko-server review, P-1).

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

// salamanderTile is the key repeated: XOR goes in chunks of it.
const salamanderTile = 2048

// SalamanderXOR sets dst to src XOR the key repeated, starting at byte off
// of the key stream; dst and src are the same slice or do not overlap.
func SalamanderXOR(dst, src []byte, key *[blake2b.Size256]byte, off int) {
	var ks [salamanderTile + blake2b.Size256]byte
	tiled := min(len(src)+blake2b.Size256, len(ks))
	for i := 0; i < tiled; i += blake2b.Size256 {
		copy(ks[i:], key[:])
	}
	stream := ks[off%blake2b.Size256 : tiled]
	for len(src) > 0 {
		n := subtle.XORBytes(dst, src, stream[:min(len(src), salamanderTile)])
		dst, src = dst[n:], src[n:]
	}
}

// salamanderBuf holds a datagram with its salt while it is read: quic-go
// reads into 1452 bytes, and a full packet is 8 more on the wire (P-6).
var salamanderBuf = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}

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
	b := (*bp)[:min(len(p)+salamanderSaltLen, len(*bp))]
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
