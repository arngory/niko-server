//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// The frame filter on a client's link (raycontrol docs/spec/lan-v1.md §2.2).
// The core would carry ironwood frames between any two of its peers: one
// user's device to another user's, or to anyone through the node. On each
// client's link the backend reads the frames as ironwood frames them, and
// of traffic, pathNotify, pathBroken and pathLookup it lets through only
// those between the client and the node; in LAN (later) also those within
// the client's group. Everything else passes as it is (keepalive, the tree,
// the bloom filters): without them there is no route at all. The filter
// says nothing in any log: counters only (§4.3).
//
// Two leaks are left, known and accepted (docs/SPEC.md §3.4):
//   - the node's bloom filter to a client holds every other on-tree peer's
//     key as the core transforms it, its /64 (iw: bloomfilter.go:216-234,
//     ygg: src/core/core.go:96-98): a client can tell whether an address
//     it already knows is at the node, not list who is;
//   - the tree: a peer gets the announcements of the node's ancestry and
//     its own (iw: router.go:332-389). The root is the least key; with no
//     public peers that is usually a client, and every client gets its key
//     (traffic to it is filtered all the same).
//
// The wire, as ironwood 0712ecc reads it (iw: its network package):
//   - a frame is a uvarint length, then that many bytes: a type and its
//     body (peers.go:247-269); binary.ReadUvarint, so a length need not be
//     minimal; over peerMaxMessageSize, or empty, it ends the link
//     (peers.go:253, 275), as does a frame its type's decoder refuses;
//   - pathLookup (6): source, dest, the path from, nothing after
//     (pathfinder.go:297-336); dest may be a key from an address;
//   - traffic (9): path, from, source, dest, a uvarint watermark, the
//     payload (traffic.go:36-69);
//   - pathNotify (7): path, a uvarint watermark, source, dest, then the
//     info: a uvarint seq, a path, a 64-byte signature, nothing after
//     (pathfinder.go:395-421, 448-481);
//   - pathBroken (8): path, a uvarint watermark, source, dest, nothing
//     after (pathfinder.go:514-543);
//   - a path is uvarints up to a zero (wire.go:80-113); a key is 32 bytes.
//
// Before the frames each side sends yggdrasil-go's handshake, "meta" and
// a big-endian uint16 length (ygg: src/core/version.go:59-96): serve reads
// the client's, the core's passes on as it is.

// yggFrameMax is the largest frame the core takes, its type byte included:
// ironwood's peerMaxMessageSize as yggdrasil-go sets it (ygg:
// src/core/core.go:104, 65535*2).
const yggFrameMax = 65535 * 2

// ironwood's frame types with a source and a destination (iw: wire.go:7-18).
const (
	yggPathLookup = 6
	yggPathNotify = 7
	yggPathBroken = 8
	yggTraffic    = 9
)

const yggKeySize = 32

// errYggFrame is a frame the core would refuse (and end the link for), or
// a stream that is no ironwood link: the link ends.
var errYggFrame = errors.New("not an ironwood frame")

// yggFrameKeys reads the source and the destination of a frame (its type
// byte and body) of type pathLookup, pathNotify, pathBroken or traffic, as
// ironwood decodes it, in place. keyed is false for any other type, ok
// false for a frame of those four that ironwood would refuse.
func yggFrameKeys(frame []byte) (source, dest *[yggKeySize]byte, keyed, ok bool) {
	if len(frame) == 0 {
		return nil, nil, false, false
	}
	b := frame[1:]
	switch frame[0] {
	case yggTraffic:
		if b, ok = yggSkipPath(b); !ok { // path
			return nil, nil, true, false
		}
		if b, ok = yggSkipPath(b); !ok { // from
			return nil, nil, true, false
		}
		if len(b) < 2*yggKeySize {
			return nil, nil, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		if _, ok = yggSkipUint(b[2*yggKeySize:]); !ok { // watermark; the payload is the rest
			return nil, nil, true, false
		}
		return source, dest, true, true
	case yggPathLookup:
		if len(b) < 2*yggKeySize {
			return nil, nil, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		if b, ok = yggSkipPath(b[2*yggKeySize:]); !ok || len(b) != 0 { // from, nothing after
			return nil, nil, true, false
		}
		return source, dest, true, true
	case yggPathNotify, yggPathBroken:
		if b, ok = yggSkipPath(b); !ok { // path
			return nil, nil, true, false
		}
		if b, ok = yggSkipUint(b); !ok { // watermark
			return nil, nil, true, false
		}
		if len(b) < 2*yggKeySize {
			return nil, nil, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		b = b[2*yggKeySize:]
		if frame[0] == yggPathNotify {
			if b, ok = yggSkipUint(b); !ok { // info: seq
				return nil, nil, true, false
			}
			if b, ok = yggSkipPath(b); !ok { // info: path
				return nil, nil, true, false
			}
			if len(b) != 64 { // info: signature
				return nil, nil, true, false
			}
		} else if len(b) != 0 {
			return nil, nil, true, false
		}
		return source, dest, true, true
	}
	return nil, nil, false, true
}

// yggSkipUint is ironwood's wireChopUint without the value.
func yggSkipUint(b []byte) ([]byte, bool) {
	_, n := binary.Uvarint(b)
	if n <= 0 {
		return nil, false
	}
	return b[n:], true
}

// yggSkipPath is ironwood's wireChopPath without the ports: uvarints up to
// a zero.
func yggSkipPath(b []byte) ([]byte, bool) {
	for {
		u, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, false
		}
		b = b[n:]
		if u == 0 {
			return b, true
		}
	}
}

// yggGroup is a key's LAN group (lan-v1 §2.2); 0 is none (∅).
type yggGroup uint32

// yggRule is lan-v1 §2.2 on one client's link: N the node's key, K the
// link's, G(x) the group of a key.
type yggRule struct {
	node, key [yggKeySize]byte
	group     func(*[yggKeySize]byte) yggGroup
}

// passes is the rule for a frame of type pathLookup, pathNotify,
// pathBroken or traffic with its source and dest. From the client (K to the
// core): the source is K, the dest N. To the client (the core to K): the
// source is N, the dest K. Either end may instead be a key of K's group,
// when K has one. pathBroken carries the source and dest of the traffic it
// reports on, but goes back to that source (iw: pathfinder.go:228-236): for
// it the two trade places. A lookup goes out to whoever might answer it:
// from the client only its source is held to the rule, K's lookups for
// anyone pass; to the client the source is N and the dest one K would
// answer. Else a client that claims every key in its bloom filter (iw:
// bloomfilter.go:301-329) would get every other client's lookup for the
// node, and the node's own for each of them, keys and all.
func (r *yggRule) passes(fromClient bool, typ byte, source, dest *[yggKeySize]byte) bool {
	switch typ {
	case yggPathLookup:
		if fromClient {
			return r.is(source, &r.key)
		}
		return r.is(source, &r.node) && (r.is(dest, &r.key) || r.answers(dest))
	case yggPathBroken:
		source, dest = dest, source
	}
	if fromClient {
		return r.is(source, &r.key) && r.is(dest, &r.node)
	}
	return r.is(source, &r.node) && r.is(dest, &r.key)
}

// answers: K would answer a lookup for dest, as ironwood decides it
// (iw: pathfinder.go:62-64) with the core's bloom transform (ygg:
// src/core/core.go:96-98), dest being a whole key or one from an address.
// Only for the node's lookups and not for K's very key: never on the way
// of traffic. A group of LAN will want G of such a key too.
func (r *yggRule) answers(dest *[yggKeySize]byte) bool {
	return bytes.Equal(address.SubnetForKey(dest[:]).GetKey(), address.SubnetForKey(r.key[:]).GetKey())
}

// is: x is want, or G(x) = G(K) ≠ ∅.
func (r *yggRule) is(x, want *[yggKeySize]byte) bool {
	if *x == *want {
		return true
	}
	g := r.group(&r.key)
	return g != 0 && r.group(x) == g
}

// The buffers of the filter, from pools: each direction of a link reads
// into one of yggReadSize, as io.Copy would; a frame larger than that is
// held whole in one of the core's largest frame, kept until what was read
// is all sent on. Pointers, so that Put allocates nothing.
const yggReadSize = 32 << 10

var (
	yggReadBufs  = sync.Pool{New: func() any { b := make([]byte, yggReadSize); return &b }}
	yggFrameBufs = sync.Pool{New: func() any { b := make([]byte, binary.MaxVarintLen64+yggFrameMax); return &b }}
)

// yggLinkFilter is the filter on one client's link.
type yggLinkFilter struct {
	rule    yggRule
	dropped *atomic.Uint64 // the backend's: frames dropped by the rule
}

// up copies the client's frames to the core, until either fails or a frame
// is one the core would refuse.
func (f *yggLinkFilter) up(core io.Writer, client io.Reader) error {
	return f.copy(core, client, true)
}

// down copies the core's handshake and then its frames to the client.
func (f *yggLinkFilter) down(client io.Writer, core io.Reader) error {
	bp := yggReadBufs.Get().(*[]byte)
	buf := *bp
	_, err := io.ReadFull(core, buf[:6])
	size := int(binary.BigEndian.Uint16(buf[4:6]))
	switch {
	case err != nil:
	case string(buf[:4]) != "meta" || size > yggMetaMax:
		err = errYggFrame
	default:
		if _, err = io.ReadFull(core, buf[6:6+size]); err == nil {
			_, err = client.Write(buf[:6+size])
		}
	}
	yggReadBufs.Put(bp)
	if err != nil {
		return err
	}
	return f.copy(client, core, false)
}

// copy passes src's frames to dst, those the rule lets through, as they
// came: runs of them in one write. A frame the core would refuse, or a
// length over its largest frame, ends the copy (what passed before it is
// written).
func (f *yggLinkFilter) copy(dst io.Writer, src io.Reader, fromClient bool) error {
	small := yggReadBufs.Get().(*[]byte)
	defer yggReadBufs.Put(small)
	var large *[]byte
	defer func() {
		if large != nil {
			yggFrameBufs.Put(large)
		}
	}()
	buf := *small
	r, w := 0, 0 // buf[r:w]: read, not yet sent on or dropped
	for {
		n, rerr := src.Read(buf[w:])
		w += n
		start, need := r, 0 // buf[start:r]: frames to send; need: what the next one takes from r
		var bad bool
		for r < w {
			size, sn := binary.Uvarint(buf[r:w])
			if sn == 0 && w-r < binary.MaxVarintLen64 {
				need = binary.MaxVarintLen64 // the length is not all here
				break
			}
			// Ten bytes and no end of the length is an overflow to
			// binary.ReadUvarint, as are a zero length and one over the
			// largest frame to ironwood.
			if sn <= 0 || size == 0 || size > yggFrameMax {
				bad = true
				break
			}
			end := r + sn + int(size)
			if end > w {
				need = end - r
				break
			}
			frame := buf[r+sn : end]
			source, dest, keyed, ok := yggFrameKeys(frame)
			if !ok {
				bad = true
				break
			}
			if keyed && !f.rule.passes(fromClient, frame[0], source, dest) {
				if err := yggWrite(dst, buf[start:r]); err != nil {
					return err
				}
				start = end
				f.dropped.Add(1)
			}
			r = end
		}
		if err := yggWrite(dst, buf[start:r]); err != nil {
			return err
		}
		switch {
		case bad:
			return errYggFrame
		case rerr != nil:
			return rerr
		case r == w:
			r, w = 0, 0
			if large != nil {
				yggFrameBufs.Put(large)
				large, buf = nil, *small
			}
		case r+need > len(buf):
			// Room for the next frame: at the start of the buffer, or in a
			// large one if it is larger than the buffer.
			if need > len(buf) {
				large = yggFrameBufs.Get().(*[]byte)
				w = copy(*large, buf[r:w])
				buf = *large
			} else {
				w = copy(buf, buf[r:w])
			}
			r = 0
		}
	}
}

func yggWrite(w io.Writer, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	_, err := w.Write(b)
	return err
}
