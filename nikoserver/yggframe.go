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
// Left, known and accepted (docs/SPEC.md §3.4):
//   - the node's bloom filter to a client holds every other on-tree peer's
//     key as the core transforms it, its /64 (iw: bloomfilter.go:216-234,
//     ygg: src/core/core.go:96-98): a client can tell whether an address
//     it already knows is at the node, not list who is;
//   - the same bloom filters are a channel between two clients that agree
//     to use one: the bits A sets in its own, the node ORs into B's, up to
//     8192 bits an update. Through the node they have the internet anyway;
//   - the tree: a peer gets the announcements of the node's ancestry and
//     its own (iw: router.go:332-389). The root is the least key; with no
//     public peers that is usually a client, and every client gets its key
//     (traffic to it is filtered all the same);
//   - memory: while a large frame comes in pieces, a link holds a buffer of
//     the largest frame, 131080 bytes, each way.
//
// A frame dropped is answered (yggLinkFilter.answer): ironwood ends a link
// whose frame gets nothing back in 3 s.
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

// yggLinkFilter is the filter on one client's link: the rule, and the two
// ends it writes to.
type yggLinkFilter struct {
	rule    yggRule
	dropped *atomic.Uint64 // the backend's: frames dropped by the rule
	core    yggOut         // the link's side to the core
	client  yggOut         // the link's side to the client
	done    chan struct{}
}

func newYggLinkFilter(rule yggRule, dropped *atomic.Uint64, core, client io.Writer) *yggLinkFilter {
	f := &yggLinkFilter{rule: rule, dropped: dropped}
	f.attach(core, client)
	return f
}

// attach gives the filter the two ends it writes to.
func (f *yggLinkFilter) attach(core, client io.Writer) {
	f.done = make(chan struct{})
	f.core.init(core)
	f.client.init(client)
}

// close ends the goroutines that write the injected frames.
func (f *yggLinkFilter) close() { close(f.done) }

// up copies the client's frames to the core, until either fails or a frame
// is one the core would refuse.
func (f *yggLinkFilter) up(client io.Reader) error {
	go f.core.run(f.done)
	return f.copy(&f.core, client, true)
}

// down copies the core's handshake and then its frames to the client.
func (f *yggLinkFilter) down(core io.Reader) error {
	if err := f.handshake(core); err != nil {
		return err
	}
	go f.client.run(f.done) // injected frames only after the handshake
	return f.copy(&f.client, core, false)
}

// handshake passes the core's handshake to the client as it is.
func (f *yggLinkFilter) handshake(core io.Reader) error {
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
			err = f.client.write(buf[:6+size])
		}
	}
	yggReadBufs.Put(bp)
	return err
}

// copy passes src's frames to dst, those the rule lets through, as they
// came: runs of them in one write. A frame the core would refuse, or a
// length over its largest frame, ends the copy (what passed before it is
// written). For each frame it drops it injects the answers (answer).
func (f *yggLinkFilter) copy(dst *yggOut, src io.Reader, fromClient bool) error {
	sender := &f.core // the end whose frames these are
	if fromClient {
		sender = &f.client
	}
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
		asks := false       // a frame in buf[start:r] asks for an answer
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
				if err := yggSend(dst, sender, buf[start:r], asks); err != nil {
					return err
				}
				start, asks = end, false
				f.dropped.Add(1)
				f.answer(fromClient, frame, source, dest)
			} else if frame[0] > yggKeepAlive {
				asks = true
			}
			r = end
		}
		if err := yggSend(dst, sender, buf[start:r], asks); err != nil {
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

// yggSend writes a run of frames on: if one of them asks for an answer, its
// sender now waits for one.
func yggSend(dst, sender *yggOut, b []byte, asks bool) error {
	if err := dst.write(b); err != nil {
		return err
	}
	if asks && !sender.waits.Load() {
		sender.waits.Store(true)
	}
	return nil
}

// answer stands in for a frame the filter dropped, as far as ironwood's
// peers keep each other alive (iw: peers.go:127-181). A peer that sends any
// frame but a keepalive (or a dummy) ends the link unless some frame comes
// back within peerTimeout, 3 s; a peer that gets one owes a keepalive within
// a second, and any frame it sends pays that debt. So:
//   - the dropped frame's sender gets the answer its receiver would have
//     given, on this link: to the client, a keepalive; to the core, for
//     traffic from or to the node, the pathBroken the client's ironwood
//     sends for traffic it cannot pass on (iw: pathfinder.go:228-236), which
//     also puts right the stale path that brought it; for anything else a
//     keepalive, which tells whoever sent it nothing about this link;
//   - the dropped frame's receiver, if it waits for an answer (the debt the
//     dropped frame paid), gets a keepalive.
//
// So one answer per dropped frame, to its sender, never elsewhere than this
// link; and a keepalive owed only while the other end waits, once for each
// of its frames that passed.
func (f *yggLinkFilter) answer(fromClient bool, frame []byte, source, dest *[yggKeySize]byte) {
	if fromClient {
		f.client.injectKeepalive()
		if f.core.waits.Load() {
			f.core.injectKeepalive()
		}
		return
	}
	if frame[0] == yggTraffic && (*source == f.rule.node || *dest == f.rule.node) {
		f.core.injectBroken(yggTrafficFrom(frame), source, dest)
	} else {
		f.core.injectKeepalive()
	}
	if f.client.waits.Load() {
		f.client.injectKeepalive()
	}
}

// yggTrafficFrom is the from path of a traffic frame the parser took, as
// it came.
func yggTrafficFrom(frame []byte) []byte {
	b, _ := yggSkipPath(frame[1:])
	rest, _ := yggSkipPath(b)
	return b[:len(b)-len(rest)]
}

// yggKeepAlive is ironwood's keepalive type; below it, the dummy. Neither
// asks for an answer (iw: peers.go:140-181).
const yggKeepAlive = 1

// yggKeepAliveFrame is ironwood's keepalive frame: the length 1, the type
// (iw: peers.go:135).
var yggKeepAliveFrame = []byte{0x01, yggKeepAlive}

// yggInjectMax bounds the injected frames waiting at one end: past it a
// pathBroken becomes a keepalive, and a keepalive waits only once.
const yggInjectMax = 16 << 10

// yggOut is one end the filter writes to, the core or the client. The copier
// writes runs of whole frames to it, answer injects frames; one lock around
// every Write keeps frames whole. Injecting never blocks the copier that
// drops: the frames wait, yggInjectMax bytes at most, for the end's own
// goroutine (run).
type yggOut struct {
	mu sync.Mutex // around every Write to w
	w  io.Writer
	// waits: this end sent a frame that asks for an answer, and has had
	// nothing since.
	waits atomic.Bool

	pmu       sync.Mutex // around pending, spare, keepalive
	pending   []byte     // injected frames, not yet written
	spare     []byte
	keepalive bool // pending holds a keepalive
	wake      chan struct{}
}

func (o *yggOut) init(w io.Writer) {
	o.w = w
	o.wake = make(chan struct{}, 1)
}

// write sends whole frames to the end.
func (o *yggOut) write(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.waits.Load() {
		o.waits.Store(false)
	}
	_, err := o.w.Write(b)
	return err
}

func (o *yggOut) injectKeepalive() {
	o.pmu.Lock()
	if !o.keepalive && len(o.pending)+len(yggKeepAliveFrame) <= yggInjectMax {
		o.pending = append(o.pending, yggKeepAliveFrame...)
		o.keepalive = true
	}
	o.pmu.Unlock()
	o.signal()
}

// injectBroken injects pathBroken as ironwood's _doBroken makes it for
// traffic (iw: pathfinder.go:228-236): the path the traffic's from, the
// watermark ^uint64(0), the traffic's source and dest; encoded as
// pathfinder.go:514-525 does, the from path as it came.
func (o *yggOut) injectBroken(from []byte, source, dest *[yggKeySize]byte) {
	size := 1 + len(from) + binary.MaxVarintLen64 + 2*yggKeySize // ^uint64(0) takes 10 bytes
	var head [binary.MaxVarintLen64]byte
	hn := binary.PutUvarint(head[:], uint64(size))
	o.pmu.Lock()
	if len(o.pending)+hn+size > yggInjectMax {
		o.pmu.Unlock()
		o.injectKeepalive()
		return
	}
	o.pending = append(o.pending, head[:hn]...)
	o.pending = append(o.pending, yggPathBroken)
	o.pending = append(o.pending, from...)
	o.pending = binary.AppendUvarint(o.pending, ^uint64(0))
	o.pending = append(o.pending, source[:]...)
	o.pending = append(o.pending, dest[:]...)
	o.pmu.Unlock()
	o.signal()
}

func (o *yggOut) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// run writes the injected frames as they come, until done or a failed
// write.
func (o *yggOut) run(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-o.wake:
		}
		if o.flush() != nil {
			return
		}
	}
}

// flush writes the injected frames that wait; one goroutine at a time.
func (o *yggOut) flush() error {
	o.pmu.Lock()
	b := o.pending
	o.pending, o.spare = o.spare[:0], b
	o.keepalive = false
	o.pmu.Unlock()
	return o.write(b)
}
