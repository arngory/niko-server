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
// those between the client and the node, and (LAN, v0.16.0) those within
// the client's group; what the node relays for a group it charges to the
// group's bucket (ygglan.go), once, mostly where it goes out to a member
// (yggRule.judge). Everything else passes as it is (keepalive, the tree,
// the bloom filters): without them there is no route at all. The filter
// says nothing in any log: counters only (§4.3).
//
// Left, known and accepted (docs/SPEC.md §3.4):
//   - between two keys of a group frames keep their path and watermark,
//     along which the node relays them: a grouped client can steer one to
//     any port of the node's and tell by what comes back (a pathBroken from
//     the node, or nothing) whether a client is on it, how many there are
//     and on which ports, never whose. The occupancy v0.15.0 hid for frames
//     to the node (yggZeroWatermark); zeroing these would leave the node no
//     path to relay them on;
//   - with public peers, a frame that comes in through theirs bears the
//     source its sender wrote: in the node's name, or that of a key linked
//     here, it passes free (yggRule.judge; lan-v1 §7.4);
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
// whose frame gets nothing back in 3 s. A frame of the client's to the node
// gets the watermark 0 (yggZeroWatermark): the node takes it itself, and no
// client steers anything with its paths.
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
	source, dest, _, keyed, ok = yggFrameRead(frame)
	return source, dest, keyed, ok
}

// yggFrameRead is yggFrameKeys, and where the watermark starts (traffic,
// pathNotify, pathBroken; else 0).
func yggFrameRead(frame []byte) (source, dest *[yggKeySize]byte, wm int, keyed, ok bool) {
	if len(frame) == 0 {
		return nil, nil, 0, false, false
	}
	b := frame[1:]
	switch frame[0] {
	case yggTraffic:
		if b, ok = yggSkipPath(b); !ok { // path
			return nil, nil, 0, true, false
		}
		if b, ok = yggSkipPath(b); !ok { // from
			return nil, nil, 0, true, false
		}
		if len(b) < 2*yggKeySize {
			return nil, nil, 0, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		wm = len(frame) - len(b) + 2*yggKeySize
		if _, ok = yggSkipUint(b[2*yggKeySize:]); !ok { // watermark; the payload is the rest
			return nil, nil, 0, true, false
		}
		return source, dest, wm, true, true
	case yggPathLookup:
		if len(b) < 2*yggKeySize {
			return nil, nil, 0, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		if b, ok = yggSkipPath(b[2*yggKeySize:]); !ok || len(b) != 0 { // from, nothing after
			return nil, nil, 0, true, false
		}
		return source, dest, 0, true, true
	case yggPathNotify, yggPathBroken:
		if b, ok = yggSkipPath(b); !ok { // path
			return nil, nil, 0, true, false
		}
		wm = len(frame) - len(b)
		if b, ok = yggSkipUint(b); !ok { // watermark
			return nil, nil, 0, true, false
		}
		if len(b) < 2*yggKeySize {
			return nil, nil, 0, true, false
		}
		source, dest = (*[yggKeySize]byte)(b), (*[yggKeySize]byte)(b[yggKeySize:])
		b = b[2*yggKeySize:]
		if frame[0] == yggPathNotify {
			if b, ok = yggSkipUint(b); !ok { // info: seq
				return nil, nil, 0, true, false
			}
			if b, ok = yggSkipPath(b); !ok { // info: path
				return nil, nil, 0, true, false
			}
			if len(b) != 64 { // info: signature
				return nil, nil, 0, true, false
			}
		} else if len(b) != 0 {
			return nil, nil, 0, true, false
		}
		return source, dest, wm, true, true
	}
	return nil, nil, 0, false, true
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

// yggGroup is a key's LAN group (lan-v1 §2.2): one per name in the users
// file, the same for the life of the process (yggLAN, ygglan.go); nil is
// none (∅).
type yggGroup = *yggLAN

// yggGroups is G as one reading of the users file gives it: the keys in a
// group, each with its group. A reading is never changed: a reload makes
// another.
type yggGroups map[[yggKeySize]byte]yggGroup

// yggRule is lan-v1 §2.2 and §4.4 on one client's link: N the node's key,
// K the link's, G(x) the group of a key, as the users file has it now.
type yggRule struct {
	node, key [yggKeySize]byte
	groups    func() yggGroups
	// public: the node has public peers (R4-18). The core dials their links
	// itself, past any filter (yggdrasil.go): a frame of a client's may
	// leave through one, and one may come in through one in anyone's name.
	public bool
	// linked: the keys with a client's link here now (yggUsers), read only
	// with public peers.
	linked func() yggKeys
}

// yggKeys is a set of keys, swapped whole, never changed.
type yggKeys map[[yggKeySize]byte]bool

// yggView is G for a run of frames: one reading of the users file, and K's
// group in it. A frame is judged on one reading, so a reload between two
// lookups of it never mixes two; a reload shows at the next read of the
// link. With public peers, the keys linked here too.
type yggView struct {
	groups yggGroups
	own    yggGroup // G(K)
	linked yggKeys
}

func (r *yggRule) view() yggView {
	g := r.groups()
	v := yggView{groups: g, own: g[r.key]}
	if r.public && r.linked != nil {
		v.linked = r.linked()
	}
	return v
}

// yggVerdict is what the rule makes of a frame (judge).
type yggVerdict uint8

const (
	yggDrop   yggVerdict = iota // dropped and answered, counted in dropped_frames
	yggPass                     // passes, free
	yggCharge                   // passes if K's group's bucket holds it, charged either way (lan-v1 §4.4)
)

// judge is lan-v1 §2.2 and §4.4 for a frame of type pathLookup,
// pathNotify, pathBroken or traffic with its source and dest, in v.
//
// The rule (§2.2). From the client (K to the core): the source is K, the
// dest N. To the client (the core to K): the source is N, the dest K.
// Either end may instead be a key of K's group, when K has one. pathBroken
// carries the source and dest of the traffic it reports on, but goes back
// to that source (iw: pathfinder.go:228-236): for it the two trade places.
// Lookups: lookup.
//
// The charge (§4.4). Only K to N and N to K are free. What the node relays
// for K's group is charged to the group's bucket once, by the frame's
// length (type and body), and dropped over the rate (at 0, all of it). A
// frame reaches a member through that member's link, whichever link it came
// in by, a client's or a public peer's: it is charged there, on its way out
// to the client:
//   - a frame from a key of K's group, the node relaying it;
//   - the node's own frame for another than K, through K: for a device
//     behind K (niko-ygg-via, lan-v1 §2.3), or a member's data. The node
//     answers a lookup along its from (iw: pathfinder.go:66-70) and sends
//     its traffic along the path a pathNotify gave it (pathfinder.go:198-210):
//     both paths are the member's to make, data and all, and lead where it
//     likes, to its neighbour's link (review of v0.16.0).
//
// From the client, what nothing charges on its way out is charged as it
// comes in:
//   - a frame for the node in a neighbour's name (a device behind K; one
//     user's devices share their keys): the node answers that neighbour,
//     its own frame to it, free on its link. An echo of the bytes, a
//     pathNotify along the lookup's from, traffic along the notified path;
//   - with public peers, a frame for a neighbour: it may leave through a
//     public peer's link. Then a frame on its way out to K from a key
//     linked here was charged where it came in, and is not again (a lookup
//     is: the node sends a copy to each peer whose bloom claims its dest).
//
// With public peers the source of a frame that comes in through theirs is
// what its sender wrote: one in the node's name, or in that of a key linked
// here, passes as that key's (their links need a hook of their own, lan-v1
// §7.4). Without them every link is a client's.
func (r *yggRule) judge(v yggView, fromClient bool, typ byte, source, dest *[yggKeySize]byte) yggVerdict {
	if typ == yggPathLookup {
		return r.lookup(v, fromClient, source, dest)
	}
	if typ == yggPathBroken {
		source, dest = dest, source
	}
	if fromClient {
		switch {
		case *source == r.key && *dest == r.node:
			return yggPass
		case !r.is(v, source, &r.key) || !r.is(v, dest, &r.node):
			return yggDrop
		case *dest == r.node || r.public: // a neighbour's for N; for a neighbour, maybe past every client
			return yggCharge
		}
		return yggPass // for a neighbour: charged where it goes out to it
	}
	switch {
	case *source == r.node && *dest == r.key:
		return yggPass
	case !r.is(v, source, &r.node) || !r.is(v, dest, &r.key):
		return yggDrop
	case *source != r.node && v.linked[*source]: // public peers: charged where it came in
		return yggPass
	}
	return yggCharge // relayed, or N's own through K
}

// lookup is judge for pathLookup, held to the rule by its source (lan-v1
// §2.2): a lookup goes to every peer whose bloom filter claims its dest (iw:
// bloomfilter.go:301-329), and the node passes one on even when it answers
// it itself (pathfinder.go:56-60).
//   - From K: K's own or its group's, for anyone. Charged: a neighbour's
//     for the node, which the node answers to that neighbour (judge); with
//     public peers, one not for the node, which may go out through theirs.
//   - To K, the node's: free, for what K would answer or a key of its group.
//     Its from is the node's own path.
//   - To K, its group's: dropped if for the node (by key or by address):
//     the node has it, and passes it on only to a client whose bloom claims
//     the node, its from as its sender made it. For anyone else (one behind
//     K, in its Wi-Fi, may be the one looked for): charged, each copy where
//     it goes out.
//   - Else dropped. A client that claims every key in its bloom would get
//     every other client's lookup for the node, and the node's own for each
//     of them, keys and all.
func (r *yggRule) lookup(v yggView, fromClient bool, source, dest *[yggKeySize]byte) yggVerdict {
	forNode := yggAnswers(dest, &r.node)
	if fromClient {
		switch {
		case !r.is(v, source, &r.key):
			return yggDrop
		case forNode && *source != r.key:
			return yggCharge
		case !forNode && r.public && v.own != nil:
			return yggCharge
		}
		return yggPass
	}
	switch {
	case *source == r.node && (r.is(v, dest, &r.key) || r.answers(dest)):
		return yggPass
	case *source == r.node || !v.in(source) || forNode:
		return yggDrop
	}
	return yggCharge
}

// answers: K would answer a lookup for dest, as ironwood decides it
// (iw: pathfinder.go:62-64), dest being a whole key or one from an address.
// Only for the node's lookups and not for K's very key: never on the way
// of traffic.
func (r *yggRule) answers(dest *[yggKeySize]byte) bool { return yggAnswers(dest, &r.key) }

// yggAnswers: the owner of key answers a lookup for dest: the two are one
// under the core's bloom transform (ygg: src/core/core.go:96-98).
func yggAnswers(dest, key *[yggKeySize]byte) bool {
	return bytes.Equal(address.SubnetForKey(dest[:]).GetKey(), address.SubnetForKey(key[:]).GetKey())
}

// is: x is want, or G(x) = G(K) ≠ ∅.
func (r *yggRule) is(v yggView, x, want *[yggKeySize]byte) bool { return *x == *want || v.in(x) }

// in: G(x) = G(K) ≠ ∅.
func (v yggView) in(x *[yggKeySize]byte) bool { return v.own != nil && v.groups[*x] == v.own }

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
// written). For each frame it drops it injects the answers (answer). A
// frame the rule charges (judge) is charged to K's group's bucket here,
// once, and dropped over the group's rate: mostly frames on their way to
// the client.
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
		view := f.rule.view() // the groups as the users file has them now
		start, need := r, 0   // buf[start:r]: frames to send; need: what the next one takes from r
		asks := false         // a frame in buf[start:r] asks for an answer
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
			source, dest, wm, keyed, ok := yggFrameRead(frame)
			if !ok {
				bad = true
				break
			}
			drop := false
			if keyed {
				switch f.rule.judge(view, fromClient, frame[0], source, dest) {
				case yggDrop:
					drop = true
					f.dropped.Add(1)
				case yggCharge: // only ever with K in a group
					drop = !view.own.pass(len(frame)) // the group counts it either way
				}
			}
			if drop {
				if err := yggSend(dst, sender, buf[start:r], asks); err != nil {
					return err
				}
				start, asks = end, false
				f.answer(fromClient, frame, source, dest)
			} else {
				if keyed && fromClient {
					yggZeroWatermark(frame, wm, &f.rule.node, source, dest)
				}
				if frame[0] > yggKeepAlive {
					asks = true
				}
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
// sender now waits for one. Marked before the write, so that an answer
// that overtakes it can only clear it (a keepalive too many at worst).
func yggSend(dst, sender *yggOut, b []byte, asks bool) error {
	if asks && !sender.waits.Load() {
		sender.waits.Store(true)
	}
	return dst.write(b)
}

// yggZeroWatermark: a frame of the client's on its way to the node itself
// (traffic or pathNotify to N, pathBroken back to N) gets the watermark 0
// (at wm, from yggFrameRead), in place, in as many bytes as it came in (n-1 bytes 0x80, then 0x00:
// binary.Uvarint reads 0). The node's _lookup then finds no next hop, as
// the watermark is never above a distance (iw: router.go:701-711), and the
// node takes the frame itself (router.go:603-616, pathfinder.go:95-103,
// 238-247), as one with a true path: the watermark is not signed and not
// read again. A client so steers nothing with its paths: neither traffic
// to another client's port (and a drop, an answer, a port's occupancy
// told) nor the answer along a from of its choosing.
func yggZeroWatermark(frame []byte, wm int, node, source, dest *[yggKeySize]byte) {
	switch {
	case frame[0] == yggTraffic && *dest == *node:
	case frame[0] == yggPathNotify && *dest == *node:
	case frame[0] == yggPathBroken && *source == *node: // back to its source
	default:
		return
	}
	_, n := binary.Uvarint(frame[wm:])
	for i := wm; i < wm+n-1; i++ {
		frame[i] = 0x80
	}
	frame[wm+n-1] = 0
}

// answer stands in for a frame the filter dropped, as far as ironwood's
// peers keep each other alive (iw: peers.go:127-181). A peer that sends any
// frame but a keepalive (or a dummy) ends the link unless some frame comes
// back within peerTimeout, 3 s; a peer that gets one owes a keepalive within
// a second, and any frame it sends pays that debt. So, on this link only:
//   - a frame of the client's: the client gets a keepalive, the answer the
//     core would have given; the core, if it waits for an answer (the debt
//     the dropped frame paid), a keepalive;
//   - traffic from or to the node, to the client: the core gets the
//     pathBroken the client's ironwood sends for traffic it cannot pass on
//     (iw: pathfinder.go:228-236), which also puts right the node's stale
//     path that brought it (clients steer none, yggZeroWatermark); the
//     client, if it waits, a keepalive;
//   - anything else to the client: the client gets a ping (yggPing), which
//     its own ironwood answers with a keepalive to the core. Nothing is
//     said to the core for the client: a link whose client is gone without
//     a word (TCP dead, no reset) gets no answer, and the core ends it in
//     3 s, whoever looks the client up meanwhile.
//
// One answer per dropped frame, pings and keepalives waiting once.
func (f *yggLinkFilter) answer(fromClient bool, frame []byte, source, dest *[yggKeySize]byte) {
	if fromClient {
		f.client.injectKeepalive()
		if f.core.waits.Load() {
			f.core.injectKeepalive()
		}
		return
	}
	if frame[0] == yggTraffic && (*source == f.rule.node || *dest == f.rule.node) &&
		f.core.injectBroken(yggTrafficFrom(frame), source, dest) {
		if f.client.waits.Load() {
			f.client.injectKeepalive()
		}
		return
	}
	f.client.injectPing(&f.rule.node, &f.rule.key)
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
	ping      bool // pending holds a ping
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
// pathfinder.go:514-525 does, the from path as it came. False: it does not
// fit with what waits.
func (o *yggOut) injectBroken(from []byte, source, dest *[yggKeySize]byte) bool {
	size := 1 + len(from) + binary.MaxVarintLen64 + 2*yggKeySize // ^uint64(0) takes 10 bytes
	var head [binary.MaxVarintLen64]byte
	hn := binary.PutUvarint(head[:], uint64(size))
	o.pmu.Lock()
	if len(o.pending)+hn+size > yggInjectMax {
		o.pmu.Unlock()
		return false
	}
	o.pending = append(o.pending, head[:hn]...)
	o.pending = append(o.pending, yggPathBroken)
	o.pending = append(o.pending, from...)
	o.pending = binary.AppendUvarint(o.pending, ^uint64(0))
	o.pending = append(o.pending, source[:]...)
	o.pending = append(o.pending, dest[:]...)
	o.pmu.Unlock()
	o.signal()
	return true
}

// yggPingSize is a ping's frame: the length, then pathBroken with an empty
// path, the watermark 0, the source N and the dest K.
const yggPingSize = 1 + 1 + 1 + 1 + 2*yggKeySize

// injectPing injects, to the client, a pathBroken from the node to it with
// an empty path and the watermark 0: its ironwood passes it nowhere (no
// distance is under 0) and drops it (the source is not its own key, iw:
// pathfinder.go:238-247), but owes the core a keepalive for it, in a
// second. 68 bytes; one waits at a time.
func (o *yggOut) injectPing(node, key *[yggKeySize]byte) {
	o.pmu.Lock()
	if !o.ping && len(o.pending)+yggPingSize <= yggInjectMax {
		o.pending = append(o.pending, yggPingSize-1, yggPathBroken, 0, 0)
		o.pending = append(o.pending, node[:]...)
		o.pending = append(o.pending, key[:]...)
		o.ping = true
	}
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
	o.keepalive, o.ping = false, false
	o.pmu.Unlock()
	return o.write(b)
}
