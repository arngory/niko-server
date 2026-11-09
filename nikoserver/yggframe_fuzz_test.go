//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// FuzzYggFrames: the link filter against ironwood's own reading and the
// spec's rule. Data as one frame: the parser and ironwood's decoders agree
// on whether it is good and on its keys. Data as a link's stream, read in
// chunks: the filter sends on exactly the frames a reference built from
// ironwood's framing and decoders and the spec (lanSpec) would, drops as
// many, charges as many, and ends the link where it would. world picks
// the groups: K, G and H in u1 (or, bit 2, G, H and A in u1, K in none; or,
// bit 3, A in u2), and the node's public peers (bit 0) with G (bit 1) and H
// (bit 4) linked here or not. The relay is unbounded, or (relayOff) 0:
// then what it charges is dropped too. Each key of a keyed frame, under the
// core's bloom transform: yggXKey as yggdrasil-go's own.
func FuzzYggFrames(f *testing.F) {
	var sig [64]byte
	addrN := [32]byte(address.AddrForKey(keyN[:]).GetKey())
	frames := [][]byte{
		iwTraffic([]uint64{1, 300}, []uint64{2}, keyK, keyN, ^uint64(0), []byte("payload")),
		iwTraffic(nil, nil, keyN, keyK, 0, nil),
		iwTraffic(nil, nil, keyN, keyG, 0, []byte("through K")),
		iwTraffic(nil, nil, keyG, keyN, 1, []byte{1}),
		iwTraffic(nil, nil, keyG, keyK, 1, []byte{1}),
		iwTraffic(nil, []uint64{4}, keyK, keyG, 1, []byte("to a neighbour")),
		iwNotify([]uint64{5}, 7, keyN, keyK, 1700000000, []uint64{1, 2, 3}, sig),
		iwNotify([]uint64{5}, 7, keyN, keyG, 1700000000, []uint64{1, 2, 3}, sig),
		iwNotify(nil, 1, keyK, keyA, 1, nil, sig),
		iwNotify(nil, 1, keyK, keyG, 1, nil, sig),
		iwNotify(nil, 1, keyG, keyN, 1, []uint64{7}, sig),
		iwBroken(nil, ^uint64(0), keyK, keyN),
		iwBroken([]uint64{9}, 1, keyN, keyK),
		iwBroken(nil, 1, keyG, keyK),
		iwBroken(nil, 1, keyG, keyN),
		iwBroken(nil, 1, keyN, keyG),
		iwLookup(keyK, keyN, 1, 2),
		iwLookup(keyK, addrN),
		iwLookup(keyG, keyN, 1),
		iwLookup(keyG, addrN, 1),
		iwLookup(keyK, [32]byte(address.AddrForKey(keyG[:]).GetKey()), 1),
		iwLookup(keyN, keyK),
		iwLookup(keyN, keyG),
		iwLookup(keyA, keyK, 3),
		iwLookup(keyG, keyA, 3),
		iwTraffic(nil, nil, keyH, keyK, 1, []byte{2}),
		iwTraffic(nil, []uint64{6}, keyG, keyH, 1, []byte("between two others of K's")),
		iwTraffic(nil, nil, keyH, keyN, 0, nil),
		iwNotify(nil, 1, keyK, keyH, 1, []uint64{2}, sig),
		iwNotify(nil, 1, keyH, keyK, 1, []uint64{2}, sig),
		iwBroken(nil, 1, keyH, keyG),
		iwBroken(nil, 1, keyK, keyH),
		iwLookup(keyH, keyN, 2),
		iwLookup(keyH, keyG),
		iwLookup(keyK, keyN, lanPorts(0, lanCoordsMax+1)...),
		iwLookup(keyG, keyA, lanPorts(0, lanCoordsMax)...),
		iwLookup(keyN, keyK, lanPorts(0, lanCoordsMax+1)...),
		iwNotify(nil, 1, keyK, keyN, 1, lanPorts(0, lanCoordsMax+1), sig),
		iwNotify(lanPorts(0, lanCoordsMax+1), 1, keyN, keyK, 1, nil, sig),
		iwNotify(lanPorts(0, lanCoordsMax), 1, keyH, keyK, 1, lanPorts(0, lanCoordsMax), sig),
		{1}, {2, 1, 2}, {5},
	}
	for i, fr := range frames {
		w := uint8(i % 32)
		f.Add(fr, uint16(7), true, false, w)
		f.Add(iwFrame(fr), uint16(3), false, false, w)
		f.Add(iwFrame(fr), uint16(5), true, true, w^1)
		f.Add(iwFrame(fr), uint16(5), false, true, w^3)
	}
	var stream []byte
	for _, fr := range frames {
		stream = append(stream, iwFrame(fr)...)
	}
	for w := range uint8(32) {
		f.Add(stream, uint16(w*7), w&1 == 0, w&2 == 0, w)
	}
	f.Add(append([]byte{0x81, 0x80, 0x00, 1}, bytes.Repeat([]byte{0x80}, 10)...), uint16(1), true, false, uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, chunk uint16, fromClient, relayOff bool, world uint8) {
		source, dest, keyed, ok := yggFrameKeys(data)
		rs, rd, rkeyed, rok := iwRefKeys(data)
		if keyed != rkeyed || ok != rok || keyed && ok && (*source != rs || *dest != rd) {
			t.Fatalf("frame %x: keyed %v ok %v, ironwood %v %v", data, keyed, ok, rkeyed, rok)
		}
		for _, k := range [][32]byte{rs, rd} {
			if keyed && ok && yggXKey(&k) != [32]byte(address.SubnetForKey(k[:]).GetKey()) {
				t.Fatalf("key %x: the transform %x, yggdrasil-go's %x", k, yggXKey(&k), address.SubnetForKey(k[:]).GetKey())
			}
		}

		relay := newYggRelay(1 << 30)
		if relayOff {
			relay = newYggRelay(0)
		}
		g := relay.group("u1")
		groups := yggGroups{keyK: g, keyG: g, keyH: g}
		spec := lanSpec{node: keyN, key: keyK, group: map[[32]byte]string{keyK: "u1", keyG: "u1", keyH: "u1"}, public: world&1 != 0}
		switch {
		case world&4 != 0:
			groups = yggGroups{keyG: g, keyH: g, keyA: g}
			spec.group = map[[32]byte]string{keyG: "u1", keyH: "u1", keyA: "u1"}
		case world&8 != 0:
			groups[keyA] = relay.group("u2")
			spec.group[keyA] = "u2"
		}
		linked := yggKeys{keyK: true, keyG: world&2 != 0, keyH: world&16 != 0}
		if spec.public {
			spec.linked = map[[32]byte]bool{keyK: true, keyG: world&2 != 0, keyH: world&16 != 0}
		}
		rule := yggRule{node: keyN, key: keyK, groups: func() yggGroups { return groups }, public: spec.public,
			linked: func() yggKeys { return linked }}
		want, wantPings, wantAnswers, wantDropped, wantRelayed, wantBad := iwRefFilter(data, spec, fromClient, relayOff)
		var dropped atomic.Uint64
		out, other := &sink{}, &sink{} // where the copy writes; the other end, which gets the answers
		var lf *yggLinkFilter
		var dst *yggOut
		if fromClient {
			lf = newYggLinkFilter(rule, &dropped, out, other)
			dst = &lf.core
		} else {
			lf = newYggLinkFilter(rule, &dropped, other, out)
			dst = &lf.client
		}
		err := lf.copy(dst, &chunks{b: data, n: int(chunk) + 1}, fromClient)
		if !bytes.Equal(out.Bytes(), want) || dropped.Load() != wantDropped || (err == errYggFrame) != wantBad {
			t.Fatalf("stream %x in reads of %d: sent %x dropped %d (%v), want %x %d bad %v",
				data, int(chunk)+1, out.Bytes(), dropped.Load(), err, want, wantDropped, wantBad)
		}
		// Each frame the relay charged: dropped at 0, else passed and
		// counted, its bytes K's group's (none but u1 is ever charged).
		relayed := relay.frames.Load() + relay.dropped.Load()
		if relayed != wantRelayed || relayOff && relay.frames.Load() != 0 || !relayOff && relay.dropped.Load() != 0 ||
			uint64(g.up.Load()) != relay.bytes.Load() || world&4 != 0 && relayed != 0 {
			t.Fatalf("stream %x: relayed %d, dropped over the rate %d, %d bytes (group %d); want %d",
				data, relay.frames.Load(), relay.dropped.Load(), relay.bytes.Load(), g.up.Load(), wantRelayed)
		}
		_ = lf.core.flush()
		_ = lf.client.flush()
		if !bytes.Equal(out.Bytes(), slices.Concat(want, wantPings)) || !bytes.Equal(other.Bytes(), wantAnswers) {
			t.Fatalf("stream %x: answers %x and %x, want %x and %x", data, out.Bytes()[len(want):], other.Bytes(), wantPings, wantAnswers)
		}
	})
}

// The reference: ironwood 0712ecc's own decoding, ported as it is,
// allocations and all (network/wire.go:20-46, 88-113; traffic.go:51-69;
// pathfinder.go:322-336, 407-421, 465-481, 527-543), and its framing
// (peers.go:247-269, 275).

func iwChopSlice(out []byte, data *[]byte) bool {
	if len(*data) < len(out) {
		return false
	}
	copy(out, *data)
	*data = (*data)[len(out):]
	return true
}

func iwChopUint(out *uint64, data *[]byte) bool {
	var u uint64
	var l int
	if u, l = binary.Uvarint(*data); l <= 0 {
		return false
	}
	*out, *data = u, (*data)[l:]
	return true
}

func iwDecodePath(path []uint64, source []byte) ([]uint64, int) {
	bs := source
	for {
		var u uint64
		if !iwChopUint(&u, &bs) {
			return nil, -1
		}
		if u == 0 {
			break
		}
		path = append(path, u)
	}
	return path, len(source) - len(bs)
}

func iwChopPath(out *[]uint64, data *[]byte) bool {
	var _path [128]uint64
	path, length := iwDecodePath(_path[:0], *data)
	if length < 0 {
		return false
	}
	*out = append(*out, path...)
	*data = (*data)[length:]
	return true
}

// iwRefKeys decodes a frame as ironwood's _handlePacket would: keyed for
// pathLookup, traffic, pathNotify and pathBroken, ok when the decoder
// takes it.
func iwRefKeys(frame []byte) (source, dest [32]byte, keyed, ok bool) {
	if len(frame) == 0 {
		return source, dest, false, false // ErrEmptyMessage
	}
	data := frame[1:]
	var path, from []uint64
	var watermark uint64
	switch frame[0] {
	case 9: // traffic.decode
		ok = iwChopPath(&path, &data) && iwChopPath(&from, &data) &&
			iwChopSlice(source[:], &data) && iwChopSlice(dest[:], &data) && iwChopUint(&watermark, &data)
	case 7: // pathNotify.decode, then pathNotifyInfo.decode on the rest
		ok = iwChopPath(&path, &data) && iwChopUint(&watermark, &data) &&
			iwChopSlice(source[:], &data) && iwChopSlice(dest[:], &data)
		if ok {
			var seq uint64
			var coords []uint64
			var sig [64]byte
			ok = iwChopUint(&seq, &data) && iwChopPath(&coords, &data) && iwChopSlice(sig[:], &data) && len(data) == 0
		}
	case 6: // pathLookup.decode
		ok = iwChopSlice(source[:], &data) && iwChopSlice(dest[:], &data) && iwChopPath(&from, &data) && len(data) == 0
	case 8: // pathBroken.decode
		ok = iwChopPath(&path, &data) && iwChopUint(&watermark, &data) &&
			iwChopSlice(source[:], &data) && iwChopSlice(dest[:], &data) && len(data) == 0
	default:
		return source, dest, false, true
	}
	if !ok {
		return [32]byte{}, [32]byte{}, true, false
	}
	return source, dest, true, true
}

// lanSpec is lan-v1 §2.2 and §4.4 on K's link, and the charge as v0.16.0
// places it, written from the spec and apart from the filter
// (yggRule.judge): the reference of FuzzYggFrames, of TestNekoServerYggRule
// and of the accounting the ironwood tests check.
type lanSpec struct {
	node, key [32]byte
	group     map[[32]byte]string // a key's group; absent or "": none
	public    bool                // the node has public peers (R4-18)
	linked    map[[32]byte]bool   // with public peers: the keys with a client's link here
}

// mate: G(x) = G(K) ≠ ∅.
func (s lanSpec) mate(x [32]byte) bool { return s.group[s.key] != "" && s.group[x] == s.group[s.key] }

// lanOwns: the owner of key answers a lookup for x, the two one under the
// core's bloom transform (iw: pathfinder.go:62-64; ygg: src/core/core.go:96-98).
func lanOwns(key, x [32]byte) bool {
	return bytes.Equal(address.SubnetForKey(key[:]).GetKey(), address.SubnetForKey(x[:]).GetKey())
}

// verdict is what becomes of a frame of type typ with source and dest, from
// the client K (up) or to it. Its ends as the spec has them: where it comes
// from, where it goes (pathBroken goes back to its traffic's source); a
// lookup goes to whoever answers for the key it looks for.
func (s lanSpec) verdict(up bool, typ byte, source, dest [32]byte) yggVerdict {
	from, to := source, dest
	if typ == yggPathBroken {
		from, to = dest, source
	}
	lookup := typ == yggPathLookup
	forNode := to == s.node || lookup && lanOwns(s.node, to)
	// §2.2: who may stand at each end. A lookup by its source; to K, the
	// node's only for what K or its group answers, its group's not for the
	// node.
	var ok bool
	switch {
	case up:
		ok = (from == s.key || s.mate(from)) && (lookup || forNode || s.mate(to))
	case lookup && from == s.node:
		ok = to == s.key || lanOwns(s.key, to) || s.mate(to)
	case lookup:
		ok = s.mate(from) && !forNode
	default:
		ok = (from == s.node || s.mate(from)) && (to == s.key || s.mate(to))
	}
	if !ok {
		return yggDrop
	}
	// §4.4: free is only what K and the node send each other; the rest is
	// relayed for K's group and charged once, where it goes out to a client,
	// or where nothing would: as it comes in from K, a frame for the node
	// in a neighbour's name (the node answers that neighbour) and, with
	// public peers, one for a neighbour (it may leave through them).
	switch {
	case up && from == s.key && forNode, !up && from == s.node && (to == s.key || lookup):
		return yggPass
	case up && !forNode && !(s.public && s.group[s.key] != ""):
		return yggPass // charged where it goes out
	case !up && from != s.node && s.public && s.linked[from]:
		return yggPass // charged where it came in from its link
	}
	return yggCharge
}

// lanCoordsMax is the most ports of a tree's coordinates a frame may carry
// on a client's link: a lookup's from, a pathNotify's path and info path.
const lanCoordsMax = 64

// iwRefCoordsFit: a frame's coordinates, as ironwood decodes them, each of
// lanCoordsMax ports or fewer.
func iwRefCoordsFit(frame []byte) bool {
	data := frame[1:]
	var path, coords []uint64
	var watermark, seq uint64
	switch frame[0] {
	case 6:
		data = data[64:]
		iwChopPath(&coords, &data)
	case 7:
		iwChopPath(&path, &data)
		iwChopUint(&watermark, &data)
		data = data[64:]
		iwChopUint(&seq, &data)
		iwChopPath(&coords, &data)
	}
	return len(path) <= lanCoordsMax && len(coords) <= lanCoordsMax
}

// iwRefFilter is the filter as ironwood frames a stream and the spec rules
// on it: what it would send on (a frame of the client's to the node with
// its watermark 0, in as many bytes), how many it would drop (by the spec,
// or for coordinates over lanCoordsMax ports), and whether
// the core would end the link; and, before a flush, the answers to the
// dropped frames (yggLinkFilter.answer): pings, to the copy's own end (the
// client), and the answers to the other end, the client's keepalive or the
// core's pathBrokens for the node's traffic. A keepalive and a ping wait
// once, all within yggInjectMax. relayed counts the frames charged to K's
// group; relayOff drops them, as an answered drop.
func iwRefFilter(stream []byte, spec lanSpec, fromClient, relayOff bool) (out, pings, answers []byte, dropped, relayed uint64, bad bool) {
	rule := struct{ node, key [32]byte }{spec.node, spec.key}
	keepalive := false
	ping := iwFrame(iwBroken(nil, 0, rule.node, rule.key))
	answer := func(frame []byte, source, dest [32]byte) {
		if fromClient {
			if !keepalive && len(answers)+2 <= yggInjectMax {
				answers, keepalive = append(answers, 1, 1), true
			}
			return
		}
		if frame[0] == yggTraffic && (source == rule.node || dest == rule.node) {
			data := frame[1:]
			var path []uint64
			iwChopPath(&path, &data)
			at := data
			var from []uint64
			iwChopPath(&from, &data)
			b := slices.Concat([]byte{yggPathBroken}, at[:len(at)-len(data)], binary.AppendUvarint(nil, ^uint64(0)), source[:], dest[:])
			if b = iwFrame(b); len(answers)+len(b) <= yggInjectMax {
				answers = append(answers, b...)
				return
			}
		}
		if len(pings) == 0 {
			pings = ping
		}
	}
	// zero sets the watermark of a frame of the client's to the node to 0.
	zero := func(frame []byte, source, dest [32]byte) {
		data := frame[1:]
		var path []uint64
		switch {
		case frame[0] == yggTraffic && dest == rule.node:
			iwChopPath(&path, &data)
			iwChopPath(&path, &data)
			data = data[64:]
		case frame[0] == yggPathNotify && dest == rule.node, frame[0] == yggPathBroken && source == rule.node:
			iwChopPath(&path, &data)
		default:
			return
		}
		var w uint64
		rest := data
		iwChopUint(&w, &rest)
		n := len(data) - len(rest)
		copy(data, append(bytes.Repeat([]byte{0x80}, n-1), 0))
	}
	br := bytes.NewReader(stream)
	for {
		at := len(stream) - br.Len()
		size, err := binary.ReadUvarint(br)
		if err != nil {
			// The end between frames or within a length; else an overflow.
			return out, pings, answers, dropped, relayed, err != io.EOF && err != io.ErrUnexpectedEOF
		}
		if size == 0 || size > yggFrameMax {
			return out, pings, answers, dropped, relayed, true
		}
		if uint64(br.Len()) < size {
			return out, pings, answers, dropped, relayed, false // the end within a frame
		}
		body := len(stream) - br.Len()
		frame := stream[body : body+int(size)]
		_, _ = br.Seek(int64(size), io.SeekCurrent)
		source, dest, keyed, ok := iwRefKeys(frame)
		if !ok {
			return out, pings, answers, dropped, relayed, true
		}
		verdict := yggPass
		if keyed {
			verdict = spec.verdict(fromClient, frame[0], source, dest)
		}
		if keyed && !iwRefCoordsFit(frame) {
			verdict = yggDrop
		}
		if verdict == yggDrop {
			dropped++
			answer(frame, source, dest)
			continue
		}
		if verdict == yggCharge {
			relayed++
			if relayOff {
				answer(frame, source, dest)
				continue
			}
		}
		start := len(out)
		out = append(out, stream[at:body+int(size)]...)
		if keyed && fromClient {
			zero(out[start+body-at:], source, dest)
		}
	}
}
