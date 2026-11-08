//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"sync/atomic"
	"testing"
)

// FuzzYggFrames: the link filter against ironwood's own reading. Data as
// one frame: the parser and ironwood's decoders agree on whether it is
// good and on its keys. Data as a link's stream, read in chunks: the filter
// sends on exactly the frames a reference built from ironwood's framing
// and decoders would, drops as many, and ends the link where it would.
func FuzzYggFrames(f *testing.F) {
	var sig [64]byte
	frames := [][]byte{
		iwTraffic([]uint64{1, 300}, []uint64{2}, keyK, keyN, ^uint64(0), []byte("payload")),
		iwTraffic(nil, nil, keyN, keyK, 0, nil),
		iwTraffic(nil, nil, keyG, keyN, 1, []byte{1}),
		iwNotify([]uint64{5}, 7, keyN, keyK, 1700000000, []uint64{1, 2, 3}, sig),
		iwNotify(nil, 1, keyK, keyA, 1, nil, sig),
		iwBroken(nil, ^uint64(0), keyK, keyN),
		iwBroken([]uint64{9}, 1, keyN, keyK),
		iwLookup(keyK, keyN, 1, 2),
		iwLookup(keyN, keyK),
		iwLookup(keyA, keyK, 3),
		{1}, {2, 1, 2}, {5},
	}
	for _, fr := range frames {
		f.Add(fr, uint16(7), true)
		f.Add(iwFrame(fr), uint16(3), false)
	}
	var stream []byte
	for _, fr := range frames {
		stream = append(stream, iwFrame(fr)...)
	}
	f.Add(stream, uint16(0), true)
	f.Add(stream, uint16(100), false)
	f.Add(append([]byte{0x81, 0x80, 0x00, 1}, bytes.Repeat([]byte{0x80}, 10)...), uint16(1), true)

	groups := func(k *[32]byte) yggGroup {
		if *k == keyK || *k == keyG {
			return 1
		}
		return 0
	}
	f.Fuzz(func(t *testing.T, data []byte, chunk uint16, fromClient bool) {
		source, dest, keyed, ok := yggFrameKeys(data)
		rs, rd, rkeyed, rok := iwRefKeys(data)
		if keyed != rkeyed || ok != rok || keyed && ok && (*source != rs || *dest != rd) {
			t.Fatalf("frame %x: keyed %v ok %v, ironwood %v %v", data, keyed, ok, rkeyed, rok)
		}

		rule := yggRule{node: keyN, key: keyK, group: groups}
		want, wantAnswers, wantDropped, wantBad := iwRefFilter(data, &rule, fromClient)
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
		_ = lf.core.flush()
		_ = lf.client.flush()
		if !bytes.Equal(out.Bytes(), want) || !bytes.Equal(other.Bytes(), wantAnswers) {
			t.Fatalf("stream %x: answers %x, want %x", data, other.Bytes(), wantAnswers)
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

// iwRefFilter is the filter as ironwood frames a stream: what it would
// send on, how many it would drop, and whether the core would end the link;
// and the answers to the dropped frames the other end would get before a
// flush (yggLinkFilter.answer): the client a keepalive, the core the
// client's pathBroken for the node's traffic and a keepalive for the rest,
// a keepalive waiting once, all within yggInjectMax.
func iwRefFilter(stream []byte, rule *yggRule, fromClient bool) (out, answers []byte, dropped uint64, bad bool) {
	keepalive := false
	answer := func(frame []byte, source, dest [32]byte) {
		if !fromClient && frame[0] == yggTraffic && (source == rule.node || dest == rule.node) {
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
		if !keepalive && len(answers)+2 <= yggInjectMax {
			answers, keepalive = append(answers, 1, 1), true
		}
	}
	br := bytes.NewReader(stream)
	for {
		at := len(stream) - br.Len()
		size, err := binary.ReadUvarint(br)
		if err != nil {
			// The end between frames or within a length; else an overflow.
			return out, answers, dropped, err != io.EOF && err != io.ErrUnexpectedEOF
		}
		if size == 0 || size > yggFrameMax {
			return out, answers, dropped, true
		}
		if uint64(br.Len()) < size {
			return out, answers, dropped, false // the end within a frame
		}
		body := len(stream) - br.Len()
		frame := stream[body : body+int(size)]
		_, _ = br.Seek(int64(size), io.SeekCurrent)
		source, dest, keyed, ok := iwRefKeys(frame)
		if !ok {
			return out, answers, dropped, true
		}
		if keyed && !rule.passes(fromClient, frame[0], &source, &dest) {
			dropped++
			answer(frame, source, dest)
			continue
		}
		out = append(out, stream[at:body+int(size)]...)
	}
}
