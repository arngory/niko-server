package nikoserver

import (
	"testing"
)

// rawHello is a real ClientHello as quic-go sends it, the TLS message
// whole (type, length, body), from its first flight's CRYPTO frames.
func rawHello(t *testing.T) []byte {
	t.Helper()
	var a helloAssembler
	for _, d := range firstFlights(t, "n.example.com", 1)[0] {
		p, err := parseQUICInitial(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.add(p.crypto); err != nil {
			t.Fatal(err)
		}
	}
	raw := make([]byte, a.prefix())
	a.fill(raw)
	return raw
}

func frame(raw []byte, from, to int) cryptoFrame {
	return cryptoFrame{offset: uint64(from), data: append([]byte(nil), raw[from:to]...)}
}

// TestHelloAssembler: frames in any order, contained in one another,
// repeated, or empty put the ClientHello together; frames that overlap and
// disagree, too many frames, or a frame past maxQUICHello do not.
func TestHelloAssembler(t *testing.T) {
	raw := rawHello(t)
	n := len(raw)
	if n < 600 {
		t.Fatalf("a ClientHello of %d bytes", n)
	}
	type packet []cryptoFrame
	for _, c := range []struct {
		name    string
		packets []packet
		ok      bool // complete; not ok: refused with an error
	}{
		{"one frame", []packet{{frame(raw, 0, n)}}, true},
		{"two packets in order", []packet{{frame(raw, 0, 500)}, {frame(raw, 500, n)}}, true},
		{"two packets reversed", []packet{{frame(raw, 500, n)}, {frame(raw, 0, 500)}}, true},
		{"frames of a packet out of order", []packet{{frame(raw, 300, n), frame(raw, 0, 300)}}, true},
		// A frame inside an earlier one (a retransmission split anew) adds
		// nothing, and the prefix goes on past it.
		{"a frame contained in another", []packet{{frame(raw, 0, 400), frame(raw, 100, 200), frame(raw, 400, n)}}, true},
		{"a contained frame first", []packet{{frame(raw, 100, 200)}, {frame(raw, 0, 400)}, {frame(raw, 400, n)}}, true},
		{"a retransmission", []packet{{frame(raw, 0, 500)}, {frame(raw, 0, 500)}, {frame(raw, 500, n)}}, true},
		{"overlapping and agreeing", []packet{{frame(raw, 0, 600)}, {frame(raw, 400, n)}}, true},
		{"empty frames", []packet{{{offset: 7}, frame(raw, 0, n), {offset: 16383}}}, true},
		{"overlapping and disagreeing", []packet{{frame(raw, 0, 600)}, {func() cryptoFrame {
			f := frame(raw, 400, n)
			f.data[50] ^= 1
			return f
		}()}}, false},
		{"disagreeing within a packet", []packet{{frame(raw, 0, 600), func() cryptoFrame {
			f := frame(raw, 100, 200)
			f.data[0] ^= 1
			return f
		}()}}, false},
		// A disagreeing frame below a held one, and one around it.
		{"disagreeing, starting below a held frame", []packet{{frame(raw, 100, 200)}, {func() cryptoFrame {
			f := frame(raw, 50, 150)
			f.data[60] ^= 1 // offset 110, inside the held frame
			return f
		}()}}, false},
		{"disagreeing, around a held frame", []packet{{frame(raw, 100, 200)}, {func() cryptoFrame {
			f := frame(raw, 0, n)
			f.data[150] ^= 1
			return f
		}()}}, false},
		{"33 frames in a packet", []packet{func() (p packet) {
			for i := range maxPacketFrames + 1 {
				p = append(p, frame(raw, i, i+1))
			}
			return
		}()}, false},
		// Empty frames do not count against maxPacketFrames.
		{"32 frames and empty ones in a packet", []packet{func() (p packet) {
			for i := range maxPacketFrames - 1 {
				p = append(p, frame(raw, i, i+1), cryptoFrame{offset: uint64(i)})
			}
			return append(p, frame(raw, maxPacketFrames-1, n))
		}()}, true},
		{"a frame past maxQUICHello", []packet{{{offset: maxQUICHello, data: []byte{1}}}}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var a helloAssembler
			var done bool
			var err error
			var h clientHello
			for _, p := range c.packets {
				if h, done, err = a.add(p); err != nil || done {
					break
				}
			}
			if c.ok != (err == nil && done) || c.ok == (err != nil) {
				t.Fatalf("done %v, err %v", done, err)
			}
			if c.ok && h.serverName != "n.example.com" {
				t.Fatalf("name %q", h.serverName)
			}
			held := 0
			for i, f := range a.frames {
				held += len(f.data)
				if i > 0 && a.frames[i-1].offset+uint64(len(a.frames[i-1].data)) > f.offset {
					t.Fatal("pieces out of order or overlapping")
				}
			}
			if held != a.size {
				t.Fatalf("size %d, holds %d", a.size, held)
			}
		})
	}
	// The last byte a ClientHello may hold is at maxQUICHello-1.
	var a helloAssembler
	if _, _, err := a.add([]cryptoFrame{{offset: maxQUICHello - 1, data: []byte{1}}}); err != nil {
		t.Fatal(err)
	}
	// At most maxHelloFrames over the packets of one ClientHello.
	var b helloAssembler
	var err error
	for i := 0; err == nil && i < maxHelloFrames/maxPacketFrames+1; i++ {
		var p []cryptoFrame
		for j := range maxPacketFrames {
			k := 1 + i*maxPacketFrames + j
			p = append(p, frame(raw, k, k+1))
		}
		_, _, err = b.add(p)
	}
	if err == nil || len(b.frames) != maxHelloFrames {
		t.Fatalf("%d frames held, err %v", len(b.frames), err)
	}
}
