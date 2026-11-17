package nikoserver

import (
	"testing"
)

// rawHello is a real ClientHello as quic-go sends it, the TLS message
// whole (type, length, body), from its first flight's CRYPTO frames.
func rawHello(t testing.TB) []byte {
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

// frame is a CRYPTO frame of raw[from:to], in an array with room past it:
// a piece kept in it, not copied, shows as its capacity.
func frame(raw []byte, from, to int) cryptoFrame {
	d := make([]byte, to-from, to-from+64)
	copy(d, raw[from:to])
	return cryptoFrame{offset: uint64(from), data: d}
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
		// In order of offset a frame may sit inside one before the last
		// piece: [0,10), [5,20) leaves [10,20) last, and [7,9) is in the
		// first.
		{"a frame inside an earlier piece of the packet", []packet{{frame(raw, 0, 10), frame(raw, 5, 20), frame(raw, 7, 9), frame(raw, 20, n)}}, true},
		{"disagreeing inside an earlier piece of the packet", []packet{{frame(raw, 0, 10), frame(raw, 5, 20), func() cryptoFrame {
			f := frame(raw, 7, 9)
			f.data[0] ^= 1
			return f
		}(), frame(raw, 20, n)}}, false},
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
				if cap(f.data) != len(f.data) {
					t.Fatalf("a piece of %d bytes keeps %d", len(f.data), cap(f.data))
				}
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
			k := 1 + 2*(i*maxPacketFrames+j) // a gap after each: they do not join
			p = append(p, frame(raw, k, k+1))
		}
		_, _, err = b.add(p)
	}
	if err == nil || len(b.frames) != maxHelloFrames {
		t.Fatalf("%d frames held, err %v", len(b.frames), err)
	}
	// A packet whose frames, against what is held, make more than
	// 2*maxHelloFrames parts is refused before they are sorted: 100 pieces
	// held, and 5 frames over all of them, 101 parts each.
	var c helloAssembler
	for i := 0; i < 100; i += maxPacketFrames {
		var p []cryptoFrame
		for j := i; j < min(i+maxPacketFrames, 100); j++ {
			p = append(p, frame(raw, 2*j+1, 2*j+2))
		}
		if _, _, err := c.add(p); err != nil {
			t.Fatal(err)
		}
	}
	var over []cryptoFrame
	for range 5 {
		over = append(over, frame(raw, 0, 201))
	}
	if _, _, err := c.add(over); err == nil {
		t.Fatal("a packet of 505 parts was taken")
	}
	// Pieces that touch join: 256 frames of a byte, then 32 over them all,
	// meet one piece.
	var d helloAssembler
	for i := range 8 {
		var p []cryptoFrame
		for j := range maxPacketFrames {
			k := 1 + i*maxPacketFrames + j
			p = append(p, frame(raw, k, k+1))
		}
		if _, _, err := d.add(p); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.frames) != 1 || d.size != 8*maxPacketFrames {
		t.Fatalf("%d pieces of %d bytes for 256 that touch", len(d.frames), d.size)
	}
	var all []cryptoFrame
	for range maxPacketFrames {
		all = append(all, frame(raw, 1, 1+8*maxPacketFrames))
	}
	if _, _, err := d.add(all); err != nil || len(d.frames) != 1 {
		t.Fatalf("%d pieces, err %v", len(d.frames), err)
	}
}

// BenchmarkHelloAssemblerWorst: held pieces at every other byte, then a
// packet of 32 frames each over 4 of them (review 4: 158 us, 353
// allocations with a merge per part).
func BenchmarkHelloAssemblerWorst(b *testing.B) {
	raw := rawHello(b)
	for b.Loop() {
		var a helloAssembler
		for i := range 4 {
			var p []cryptoFrame
			for j := range maxPacketFrames {
				k := 2 * (i*maxPacketFrames + j)
				p = append(p, cryptoFrame{offset: uint64(k), data: raw[k : k+1]})
			}
			a.add(p)
		}
		var p []cryptoFrame
		for j := range maxPacketFrames {
			p = append(p, cryptoFrame{offset: uint64(8 * j), data: raw[8*j : 8*j+8]})
		}
		a.add(p)
	}
}

// BenchmarkHelloAssemblerTouching: 256 one-byte frames that touch, then a
// packet of 32 frames over all of them (review 5: 38 us a packet, the 256
// pieces apart).
func BenchmarkHelloAssemblerTouching(b *testing.B) {
	raw := rawHello(b)
	for b.Loop() {
		var a helloAssembler
		for i := range 8 {
			var p []cryptoFrame
			for j := range maxPacketFrames {
				k := i*maxPacketFrames + j
				p = append(p, cryptoFrame{offset: uint64(k), data: raw[k : k+1]})
			}
			a.add(p)
		}
		var p []cryptoFrame
		for range maxPacketFrames {
			p = append(p, cryptoFrame{offset: 0, data: raw[:8*maxPacketFrames]})
		}
		for range 8 {
			a.add(p)
		}
	}
}
