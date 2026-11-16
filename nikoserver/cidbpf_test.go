//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"golang.org/x/net/bpf"
)

// cidBPF is a classic BPF program that reads the label of a short
// header's connection ID and returns the socket of the label (labels[i]
// is socket i+1), 0 for anything else: the selector of a SO_REUSEPORT
// group (raycontrol docs/spec/naive-udp-v1.md §5.2, step (г);
// SO_ATTACH_REUSEPORT_CBPF, which needs no privilege). Not used yet: it
// shows that the label serves that step too. Speck64/128 is 32-bit adds,
// xors and shifts, which classic BPF has; its 27 rounds take 21
// instructions each, the program some 600 of BPF_MAXINSNS' 4096.
func cidBPF(c *cidCodec, labels []uint16) []bpf.Instruction {
	const x, y, t = 0, 1, 2 // scratch words
	p := []bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: minCIDPacket, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xc0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.LoadAbsolute{Off: 1, Size: 4},
		bpf.StoreScratch{Src: bpf.RegA, N: x},
		bpf.LoadAbsolute{Off: 5, Size: 4},
		bpf.StoreScratch{Src: bpf.RegA, N: y},
	}
	// A = rotate(A, by) left, through t and X.
	rotl := func(by uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.StoreScratch{Src: bpf.RegA, N: t},
			bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 32 - by},
			bpf.TAX{},
			bpf.LoadScratch{Dst: bpf.RegA, N: t},
			bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: by},
			bpf.ALUOpX{Op: bpf.ALUOpOr},
		}
	}
	for i := cidRounds - 1; i >= 0; i-- {
		// y = ror(x^y, 3)
		p = append(p, bpf.LoadScratch{Dst: bpf.RegX, N: x}, bpf.LoadScratch{Dst: bpf.RegA, N: y}, bpf.ALUOpX{Op: bpf.ALUOpXor})
		p = append(p, rotl(32-3)...)
		p = append(p, bpf.StoreScratch{Src: bpf.RegA, N: y})
		// x = rol((x^k)-y, 8)
		p = append(p, bpf.LoadScratch{Dst: bpf.RegA, N: x}, bpf.ALUOpConstant{Op: bpf.ALUOpXor, Val: c.rk[i]},
			bpf.LoadScratch{Dst: bpf.RegX, N: y}, bpf.ALUOpX{Op: bpf.ALUOpSub})
		p = append(p, rotl(8)...)
		p = append(p, bpf.StoreScratch{Src: bpf.RegA, N: x})
	}
	p = append(p,
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xff00},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.LoadScratch{Dst: bpf.RegA, N: x},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 16},
	)
	for i, label := range labels {
		p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(label), SkipFalse: 1}, bpf.RetConstant{Val: uint32(i + 1)})
	}
	return append(p, bpf.RetConstant{Val: 0})
}

func TestCIDBPF(t *testing.T) {
	c := newCIDCodec(cidSecret)
	labels := []uint16{7, 300, MaxCIDLabel}
	prog := cidBPF(c, labels)
	if len(prog) > 4096 {
		t.Fatalf("%d instructions, over BPF_MAXINSNS", len(prog))
	}
	if _, err := bpf.Assemble(prog); err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	socket := func(d []byte) int {
		n, err := vm.Run(d)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	r := rand.New(rand.NewPCG(3, 4))
	for i, label := range labels {
		for range 100 {
			if got := socket(shortPacket(c.encode(label, r.Uint64()), 60)); got != i+1 {
				t.Fatalf("label %d: socket %d, want %d", label, got, i+1)
			}
		}
	}
	// The program and the front agree on anything else: none of these is
	// a label of the group's.
	other := newCIDCodec(bytes.Repeat([]byte{9}, 32))
	for range 20000 {
		d := shortPacket(other.encode(7, r.Uint64()), 40)
		if r.IntN(4) == 0 {
			binary.BigEndian.PutUint64(d[1:], r.Uint64())
		}
		want := 0
		if label, ok := c.label(d[1:9]); ok {
			for i, l := range labels {
				if l == label {
					want = i + 1
				}
			}
		}
		if got := socket(d); got != want {
			t.Fatalf("%x: socket %d, the front says %d", d[:9], got, want)
		}
	}
	for _, d := range [][]byte{shortPacket(c.encode(7, 1), minCIDPacket-1), handshakePacket(c.encode(7, 1), 60), {0x40}} {
		if got := socket(d); got != 0 {
			t.Fatalf("%x: socket %d", d, got)
		}
	}
	t.Logf("%d instructions", len(prog))
}
