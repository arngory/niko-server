//go:build linux

package nikoserver

import (
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
// instructions each. Each label has its own key, so the program tries each
// label's in turn: some 590 instructions a label, of BPF_MAXINSNS' 4096
// (six labels).
func cidBPF(labels []labelRoute) []bpf.Instruction {
	const x, y, t = 0, 1, 2 // scratch words
	p := []bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: minCIDPacket, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xc0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
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
	for i, l := range labels {
		p = append(p,
			bpf.LoadAbsolute{Off: 1, Size: 4},
			bpf.StoreScratch{Src: bpf.RegA, N: x},
			bpf.LoadAbsolute{Off: 5, Size: 4},
			bpf.StoreScratch{Src: bpf.RegA, N: y},
		)
		for r := cidRounds - 1; r >= 0; r-- {
			// y = ror(x^y, 3)
			p = append(p, bpf.LoadScratch{Dst: bpf.RegX, N: x}, bpf.LoadScratch{Dst: bpf.RegA, N: y}, bpf.ALUOpX{Op: bpf.ALUOpXor})
			p = append(p, rotl(32-3)...)
			p = append(p, bpf.StoreScratch{Src: bpf.RegA, N: y})
			// x = rol((x^k)-y, 8)
			p = append(p, bpf.LoadScratch{Dst: bpf.RegA, N: x}, bpf.ALUOpConstant{Op: bpf.ALUOpXor, Val: l.codec.rk[r]},
				bpf.LoadScratch{Dst: bpf.RegX, N: y}, bpf.ALUOpX{Op: bpf.ALUOpSub})
			p = append(p, rotl(8)...)
			p = append(p, bpf.StoreScratch{Src: bpf.RegA, N: x})
		}
		// The label and the zero byte after it: this label's socket;
		// otherwise the next label's key.
		p = append(p,
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.label) << 16, SkipFalse: 1},
			bpf.RetConstant{Val: uint32(i + 1)},
		)
	}
	return append(p, bpf.RetConstant{Val: 0})
}

func TestCIDBPF(t *testing.T) {
	var labels []labelRoute
	for _, l := range []uint16{7, 300, MaxCIDLabel} {
		labels = append(labels, labelRoute{label: l, codec: labelCodec(cidSecret, l)})
	}
	prog := cidBPF(labels)
	var six []labelRoute
	for l := range uint16(6) {
		six = append(six, labelRoute{label: l + 1, codec: labelCodec(cidSecret, l+1)})
	}
	if n := len(cidBPF(six)); n > 4096 {
		t.Fatalf("six labels: %d instructions, over BPF_MAXINSNS", n)
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
	for i, l := range labels {
		for range 100 {
			if got := socket(shortPacket(l.codec.encode(l.label, r.Uint64()), 60)); got != i+1 {
				t.Fatalf("label %d: socket %d, want %d", l.label, got, i+1)
			}
		}
	}
	// The program and the front agree on anything else: an ID of another
	// node, a label's ID under another label's key, random bytes.
	for range 20000 {
		d := shortPacket(cidID(otherSecret, 7, r.Uint64()), 40)
		switch r.IntN(4) {
		case 0:
			binary.BigEndian.PutUint64(d[1:], r.Uint64())
		case 1:
			id := labels[0].codec.encode(300, r.Uint64()) // label 300 under label 7's key
			copy(d[1:], id[:])
		}
		want := 0
		for i, l := range labels {
			if label, ok := l.codec.label(d[1:9]); ok && label == l.label {
				want = i + 1
				break
			}
		}
		if got := socket(d); got != want {
			t.Fatalf("%x: socket %d, the front says %d", d[:9], got, want)
		}
	}
	for _, d := range [][]byte{shortPacket(labels[0].codec.encode(7, 1), minCIDPacket-1), handshakePacket(labels[0].codec.encode(7, 1), 60), {0x40}} {
		if got := socket(d); got != 0 {
			t.Fatalf("%x: socket %d", d, got)
		}
	}
	t.Logf("%d instructions for %d labels", len(prog), len(labels))
}
