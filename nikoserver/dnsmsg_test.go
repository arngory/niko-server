//go:build linux

package nikoserver

import (
	"strings"
	"testing"
)

// queryName: the name lower case in ASCII only (RFC 4343), no final dot;
// anything but a well-formed query refused, a name that would read as
// other labels or is longer than a name may be too.
func TestQueryName(t *testing.T) {
	q := probeQuery("AbC.T.Example.COM", 16, 1232)
	name, end, ok := queryName(q)
	if !ok || name != "abc.t.example.com" || end != 12+len("AbC.T.Example.COM")+2+4 {
		t.Fatalf("%q %d %v", name, end, ok)
	}
	// Bytes over 0x7f stay as they are: no Unicode folding (the Kelvin
	// sign is no "k").
	kelvin := probeQuery("xK.t.example.com", 16, 0)
	if name, _, ok := queryName(kelvin); !ok || name != "xK.t.example.com" || zoneOf(name, []string{"xk.t.example.com"}) != "" {
		t.Fatalf("%q %v", name, ok)
	}
	long := strings.Repeat("a.", 125) + "com" // 253 characters
	if name, _, ok := queryName(probeQuery(long, 16, 0)); !ok || name != long {
		t.Fatalf("a name of 253 characters: %v", ok)
	}
	// A dot inside a label: in no zone (REFUSED), the question still ends
	// where it does.
	dotted := append(append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 5}, "t.exa"...), 3, 'c', 'o', 'm', 0, 0, 16, 0, 1)
	if name, end, ok := queryName(dotted); !ok || name != "" || end != len(dotted) || zoneOf(name, []string{"t.example.com", "exa.com"}) != "" {
		t.Fatalf("a dot in a label: %q %d %v", name, end, ok)
	}
	for what, bad := range map[string][]byte{
		"254 characters": probeQuery("b"+long, 16, 0),
		"a response":     func() []byte { r := append([]byte(nil), q...); r[2] |= 0x80; return r }(),
		"no question":    func() []byte { r := append([]byte(nil), q...); r[5] = 0; return r }(),
		"compression":    append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12}, 0, 16, 0, 1),
		"cut short":      q[:20],
		"no type":        q[:12+len("AbC.T.Example.COM")+2+2],
	} {
		if _, _, ok := queryName(bad); ok {
			t.Errorf("%s: taken", what)
		}
	}
}

func BenchmarkQueryName(b *testing.B) {
	q := probeQuery(strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 2)[:63]+"."+strings.Repeat("ABCDEFGH", 8)[:63]+".T.Example.COM", 16, 1232)
	zones := []string{"t.example.com", "s.example.net", "u.example.org"}
	b.ReportAllocs()
	for b.Loop() {
		name, _, ok := queryName(q)
		if !ok || zoneOf(name, zones) == "" {
			b.Fatal("no zone")
		}
	}
}
