//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2b"
)

// packetBackend is a backend's end of mode packet, as RunBackend opens it.
func packetBackend(t *testing.T, path string) *packetConn {
	t.Helper()
	ln, err := listenPacketSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	c := newPacketConn(ln, os.Getuid(), NewLogger("warn", io.Discard))
	go c.acceptLoop()
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNekoServerUDPFront(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	uid := os.Getuid()
	masq := packetBackend(t, filepath.Join(dir, "masq.sock"))
	obfs := packetBackend(t, filepath.Join(dir, "obfs.sock"))
	password := "c2FsYW1hbmRlci1wYXNzd29yZA"
	pwFile := filepath.Join(dir, "salamander")
	os.WriteFile(pwFile, []byte(password+"\n"), 0o600)

	c := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{
		{SNI: []string{"h.example.com"}, Backend: "hy2-masq"},
		{SalamanderPasswordFile: pwFile, Backend: "hy2-obfs"},
	}}
	backends := map[string]BackendRef{
		"hy2-masq": {Socket: filepath.Join(dir, "masq.sock"), Mode: "packet", UID: uid},
		"hy2-obfs": {Socket: filepath.Join(dir, "obfs.sock"), Mode: "packet", UID: uid},
	}
	var e configErrors
	c.validate(&e, backends)
	if len(e) > 0 {
		t.Fatal(e)
	}
	front, err := newUDPFront(c, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if err := front.listen(c.Listen); err != nil {
		t.Fatal(err)
	}
	var addr *net.UDPAddr
	for a := range front.sockets {
		addr = net.UDPAddrFromAddrPort(front.sockets[a].LocalAddr().(*net.UDPAddr).AddrPort())
	}
	go front.run(ctx)
	for _, l := range front.links {
		for i := 0; ; i++ {
			l.access.Lock()
			up := l.conn != nil
			l.access.Unlock()
			if up {
				break
			}
			if i == 100 {
				t.Fatalf("backend %s never connected", l.name)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	receive := func(b *packetConn, within time.Duration) ([]byte, net.Addr, bool) {
		b.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 2048)
		n, from, err := b.ReadFrom(buf)
		if err != nil {
			return nil, nil, false
		}
		return buf[:n], from, true
	}
	client := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	// Fakes first: garbage and an Initial for another name; then the real
	// one. Only the real one pins the flow, and everything after it follows.
	c1 := client()
	c1.Write([]byte("not quic at all"))
	for _, d := range initials(t, "other.example.com", quic.Version1) {
		c1.Write(d)
	}
	real := initials(t, "h.example.com", quic.Version1)
	for _, d := range real {
		c1.Write(d)
	}
	if got, from, ok := receive(masq, 2*time.Second); !ok || string(got) != string(real[0]) || from.String() != c1.LocalAddr().String() {
		t.Fatalf("hy2-masq got %d bytes from %v (%v)", len(got), from, ok)
	}
	for i := 1; i < 100; i++ {
		if _, _, ok := receive(masq, 50*time.Millisecond); !ok {
			break
		}
	}
	c1.Write([]byte("short header packet"))
	if got, _, ok := receive(masq, 2*time.Second); !ok || string(got) != "short header packet" {
		t.Fatalf("a pinned flow lost a packet: %q", got)
	}
	// The backend answers through the front, from the port the client used.
	masq.WriteTo([]byte("answer"), c1.LocalAddr())
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := c1.Read(buf); err != nil || string(buf[:n]) != "answer" {
		t.Fatalf("answer: %q %v", buf[:n], err)
	}
	if _, _, ok := receive(obfs, 100*time.Millisecond); ok {
		t.Fatal("hy2-obfs got another flow's packets")
	}

	// Salamander: the packet goes to hy2-obfs as it came, still obfuscated.
	c2 := client()
	salt := make([]byte, 8)
	rand.Read(salt)
	key := blake2b.Sum256(append([]byte(password), salt...))
	obfuscated := append([]byte(nil), salt...)
	for i, b := range real[0] {
		obfuscated = append(obfuscated, b^key[i%32])
	}
	c2.Write(obfuscated)
	if got, _, ok := receive(obfs, 2*time.Second); !ok || string(got) != string(obfuscated) {
		t.Fatalf("hy2-obfs got %d bytes (%v)", len(got), ok)
	}

	// Garbage alone goes nowhere.
	c3 := client()
	junk := make([]byte, 1200)
	rand.Read(junk)
	c3.Write(junk)
	if _, _, ok := receive(masq, 200*time.Millisecond); ok {
		t.Fatal("garbage reached hy2-masq")
	}
	if _, _, ok := receive(obfs, 100*time.Millisecond); ok {
		t.Fatal("garbage reached hy2-obfs")
	}

	// Idle flows go away; the next packet is classified again.
	front.expire(time.Now().Add(2 * front.idle))
	front.access.Lock()
	left := len(front.flows)
	front.access.Unlock()
	if left != 0 {
		t.Fatalf("%d flows left after expiry", left)
	}
	c1.Write([]byte("short header packet"))
	if _, _, ok := receive(masq, 200*time.Millisecond); ok {
		t.Fatal("an expired flow still forwards")
	}
}
