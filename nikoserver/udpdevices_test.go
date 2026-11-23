//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// devicePassword is a device's salamander password as raycontrol makes
// them: 32 characters of base64url.
func devicePassword(i int) string { return fmt.Sprintf("device-%025d", i) }

// writePasswords writes a route's passwords file as rayd does: whole, by
// a rename.
func writePasswords(t testing.TB, file string, passwords ...string) {
	t.Helper()
	tmp := file + ".tmp"
	var b strings.Builder
	for _, pw := range passwords {
		b.WriteString(pw + "\n")
	}
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
}

// deviceFront is a front with a device route to "s" (label 3, the front
// with the labels' keys) and a plain one to "a". Its links are not up:
// classify only.
func deviceFront(t testing.TB, passwords ...string) (*udpFront, string) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "s.salamander.keys")
	writePasswords(t, file, passwords...)
	c := &FrontUDP{Listen: []string{"127.0.0.1:0"}, CIDKeysFile: writeCIDKeys(t, dir, cidSecret, 1, 3), Routes: []UDPRoute{
		{SNI: []string{"a.example.com"}, Backend: "a"},
		{SalamanderPasswordsFile: file, Backend: "s"},
	}}
	backends := map[string]BackendRef{
		"a": {Socket: filepath.Join(dir, "a.sock"), Mode: "packet", UID: os.Getuid(), CIDLabel: 1},
		"s": {Socket: filepath.Join(dir, "s.sock"), Mode: "packet", UID: os.Getuid(), CIDLabel: 3},
	}
	fc := &FrontConfig{Schema: 1, Role: "front", UDP: c, Backends: backends}
	if errs := fc.validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f, err := newUDPFront(c, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return f, file
}

// initialPacket is the start of a client's Initial (v1), size bytes.
func initialPacket(size int) []byte {
	d := handshakePacket(cidID(cidSecret, 9, 9), size)
	d[0] = 0xc0 | d[0]&0x0f
	return d
}

// ingestDevice is serve's decision for a datagram, as ingest, with what
// goes to the backend: opened under a device's key.
func ingestDevice(f *udpFront, key flowKey, d []byte, now time.Time) (*backendLink, []byte) {
	d = append([]byte(nil), d...)
	var k [32]byte
	if link, route, keyed := f.pinnedFlow(key, d, netip.Addr{}, now, &k); link != nil {
		if route != nil && route.front {
			if !keyed {
				k = salamanderKey(route.password, d[:8])
			}
			for i := range d[8:] {
				d[8+i] ^= k[i%32]
			}
			d = d[8:]
		}
		return link, d
	}
	link, route, packets := f.classifyFlow(key, d, now)
	if link == nil {
		return nil, nil
	}
	if !f.pinWith(key, link, route, d, len(packets[0])+8, netip.Addr{}, now) {
		return nil, nil
	}
	return link, packets[0]
}

func TestSalamanderPasswordsParse(t *testing.T) {
	got, err := parseSalamanderPasswords([]byte("# rayd\n\nb-password\r\na-password  \n#not one\nb-password\n   \nc pass\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"b-password", "a-password", "c pass"}
	if len(got) != len(want) {
		t.Fatalf("%d passwords, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("password %d: %q, want %q", i, got[i], want[i])
		}
	}
	for _, empty := range []string{"", "\n", "# none\n"} {
		if got, err := parseSalamanderPasswords([]byte(empty)); err != nil || len(got) != 0 {
			t.Errorf("%q: %d passwords, %v", empty, len(got), err)
		}
	}
	var b strings.Builder
	for i := range maxSalamanderPasswords {
		fmt.Fprintf(&b, "p%d\n", i)
	}
	if got, err := parseSalamanderPasswords([]byte(b.String() + "p0\n")); err != nil || len(got) != maxSalamanderPasswords {
		t.Fatalf("%d passwords and a repeat: %d, %v", maxSalamanderPasswords, len(got), err)
	}
	_, err = parseSalamanderPasswords([]byte(b.String() + "one more\n"))
	if err == nil {
		t.Fatal("more than the bound taken")
	}
	if strings.Contains(err.Error(), "p1") || strings.Contains(err.Error(), "one more") {
		t.Fatalf("the error says what the file holds: %v", err)
	}
}

// Two devices, each its own key: each flow is pinned by its key, goes to
// the backend opened, and its answers come back under its own key with a
// salt of their own; a key not on the list opens nothing. A packet of a
// connection under way (the label) opens on the key too.
func TestUDPFrontDeviceKeys(t *testing.T) {
	a, b, c := devicePassword(1), devicePassword(2), devicePassword(3)
	f, _ := deviceFront(t, a, b)
	now := time.Now()
	from := func(ip string, port uint16) flowKey {
		return flowKey{netip.AddrPortFrom(netip.MustParseAddr(ip), port), netip.MustParseAddrPort("127.0.0.1:443")}
	}
	initial := initialPacket(1200)
	for _, x := range []struct {
		name string
		key  flowKey
		d    []byte
		want string
	}{
		{"device a", from("192.0.2.1", 1000), obfuscate(a, initial), "s"},
		{"device b", from("192.0.2.2", 1000), obfuscate(b, initial), "s"},
		{"a key not on the list", from("192.0.2.3", 1000), obfuscate(c, initial), ""},
		{"the label under a's key", from("192.0.2.4", 1000), obfuscate(a, shortPacket(cidID(cidSecret, 3, 4), 100)), "s"},
		{"another label under a's key", from("192.0.2.5", 1000), obfuscate(a, shortPacket(cidID(cidSecret, 1, 5), 100)), ""},
		{"the label in the clear", from("192.0.2.6", 1000), shortPacket(cidID(cidSecret, 3, 6), 100), ""},
		{"an Initial short of 1200 under its salt", from("192.0.2.7", 1000), obfuscate(a, initialPacket(1199)), ""},
		{"garbage", from("192.0.2.8", 1000), obfuscate(c, make([]byte, 1300)), ""},
	} {
		link, got := ingestDevice(f, x.key, x.d, now)
		name := ""
		if link != nil {
			name = link.name
			plain, _ := salamanderOpen(f.flows[x.key].route.password, x.d)
			if !bytes.Equal(got, plain) || len(got) != len(x.d)-8 {
				t.Errorf("%s: the backend gets %d bytes, not the datagram opened", x.name, len(got))
			}
		}
		if name != x.want {
			t.Errorf("%s: backend %q, want %q", x.name, name, x.want)
		}
	}
	// The flows' datagrams go opened, each under its own key.
	link := f.links["s"]
	for _, x := range []struct {
		key flowKey
		pw  string
	}{{from("192.0.2.1", 1000), a}, {from("192.0.2.2", 1000), b}} {
		data := []byte("a short header of the flow's")
		data[0] = 0x40
		if l, got := ingestDevice(f, x.key, obfuscate(x.pw, data), now); l != link || !bytes.Equal(got, data) {
			t.Errorf("a pinned flow's datagram: %q to %v", got, l)
		}
		// Its answer: plain from the backend, under the flow's key.
		ok, _, route := f.answeredFlow(link, x.key, []byte("answer"), now)
		if !ok || route == nil || !route.front || string(route.password) != x.pw {
			t.Fatalf("an answer to the flow of %s: %v, %v", x.key.client, ok, route)
		}
		one := salamanderSeal(make([]byte, 64), route.password, []byte("answer"))
		two := salamanderSeal(make([]byte, 64), route.password, []byte("answer"))
		if bytes.Equal(one[:8], two[:8]) {
			t.Error("two answers, one salt")
		}
		if got, _ := salamanderOpen([]byte(x.pw), one); string(got) != "answer" {
			t.Errorf("the answer under the flow's key: %q", got)
		}
		other := a
		if x.pw == a {
			other = b
		}
		if got, _ := salamanderOpen([]byte(other), one); string(got) == "answer" {
			t.Error("another device's key opens the answer")
		}
	}
	// An answer to an address with no flow goes nowhere: no key to put it
	// under (and no flow asked for it).
	if f.answered(link, from("192.0.2.3", 1000), []byte("answer"), now) {
		t.Error("an answer to an address with no flow went")
	}
	probe := make([]byte, quicProbeSize)
	probe[0] = 0x40
	if f.answered(link, from("192.0.2.9", 1000), probe, now) {
		t.Error("a path probe to an address with no flow went")
	}
}

// A path probe of the backend's (plain, 1200 bytes) counts with the
// salt it goes under, against the flow's 3x.
func TestUDPFrontDeviceProbe(t *testing.T) {
	a := devicePassword(1)
	f, _ := deviceFront(t, a)
	now := time.Now()
	key := flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("127.0.0.1:443")}
	if link, _ := ingestDevice(f, key, obfuscate(a, initialPacket(1200)), now); link == nil {
		t.Fatal("not pinned")
	}
	link := f.links["s"]
	probe := make([]byte, quicProbeSize)
	probe[0] = 0x40
	sent := 0
	for f.answered(link, key, probe, now) {
		sent++
		if sent > 10 {
			t.Fatal("probes past 3x")
		}
	}
	// 1208 from the client: 3 probes of 1208 within its 3x, one more
	// past it (pathProbeFree).
	if sent != 4 {
		t.Fatalf("%d probes went, want 4", sent)
	}
	if fl := f.flows[key]; fl.sent != 4*(quicProbeSize+salamanderSalt) {
		t.Fatalf("probes counted %d bytes", fl.sent)
	}
}

// A key removed from the file cuts its flows at once; the next datagram
// of one is tried and opens under nothing. The other devices' flows stay.
// A file that does not read leaves the list in force.
func TestUDPFrontDeviceRevoke(t *testing.T) {
	a, b := devicePassword(1), devicePassword(2)
	f, file := deviceFront(t, a, b)
	now := time.Now()
	ka := flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("127.0.0.1:443")}
	kb := flowKey{netip.MustParseAddrPort("192.0.2.2:1000"), netip.MustParseAddrPort("127.0.0.1:443")}
	for k, pw := range map[flowKey]string{ka: a, kb: b} {
		if link, _ := ingestDevice(f, k, obfuscate(pw, initialPacket(1200)), now); link == nil {
			t.Fatal("not pinned")
		}
	}
	r := f.devices[0]
	writePasswords(t, file, b)
	if changed, err := f.loadDevices(r); !changed || err != nil {
		t.Fatalf("reload: %v %v", changed, err)
	}
	if f.flows[ka] != nil {
		t.Fatal("the flow of the key removed stays")
	}
	if f.flows[kb] == nil {
		t.Fatal("the flow of a key kept is gone")
	}
	if f.devStats.cut.Load() != 1 {
		t.Fatalf("%d flows cut", f.devStats.cut.Load())
	}
	data := shortPacket(cidID(cidSecret, 3, 1), 100)
	if link, _ := ingestDevice(f, ka, obfuscate(a, data), now); link != nil {
		t.Fatal("the key removed opens a packet of its connection")
	}
	if link, _ := ingestDevice(f, kb, obfuscate(b, data), now); link == nil {
		t.Fatal("the key kept lost its flow")
	}
	// A trial under way that found the key just removed pins nothing.
	if f.pinWith(ka, f.links["s"], &flowRoute{password: []byte(a), front: true, device: r, gone: true}, obfuscate(a, data), 100, netip.Addr{}, now) {
		t.Fatal("a key gone pinned a flow")
	}
	// Unchanged: nothing to do. Gone, or not a list: the list stays.
	if changed, err := f.loadDevices(r); changed || err != nil {
		t.Fatalf("the same file: %v %v", changed, err)
	}
	os.Remove(file)
	if _, err := f.loadDevices(r); err == nil || len(r.list()) != 1 {
		t.Fatalf("a file gone: %v, %d keys", err, len(r.list()))
	}
	var many strings.Builder
	for i := range maxSalamanderPasswords + 1 {
		fmt.Fprintf(&many, "p%d\n", i)
	}
	os.WriteFile(file, []byte(many.String()), 0o640)
	if _, err := f.loadDevices(r); err == nil || len(r.list()) != 1 {
		t.Fatalf("a file of too many: %v, %d keys", err, len(r.list()))
	}
	// Emptied: nobody.
	writePasswords(t, file)
	if changed, err := f.loadDevices(r); !changed || err != nil || len(r.list()) != 0 || f.flows[kb] != nil {
		t.Fatalf("emptied: %v %v, %d keys", changed, err, len(r.list()))
	}
}

// The watch takes a new file by itself, and says a file that does not
// read once, without what it holds.
func TestUDPFrontDeviceWatch(t *testing.T) {
	a, b := devicePassword(1), devicePassword(2)
	f, file := deviceFront(t, a)
	var out syncBuffer
	f.log = NewLogger("info", &out)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := f.devices[0]
	go f.watchDevices(ctx, r, 10*time.Millisecond)
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; !ok(); i++ {
			if i == 300 {
				t.Fatalf("%s: never", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	writePasswords(t, file, a, b)
	waitFor("the new list", func() bool { return len(r.list()) == 2 })
	os.Remove(file)
	waitFor("the warning", func() bool { return strings.Contains(out.String(), "not read") })
	time.Sleep(100 * time.Millisecond)
	if n := strings.Count(out.String(), "not read"); n != 1 {
		t.Fatalf("said %d times", n)
	}
	if len(r.list()) != 2 {
		t.Fatal("a file gone took the list")
	}
	writePasswords(t, file, b)
	waitFor("the list again", func() bool { return len(r.list()) == 1 })
	if s := out.String(); strings.Contains(s, a) || strings.Contains(s, b) {
		t.Fatalf("the log has a password: %s", s)
	}
}

// syncBuffer is a log's output, read while it is written.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// trialsTaken is what a source's trial bucket lost, at now.
func trialsTaken(f *udpFront, src string, now time.Time) float64 {
	b := f.trialSources.bucket(netip.MustParseAddr(src), now)
	if b.last.IsZero() {
		return 0
	}
	return trialBurst - min(trialBurst, b.tokens+now.Sub(b.last).Seconds()*trialRate)
}

// A client whose NAT gave it a new port: same address, its key first, one
// trial whatever the list. A device behind the same IPv6 /64 too.
func TestUDPFrontDeviceRebind(t *testing.T) {
	var passwords []string
	for i := range 1000 {
		passwords = append(passwords, devicePassword(i))
	}
	pw := passwords[999] // the last tried in the list's order
	f, _ := deviceFront(t, passwords...)
	now := time.Now()
	key := flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("127.0.0.1:443")}
	if link, _ := ingestDevice(f, key, obfuscate(pw, initialPacket(1200)), now); link == nil {
		t.Fatal("not pinned")
	}
	if got := trialsTaken(f, "192.0.2.1", now); got != 1000 {
		t.Fatalf("the first Initial took %v trials", got)
	}
	moved := flowKey{netip.MustParseAddrPort("192.0.2.1:2000"), key.local}
	if link, _ := ingestDevice(f, moved, obfuscate(pw, shortPacket(cidID(cidSecret, 3, 1), 100)), now); link == nil {
		t.Fatal("the new port not pinned")
	}
	if got := trialsTaken(f, "192.0.2.1", now); got != 1001 {
		t.Fatalf("the new port took %v trials", got-1000)
	}
	if fl := f.flows[moved]; fl == nil || string(fl.route.password) != pw {
		t.Fatal("the new port pinned to another key")
	}
	v6 := flowKey{netip.MustParseAddrPort("[2001:db8:1:2::1]:1000"), key.local}
	v6moved := flowKey{netip.MustParseAddrPort("[2001:db8:1:2::77]:3000"), key.local}
	ingestDevice(f, v6, obfuscate(pw, initialPacket(1200)), now)
	if link, _ := ingestDevice(f, v6moved, obfuscate(pw, shortPacket(cidID(cidSecret, 3, 2), 100)), now); link == nil {
		t.Fatal("the /64's new address not pinned")
	}
	if got := trialsTaken(f, "2001:db8:1:2::1", now); got != 1001 {
		t.Fatalf("the /64 took %v trials", got)
	}
}

// A copy of a matched Initial, from anywhere, gets nothing (§7); the
// client's next Initial, a salt of its own, goes.
func TestUDPFrontDeviceReplay(t *testing.T) {
	a := devicePassword(1)
	f, _ := deviceFront(t, a)
	now := time.Now()
	local := netip.MustParseAddrPort("127.0.0.1:443")
	d := obfuscate(a, initialPacket(1200))
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), local}, d, now); link == nil {
		t.Fatal("not pinned")
	}
	for _, from := range []string{"192.0.2.1:1001", "198.51.100.1:1000"} {
		if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort(from), local}, d, now); link != nil {
			t.Fatalf("a copy from %s went", from)
		}
	}
	if f.devStats.replayed.Load() != 2 {
		t.Fatalf("%d copies counted", f.devStats.replayed.Load())
	}
	// The flow's next Initial (a ClientHello in two) is remembered too.
	second := obfuscate(a, initialPacket(1200))
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), local}, second, now); link == nil {
		t.Fatal("the flow's second Initial dropped")
	}
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("198.51.100.1:1001"), local}, second, now); link != nil {
		t.Fatal("a copy of the flow's second Initial went")
	}
	// Two generations: a copy within them stays out, past them it is new.
	f.salts.age(now.Add(saltsFor + time.Second))
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1002"), local}, d, now); link != nil {
		t.Fatal("a copy went in the older generation")
	}
	f.salts.age(now.Add(2*saltsFor + 2*time.Second))
	f.salts.age(now.Add(3*saltsFor + 3*time.Second))
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1003"), local}, d, now); link == nil {
		t.Fatal("forgotten after two generations, still dropped")
	}
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1004"), local}, obfuscate(a, initialPacket(1200)), now); link == nil {
		t.Fatal("a fresh Initial dropped")
	}
}

// Past its source's budget a datagram of no flow is dropped untried,
// even under a key on the list; another source has its own, within the
// front's.
func TestUDPFrontDeviceBudget(t *testing.T) {
	var passwords []string
	for i := range 1000 {
		passwords = append(passwords, devicePassword(i))
	}
	f, _ := deviceFront(t, passwords...)
	now := time.Now() // no refill: the clock stands
	local := netip.MustParseAddrPort("127.0.0.1:443")
	junk := obfuscate("not a device", make([]byte, 1300))
	source := func(ip string, n int) {
		for i := range n {
			ingestDevice(f, flowKey{netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(1000+i)), local}, junk, now)
		}
	}
	source("192.0.2.1", trialBurst/1000)
	if got := f.devStats.unmatched.Load(); got != trialBurst/1000 {
		t.Fatalf("%d datagrams tried, want %d", got, trialBurst/1000)
	}
	real := obfuscate(passwords[0], initialPacket(1200))
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:9999"), local}, real, now); link != nil {
		t.Fatal("past its budget, a source's Initial was tried")
	}
	if f.devStats.overBudget.Load() != 1 {
		t.Fatalf("%d over the budget", f.devStats.overBudget.Load())
	}
	// Two more sources take the front's 500 000 with this one's 200 000.
	source("192.0.2.2", trialBurst/1000)
	source("192.0.2.3", (trialTotalBurst-2*trialBurst)/1000)
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.4:1000"), local}, obfuscate(passwords[0], initialPacket(1200)), now); link != nil {
		t.Fatal("past the front's budget, an Initial was tried")
	}
	// A second on, both have room again.
	later := now.Add(time.Second)
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.4:1001"), local}, obfuscate(passwords[0], initialPacket(1200)), later); link == nil {
		t.Fatal("a second later, an Initial was not tried")
	}
	// Pinned flows are never tried.
	before := f.allTrials.tokens
	key := flowKey{netip.MustParseAddrPort("192.0.2.4:1001"), local}
	for range 10 {
		ingestDevice(f, key, obfuscate(passwords[0], shortPacket(cidID(cidSecret, 3, 1), 100)), later)
	}
	if f.allTrials.tokens != before {
		t.Fatal("a pinned flow's datagrams were tried")
	}
}

// The front on its sockets: two devices through to a backend, each one's
// answers under its own key; a third key gets nothing; an answer to an
// address with no flow goes nowhere; a key removed from the file cuts its
// flow.
func TestNekoServerUDPFrontDevices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	backend := packetBackend(t, filepath.Join(dir, "s.sock"))
	a, b, c := devicePassword(1), devicePassword(2), devicePassword(3)
	file := filepath.Join(dir, "s.salamander.keys")
	writePasswords(t, file, a, b)
	fc := &FrontUDP{Listen: []string{"127.0.0.1:0"}, Routes: []UDPRoute{{SalamanderPasswordsFile: file, Backend: "s"}}}
	backends := map[string]BackendRef{"s": {Socket: filepath.Join(dir, "s.sock"), Mode: "packet", UID: os.Getuid()}}
	var e configErrors
	fc.validate(&e, backends)
	if len(e) > 0 {
		t.Fatal(e)
	}
	front, err := newUDPFront(fc, backends, NewLogger("warn", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	front.devicesEvery = 20 * time.Millisecond
	if err := front.listen(fc.Listen); err != nil {
		t.Fatal(err)
	}
	var addr *net.UDPAddr
	for _, s := range front.sockets {
		addr = s.LocalAddr().(*net.UDPAddr)
	}
	go front.run(ctx)
	for i := 0; ; i++ {
		l := front.links["s"]
		l.access.Lock()
		up := l.conn != nil
		l.access.Unlock()
		if up {
			break
		}
		if i == 100 {
			t.Fatal("backend never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	receive := func(within time.Duration) ([]byte, net.Addr, bool) {
		backend.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 2048)
		n, from, err := backend.ReadFrom(buf)
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
	read := func(c *net.UDPConn, within time.Duration) ([]byte, bool) {
		c.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 2048)
		n, err := c.Read(buf)
		return buf[:n], err == nil
	}
	clients := map[string]*net.UDPConn{a: client(), b: client()}
	for pw, cl := range clients {
		initial := initialPacket(1200)
		cl.Write(obfuscate(pw, initial))
		got, from, ok := receive(2 * time.Second)
		if !ok || !bytes.Equal(got, initial) || from.String() != cl.LocalAddr().String() {
			t.Fatalf("the backend got %d bytes from %v (%v), not the Initial opened", len(got), from, ok)
		}
		backend.WriteTo([]byte("answer"), cl.LocalAddr())
		d, ok := read(cl, 2*time.Second)
		if !ok || len(d) != 8+len("answer") {
			t.Fatalf("answer: %d bytes (%v)", len(d), ok)
		}
		if plain, _ := salamanderOpen([]byte(pw), d); string(plain) != "answer" {
			t.Fatalf("the answer does not open under the flow's key: %q", plain)
		}
	}
	third := client()
	third.Write(obfuscate(c, initialPacket(1200)))
	if _, _, ok := receive(200 * time.Millisecond); ok {
		t.Fatal("a key not on the list got through")
	}
	backend.WriteTo([]byte("answer"), third.LocalAddr())
	if d, ok := read(third, 200*time.Millisecond); ok {
		t.Fatalf("an address with no flow got %d bytes", len(d))
	}

	// b removed: its flow is cut, a's goes on.
	writePasswords(t, file, a)
	for i := 0; len(front.devices[0].list()) != 1; i++ {
		if i == 200 {
			t.Fatal("the file never read again")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data := shortPacket(cidID(cidSecret, 3, 1), 100)
	clients[b].Write(obfuscate(b, data))
	if _, _, ok := receive(200 * time.Millisecond); ok {
		t.Fatal("a key removed kept its flow")
	}
	backend.WriteTo([]byte("answer"), clients[b].LocalAddr())
	if _, ok := read(clients[b], 200*time.Millisecond); ok {
		t.Fatal("the flow of a key removed got an answer")
	}
	clients[a].Write(obfuscate(a, data))
	if got, _, ok := receive(2 * time.Second); !ok || !bytes.Equal(got, data) {
		t.Fatal("a key kept lost its flow")
	}
}

// What a datagram of no flow costs the front on a device route, by the
// keys it is tried under: the worst case is one no key opens, every key
// tried (the trial budget's unit). "rebind" is a device's packet from a
// new port of its address, its key tried first.
func BenchmarkUDPFrontDeviceTrial(b *testing.B) {
	for _, n := range []int{1, 1000} {
		var passwords []string
		for i := range n {
			passwords = append(passwords, devicePassword(i))
		}
		f, _ := deviceFront(b, passwords...)
		local := netip.MustParseAddrPort("127.0.0.1:443")
		now := time.Now()
		for name, d := range map[string][]byte{
			"garbage":    obfuscate("not a device", make([]byte, 1200)),
			"label miss": obfuscate("not a device", shortPacket(cidID(cidSecret, 3, 1), 100)),
		} {
			b.Run(fmt.Sprintf("%s/%d keys", name, n), func(b *testing.B) {
				key := flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), local}
				for i := 0; b.Loop(); i++ {
					if i%100 == 0 { // within the budget: the cost of the keys alone
						f.trialSources, f.allTrials = sourceLimits{}, tokenBucket{}
					}
					if link, _, _ := f.tryKeys(key, d, now); link != nil {
						b.Fatal("matched")
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/key")
			})
		}
	}
	var passwords []string
	for i := range 1000 {
		passwords = append(passwords, devicePassword(i))
	}
	f, _ := deviceFront(b, passwords...)
	local := netip.MustParseAddrPort("127.0.0.1:443")
	now := time.Now()
	pw := passwords[999]
	if link, _ := ingestDevice(f, flowKey{netip.MustParseAddrPort("192.0.2.1:1000"), local}, obfuscate(pw, initialPacket(1200)), now); link == nil {
		b.Fatal("not pinned")
	}
	d := obfuscate(pw, shortPacket(cidID(cidSecret, 3, 1), 100))
	b.Run("rebind/1000 keys", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			if link, _, _ := f.tryKeys(flowKey{netip.MustParseAddrPort("192.0.2.1:2000"), local}, d, now); link == nil {
				b.Fatal("not matched")
			}
			if i%100 == 0 {
				f.cidSources, f.trialSources, f.allTrials = sourceLimits{}, sourceLimits{}, tokenBucket{}
			}
		}
	})
}

// FuzzDeviceKeys is a device route's path for a datagram no flow
// explains, and the flow it pins: nothing panics, and a datagram goes to
// the backend only opened under a key of the list, as an Initial of its
// size or to the route's label; the flow's next datagram goes opened
// under the same key.
func FuzzDeviceKeys(f *testing.F) {
	a, b := devicePassword(1), devicePassword(2)
	front, _ := deviceFront(f, a, b)
	f.Add(obfuscate(a, initialPacket(1200)))
	f.Add(obfuscate(b, shortPacket(cidID(cidSecret, 3, 1), 64)))
	f.Add(obfuscate(b, handshakePacket(cidID(cidSecret, 3, 2), 64)))
	f.Add(obfuscate(a, initialPacket(1199)))
	f.Add(make([]byte, 16))
	f.Add([]byte{1, 2, 3})
	var n uint32
	now := time.Now()
	local := netip.MustParseAddrPort("127.0.0.1:443")
	f.Fuzz(func(t *testing.T, d []byte) {
		n++
		key := flowKey{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)}), 1), local}
		link, route, packets := front.classifyFlow(key, d, now)
		if link == nil {
			return
		}
		if route == nil || !route.front || len(packets) != 1 {
			t.Fatalf("to %s not by a key", link.name)
		}
		plain, _ := salamanderOpen(route.password, d)
		if !bytes.Equal(plain, packets[0]) {
			t.Fatal("not the datagram opened under its key")
		}
		initial := isQUICInitial(plain) && len(d) >= salamanderSalt+minInitialDatagram
		id := clientCID(plain[:min(len(plain), cidHead)], len(plain))
		if label, ok := labelCodec(cidSecret, 3).label(id); !initial && (id == nil || !ok || label != 3) {
			t.Fatalf("opened neither to an Initial nor to the label: %x", plain[:min(len(plain), 24)])
		}
		if !front.pinWith(key, link, route, d, len(d), netip.Addr{}, now) {
			t.Fatal("not pinned")
		}
		if l, got := ingestDevice(front, key, d, now); l != link || !bytes.Equal(got, plain) {
			t.Fatal("the flow's datagram not opened under its key")
		}
		front.access.Lock()
		front.unpin(key)
		front.access.Unlock()
	})
}
