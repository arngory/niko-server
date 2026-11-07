package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// slipQuery is a slipstream client's query: the dnsauth-v2 field and the
// QUIC packet, base32 in labels of 57 before the zone, TXT, with an OPT
// (DO) when do.
func slipQuery(t *testing.T, field [8]byte, packet []byte, zone string, qtype uint16, do bool) []byte {
	t.Helper()
	enc := strings.ToLower(slipBase32.EncodeToString(append(field[:], packet...)))
	var labels []string
	for enc != "" {
		n := min(57, len(enc))
		labels, enc = append(labels, enc[:n]), enc[n:]
	}
	labels = append(labels, strings.Split(zone, ".")...)
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range labels {
		// A resolver's 0x20: the case of the name changes.
		q = append(q, byte(len(l)))
		q = append(q, strings.ToUpper(l[:1])+l[1:]...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	if do {
		binary.BigEndian.PutUint16(q[10:12], 1)
		// root, OPT, 4096, rcode 0, version 0, DO, an option (cookie)
		q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 12, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	}
	return q
}

// A slipstream zone's queries reach the backend only with a device's
// dnsauth-v2 tag over the QUIC packet (raycontrol slipstream-v1 §2), rebuilt:
// the question as it came, an OPT with the size and DO and no options.
func TestTaggedZone(t *testing.T) {
	now := time.Now()
	var key, other [32]byte
	rand.Read(key[:])
	rand.Read(other[:])
	auth := &dnsttserver.DeviceAuth{Hint: dnsttserver.HintRequired}
	if err := auth.SetKeys([]byte("d1 " + hex.EncodeToString(key[:]) + "\n")); err != nil {
		t.Fatal(err)
	}
	zone := "s.example.com"
	packet := bytes.Repeat([]byte{0xc3}, 120) // a long header: a name of 223 characters
	epoch := dnsttserver.EpochOf(now)
	// Each query to a zone of its own: a field passes once (replays below).
	check := func(q []byte) []byte {
		t.Helper()
		name, end, ok := queryName(q)
		if !ok {
			t.Fatal("the query does not read")
		}
		out, _, _, _ := newTaggedZone(zone, auth, nil).check(q, name, end, nil, nil)
		return out
	}

	q := slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, true)
	out := check(q)
	if out == nil {
		t.Fatal("a device's query refused")
	}
	_, end, _ := queryName(q)
	if !bytes.Equal(out[:2], q[:2]) || !bytes.Equal(out[12:end], q[12:end]) || out[2] != 0x01 || out[3] != 0 {
		t.Fatalf("rebuilt header or question %x", out[:end])
	}
	if binary.BigEndian.Uint16(out[10:12]) != 1 || !bytes.Equal(out[end:], []byte{0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0}) {
		t.Fatalf("rebuilt OPT %x", out[end:])
	}
	if out := check(slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, false)); out == nil || binary.BigEndian.Uint16(out[10:12]) != 0 {
		t.Fatalf("without OPT: %x", out)
	}

	for what, q := range map[string][]byte{
		"another key":    slipQuery(t, dnsttserver.Tag2(&other, epoch, packet), packet, zone, 16, true),
		"a v1 tag":       slipQuery(t, dnsttserver.Tag(&key, epoch, packet), packet, zone, 16, true),
		"another packet": slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), append([]byte{0}, packet...), zone, 16, true),
		"an old epoch":   slipQuery(t, dnsttserver.Tag2(&key, epoch-5, packet), packet, zone, 16, true),
		"type A":         slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 1, true),
		"no data":        slipQuery(t, [8]byte{}, nil, zone, 16, false)[:0],
		"another zone":   slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, "x.example.com", 16, true),
		"an answer count": func() []byte {
			q := slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, false)
			q[7] = 1
			return q
		}(),
		"opcode 2": func() []byte {
			q := slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, false)
			q[2] |= 0x10
			return q
		}(),
	} {
		name, end, ok := queryName(q)
		if out, _, _, _ := newTaggedZone(zone, auth, nil).check(q, name, end, nil, nil); ok && out != nil {
			t.Errorf("%s: passed on", what)
		}
	}

	// What the front answers instead: NOERROR, no records, the question,
	// and the OPT slipstream's server answers with (1232, DO, no options).
	_, end, _ = queryName(q)
	a := nodata(q, end)
	if a[2]&0x84 != 0x84 || a[3]&0x0f != 0 || binary.BigEndian.Uint16(a[6:8]) != 0 || !bytes.Equal(a[12:end], q[12:end]) {
		t.Fatalf("nodata %x", a)
	}
	if binary.BigEndian.Uint16(a[10:12]) != 1 || !bytes.Equal(a[end:], []byte{0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0}) {
		t.Fatalf("nodata's OPT %x", a[end:])
	}
	q = slipQuery(t, dnsttserver.Tag2(&other, epoch, packet), packet, zone, 16, false)
	if _, end, _ = queryName(q); len(nodata(q, end)) != end {
		t.Fatal("an OPT for a query without one")
	}
	// Another opcode: NOTIMP, authoritative, as dnstt answers it.
	q[2] |= 0x28 // UPDATE
	if a := nodata(q, end); a[2]&0x04 == 0 || a[3]&0x0f != 4 {
		t.Fatalf("nodata to UPDATE %x", a[:4])
	}
}

// A device's query passes once: a copy (another ID, case, label split, OPT
// or address: the same field) does not, for as long as its tag holds; a
// generation full starts the next one.
func TestTaggedZoneReplay(t *testing.T) {
	now := time.Unix(1767268800, 0)
	var key [32]byte
	rand.Read(key[:])
	auth := &dnsttserver.DeviceAuth{Hint: dnsttserver.HintRequired, Now: func() time.Time { return now }}
	if err := auth.SetKeys([]byte("d1 " + hex.EncodeToString(key[:]) + "\n")); err != nil {
		t.Fatal(err)
	}
	zone := "s.example.com"
	tz := newTaggedZone(zone, auth, nil)
	tz.now = func() time.Time { return now }
	packet := bytes.Repeat([]byte{0x41}, 60)
	epoch := dnsttserver.EpochOf(now)
	raw := make([]byte, 0, maxNameText)
	verdict := func(q []byte) int {
		t.Helper()
		name, end, ok := queryName(q)
		if !ok {
			t.Fatal("the query does not read")
		}
		_, _, _, v := tz.check(q, name, end, make([]byte, 0, 512), raw)
		return v
	}
	q := slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, true)
	if v := verdict(q); v != tagPassed {
		t.Fatalf("first sight: %d", v)
	}
	copyOf := slipQuery(t, dnsttserver.Tag2(&key, epoch, packet), packet, zone, 16, false)
	copyOf[0], copyOf[1] = 0x56, 0x78
	// Right after the original: a resolver's retry, left without answer
	// (the original's is on its way); later, a copy: NOERROR.
	if v := verdict(copyOf); v != tagEcho {
		t.Fatalf("a copy at once: %d", v)
	}
	now = now.Add(seenQuiet)
	if v := verdict(copyOf); v != tagReplayed {
		t.Fatalf("a copy with another ID and no OPT: %d", v)
	}
	// An epoch later the tag still holds (a tag of epoch e is taken while
	// the clock is in e-1..e+1), and the copy is still caught.
	now = now.Add(dnsttserver.AuthEpoch)
	if v := verdict(q); v != tagReplayed {
		t.Fatalf("a copy an epoch later: %d", v)
	}
	// A query that never reached the backend: one retry within 10 s
	// passes, and not one more, nor one later.
	again := append(bytes.Clone(packet), 2)
	q2 := slipQuery(t, dnsttserver.Tag2(&key, dnsttserver.EpochOf(now), again), again, zone, 16, true)
	name2, end2, _ := queryName(q2)
	_, field, _, v := tz.check(q2, name2, end2, nil, nil)
	if v != tagPassed {
		t.Fatalf("a new packet: %d", v)
	}
	tz.seen.forget(field, now)
	if v := verdict(q2); v != tagPassed {
		t.Fatalf("a retry of a query the backend never got: %d", v)
	}
	if v := verdict(q2); v == tagPassed {
		t.Fatal("a second retry passed")
	}
	tz.seen.forget(field, now)
	now = now.Add(seenRetry)
	if v := verdict(q2); v == tagPassed {
		t.Fatal("a retry after 10 s passed")
	}
	// Another packet passes.
	other := append(bytes.Clone(packet), 1)
	if v := verdict(slipQuery(t, dnsttserver.Tag2(&key, dnsttserver.EpochOf(now), other), other, zone, 16, true)); v != tagPassed {
		t.Fatalf("another packet: %d", v)
	}

	// The memory: a field stays four epochs, and a full generation turns,
	// counted.
	at := func(e uint32) time.Time { return time.Unix(int64(e)*int64(dnsttserver.AuthEpoch/time.Second), 0) }
	var s seenFields
	f := [8]byte{1}
	if s.sight(f, at(100)) != tagPassed || s.sight(f, at(100)) == tagPassed || s.sight(f, at(103)) != tagReplayed {
		t.Fatal("a field seen in epoch 100 passed again by 103")
	}
	if s.sight(f, at(104)) != tagPassed {
		t.Fatal("a field seen in epoch 100 still caught in 104")
	}
	var early atomic.Uint64
	g := seenFields{early: &early}
	for i := range seenCap + 1 {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(i))
		g.sight(x, at(7))
	}
	if len(g.gens[0]) != 1 || len(g.gens[1]) != seenCap || early.Load() != 1 {
		t.Fatalf("a full generation did not turn: %d, %d, %d early", len(g.gens[0]), len(g.gens[1]), early.Load())
	}
	if g.sight([8]byte{}, at(7)) == tagPassed {
		t.Fatal("a field of the turned generation passed again")
	}
}

// The labels decode only as the server's decoder reads them: base32 letters
// and digits 2-7, any case, dots anywhere, a whole number of bytes, the
// last character's unused bits zero (review: Go's decoder skips CR and LF
// and takes any last bits).
func TestSlipDecode(t *testing.T) {
	data := []byte("tagged-zone-dat") // 15 bytes: 24 characters, no remainder
	enc := strings.ToLower(slipBase32.EncodeToString(data))
	if raw, ok := slipDecode(enc[:7]+"."+enc[7:], nil); !ok || !bytes.Equal(raw, data) {
		t.Fatalf("%q: %x %v", enc, raw, ok)
	}
	for _, bad := range []string{
		enc[:5] + "\n" + enc[5:], // CR and LF are bytes a label may hold
		enc[:5] + "\r" + enc[5:],
		enc + "======",
		enc[:4] + "0" + enc[5:], // not in the alphabet
		enc[:4] + "8" + enc[5:],
		enc[:4] + "-" + enc[5:],
		enc + "a",      // 1 left over: no whole byte
		enc + "aaa",    // 3
		enc + "aaaaaa", // 6
		"ab",           // 0x00 with a set unused bit
		"", ".",
	} {
		if raw, ok := slipDecode(bad, nil); ok {
			t.Errorf("%q decoded: %x", bad, raw)
		}
	}
}

// The front and the fork's slipstream server (arngory/slipstream,
// --front-socket, SLIPSTREAM_SERVER the binary): a device's query reaches
// the server, rebuilt, and its answer comes back through the front; a query
// without the tag gets NOERROR from the front and never reaches it.
func TestTaggedZoneSlipstream(t *testing.T) {
	bin := os.Getenv("SLIPSTREAM_SERVER")
	if bin == "" {
		t.Skip("SLIPSTREAM_SERVER: the fork's slipstream-server (server-v0.2.0 or later)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	var key [32]byte
	rand.Read(key[:])
	keys := filepath.Join(dir, "auth.keys")
	os.WriteFile(keys, []byte("d1 "+hex.EncodeToString(key[:])+"\n"), 0o600)
	cert, certKey := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", certKey, "-out", cert, "-days", "1", "-subj", "/CN=x").CombinedOutput(); err != nil {
		t.Skipf("openssl: %v %s", err, out)
	}
	sock := filepath.Join(dir, "slip.sock")
	srv := exec.CommandContext(ctx, bin, "--front-socket", sock, "--front-uid", strconv.Itoa(os.Getuid()), "--tag-len", "8",
		"--max-connections-per-device", "4",
		"-a", "127.0.0.1:9", "-c", cert, "-k", certKey, "-d", "s.example.com", "-n", "abcdefgh")
	srv.Stderr = os.Stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Wait()
	defer srv.Process.Kill()
	for i := 0; ; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if i == 100 {
			t.Fatal("no front socket")
		}
		time.Sleep(20 * time.Millisecond)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	statsSock := filepath.Join(dir, "front-stats.sock")
	c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{fmt.Sprintf("127.0.0.1:%d", port)}, StatsSocket: statsSock,
		Zones: []DNSZone{{Zone: "s.example.com", Backend: "slip", Tag: "slipstream", AuthKeysFile: keys}}},
		// The device named (IPC version 2): server-v0.2.0 or later.
		Backends: map[string]BackendRef{"slip": {Socket: sock, Mode: "packet", UID: os.Getuid(), Devices: true}}}
	go RunFront(ctx, c, NewLogger("warn", io.Discard))
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ask := func(q []byte) []byte {
		t.Helper()
		buf := make([]byte, 4096)
		for range 50 { // until the front is up and has the backend
			conn.Write(q)
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, err := conn.Read(buf); err == nil {
				return buf[:n]
			}
		}
		t.Fatal("no answer")
		return nil
	}
	// A QUIC Initial the server takes: a long header of version 1, too
	// short to be a valid one; the server answers it empty.
	packet := append([]byte{0xc0, 0, 0, 0, 1, 8}, bytes.Repeat([]byte{7}, 100)...)
	q := slipQuery(t, dnsttserver.Tag2(&key, dnsttserver.EpochOf(time.Now()), packet), packet, "s.example.com", 16, true)
	a := ask(q)
	_, end, _ := queryName(q)
	if a[2]&0x80 == 0 || a[3]&0x0f != 0 || !bytes.Equal(a[:2], q[:2]) || !bytes.Equal(a[12:end], q[12:end]) {
		t.Fatalf("the server's answer through the front: %x", a)
	}
	// The front's counters tell whose answer it was: the server's and the
	// front's read the same (an OPT of 4096, no records).
	stats := func() (forwarded, answers, untagged, replayed uint64) {
		t.Helper()
		sc, err := net.Dial("unix", statsSock)
		if err != nil {
			t.Fatal(err)
		}
		defer sc.Close()
		var st struct{ Forwarded, Answers, Untagged, Replayed uint64 }
		if err := json.NewDecoder(sc).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st.Forwarded, st.Answers, st.Untagged, st.Replayed
	}
	fw, an, un, _ := stats()
	if fw == 0 || an == 0 || un != 0 || binary.BigEndian.Uint16(a[10:12]) != 1 {
		t.Fatalf("the server's answer: forwarded %d, answers %d, untagged %d: %x", fw, an, un, a)
	}
	// A copy of the device's query (another ID): no answer within 5 s of
	// the original (a resolver's retry), then the front's NOERROR; the
	// server sees nothing of it.
	device := q
	device[0] ^= 0x5a
	if c := ask(device); binary.BigEndian.Uint16(c[6:8]) != 0 {
		t.Fatalf("a copy's answer: %x", c)
	}
	if fw2, _, _, rp := stats(); fw2 != fw || rp == 0 {
		t.Fatalf("a copy: forwarded %d (was %d), replayed %d", fw2, fw, rp)
	}
	var other [32]byte
	q = slipQuery(t, dnsttserver.Tag2(&other, dnsttserver.EpochOf(time.Now()), packet), packet, "s.example.com", 16, true)
	b := ask(q)
	_, endB, _ := queryName(q)
	// The same but the question (another tag: another name).
	if binary.BigEndian.Uint16(b[6:8]) != 0 || !bytes.Equal(b[2:12], a[2:12]) || !bytes.Equal(b[endB:], a[end:]) {
		t.Fatalf("an untagged query's answer differs from the server's empty one:\n%x\n%x", b, a)
	}
	if fw2, _, un, _ := stats(); fw2 != fw || un != 1 {
		t.Fatalf("an untagged query: forwarded %d (was %d), untagged %d", fw2, fw, un)
	}
}

// A backend with devices (v0.14.0) gets each query in IPC version 2 with
// the token of the device whose tag it carried, the same for all its
// queries and another for another device, then the query as check()
// builds it; without devices, version 1 as before. The server's
// --max-connections-per-device counts by it.
func TestTaggedZoneDevices(t *testing.T) {
	// The token is a contract with the server and docs/IPC.md.
	if d := deviceToken("d1"); hex.EncodeToString(d[:]) != "d88741ec56ed78ad" {
		t.Fatalf("deviceToken(d1) %x", d)
	}
	for _, devices := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		dir := t.TempDir()
		var k1, k2 [32]byte
		rand.Read(k1[:])
		rand.Read(k2[:])
		keys := filepath.Join(dir, "auth.keys")
		os.WriteFile(keys, []byte("d1 "+hex.EncodeToString(k1[:])+"\nd2 "+hex.EncodeToString(k2[:])+"\n"), 0o600)
		auth := &dnsttserver.DeviceAuth{Hint: dnsttserver.HintRequired}
		if err := auth.LoadKeys(keys); err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "slip.sock")
		ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sock, Net: "unixpacket"})
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		udp.Close()
		c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{fmt.Sprintf("127.0.0.1:%d", port)},
			Zones: []DNSZone{{Zone: "s.example.com", Backend: "slip", Tag: "slipstream", AuthKeysFile: keys}}},
			Backends: map[string]BackendRef{"slip": {Socket: sock, Mode: "packet", UID: os.Getuid(), Devices: devices}}}
		if errs := c.validate(); len(errs) != 0 {
			t.Fatalf("devices %v: %v", devices, errs)
		}
		go RunFront(ctx, c, NewLogger("warn", io.Discard))
		be, err := ln.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		n := byte(0)
		// got sends a fresh query of the device until the backend reads
		// one (the front takes the backend a moment after the accept),
		// and returns the message with the query check() makes of it.
		got := func(key *[32]byte) (msg, want []byte) {
			t.Helper()
			buf := make([]byte, 70000)
			for range 30 {
				n++
				packet := append([]byte{0xc0, 0, 0, 0, 1, 8, n}, bytes.Repeat([]byte{7}, 100)...)
				q := slipQuery(t, dnsttserver.Tag2(key, dnsttserver.EpochOf(time.Now()), packet), packet, "s.example.com", 16, true)
				name, end, _ := queryName(q)
				want, _, _, _ = newTaggedZone("s.example.com", auth, nil).check(q, name, end, nil, nil)
				conn.Write(q)
				be.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				if m, err := be.Read(buf); err == nil {
					return buf[:m:m], want
				}
			}
			t.Fatalf("devices %v: the backend got nothing", devices)
			return nil, nil
		}
		check := func(m, want []byte, token *[deviceSize]byte) {
			t.Helper()
			head := packetHeader
			version := byte(1)
			if token != nil {
				head, version = packetHeader+deviceSize, 2
			}
			if len(m) != head+len(want) || m[0] != 'N' || m[1] != 'U' || m[2] != version || !bytes.Equal(m[head:], want) ||
				(token != nil && !bytes.Equal(m[packetHeader:head], token[:])) {
				t.Fatalf("devices %v: %x\nwant the query %x", devices, m, want)
			}
		}
		m1, w1 := got(&k1)
		m1b, w1b := got(&k1)
		m2, w2 := got(&k2)
		if !devices {
			check(m1, w1, nil)
			check(m1b, w1b, nil)
			check(m2, w2, nil)
		} else {
			d1, d2 := deviceToken("d1"), deviceToken("d2")
			check(m1, w1, &d1)
			check(m1b, w1b, &d1)
			check(m2, w2, &d2)
			if d1 == d2 {
				t.Fatal("two devices, one token")
			}
		}
		conn.Close()
		be.Close()
		ln.Close()
		cancel()
	}

	// devices only on a tagged zone's backend; one socket, one backend.
	tagged := func(zone string) DNSZone {
		return DNSZone{Zone: zone, Backend: "slip", Tag: "slipstream", AuthKeysFile: "/run/x/auth.keys"}
	}
	slip := map[string]BackendRef{"slip": {Socket: "/run/x/packet.sock", Mode: "packet", Devices: true}}
	for _, c := range []struct {
		cfg   *FrontConfig
		field string
	}{
		{&FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{"127.0.0.1:53"}, Zones: []DNSZone{{Zone: "t.example.com", Backend: "dns"}}},
			Backends: map[string]BackendRef{"dns": {Socket: "/run/x/packet.sock", Mode: "packet", Devices: true}}}, ".devices"},
		{&FrontConfig{Schema: 1, Role: "front", TCP: &FrontTCP{Listen: []string{"0.0.0.0:443"}, Routes: []TCPRoute{{SNI: []string{"a.example.com"}, Backend: "x"}}},
			Backends: map[string]BackendRef{"x": {Socket: "/run/x/fd.sock", Mode: "fd", Devices: true}}}, ".devices"},
		{&FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{"127.0.0.1:53"}, Zones: []DNSZone{tagged("s.example.com")}},
			UDP:      &FrontUDP{Listen: []string{"0.0.0.0:443"}, Routes: []UDPRoute{{SNI: []string{"q.example.com"}, Backend: "slip"}}},
			Backends: slip}, ".devices"},
		{&FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{"127.0.0.1:53"}, Zones: []DNSZone{tagged("s.example.com"), {Zone: "t.example.com", Backend: "dns"}}},
			Backends: map[string]BackendRef{"slip": slip["slip"], "dns": {Socket: "/run/x/packet.sock", Mode: "packet"}}}, ".socket"},
	} {
		if errs := c.cfg.validate(); !strings.Contains(fmt.Sprint(errs), c.field) {
			t.Errorf("accepted (want %s refused): %v", c.field, errs)
		}
	}
	two := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{"127.0.0.1:53"},
		Zones: []DNSZone{tagged("s.example.com"), tagged("u.example.org")}}, Backends: slip}
	if errs := two.validate(); len(errs) != 0 {
		t.Errorf("two tagged zones of a backend with devices: %v", errs)
	}
}
