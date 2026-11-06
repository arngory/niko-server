package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	tz := &taggedZone{zone: zone, auth: auth}
	packet := bytes.Repeat([]byte{0xc3}, 120) // a long header: a name of 223 characters
	epoch := dnsttserver.EpochOf(now)
	check := func(q []byte) []byte {
		t.Helper()
		name, end, ok := queryName(q)
		if !ok {
			t.Fatal("the query does not read")
		}
		return tz.check(q, name, end)
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
		if ok && tz.check(q, name, end) != nil {
			t.Errorf("%s: passed on", what)
		}
	}

	// What the front answers instead: NOERROR, no records, the question.
	_, end, _ = queryName(q)
	a := nodata(q, end)
	if a[2]&0x84 != 0x84 || a[3]&0x0f != 0 || binary.BigEndian.Uint16(a[6:8]) != 0 || !bytes.Equal(a[12:end], q[12:end]) {
		t.Fatalf("nodata %x", a)
	}
}

// The front and the fork's slipstream server (arngory/slipstream,
// --front-socket, SLIPSTREAM_SERVER the binary): a device's query reaches
// the server, rebuilt, and its answer comes back through the front; a query
// without the tag gets NOERROR from the front and never reaches it.
func TestTaggedZoneSlipstream(t *testing.T) {
	bin := os.Getenv("SLIPSTREAM_SERVER")
	if bin == "" {
		t.Skip("SLIPSTREAM_SERVER: the fork's slipstream-server")
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
	c := &FrontConfig{Schema: 1, Role: "front", DNS: &FrontDNS{Listen: []string{fmt.Sprintf("127.0.0.1:%d", port)},
		Zones: []DNSZone{{Zone: "s.example.com", Backend: "slip", Tag: "slipstream", AuthKeysFile: keys}}},
		Backends: map[string]BackendRef{"slip": {Socket: sock, Mode: "packet", UID: os.Getuid()}}}
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
	// The server's answer carries an OPT (the query had one): the front
	// answers its own without.
	if binary.BigEndian.Uint16(a[10:12]) != 1 {
		t.Fatalf("the answer is not the server's (no OPT): %x", a)
	}
	var other [32]byte
	q = slipQuery(t, dnsttserver.Tag2(&other, dnsttserver.EpochOf(time.Now()), packet), packet, "s.example.com", 16, true)
	if a := ask(q); binary.BigEndian.Uint16(a[10:12]) != 0 || binary.BigEndian.Uint16(a[6:8]) != 0 {
		t.Fatalf("an untagged query's answer: %x", a)
	}
}
