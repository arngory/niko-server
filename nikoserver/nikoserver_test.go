//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	mdvembed "masterdnsvpn-go/embed"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// echoInner stands in for the inner stage: a unix stream socket that echoes.
func echoInner(t *testing.T, dir string) string {
	path := filepath.Join(dir, "inner.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return path
}

func freeUDPPort(t *testing.T) string {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func writeJSON(t *testing.T, path string, v any) {
	raw, _ := json.Marshal(v)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T, path string) any {
	config, errs, err := Load(path)
	if err != nil || len(errs) > 0 {
		t.Fatalf("load %s: %v %v", path, err, errs)
	}
	return config
}

// startNode runs a front and one backend in process, as raycontrol renders them.
func startNode(t *testing.T, kind, zone string, options map[string]any) (resolver string) {
	return startNodeWith(t, kind, zone, options, "")
}

// startNodeWith is startNode with the front's dnsprobe-v1 key file.
func startNodeWith(t *testing.T, kind, zone string, options map[string]any, probeKeyFile string) (resolver string) {
	dir := t.TempDir()
	uid := os.Getuid()
	inner := echoInner(t, dir)
	socket := filepath.Join(dir, "dns", "packet.sock")
	os.MkdirAll(filepath.Dir(socket), 0o710)
	resolver = freeUDPPort(t)

	backendPath := filepath.Join(dir, "backend.json")
	writeJSON(t, backendPath, map[string]any{
		"schema": 1, "role": "backend", "kind": kind, "log": map[string]string{"level": "warn"},
		"socket": socket, "front_uid": uid, "options": options, "inner": inner,
	})
	frontPath := filepath.Join(dir, "front.json")
	writeJSON(t, frontPath, map[string]any{
		"schema": 1, "role": "front", "log": map[string]string{"level": "warn"},
		"backends": map[string]any{"dns": map[string]any{"socket": socket, "mode": "packet", "uid": uid}},
		"dns": map[string]any{"listen": []string{resolver}, "zones": []map[string]string{{"zone": zone, "backend": "dns"}},
			"probe_key_file": probeKeyFile},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := NewLogger("warn", io.Discard)
	go func() {
		if err := RunBackend(ctx, load(t, backendPath).(*BackendConfig), log); err != nil {
			t.Errorf("backend: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	go func() {
		if err := RunFront(ctx, load(t, frontPath).(*FrontConfig), log); err != nil {
			t.Errorf("front: %v", err)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	return resolver
}

func echoRound(t *testing.T, conn net.Conn) {
	defer conn.Close()
	message := make([]byte, 20000)
	rand.Read(message)
	go conn.Write(message)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	echo := make([]byte, len(message))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, message) {
		t.Fatal("echo differs")
	}
}

type udpDialer struct{}

func (udpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.Dial(network, destination.String())
}

func (udpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// A dnstt client reaches the inner stage through the front and the dnstt backend.
func TestNekoServerDNSTT(t *testing.T) {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	resolver := startNode(t, "dnstt", "t.example.com", map[string]any{"zone": "t.example.com", "private_key_file": keyFile})

	parsed, err := dnstt.ParseResolver("udp://" + resolver)
	if err != nil {
		t.Fatal(err)
	}
	client, err := dnstt.NewClient(dnstt.ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Dialer: udpDialer{},
		Domain: "t.example.com", PubKey: hex.EncodeToString(noise.PubkeyFromPrivkey(privkey)), Resolver: parsed,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	echoRound(t, conn)
}

// A MasterDnsVPN client (TCP mode, AES-256-GCM) reaches the inner stage.
func TestNekoServerMasterDNS(t *testing.T) {
	key := hex.EncodeToString(randomBytes(16)) // 32 characters, as the server generates
	keyFile := filepath.Join(t.TempDir(), "encryption.key")
	os.WriteFile(keyFile, []byte(key), 0o600)
	resolver := startNode(t, "masterdns", "v.example.com", map[string]any{
		"zones": []string{"v.example.com"}, "encryption_method": 5, "encryption_key_file": keyFile,
	})
	conns := make(chan net.Conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mdvembed.Run(ctx, mdvembed.Options{
		Config: map[string]any{
			"DOMAINS": []string{"v.example.com"}, "PROTOCOL_TYPE": "TCP",
			"DATA_ENCRYPTION_METHOD": 5, "ENCRYPTION_KEY": key, "LOG_LEVEL": "ERROR",
		},
		Resolvers: []string{resolver},
		WorkDir:   t.TempDir(),
		Conns:     conns,
	})
	local, remote := net.Pipe()
	select {
	case conns <- remote:
	case <-time.After(60 * time.Second):
		t.Fatal("the client did not take the connection")
	}
	echoRound(t, local)
}

// Names outside the zones get REFUSED: the node is not an open resolver.
func TestNekoServerRefused(t *testing.T) {
	privkey, _ := noise.GeneratePrivkey()
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	resolver := startNode(t, "dnstt", "t.example.com", map[string]any{"zone": "t.example.com", "private_key_file": keyFile})
	conn, err := net.Dial("udp", resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// query example.org A, ID 0x1234, RD
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}
	conn.Write(query)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer := make([]byte, 512)
	n, err := conn.Read(answer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(query) || answer[0] != 0x12 || answer[1] != 0x34 || answer[2] != 0x81 || answer[3]&0x0f != 5 {
		t.Fatalf("answer % x", answer[:n])
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// smallResolver stands for a resolver that advertises an EDNS size of 512
// to the node and drops answers larger than that: the queries' OPT gets
// 512, answers over 512 bytes go nowhere.
func smallResolver(t *testing.T, node string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	up, err := net.ResolveUDPAddr("udp4", node)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, client, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			// The OPT record is the last 11 bytes of a dnstt query.
			if n > 11 && q[n-11] == 0 && q[n-10] == 0 && q[n-9] == 41 {
				q[n-8], q[n-7] = 0x02, 0x00 // 512
			}
			go func() {
				c, err := net.DialUDP("udp4", nil, up)
				if err != nil {
					return
				}
				defer c.Close()
				c.Write(q)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				r := make([]byte, 4096)
				m, err := c.Read(r)
				if err != nil || m > 512 {
					return
				}
				pc.WriteTo(r[:m], client)
			}()
		}
	}()
	return pc.LocalAddr().String()
}

// A dnstt client through a resolver with EDNS 512: the session gets a
// small MTU and goes on, slower, where dnstt answered FORMERR before.
func TestNekoServerDNSTTSmallResolver(t *testing.T) {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	node := startNode(t, "dnstt", "t.example.com", map[string]any{"zone": "t.example.com", "private_key_file": keyFile})
	parsed, err := dnstt.ParseResolver("udp://" + smallResolver(t, node))
	if err != nil {
		t.Fatal(err)
	}
	client, err := dnstt.NewClient(dnstt.ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Dialer: udpDialer{},
		Domain: "t.example.com", PubKey: hex.EncodeToString(noise.PubkeyFromPrivkey(privkey)), Resolver: parsed,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	echoRound(t, conn)
}

// The front answers dnsprobe-v1 itself, beside a dnstt backend with
// dnsauth required (a probe never reaches it); a query without the key's
// MAC goes to the backend as before.
func TestNekoServerDNSProbe(t *testing.T) {
	privkey, _ := noise.GeneratePrivkey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	authFile := filepath.Join(dir, "auth.keys")
	os.WriteFile(authFile, nil, 0o600)
	probeKey := bytes.Repeat([]byte{5}, 32)
	probeFile := filepath.Join(dir, "dnsprobe.key")
	os.WriteFile(probeFile, []byte(hex.EncodeToString(probeKey)+"\n"), 0o600)
	zone := "t.example.com"
	node := startNodeWith(t, "dnstt", zone, map[string]any{"zone": zone, "private_key_file": keyFile,
		"auth": "required", "auth_keys_file": authFile}, probeFile)

	c, err := net.Dial("udp", node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query := func(label string, edns int) []byte {
		c.Write(probeQuery(label+"."+zone, 16, edns))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("no answer for %s: %v", label, err)
		}
		return buf[:n]
	}
	minute := uint32(time.Now().Unix() / 60)
	for _, large := range []bool{false, true} {
		label := probeLabel(probeKey, zone, large, minute, [8]byte{1, byte(map[bool]int{false: 0, true: 1}[large])})
		plain := probeOpen(t, probeKey, label, query(label, 1232), true)
		if want := map[bool]int{false: probeSmall, true: probeLarge}[large]; len(plain) != want ||
			binary.BigEndian.Uint16(plain[16:18]) != 1232 || netip.AddrFrom16([16]byte(plain[19:35])).Unmap() != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("large %v: %d bytes, % x", large, len(plain), plain[:35])
		}
	}
	// Another key's label: the backend's answer, NODATA under dnsauth
	// (NOERROR with no record).
	label := probeLabel(bytes.Repeat([]byte{6}, 32), zone, false, minute, [8]byte{2})
	if reply := query(label, 1232); reply[3]&0x0f != 0 || binary.BigEndian.Uint16(reply[6:8]) != 0 {
		t.Fatalf("a label without the key: rcode %d, %d answers, want NODATA from the backend", reply[3]&0x0f, binary.BigEndian.Uint16(reply[6:8]))
	}
}
