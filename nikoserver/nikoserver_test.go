//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	mdvembed "masterdnsvpn-go/embed"

	"github.com/arngory/niko-server/dnsttserver"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// echoDelay holds each echo back (TestNekoServerDNSTTRetryingResolver):
// data that comes while the node holds a poll.
var echoDelay time.Duration

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
				if echoDelay == 0 {
					io.Copy(conn, conn)
					return
				}
				buf := make([]byte, 32<<10)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					time.Sleep(echoDelay)
					if _, err := conn.Write(buf[:n]); err != nil {
						return
					}
				}
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

// nsFor is the zone's NS names as raycontrol renders a dnstt zone with the
// probe: the front answers its apex.
func nsFor(probeKeyFile string) []string {
	if probeKeyFile == "" {
		return nil
	}
	return []string{"ns1.example.com"}
}

// startNodeWith is startNode with the front's dnsprobe-v1 key file (and
// the zone's NS names, the front answering its apex).
func startNodeWith(t *testing.T, kind, zone string, options map[string]any, probeKeyFile string) (resolver string) {
	return startNodeFull(t, kind, zone, options, probeKeyFile, "", "")
}

// frontZones are the front's zones of a node's backend: its zone, and the
// spare zones of a dnstt backend (options "zones"), all to the same backend.
func frontZones(zone string, options map[string]any, probeKeyFile string) []map[string]any {
	zones := []map[string]any{{"zone": zone, "backend": "dns", "probe": probeKeyFile != "", "ns": nsFor(probeKeyFile)}}
	if spare, ok := options["zones"].([]string); ok && options["zone"] != nil {
		for _, z := range spare {
			zones = append(zones, map[string]any{"zone": z, "backend": "dns", "probe": probeKeyFile != "", "ns": nsFor(probeKeyFile)})
		}
	}
	return zones
}

// startNodeFull is startNodeWith with the backend's stats socket and the
// front's (dns.stats_socket).
func startNodeFull(t *testing.T, kind, zone string, options map[string]any, probeKeyFile, statsSocket, frontStats string) (resolver string) {
	dir := t.TempDir()
	uid := os.Getuid()
	inner := echoInner(t, dir)
	socket := filepath.Join(dir, "dns", "packet.sock")
	os.MkdirAll(filepath.Dir(socket), 0o710)
	resolver = freeUDPPort(t)

	backendPath := filepath.Join(dir, "backend.json")
	backend := map[string]any{
		"schema": 1, "role": "backend", "kind": kind, "log": map[string]string{"level": "warn"},
		"socket": socket, "front_uid": uid, "options": options, "inner": inner,
	}
	if statsSocket != "" {
		backend["stats_socket"] = statsSocket
	}
	writeJSON(t, backendPath, backend)
	frontPath := filepath.Join(dir, "front.json")
	dnsFront := map[string]any{"listen": []string{resolver}, "zones": frontZones(zone, options, probeKeyFile),
		"probe_key_file": probeKeyFile}
	if frontStats != "" {
		dnsFront["stats_socket"] = frontStats
	}
	writeJSON(t, frontPath, map[string]any{
		"schema": 1, "role": "front", "log": map[string]string{"level": "warn"},
		"backends": map[string]any{"dns": map[string]any{"socket": socket, "mode": "packet", "uid": uid}},
		"dns":      dnsFront,
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
	// The apex: SOA from the front, under dnsauth required too.
	c.Write(probeQuery(zone, 6, 1232))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("apex SOA: %v", err)
	}
	if m, err := dns.MessageFromWireFormat(buf[:n]); err != nil || m.Flags != 0x8400 || len(m.Answer) != 1 || m.Answer[0].Type != 6 {
		t.Fatalf("apex SOA: %+v %v", m, err)
	}
	// Another key's label: the backend's answer, NODATA under dnsauth
	// (NOERROR with no record).
	label := probeLabel(bytes.Repeat([]byte{6}, 32), zone, false, minute, [8]byte{2})
	if reply := query(label, 1232); reply[3]&0x0f != 0 || binary.BigEndian.Uint16(reply[6:8]) != 0 {
		t.Fatalf("a label without the key: rcode %d, %d answers, want NODATA from the backend", reply[3]&0x0f, binary.BigEndian.Uint16(reply[6:8]))
	}
}

// A probe key the front cannot read: no probes, and the front goes on,
// probes reaching the backend like any query of the tunnel.
func TestNekoServerDNSProbeKeyMissing(t *testing.T) {
	privkey, _ := noise.GeneratePrivkey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	probeKey := bytes.Repeat([]byte{5}, 32)
	zone := "t.example.com"
	node := startNodeWith(t, "dnstt", zone, map[string]any{"zone": zone, "private_key_file": keyFile},
		filepath.Join(dir, "missing", "dnsprobe.key"))
	c, err := net.Dial("udp", node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	label := probeLabel(probeKey, zone, false, uint32(time.Now().Unix()/60), [8]byte{3})
	c.Write(probeQuery(label+"."+zone, 16, 1232))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 4096)
	n, err := c.Read(reply)
	if err != nil {
		t.Fatalf("no answer with the probe key missing: %v", err)
	}
	// The backend's answer (dnstt's, with no data for this client), not
	// a probe's.
	m, err := dns.MessageFromWireFormat(reply[:n])
	if err != nil || m.Rcode() != dns.RcodeNoError {
		t.Fatalf("answer %+v: %v", m, err)
	}
	for _, rr := range m.Answer {
		if data, _ := dns.DecodeRDataTXT(rr.Data); len(data) == probeNonceLen+probeSmall {
			t.Fatalf("a probe answered with the key missing: %x", data)
		}
	}
}

// The DNS front's counters on dns.stats_socket (v0.11.0): queries by zone,
// and what became of them: refused outside the zones, the apex, probes,
// passed to the backend and answered; datagrams that are no query.
func TestNekoServerDNSFrontStats(t *testing.T) {
	privkey, _ := noise.GeneratePrivkey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	probeKey := bytes.Repeat([]byte{5}, 32)
	probeFile := filepath.Join(dir, "dnsprobe.key")
	os.WriteFile(probeFile, []byte(hex.EncodeToString(probeKey)+"\n"), 0o600)
	frontStats := filepath.Join(dir, "front-stats.sock")
	zone, spare := "t.example.com", "s.example.net"
	node := startNodeFull(t, "dnstt", zone, map[string]any{"zone": zone, "zones": []string{spare}, "private_key_file": keyFile},
		probeFile, "", frontStats)
	c, err := net.Dial("udp", node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	round := func(q []byte) {
		t.Helper()
		c.Write(q)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(make([]byte, 4096)); err != nil {
			t.Fatalf("no answer: %v", err)
		}
	}
	round(probeQuery("www.example.org", 1, 1232))                                                                     // refused
	round(probeQuery(zone, 6, 1232))                                                                                  // the apex
	round(probeQuery(probeLabel(probeKey, zone, false, uint32(time.Now().Unix()/60), [8]byte{1})+"."+zone, 16, 1232)) // a probe
	round(probeQuery("x."+spare, 1, 1232))                                                                            // the backend: NODATA
	round(probeQuery("y."+spare, 16, 1232))                                                                           // the backend: not the tunnel's
	c.Write([]byte{1, 2, 3})                                                                                          // no query
	time.Sleep(100 * time.Millisecond)
	s, err := net.Dial("unix", frontStats)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var st DNSFrontSnapshot
	if err := json.NewDecoder(s).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Queries[zone] != 2 || st.Queries[spare] != 2 || len(st.Queries) != 2 || st.Refused != 1 || st.Apex != 1 || st.Probes != 1 ||
		st.ProbesOverRate != 0 || st.Forwarded != 2 || st.Answers != 2 || st.BackendAway != 0 || st.Unmatched != 0 || st.Malformed != 1 ||
		time.Since(time.Unix(st.Started, 0)) > time.Minute {
		t.Fatalf("front stats %+v", st)
	}
}

// mdClient is a client of the fork against a node, run until stop.
type mdClient struct {
	conns  chan net.Conn
	cancel context.CancelFunc
	done   chan struct{} // closed when Run returns, err set before
	err    error
}

// errNoEcho: the client ran through the wait and no echo came back: what a
// node refusing it looks like. errClientExited: the client stopped on its
// own (a config the fork refuses), which says nothing of the node.
var (
	errNoEcho       = errors.New("no echo within the wait")
	errClientExited = errors.New("the client exited")
)

// startMasterdns runs a client of the fork: seal is NIKO_MDSEAL ("" for
// none), tagger the device's tags (nil for none).
func startMasterdns(resolver, key, zone, seal string, tagger func(nonce, frame []byte) [8]byte, dir string) *mdClient {
	config := map[string]any{
		"DOMAINS": []string{zone}, "PROTOCOL_TYPE": "TCP",
		"DATA_ENCRYPTION_METHOD": 5, "ENCRYPTION_KEY": key, "LOG_LEVEL": "ERROR",
	}
	if seal != "" {
		config["NIKO_MDSEAL"] = seal
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &mdClient{conns: make(chan net.Conn), cancel: cancel, done: make(chan struct{})}
	go func() {
		c.err = mdvembed.Run(ctx, mdvembed.Options{Config: config, Resolvers: []string{resolver}, WorkDir: dir, Conns: c.conns, Tagger: tagger})
		close(c.done)
	}()
	return c
}

// stop ends the client and waits for it, a while at most.
func (c *mdClient) stop() {
	c.cancel()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
	}
}

// echo sends an echo round through a new connection of the client, within
// wait.
func (c *mdClient) echo(wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	local, remote := net.Pipe()
	defer local.Close()
	select {
	case c.conns <- remote:
	case <-c.done:
		return fmt.Errorf("%w: %v", errClientExited, c.err)
	case <-timer.C:
		return fmt.Errorf("%w: the client did not take the connection", errNoEcho)
	}
	message := randomBytes(4000)
	go local.Write(message)
	read := make(chan error, 1)
	go func() {
		echo := make([]byte, len(message))
		_, err := io.ReadFull(local, echo)
		if err == nil && !bytes.Equal(echo, message) {
			err = errors.New("echo differs")
		}
		read <- err
	}()
	select {
	case err := <-read:
		return err
	case <-c.done:
		return fmt.Errorf("%w: %v", errClientExited, c.err)
	case <-timer.C:
		return errNoEcho
	}
}

// masterdnsEcho runs a client against a node for one echo round within
// wait.
func masterdnsEcho(resolver, key, zone, seal string, tagger func(nonce, frame []byte) [8]byte, wait time.Duration, dir string) error {
	c := startMasterdns(resolver, key, zone, seal, tagger, dir)
	defer c.stop()
	return c.echo(wait)
}

// deviceTagger tags masterdns queries with a device's key
// (dnsauth-masterdns §2).
func deviceTagger(k [32]byte) func(nonce, frame []byte) [8]byte {
	return func(nonce, frame []byte) [8]byte {
		return dnsttserver.Tag(&k, dnsttserver.EpochOf(time.Now()), append(append([]byte(nil), nonce...), frame...))
	}
}

// readFrontStats reads the front's counters from its stats socket.
func readFrontStats(path string) (DNSFrontSnapshot, error) {
	var st DNSFrontSnapshot
	c, err := net.Dial("unix", path)
	if err != nil {
		return st, err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	return st, json.NewDecoder(c).Decode(&st)
}

// writeKeys replaces a keys file whole, as raycontrol does (a rename): the
// reread never sees it half written.
func writeKeys(t *testing.T, path string, text string) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// masterdns with mdseal-v1 and dnsauth (v0.11.0, the client's fork):
// required, a client that seals and tags with its device's key reaches the
// inner stage; one that does not seal, does not tag, or tags with another
// key gets no session. Each refused one on a node of its own, all at once:
// the client runs through its wait (it did not stop on a config of its
// own), its queries reach the backend through the front, and no echo
// comes back.
func TestNekoServerMasterDNSSealAuth(t *testing.T) {
	key := hex.EncodeToString(randomBytes(16))
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encryption.key")
	os.WriteFile(keyFile, []byte(key), 0o600)
	var dev, other [32]byte
	copy(dev[:], randomBytes(32))
	copy(other[:], randomBytes(32))
	authFile := filepath.Join(dir, "auth.keys")
	os.WriteFile(authFile, []byte("d1 "+hex.EncodeToString(dev[:])+"\n"), 0o600)
	zone := "v.example.com"
	options := map[string]any{
		"zones": []string{zone}, "encryption_method": 5, "encryption_key_file": keyFile,
		"seal": "required", "auth": "required", "auth_keys_file": authFile,
	}
	resolver := startNode(t, "masterdns", zone, options)
	if err := masterdnsEcho(resolver, key, zone, "required", deviceTagger(dev), 60*time.Second, t.TempDir()); err != nil {
		t.Fatalf("sealed and tagged: %v", err)
	}
	var wg sync.WaitGroup
	for what, c := range map[string]struct {
		seal   string
		tagger func(nonce, frame []byte) [8]byte
	}{
		"open":        {"", deviceTagger(dev)},
		"untagged":    {"required", nil},
		"another key": {"required", deviceTagger(other)},
	} {
		stats := filepath.Join(t.TempDir(), "front-stats.sock")
		resolver := startNodeFull(t, "masterdns", zone, options, "", "", stats)
		dir := t.TempDir()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := masterdnsEcho(resolver, key, zone, c.seal, c.tagger, 8*time.Second, dir); !errors.Is(err, errNoEcho) {
				t.Errorf("%s: %v, want no echo with seal and auth required", what, err)
			}
			if st, err := readFrontStats(stats); err != nil || st.Forwarded == 0 {
				t.Errorf("%s: the client's queries did not reach the backend: %+v %v", what, st, err)
			}
		}()
	}
	wg.Wait()
}

// The keys file reread (every 5 s): a device removed loses its live
// session's answers, one added gets a session.
func TestNekoServerMasterDNSRevoke(t *testing.T) {
	key := hex.EncodeToString(randomBytes(16))
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encryption.key")
	os.WriteFile(keyFile, []byte(key), 0o600)
	var dev, late [32]byte
	copy(dev[:], randomBytes(32))
	copy(late[:], randomBytes(32))
	authFile := filepath.Join(dir, "auth.keys")
	writeKeys(t, authFile, "d1 "+hex.EncodeToString(dev[:])+"\n")
	zone := "v.example.com"
	resolver := startNode(t, "masterdns", zone, map[string]any{
		"zones": []string{zone}, "encryption_method": 5, "encryption_key_file": keyFile,
		"seal": "required", "auth": "required", "auth_keys_file": authFile,
	})
	c := startMasterdns(resolver, key, zone, "required", deviceTagger(dev), t.TempDir())
	defer c.stop()
	if err := c.echo(60 * time.Second); err != nil {
		t.Fatalf("before: %v", err)
	}
	writeKeys(t, authFile, "d2 "+hex.EncodeToString(late[:])+"\n")
	// The keys are reread every 5 s: until then the session answers, and
	// an echo that comes late before then says nothing (review 14: a fixed
	// wait left a second of margin, a slow echo ended the wait early).
	written := time.Now()
	for {
		err := c.echo(4 * time.Second)
		if errors.Is(err, errNoEcho) && time.Since(written) > 6*time.Second {
			break
		}
		if err != nil && !errors.Is(err, errNoEcho) {
			t.Fatalf("a removed device's live session: %v", err)
		}
		if time.Since(written) > 20*time.Second {
			t.Fatal("a removed device's live session still answers 20 s after its key went")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := c.echo(8 * time.Second); !errors.Is(err, errNoEcho) {
		t.Fatalf("a removed device's live session afterwards: %v, want no echo", err)
	}
	if err := masterdnsEcho(resolver, key, zone, "required", deviceTagger(late), 60*time.Second, t.TempDir()); err != nil {
		t.Fatalf("a device added: %v", err)
	}
}

// optional: a client of before (no seal, no tag) goes on as it did, and
// one that seals and tags too.
func TestNekoServerMasterDNSOptional(t *testing.T) {
	key := hex.EncodeToString(randomBytes(16))
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encryption.key")
	os.WriteFile(keyFile, []byte(key), 0o600)
	var dev [32]byte
	copy(dev[:], randomBytes(32))
	authFile := filepath.Join(dir, "auth.keys")
	os.WriteFile(authFile, []byte("d1 "+hex.EncodeToString(dev[:])+"\n"), 0o600)
	zone := "v.example.com"
	resolver := startNode(t, "masterdns", zone, map[string]any{
		"zones": []string{zone}, "encryption_method": 5, "encryption_key_file": keyFile,
		"seal": "optional", "auth": "optional", "auth_keys_file": authFile,
	})
	if err := masterdnsEcho(resolver, key, zone, "", nil, 60*time.Second, t.TempDir()); err != nil {
		t.Fatalf("a client of before: %v", err)
	}
	if err := masterdnsEcho(resolver, key, zone, "optional", deviceTagger(dev), 60*time.Second, t.TempDir()); err != nil {
		t.Fatalf("a client that seals and tags: %v", err)
	}
}
