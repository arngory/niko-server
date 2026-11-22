//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

// options.pq (v0.19.0): a Yggdrasil option, off, answer or on; absent off.
func TestNekoServerConfigPQ(t *testing.T) {
	ygg := `{"schema":1,"role":"backend","kind":"yggdrasil","socket":"/run/niko/ygg/fd.sock","front_uid":9100,
		"users_file":"/run/niko-rendered/ygg/users.json",
		"tls":{"certificate_file":"/run/credentials/niko-ygg.service/chain.pem","key_file":"/run/credentials/niko-ygg.service/key.pem"},
		"options":{"private_key_file":"/run/credentials/niko-ygg.service/node.key","exit_ports":[4433]%s},
		"inner":"/run/niko/inner/vless.sock"}`
	for _, opt := range []string{``, `,"pq":"off"`, `,"pq":"answer"`, `,"pq":"on"`} {
		if errs := checkConfig(t, fmt.Sprintf(ygg, opt)); len(errs) > 0 {
			t.Errorf("%q: %v", opt, errs)
		}
	}
	for _, opt := range []string{`,"pq":"yes"`, `,"pq":"ON"`, `,"pq":true`, `,"pq":1`} {
		errs := checkConfig(t, fmt.Sprintf(ygg, opt))
		if len(errs) == 0 {
			t.Errorf("%q passed", opt)
		}
	}
	if errs := checkConfig(t, fmt.Sprintf(ygg, `,"pq":"yes"`)); len(errs) != 1 || errs[0].Path != "options.pq" {
		t.Errorf("yes: %v", errs)
	}
	hy2 := `{"schema":1,"role":"backend","kind":"hy2-masq","socket":"/run/niko/h/packet.sock","front_uid":9100,
		"users_file":"/r/h/users.json","tls":{"certificate_file":"/r/h/chain.pem","key_file":"/run/niko/h/key.pem"},
		"options":{"pq":"on"}}`
	if errs := checkConfig(t, hy2); len(errs) != 1 || errs[0].Path != "options.pq" {
		t.Errorf("pq on hy2-masq: %v", errs)
	}
}

// options.pq to the core's option: none off, AnswerOnly answer, the option
// alone on (core.PQSessions: off, answer only, on).
func TestYggPQOption(t *testing.T) {
	for mode, want := range map[string]string{"": "[]", "off": "[]", "answer": "[{<nil> true}]", "on": "[{<nil> false}]"} {
		if got := fmt.Sprint(yggPQ(mode)); got != want {
			t.Errorf("%q: %s, want %s", mode, got, want)
		}
	}
}

// The core's lines, ironwood's PQ warnings among them, reach the journal
// without a key: neither ironwood's 8-byte prefix nor a whole key. Below
// the level, nothing is formatted.
func TestYggLogNoKeys(t *testing.T) {
	var out bytes.Buffer
	l := yggLog{NewLogger("info", &out)}
	key := make([]byte, 32)
	rand.Read(key)
	key[0] = 0xab // a letter in every run: one of digits alone would stay
	l.Warnf("PQ: %x answers no PQ init under its ML-KEM key number %d", key[:8], 3)
	l.Errorf("link with %s: %v", hex.EncodeToString(key), io.EOF)
	l.Warnln("key", hex.EncodeToString(key[:16]))
	l.Debugf("PQ: %x", key[:8])                             // below info: not written
	l.Warnf("refused until %d", int64(1795000000123456789)) // digits alone: a time, kept
	got := out.String()
	for _, k := range []string{hex.EncodeToString(key[:8]), hex.EncodeToString(key[:4])} {
		if strings.Contains(got, k) {
			t.Fatalf("a key in the log: %q", got)
		}
	}
	if strings.Count(got, "\n") != 4 || strings.Count(got, "<key>") != 3 || !strings.Contains(got, "key number 3") ||
		!strings.Contains(got, "until 1795000000123456789") {
		t.Fatalf("log: %q", got)
	}
}

// A Niko client in each PQ mode against the node in each, with the
// client's key above the node's and below it (of two ends with a classic
// session, the one with the lower key starts the PQ one): echo through the
// exit port in every pair, and a PQ session only where one end starts it
// and the other takes it (on with on or answer); a client without PQ
// sessions still reaches the node in a classic one. The client's ironwood
// lines go to the test's log.
func TestNekoServerYggdrasilPQ(t *testing.T) {
	type pair struct {
		node   string
		client *core.PQSessions // nil: an upstream client, no PQ sessions
		want   string
	}
	for _, c := range []pair{
		{"off", &core.PQSessions{}, "classic"},
		{"answer", &core.PQSessions{}, "pq"},
		{"on", &core.PQSessions{}, "pq"},
		{"answer", &core.PQSessions{AnswerOnly: true}, "classic"},
		{"on", nil, "classic"},
		{"answer", nil, "classic"},
	} {
		mode := "none"
		if c.client != nil {
			mode = "on"
			if c.client.AnswerOnly {
				mode = "answer"
			}
		}
		for _, higher := range []bool{true, false} {
			order := "client key lower"
			if higher {
				order = "client key higher"
			}
			t.Run("node "+c.node+", client "+mode+", "+order, func(t *testing.T) {
				testYggPQPair(t, c.node, c.client, c.want, higher)
			})
		}
	}
}

// tLog is a Logger's writer into the test's log.
type tLog struct{ t *testing.T }

func (w tLog) Write(b []byte) (int, error) {
	w.t.Helper()
	w.t.Logf("client: %s", strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

func testYggPQPair(t *testing.T, nodeMode string, clientPQ *core.PQSessions, want string, higher bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := startYggNode(t, ctx, func(b *BackendConfig) { b.Options.PQ = nodeMode })
	var public ed25519.PublicKey
	var private ed25519.PrivateKey
	for {
		public, private, _ = ed25519.GenerateKey(rand.Reader)
		if (bytes.Compare(public, n.key) > 0) == higher {
			break
		}
	}
	cert, err := yggCertificate(private)
	if err != nil {
		t.Fatal(err)
	}
	opts := []core.SetupOption{core.Peer{URI: n.peer}}
	if clientPQ != nil {
		opts = append(opts, *clientPQ)
	}
	n.setUsers(t, public)
	client, err := core.New(cert, yggLog{NewLogger("warn", tLog{t})}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	rwc := ipv6rwc.NewReadWriteCloser(client)
	defer rwc.Close()
	addr, _ := netip.AddrFromSlice(client.Address())
	s, err := yggNetstack(ctx, rwc, addr, uint32(rwc.MTU()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !waitFor(10*time.Second, func() bool { return peerUp(client) }) {
		t.Fatalf("the link is not up: %+v", client.GetPeers())
	}
	nodeAddr := tcpip.AddrFrom16Slice(address.AddrForKey(n.key)[:])
	session := func() string {
		for _, s := range client.PacketConn.Debug.GetSessions() {
			if bytes.Equal(s.Key, n.key) {
				if s.PQ && s.PQConfirmed {
					return "pq"
				}
				if s.PQ {
					return "pq, unconfirmed"
				}
				return "classic"
			}
		}
		return "none"
	}
	echo := func() error {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(dctx, s, tcpip.FullAddress{NIC: 1, Addr: nodeAddr, Port: 4433}, ipv6.ProtocolNumber)
		if err != nil {
			return err
		}
		defer conn.Close()
		payload := make([]byte, 64<<10)
		rand.Read(payload)
		go conn.Write(payload)
		got := make([]byte, len(payload))
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("the echo differs")
		}
		return nil
	}
	if err := echo(); err != nil {
		t.Fatalf("echo through inner: %v", err)
	}
	// the upgrade to PQ comes after the first traffic: echo until the
	// session settles, and once more on it
	got := session()
	for deadline := time.Now().Add(20 * time.Second); got != want && time.Now().Before(deadline); got = session() {
		if err := echo(); err != nil {
			t.Fatalf("echo through inner, session %s: %v", got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("session %s, want %s", got, want)
	}
	if want == "classic" {
		// and it stays so: no upgrade a second later
		time.Sleep(time.Second)
		if err := echo(); err != nil {
			t.Fatalf("echo: %v", err)
		}
		if got := session(); got != "classic" {
			t.Fatalf("session %s a second on, want classic", got)
		}
	}
	if err := echo(); err != nil {
		t.Fatalf("echo through inner, session %s: %v", got, err)
	}
}
