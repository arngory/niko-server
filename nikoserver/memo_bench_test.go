//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// retryingResolver stands for a resolver that asks the node again when an
// answer is late (dnstt holds a poll up to a second) and passes on the
// first answer that comes, dropping the others, as resolvers do.
func retryingResolver(t *testing.T, node string, retry time.Duration) string {
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
			go func() {
				c, err := net.DialUDP("udp4", nil, up)
				if err != nil {
					return
				}
				defer c.Close()
				r := make([]byte, 4096)
				for tries := 0; tries < 3; tries++ {
					c.Write(q)
					c.SetReadDeadline(time.Now().Add(retry))
					if m, err := c.Read(r); err == nil {
						pc.WriteTo(r[:m], client)
						return
					}
				}
			}()
		}
	}()
	return pc.LocalAddr().String()
}

// Measures a transfer through a resolver that retries after 300 ms (run
// with NIKO_MEMO_BENCH=1): with the answer memo the retries cost nothing.
func TestNekoServerDNSTTRetryingResolver(t *testing.T) {
	if os.Getenv("NIKO_MEMO_BENCH") == "" {
		t.Skip("NIKO_MEMO_BENCH=1 to measure")
	}
	echoDelay = 200 * time.Millisecond
	t.Cleanup(func() { echoDelay = 0 })
	privkey, _ := noise.GeneratePrivkey()
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	node := startNode(t, "dnstt", "t.example.com", map[string]any{"zone": "t.example.com", "private_key_file": keyFile})
	retry := 300 * time.Millisecond
	if ms, err := time.ParseDuration(os.Getenv("NIKO_MEMO_RETRY")); err == nil {
		retry = ms
	}
	parsed, _ := dnstt.ParseResolver("udp://" + retryingResolver(t, node, retry))
	client, err := dnstt.NewClient(dnstt.ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Dialer: udpDialer{},
		Domain: "t.example.com", PubKey: hex.EncodeToString(noise.PubkeyFromPrivkey(privkey)), Resolver: parsed,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Interactive: small messages with pauses; each echo comes 200 ms
	// later, while the node holds a poll the resolver retries.
	var total, worst time.Duration
	for range 20 {
		time.Sleep(400 * time.Millisecond)
		message := make([]byte, 1000)
		rand.Read(message)
		start := time.Now()
		conn.Write(message)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		echo := make([]byte, len(message))
		if _, err := io.ReadFull(conn, echo); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(echo, message) {
			t.Fatal("echo differs")
		}
		d := time.Since(start)
		total += d
		worst = max(worst, d)
	}
	t.Logf("20 echoes of 1 KB: mean %s, worst %s", (total / 20).Round(time.Millisecond), worst.Round(time.Millisecond))
}
