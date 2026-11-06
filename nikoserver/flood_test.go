//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// A flood of fresh ClientIDs, each with a packet of random bytes, takes no
// place of the handshakes (review 7: at 300 queries a second a client got
// no session within 40 s), so a client still gets its session at once.
func TestNekoServerDNSTTFreshClientIDFlood(t *testing.T) {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
	resolver := startNode(t, "dnstt", "t.example.com", map[string]any{"zone": "t.example.com", "private_key_file": keyFile})

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		c, err := net.Dial("udp", resolver)
		if err != nil {
			return
		}
		defer c.Close()
		zone, _ := dns.ParseName("t.example.com")
		tick := time.NewTicker(time.Second / 300)
		defer tick.Stop()
		for id := uint16(0); ; id++ {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			payload := make([]byte, 8+1+1+32)
			rand.Read(payload[:8])
			payload[8] = 0xe0 // no padding
			payload[9] = 32   // a packet of 32 random bytes
			rand.Read(payload[10:])
			enc := []byte(strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(payload)))
			var labels [][]byte
			for len(enc) > 0 {
				n := min(len(enc), 63)
				labels, enc = append(labels, enc[:n]), enc[n:]
			}
			name, err := dns.NewName(append(labels, zone...))
			if err != nil {
				continue
			}
			q := dns.Message{ID: id, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
				Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 1232, Data: []byte{}}}}
			b, _ := q.WireFormat()
			c.Write(b)
		}
	}()
	time.Sleep(3 * time.Second) // what the flood can take, it has taken

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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := client.DialConn(ctx)
	if err != nil {
		t.Fatalf("under the flood, no session in %v: %v", time.Since(start).Round(time.Millisecond), err)
	}
	conn.Close()
	t.Logf("under a flood of 300 fresh ClientIDs a second: a session in %v", time.Since(start).Round(time.Millisecond))
}

// A session gets dnsttserver.MaxStreams streams at once: one over the
// bound is closed at once, and a stream closed frees its place (review 8:
// each stream dials the inner stage, and a session opened as many as it
// liked). The bound as it is: a test that set it raced with the backend's
// sessions, which read it.
func TestNekoServerDNSTTStreamBound(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// echo writes a line and reads it back: nil when the stream is served.
	echo := func(conn net.Conn) error {
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := conn.Write([]byte("hello\n")); err != nil {
			return err
		}
		buf := make([]byte, 6)
		_, err := io.ReadFull(conn, buf)
		return err
	}
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for range dnsttserver.MaxStreams {
		conn, err := client.DialConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, conn)
	}
	// The last of the bound is served, so all before it were taken.
	if err := echo(open[len(open)-1]); err != nil {
		t.Fatalf("stream %d: %v", len(open), err)
	}
	over, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	if err := echo(over); err == nil {
		t.Fatal("a stream over the bound was served")
	}
	open[0].Close()
	time.Sleep(time.Second) // the close reaches the node
	again, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := echo(again); err != nil {
		t.Fatalf("a stream after one closed: %v", err)
	}
}
