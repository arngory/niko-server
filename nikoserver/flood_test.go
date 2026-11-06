//go:build linux

package nikoserver

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
