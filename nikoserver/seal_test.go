//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/crypto/chacha20"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// sealXOR is ChaCha20 under key and nonce || 0^4, from the spec alone
// (raycontrol docs/spec/dnsseal-v1.md §2): this file does not use
// dnsttserver's seal.
func specSealXOR(key, nonce, p []byte) {
	n := make([]byte, chacha20.NonceSize)
	copy(n, nonce)
	c, err := chacha20.NewUnauthenticatedCipher(key, n)
	if err != nil {
		panic(err)
	}
	c.XORKeyStream(p, p)
}

func specMAC(key []byte, label string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	return m.Sum(nil)
}

var sealB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// sealingResolver stands for a client that seals (dnsseal-v1) in front of
// a stock dnstt client: it seals the queries, splitting the names into
// labels of random lengths, and takes the seal off the answers. The stock
// client asks under clientZone, one label longer than the node's zone, so
// that its names leave room for what the seal adds; that label goes.
func sealingResolver(t *testing.T, node, clientZone, zone string, key []byte) string {
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
	ku, kd := specMAC(key, "dnsseal-v1 up"), specMAC(key, "dnsseal-v1 down")
	cz, _ := dns.ParseName(clientZone)
	nz, _ := dns.ParseName(zone)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, client, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dns.MessageFromWireFormat(buf[:n])
			if err != nil || len(q.Question) != 1 {
				continue
			}
			asked := q.Question[0]
			prefix, ok := asked.Name.TrimSuffix(cz)
			if !ok {
				continue
			}
			payload, err := sealB32.DecodeString(strings.ToUpper(string(bytes.Join(prefix, nil))))
			if err != nil || len(payload) < 8 {
				continue
			}
			// The padding dnstt puts after the ClientID is not needed
			// under the seal: N makes the name unique (§3).
			if len(payload) > 8 && payload[8] >= 224 {
				payload = append(payload[:8:8], payload[min(len(payload), 9+int(payload[8]-224)):]...)
			}
			sealed := make([]byte, 8, 8+2+len(payload))
			rand.Read(sealed)
			sealed = append(sealed, 0, 0)
			sealed = append(sealed, payload...)
			specSealXOR(ku, sealed[:8], sealed[8:])
			text := strings.ToLower(sealB32.EncodeToString(sealed))
			var labels [][]byte
			for len(text) > 0 {
				l, _ := rand.Int(rand.Reader, big.NewInt(32))
				size := min(len(text), 32+int(l.Int64()))
				labels, text = append(labels, []byte(text[:size])), text[size:]
			}
			name, err := dns.NewName(append(labels, nz...))
			if err != nil {
				t.Errorf("a sealed name too long: %v", err)
				continue
			}
			fwd := q
			fwd.Question = []dns.Question{{Name: name, Type: asked.Type, Class: asked.Class}}
			wire, err := fwd.WireFormat()
			if err != nil {
				continue
			}
			go func() {
				c, err := net.DialUDP("udp4", nil, up)
				if err != nil {
					return
				}
				defer c.Close()
				c.Write(wire)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				r := make([]byte, 4096)
				m, err := c.Read(r)
				if err != nil {
					return
				}
				resp, err := dns.MessageFromWireFormat(r[:m])
				if err != nil {
					return
				}
				resp.Question = []dns.Question{asked}
				for i := range resp.Answer {
					resp.Answer[i].Name = asked.Name
					data, err := dns.DecodeRDataTXT(resp.Answer[i].Data)
					if err != nil || len(data) < 8 {
						t.Errorf("a sealed answer of %d bytes", len(data))
						return
					}
					if len(data)%64 != 0 && len(data) < 900 {
						t.Errorf("TXT data of %d bytes: not padded to 64", len(data))
					}
					plain := append([]byte(nil), data[8:]...)
					specSealXOR(kd, data[:8], plain)
					var frames []byte
					for i := 0; i+2 <= len(plain); {
						l := int(binary.BigEndian.Uint16(plain[i:]))
						if l == 0 || i+2+l > len(plain) {
							break
						}
						frames = append(frames, plain[i:i+2+l]...)
						i += 2 + l
					}
					resp.Answer[i].Data = dns.EncodeRDataTXT(frames)
				}
				out, err := resp.WireFormat()
				if err == nil {
					pc.WriteTo(out, client)
				}
			}()
		}
	}()
	return pc.LocalAddr().String()
}

func sealedClient(t *testing.T, resolver, zone string, privkey []byte) net.Conn {
	t.Helper()
	parsed, err := dnstt.ParseResolver("udp://" + resolver)
	if err != nil {
		t.Fatal(err)
	}
	client, err := dnstt.NewClient(dnstt.ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Dialer: udpDialer{},
		Domain: zone, PubKey: hex.EncodeToString(noise.PubkeyFromPrivkey(privkey)), Resolver: parsed,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// dnsseal-v1 through the real backend: a sealing client reaches the inner
// stage; in optional mode an open client too; in required mode an open
// query gets NODATA.
func TestNekoServerDNSTTSealed(t *testing.T) {
	for _, mode := range []string{"required", "optional"} {
		t.Run(mode, func(t *testing.T) {
			privkey, _ := noise.GeneratePrivkey()
			dir := t.TempDir()
			keyFile := filepath.Join(dir, "noise.key")
			os.WriteFile(keyFile, []byte(hex.EncodeToString(privkey)+"\n"), 0o600)
			sealKey := make([]byte, 32)
			rand.Read(sealKey)
			sealFile := filepath.Join(dir, "seal.keys")
			os.WriteFile(sealFile, []byte(hex.EncodeToString(sealKey)+"\n"), 0o600)
			zone := "t.example.com"
			node := startNode(t, "dnstt", zone, map[string]any{"zone": zone, "private_key_file": keyFile,
				"seal": mode, "seal_key_file": sealFile})

			clientZone := "padpadpadpadpadpadpadpadpad." + zone
			echoRound(t, sealedClient(t, sealingResolver(t, node, clientZone, zone, sealKey), clientZone, privkey))

			if mode == "optional" {
				echoRound(t, sealedClient(t, node, zone, privkey))
				return
			}
			// An open query (ClientID, a padding frame, a packet): NODATA.
			open := append(make([]byte, 8), 224+3, 1, 2, 3, 4, 9, 9, 9, 9)
			rand.Read(open[:8])
			c, err := net.Dial("udp", node)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write(probeQuery(strings.ToLower(sealB32.EncodeToString(open))+"."+zone, 16, 1232))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			r := make([]byte, 4096)
			n, err := c.Read(r)
			if err != nil {
				t.Fatal(err)
			}
			if m, err := dns.MessageFromWireFormat(r[:n]); err != nil || m.Rcode() != dns.RcodeNoError || len(m.Answer) != 0 {
				t.Fatalf("an open query in a required zone: %+v %v", m, err)
			}
		})
	}
}
