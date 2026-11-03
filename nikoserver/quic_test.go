package nikoserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2b"
)

// initials captures the datagrams a quic-go client sends to a silent server.
func initials(t *testing.T, name string, version quic.Version) [][]byte {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go quic.DialAddr(ctx, ln.LocalAddr().String(),
		&tls.Config{ServerName: name, NextProtos: []string{"h3"}, InsecureSkipVerify: true},
		&quic.Config{Versions: []quic.Version{version}})
	var out [][]byte
	buf := make([]byte, 2048)
	ln.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	for {
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	if len(out) == 0 {
		t.Fatal("the client sent nothing")
	}
	return out
}

func TestNekoServerQUICInitial(t *testing.T) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		var a helloAssembler
		var hello clientHello
		done := false
		for _, d := range initials(t, "H.Example.com", v) {
			if !isQUICInitial(d) {
				t.Fatalf("%v: not an Initial: %x", v, d[:8])
			}
			p, err := parseQUICInitial(d)
			if err != nil {
				t.Fatalf("%v: %v", v, err)
			}
			if hello, done, err = a.add(p.crypto); err != nil {
				t.Fatal(err)
			}
			if done {
				break
			}
		}
		if !done || hello.serverName != "h.example.com" || len(hello.alpn) != 1 || hello.alpn[0] != "h3" {
			t.Fatalf("%v: hello %+v (complete %v)", v, hello, done)
		}
	}
	// A corrupted packet does not decrypt.
	d := initials(t, "h.example.com", quic.Version1)[0]
	d[len(d)-30] ^= 0xff
	if _, err := parseQUICInitial(d); err == nil {
		t.Fatal("a corrupted Initial decrypted")
	}
	for name, b := range map[string][]byte{"short": {0xc0, 0, 0, 0, 1}, "short header": append([]byte{0x40}, make([]byte, 40)...),
		"unknown version": append([]byte{0xc0, 0xfa, 0xce, 0xb0, 0x0c}, make([]byte, 40)...)} {
		if isQUICInitial(b) {
			t.Errorf("%s: taken for an Initial", name)
		}
	}
}

func TestNekoServerSalamander(t *testing.T) {
	d := initials(t, "x.invalid", quic.Version1)[0]
	password := []byte("cxNlY3JldC1zYWxhbWFuZGVy")
	salt := make([]byte, 8)
	rand.Read(salt)
	key := blake2b.Sum256(append(append([]byte(nil), password...), salt...))
	obfs := append([]byte(nil), salt...)
	for i, b := range d {
		obfs = append(obfs, b^key[i%32])
	}
	if isQUICInitial(obfs) {
		t.Fatal("an obfuscated packet looks like QUIC")
	}
	open, ok := salamanderOpen(password, obfs)
	if !ok || !isQUICInitial(open) || string(open) != string(d) {
		t.Fatal("salamander did not open")
	}
	if wrong, _ := salamanderOpen([]byte("another password"), obfs); isQUICInitial(wrong) {
		t.Fatal("a wrong password opened it")
	}
}
