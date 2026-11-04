package dnsttserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestAuth(t *testing.T) {
	var alice, bob [32]byte
	rand.Read(alice[:])
	rand.Read(bob[:])
	now := time.Unix(1_800_000_000, 0)
	a := &Auth{Mode: AuthRequired, Now: func() time.Time { return now }}
	keys := "# devices\nd-alice " + hex.EncodeToString(alice[:]) + "\n\nd-bob " + hex.EncodeToString(bob[:]) + "\n"
	if err := a.SetKeys([]byte(keys)); err != nil {
		t.Fatal(err)
	}
	body := append([]byte("CLIENTID"), []byte("\xe0padding and packets")...)
	signed := func(key *[32]byte, at time.Time) []byte {
		tag := Tag(key, EpochOf(at), body)
		return append(tag[:], body...)
	}

	for name, c := range map[string]struct {
		payload []byte
		mode    AuthMode
		ok      bool
		rest    []byte
	}{
		"alice":                  {signed(&alice, now), AuthRequired, true, body},
		"bob, the epoch before":  {signed(&bob, now.Add(-AuthEpoch)), AuthRequired, true, body},
		"alice, the epoch after": {signed(&alice, now.Add(AuthEpoch)), AuthRequired, true, body},
		"alice, two epochs late": {signed(&alice, now.Add(-2*AuthEpoch)), AuthRequired, false, nil},
		"untagged, required":     {body, AuthRequired, false, nil},
		"untagged, optional":     {body, AuthOptional, true, body},
		"tagged, optional":       {signed(&bob, now), AuthOptional, true, body},
		"untagged, off":          {body, AuthOff, true, body},
		"short":                  {[]byte("short"), AuthRequired, false, nil},
		"tampered after the tag": {append(signed(&alice, now)[:len(body)+AuthTagLen-1], 'X'), AuthRequired, false, nil},
	} {
		a.Mode = c.mode
		rest, ok := a.Check(c.payload)
		if ok != c.ok || !bytes.Equal(rest, c.rest) {
			t.Errorf("%s: ok %v rest %q, want %v %q", name, ok, rest, c.ok, c.rest)
		}
	}

	// A device that is gone: its tags stop, also for a session cached on it.
	a.Mode = AuthRequired
	if err := a.SetKeys([]byte("d-bob " + hex.EncodeToString(bob[:]) + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(signed(&alice, now)); ok {
		t.Fatal("a removed key still signs")
	}
	if _, ok := a.Check(signed(&bob, now)); !ok {
		t.Fatal("a kept key no longer signs")
	}
	if a.Refused.Load() == 0 || a.Valid.Load() == 0 || a.Untagged.Load() == 0 {
		t.Fatalf("counters %d %d %d", a.Valid.Load(), a.Untagged.Load(), a.Refused.Load())
	}

	for _, bad := range []string{"d-x 1234", "d-x zz" + hex.EncodeToString(bob[:])[2:], "only-one-field"} {
		if err := a.SetKeys([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// No keys at all: nothing passes in required mode.
	a.SetKeys(nil)
	if _, ok := a.Check(signed(&bob, now)); ok {
		t.Fatal("a tag passed without keys")
	}
	for _, s := range []string{"", "off", "optional", "required"} {
		if _, err := ParseAuthMode(s); err != nil {
			t.Error(s, err)
		}
	}
	if _, err := ParseAuthMode("strict"); err == nil {
		t.Error("strict accepted")
	}
}

// The real server on UDP: in required mode a query without a valid tag is
// answered NXDOMAIN, as by an empty zone; a tagged one is the tunnel's
// (NOERROR, authoritative).
func TestAuthServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := hex.DecodeString(priv)
	var dev [32]byte
	rand.Read(dev[:])
	auth := &Auth{Mode: AuthRequired}
	if err := auth.SetKeys([]byte("d1 " + hex.EncodeToString(dev[:]))); err != nil {
		t.Fatal(err)
	}
	go RunAuth(privKey, "t.example.com", pc, func(time.Duration) (net.Conn, error) { return nil, errors.New("no upstream") }, auth)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ask := func(payload []byte) uint16 {
		t.Helper()
		enc := []byte(strings.ToLower(base32Encoding.EncodeToString(payload)))
		var labels [][]byte
		for len(enc) > 0 {
			n := min(len(enc), 63)
			labels, enc = append(labels, enc[:n]), enc[n:]
		}
		zone, _ := dns.ParseName("t.example.com")
		name, err := dns.NewName(append(labels, zone...))
		if err != nil {
			t.Fatal(err)
		}
		q := dns.Message{ID: 7, Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
			Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}}}}
		b, err := q.WireFormat()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		r, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return r.Rcode()
	}
	body := append([]byte("CLIENTID"), 0xe0) // a ClientID, no packets
	if rc := ask(body); rc != dns.RcodeNameError {
		t.Fatalf("untagged query: rcode %d, want NXDOMAIN", rc)
	}
	tag := Tag(&dev, EpochOf(time.Now()), body)
	if rc := ask(append(tag[:], body...)); rc != dns.RcodeNoError {
		t.Fatalf("tagged query: rcode %d, want NOERROR", rc)
	}
	var other [32]byte
	tag = Tag(&other, EpochOf(time.Now()), body)
	if rc := ask(append(tag[:], body...)); rc != dns.RcodeNameError {
		t.Fatalf("query tagged by another key: rcode %d, want NXDOMAIN", rc)
	}
}
