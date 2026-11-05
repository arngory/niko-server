//go:build linux

package nikoserver

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// The apex answers, as an authoritative server's and dnstt's: SOA, NS,
// NODATA with the SOA for another type, the question as asked, OPT only
// when the query had one; what the front does not answer is the backend's.
func TestApex(t *testing.T) {
	a := newApexZone("t.example.com", []string{"ns1.example.com.", "NS2.example.com"}, 1_800_000_000)
	ask := func(name string, qtype uint16, edns int) (dns.Message, []byte) {
		t.Helper()
		reply, ok := a.answer(probeQuery(name, qtype, edns))
		if !ok {
			t.Fatalf("%s type %d: not answered", name, qtype)
		}
		m, err := dns.MessageFromWireFormat(reply)
		if err != nil {
			t.Fatal(err)
		}
		if m.ID != 0x1234 || m.Flags != 0x8400 || len(m.Question) != 1 || m.Question[0].Name.String() != name {
			t.Fatalf("%s: header %+v", name, m)
		}
		if (edns > 0) != (len(m.Additional) == 1 && m.Additional[0].Type == dns.RRTypeOPT && m.Additional[0].Class == 4096) {
			t.Fatalf("%s: OPT %+v for EDNS %d", name, m.Additional, edns)
		}
		return m, reply
	}
	m, soaWire := ask("T.example.COM", 6, 1232)
	if len(m.Answer) != 1 || m.Answer[0].Type != 6 || m.Answer[0].TTL != 300 || len(m.Authority) != 0 {
		t.Fatalf("SOA: %+v", m)
	}
	m, nsWire := ask("t.example.com", 2, 0)
	if len(m.Answer) != 2 || !bytes.Equal(m.Answer[1].Data, wireName("ns2.example.com")) {
		t.Fatalf("NS: %+v", m)
	}
	m, nodataWire := ask("t.example.com", 1, 1232)
	if len(m.Answer) != 0 || len(m.Authority) != 1 || m.Authority[0].Type != 6 || m.Authority[0].TTL != 60 {
		t.Fatalf("A: %+v", m)
	}
	// For the check apart from this code (dnspython, test/apex.py).
	if dir := os.Getenv("APEX_WIRE_DIR"); dir != "" {
		os.WriteFile(dir+"/soa.bin", soaWire, 0o644)
		os.WriteFile(dir+"/ns.bin", nsWire, 0o644)
		os.WriteFile(dir+"/nodata.bin", nodataWire, 0o644)
	}

	// Left to the backend.
	badvers := probeQuery("t.example.com", 6, 1232)
	badvers[len(badvers)-5] = 1 // EDNS version 1
	notify := probeQuery("t.example.com", 6, 0)
	notify[2] |= 4 << 3 // opcode NOTIFY
	chaos := probeQuery("t.example.com", 6, 0)
	binary.BigEndian.PutUint16(chaos[len(chaos)-2:], 3)
	for name, q := range map[string][]byte{"EDNS version 1": badvers, "NOTIFY": notify, "class CH": chaos, "garbage": {1, 2, 3}} {
		if _, ok := a.answer(q); ok {
			t.Errorf("%s: answered by the front", name)
		}
	}
}
