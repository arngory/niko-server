//go:build linux

package nikoserver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkConfig(t *testing.T, content string) []ConfigError {
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(content), 0o600)
	_, errs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return errs
}

// The configs raycontrol renders (internal/render, R1) pass; mistakes name their path.
func TestNekoServerConfigCheck(t *testing.T) {
	front := `{"schema":1,"role":"front","log":{"level":"warn"},
		"backends":{"dns":{"socket":"/run/niko/dns/packet.sock","mode":"packet","uid":9110}},
		"dns":{"listen":["0.0.0.0:53","[::]:53"],"zones":[{"zone":"t.example.com","backend":"dns"}]}}`
	if errs := checkConfig(t, front); len(errs) > 0 {
		t.Fatal(errs)
	}
	// dnsprobe-v1 in the dnstt zone (v0.8.3).
	probed := strings.Replace(front, `"backend":"dns"}]`, `"backend":"dns","probe":true,"ns":["xk2.example.com"]}],"probe_key_file":"/run/niko/front/dnsprobe.key"`, 1)
	if errs := checkConfig(t, probed); len(errs) > 0 {
		t.Fatal(errs)
	}
	// R2: tcpmux, as raycontrol renders it with the front on TCP 443.
	tcpFront := `{"schema":1,"role":"front","log":{"level":"warn"},
		"backends":{"reality":{"socket":"/run/niko/reality/reality.sock","mode":"proxy-v2","uid":9111},
			"naive":{"socket":"/run/niko/naive-in/fd.sock","mode":"fd","uid":9112}},
		"tcp":{"listen":["0.0.0.0:443","[::]:443"],"sniff_timeout":"5s",
			"routes":[{"sni":["r.example.com"],"backend":"reality"},{"sni":["n.example.com"],"backend":"naive"}],
			"default":"reality"}}`
	if errs := checkConfig(t, tcpFront); len(errs) > 0 {
		t.Fatal(errs)
	}
	dnstt := `{"schema":1,"role":"backend","kind":"dnstt","log":{"level":"warn"},"socket":"/run/niko/dns/packet.sock",
		"front_uid":9100,"options":{"zone":"t.example.com","private_key_file":"/run/credentials/niko-dns.service/noise.key"},
		"inner":"/run/niko/inner/vless.sock"}`
	if errs := checkConfig(t, dnstt); len(errs) > 0 {
		t.Fatal(errs)
	}
	// dnsseal-v1.
	sealed := strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","seal":"optional","seal_key_file":"/run/credentials/niko-dns.service/seal.keys"`, 1)
	if errs := checkConfig(t, sealed); len(errs) > 0 {
		t.Fatal(errs)
	}
	// dnsauth-v1 (raycontrol S-9).
	authed := strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","auth":"optional","auth_keys_file":"/var/lib/raycontrol/rendered/dns/auth.keys"`, 1)
	if errs := checkConfig(t, authed); len(errs) > 0 {
		t.Fatal(errs)
	}
	masterdns := `{"schema":1,"role":"backend","kind":"masterdns","socket":"/run/niko/mdns/packet.sock","front_uid":9100,
		"options":{"zones":["v.example.com"],"encryption_method":5,"encryption_key_file":"/run/credentials/niko-mdns.service/encryption.key"},
		"inner":"/run/niko/inner/vless.sock"}`
	if errs := checkConfig(t, masterdns); len(errs) > 0 {
		t.Fatal(errs)
	}
	// R4: Yggdrasil behind tcpmux.
	ygg := `{"schema":1,"role":"backend","kind":"yggdrasil","socket":"/run/niko/ygg/fd.sock","front_uid":9100,
		"users_file":"/run/niko-rendered/ygg/users.json",
		"tls":{"certificate_file":"/run/credentials/niko-ygg.service/chain.pem","key_file":"/run/credentials/niko-ygg.service/key.pem"},
		"options":{"private_key_file":"/run/credentials/niko-ygg.service/node.key","exit_ports":[4433]},
		"inner":"/run/niko/inner/vless.sock"}`
	if errs := checkConfig(t, ygg); len(errs) > 0 {
		t.Fatal(errs)
	}

	hy2 := `{"schema":1,"role":"backend","kind":"hy2-masq","socket":"/run/niko/h/packet.sock","front_uid":9100,
		"users_file":"/r/h/users.json","tls":{"certificate_file":"/r/h/chain.pem","key_file":"/run/niko/h/key.pem"},
		"stats_socket":"/run/niko/h/stats.sock",
		"options":{"probe":{"name":"probe.raycontrol.invalid","address":"127.0.0.1:34567"}}}`
	if errs := checkConfig(t, hy2); len(errs) > 0 {
		t.Fatal(errs)
	}
	// dnstt with spare zones (v0.11.0, raycontrol dnszones-v1).
	if errs := checkConfig(t, strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","zones":["s.example.net","u.example.org."]`, 1)); len(errs) > 0 {
		t.Fatalf("dnstt with spare zones: %v", errs)
	}
	// dnstt has its counters on a stats socket (v0.11.0).
	if errs := checkConfig(t, strings.Replace(dnstt, `"inner":`, `"stats_socket":"/run/niko/dns/stats.sock","inner":`, 1)); len(errs) > 0 {
		t.Fatalf("dnstt with a stats socket: %v", errs)
	}
	for want, content := range map[string]string{
		"stats_socket":              strings.Replace(masterdns, `"inner":`, `"stats_socket":"/run/niko/mdns/stats.sock","inner":`, 1),
		"options.probe.address":     strings.Replace(hy2, `127.0.0.1:34567`, `203.0.113.7:34567`, 1),
		"options.probe.name":        strings.Replace(hy2, `"probe.raycontrol.invalid"`, `"bad name"`, 1),
		"options.probe":             strings.Replace(ygg, `"exit_ports":[4433]`, `"exit_ports":[4433],"probe":{"name":"p.invalid","address":"127.0.0.1:1"}`, 1),
		"options.exit_ports":        strings.Replace(ygg, `"exit_ports":[4433]`, `"exit_ports":[]`, 1),
		"options.exit_ports[1]":     strings.Replace(ygg, `"exit_ports":[4433]`, `"exit_ports":[4433,4433]`, 1),
		"options.peers[0]":          strings.Replace(ygg, `"exit_ports":[4433]`, `"exit_ports":[4433],"peers":["unix:///tmp/x"]`, 1),
		"tls.curves[0]":             strings.Replace(ygg, `"key_file"`, `"curves":["X25519"],"key_file"`, 1),
		"options":                   strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","exit_ports":[1]`, 1),
		"schema":                    `{"schema":2,"role":"front"}`,
		"tcp.routes":                strings.Replace(front, `"dns":{"listen"`, `"tcp":{"listen":["0.0.0.0:443"],"routes":[]},"dns":{"listen"`, 1),
		"tcp.routes[0].backend":     strings.Replace(front, `"dns":{"listen"`, `"tcp":{"listen":["0.0.0.0:443"],"routes":[{"sni":["r.example.com"],"backend":"dns"}]},"dns":{"listen"`, 1),
		"tcp.acme_listen":           strings.Replace(tcpFront, `"default"`, `"acme_listen":["0.0.0.0:9443"],"default"`, 1),
		"tcp.routes[1].sni[0]":      strings.Replace(tcpFront, `"sni":["n.example.com"]`, `"sni":["R.example.com."]`, 1),
		"udp.routes":                strings.Replace(front, `"dns":{"listen"`, `"udp":{"listen":["0.0.0.0:443"]},"dns":{"listen"`, 1),
		"dns.zones[0].backend":      strings.Replace(front, `"backend":"dns"}]`, `"backend":"nope"}]`, 1),
		"dns.stats_socket":          strings.Replace(front, `"dns":{"listen"`, `"dns":{"stats_socket":"front-stats.sock","listen"`, 1),
		"dns.zones[0].probe":        strings.Replace(front, `"backend":"dns"}]`, `"backend":"dns","probe":true}]`, 1),
		"dns.zones[0].ns[1]":        strings.Replace(front, `"backend":"dns"}]`, `"backend":"dns","ns":["ns1.example.com","bad name"]}]`, 1),
		"dns.zones[0].seal_pad":     strings.Replace(front, `"backend":"dns"}]`, `"backend":"dns","seal_pad":true}]`, 1),
		"options.seal":              strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","seal":"on"`, 1),
		"options.seal_key_file":     strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","seal":"required"`, 1),
		"dns.listen[1]":             strings.Replace(front, `"[::]:53"`, `"localhost:53"`, 1),
		"options.encryption_method": strings.Replace(masterdns, `"encryption_method":5`, `"encryption_method":2`, 1),
		"inner":                     strings.Replace(dnstt, `"inner":"/run/niko/inner/vless.sock"`, `"inner":"relative.sock"`, 1),
		"kind":                      strings.Replace(dnstt, `"kind":"dnstt"`, `"kind":"naive"`, 1),
		"options.auth":              strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","auth":"strict"`, 1),
		"options.auth_keys_file":    strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","auth":"required"`, 1),
		"options.zones[0]":          strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","zones":["T.example.com."]`, 1),
		"options.zones[1]":          strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","zones":["s.example.net","bad name"]`, 1),
		"options.zones":             strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","zones":["a.ex.com","b.ex.com","c.ex.com","d.ex.com","e.ex.com"]`, 1),
	} {
		errs := checkConfig(t, content)
		found := false
		for _, e := range errs {
			found = found || e.Path == want
		}
		if !found {
			t.Errorf("%s: no error at that path, got %v", want, errs)
		}
	}
}

func TestNekoServerZoneMatch(t *testing.T) {
	zones := []string{"t.example.com", "v.example.com"}
	for name, want := range map[string]string{
		"abc.t.example.com": "t.example.com", "T.EXAMPLE.COM.": "t.example.com",
		"xt.example.com": "", "example.com": "", "a.v.example.com": "v.example.com",
	} {
		if got := zoneOf(name, zones); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// Zones that nest are refused, in a tunnel and in the front: a name under
// both is either's (review 11); so are names over 253 characters, which
// passed check and stopped the backend at its start.
func TestNekoServerConfigZonesNestAndLength(t *testing.T) {
	front := `{"schema":1,"role":"front","log":{"level":"warn"},
		"backends":{"dns":{"socket":"/run/niko/dns/packet.sock","mode":"packet","uid":9110},
			"mdns":{"socket":"/run/niko/mdns/packet.sock","mode":"packet","uid":9111}},
		"dns":{"listen":["0.0.0.0:53"],"zones":[{"zone":"t.example.com","backend":"dns"},{"zone":"ZONE2","backend":"mdns"}]}}`
	dnstt := `{"schema":1,"role":"backend","kind":"dnstt","log":{"level":"warn"},"socket":"/run/niko/dns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zone":"ZONE1","zones":["ZONE2"],"private_key_file":"/run/credentials/niko-dns.service/dnstt.key"}}`
	long := strings.Repeat("a.", 126) + "com" // 255 characters
	for _, c := range []struct {
		content, path string
	}{
		{strings.Replace(front, "ZONE2", "x.t.example.com", 1), "dns.zones[1].zone"},
		{strings.Replace(front, "ZONE2", "example.com", 1), "dns.zones[1].zone"},
		{strings.Replace(front, "ZONE2", long, 1), "dns.zones[1].zone"},
		{strings.Replace(strings.Replace(dnstt, "ZONE1", "t.example.com", 1), "ZONE2", "x.T.example.com.", 1), "options.zones[0]"},
		{strings.Replace(strings.Replace(dnstt, "ZONE1", "x.t.example.com", 1), "ZONE2", "t.example.com", 1), "options.zones[0]"},
		{strings.Replace(strings.Replace(dnstt, "ZONE1", long, 1), "ZONE2", "s.example.net", 1), "options.zone"},
		{strings.Replace(strings.Replace(dnstt, "ZONE1", "t.example.com", 1), "ZONE2", long, 1), "options.zones[0]"},
	} {
		errs := checkConfig(t, c.content)
		found := false
		for _, e := range errs {
			found = found || e.Path == c.path
		}
		if !found {
			t.Errorf("%s: no error at that path, got %v", c.path, errs)
		}
	}
	// Siblings and a zone ending as another without a dot between are fine.
	for _, ok := range []string{
		strings.Replace(front, "ZONE2", "u.example.com", 1),
		strings.Replace(front, "ZONE2", "at.example.com", 1),
		strings.Replace(strings.Replace(dnstt, "ZONE1", "t.example.com", 1), "ZONE2", "at.example.com", 1),
		strings.Replace(strings.Replace(dnstt, "ZONE1", strings.Repeat("a.", 125)+"com", 1), "ZONE2", "s.example.net", 1),
	} {
		if errs := checkConfig(t, ok); len(errs) > 0 {
			t.Errorf("%v", errs)
		}
	}
}

// Review 12: a name that folds into ASCII (the Kelvin sign) is no zone; a
// stats socket on another socket's path, entries of one tunnel unlike,
// masterdns zones twice or nested, are refused.
func TestNekoServerConfigReview12(t *testing.T) {
	front := `{"schema":1,"role":"front","log":{"level":"warn"},
		"backends":{"dns":{"socket":"/run/niko/dns/packet.sock","mode":"packet","uid":9110}},
		"dns":{"listen":["0.0.0.0:53"],"probe_key_file":"/run/niko/front/dnsprobe.key","zones":[ZONES]}}`
	dnstt := `{"schema":1,"role":"backend","kind":"dnstt","log":{"level":"warn"},"socket":"/run/niko/dns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zone":"ZONE1","private_key_file":"/run/credentials/niko-dns.service/dnstt.key"}}`
	masterdns := `{"schema":1,"role":"backend","kind":"masterdns","log":{"level":"warn"},"socket":"/run/niko/mdns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zones":[MZONES],"encryption_method":5,"encryption_key_file":"/run/credentials/niko-mdns.service/encryption.key"}}`
	entry := `{"zone":"%s","backend":"dns","probe":%v,"seal_pad":%v,"ns":["ns1.example.com"]}`
	mdOne := strings.Replace(masterdns, "MZONES", `"m.example.com"`, 1)
	zones := func(es ...string) string { return strings.Replace(front, "ZONES", strings.Join(es, ","), 1) }
	for _, c := range []struct{ content, path string }{
		{strings.Replace(dnstt, "ZONE1", "K.example.com", 1), "options.zone"},
		{zones(fmt.Sprintf(entry, "K.example.com", true, true)), "dns.zones[0].zone"},
		{strings.Replace(front, `"zones":[ZONES]`, `"stats_socket":"/run/niko/dns/packet.sock","zones":[`+fmt.Sprintf(entry, "t.example.com", true, true)+`]`, 1), "dns.stats_socket"},
		{strings.Replace(dnstt, `"inner":`, `"stats_socket":"/run/niko/dns/packet.sock","inner":`, 1), "stats_socket"},
		{zones(fmt.Sprintf(entry, "t.example.com", true, true), fmt.Sprintf(entry, "s.example.net", true, false)), "dns.zones[1]"},
		{zones(fmt.Sprintf(entry, "t.example.com", true, true), strings.Replace(fmt.Sprintf(entry, "s.example.net", true, true), "ns1.", "ns2.", 1)), "dns.zones[1]"},
		{strings.Replace(masterdns, "MZONES", `"m.example.com","M.example.com."`, 1), "options.zones[1]"},
		{strings.Replace(masterdns, "MZONES", `"m.example.com","x.m.example.com"`, 1), "options.zones[1]"},
		{strings.Replace(masterdns, "MZONES", `"K.example.com"`, 1), "options.zones[0]"},
		{strings.Replace(mdOne, `"encryption_method":5`, `"encryption_method":5,"seal":"sealed"`, 1), "options.seal"},
		// mdseal-v1 seals with the service's key: no key file of its own.
		{strings.Replace(mdOne, `"encryption_method":5`, `"encryption_method":5,"seal":"required","seal_key_file":"/run/x/seal.keys"`, 1), "options.seal_key_file"},
		{strings.Replace(mdOne, `"encryption_method":5`, `"encryption_method":5,"auth":"strict"`, 1), "options.auth"},
		{strings.Replace(mdOne, `"encryption_method":5`, `"encryption_method":5,"auth":"required"`, 1), "options.auth_keys_file"},
		{strings.Replace(mdOne, `"encryption_method":5`, `"encryption_method":5,"auth":"required","auth_keys_file":"rel.keys"`, 1), "options.auth_keys_file"},
	} {
		errs := checkConfig(t, c.content)
		found := false
		for _, e := range errs {
			found = found || e.Path == c.path
		}
		if !found {
			t.Errorf("%s: no error at that path, got %v", c.path, errs)
		}
	}
	// Alike entries of one tunnel, and masterdns's spares, pass.
	for _, ok := range []string{
		zones(fmt.Sprintf(entry, "t.example.com", true, true), fmt.Sprintf(entry, "S.example.net.", true, true)),
		strings.Replace(masterdns, "MZONES", `"m.example.com","v.example.net"`, 1),
		strings.Replace(strings.Replace(masterdns, "MZONES", `"m.example.com"`, 1), `"encryption_method":5`,
			`"encryption_method":5,"seal":"required","auth":"optional","auth_keys_file":"/run/niko/mdns-in/auth.keys","auth_scan_hmacs":50000`, 1),
		strings.Replace(dnstt, "ZONE1", "T.Example.COM.", 1),
	} {
		if errs := checkConfig(t, ok); len(errs) > 0 {
			t.Errorf("%v", errs)
		}
	}
}

// Review 13: a name the zones are delegated to that lies in a zone is
// refused (the front would send the queries for its address to the
// tunnel); a stats socket on the path of any file the process uses, as
// written or cleaned, is refused (it is removed before the listen); one
// tunnel's ns compare as names.
func TestNekoServerConfigReview13(t *testing.T) {
	front := `{"schema":1,"role":"front","log":{"level":"warn"},
		"backends":{"dns":{"socket":"/run/niko/dns/packet.sock","mode":"packet","uid":9110}},
		"dns":{"listen":["0.0.0.0:53"],"probe_key_file":"/run/niko/front/dnsprobe.key","zones":[ZONES]}}`
	dnstt := `{"schema":1,"role":"backend","kind":"dnstt","log":{"level":"warn"},"socket":"/run/niko/dns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zone":"t.example.com","private_key_file":"/run/credentials/niko-dns.service/dnstt.key",
		"auth":"optional","auth_keys_file":"/run/niko/dns-in/auth.keys","seal":"optional","seal_key_file":"/run/niko/dns-in/seal.keys"}}`
	entry := `{"zone":"%s","backend":"dns","ns":["%s"]}`
	hy2 := `{"schema":1,"role":"backend","kind":"hy2-masq","socket":"/run/niko/h/packet.sock","front_uid":9100,
		"users_file":"/r/h/users.json","tls":{"certificate_file":"/r/h/chain.pem","key_file":"/run/niko/h/key.pem"},
		"stats_socket":"STATS","options":{"obfs_password_file":"/r/h/obfs.pass"}}`
	zones := func(es ...string) string { return strings.Replace(front, "ZONES", strings.Join(es, ","), 1) }
	stats := func(path string) string {
		return strings.Replace(dnstt, `"inner":`, `"stats_socket":"`+path+`","inner":`, 1)
	}
	for _, c := range []struct{ content, path string }{
		{zones(fmt.Sprintf(entry, "t.example.com", "ns.t.example.com")), "dns.zones[0].ns[0]"},
		{zones(fmt.Sprintf(entry, "t.example.com", "T.example.com.")), "dns.zones[0].ns[0]"},
		{zones(fmt.Sprintf(entry, "t.example.com", "ns.s.example.net"), fmt.Sprintf(entry, "s.example.net", "ns.s.example.net")), "dns.zones[0].ns[0]"},
		{strings.Replace(zones(fmt.Sprintf(entry, "t.example.com", "ns.example.com")), `"zones":`, `"stats_socket":"/run/niko//dns/./packet.sock","zones":`, 1), "dns.stats_socket"},
		{strings.Replace(zones(fmt.Sprintf(entry, "t.example.com", "ns.example.com")), `"zones":`, `"stats_socket":"/run/niko/front/dnsprobe.key","zones":`, 1), "dns.stats_socket"},
		{stats("/run/niko//dns/packet.sock"), "stats_socket"},
		{stats("/run/credentials/niko-dns.service/dnstt.key"), "stats_socket"},
		{stats("/run/niko/dns-in/auth.keys"), "stats_socket"},
		{stats("/run/niko/dns-in/./seal.keys"), "stats_socket"},
		{stats("/run/niko/inner/vless.sock"), "stats_socket"},
		// Review 14: the Hysteria2 backends' own files.
		{strings.Replace(hy2, "STATS", "/r/h//users.json", 1), "stats_socket"},
		{strings.Replace(hy2, "STATS", "/r/h/chain.pem", 1), "stats_socket"},
		{strings.Replace(hy2, "STATS", "/run/niko/h/./key.pem", 1), "stats_socket"},
		{strings.Replace(strings.Replace(hy2, "hy2-masq", "hy2-obfs", 1), "STATS", "/r/h/obfs.pass", 1), "stats_socket"},
	} {
		errs := checkConfig(t, c.content)
		found := false
		for _, e := range errs {
			found = found || e.Path == c.path
		}
		if !found {
			t.Errorf("%s: no error at that path, got %v", c.path, errs)
		}
	}
	for _, ok := range []string{
		// A zone under the name, and one tunnel's ns as one name.
		zones(fmt.Sprintf(entry, "t.ns.example.com", "ns.example.com")),
		zones(fmt.Sprintf(entry, "t.example.com", "NS.example.net."), fmt.Sprintf(entry, "s.example.org", "ns.example.net")),
		stats("/run/niko/dns/stats.sock"),
		strings.Replace(strings.Replace(hy2, "hy2-masq", "hy2-obfs", 1), "STATS", "/run/niko/h/stats.sock", 1),
	} {
		if errs := checkConfig(t, ok); len(errs) > 0 {
			t.Errorf("%v", errs)
		}
	}
}

// auth_hint (v0.12.0, dnsauth-v2): off, optional or required on the DNS
// tunnels, and only with auth on.
func TestNekoServerConfigAuthHint(t *testing.T) {
	dnstt := `{"schema":1,"role":"backend","kind":"dnstt","log":{"level":"warn"},"socket":"/run/niko/dns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zone":"t.example.com","private_key_file":"/run/credentials/niko-dns.service/dnstt.key"OPTS}}`
	masterdns := `{"schema":1,"role":"backend","kind":"masterdns","log":{"level":"warn"},"socket":"/run/niko/mdns/packet.sock",
		"inner":"/run/niko/inner/vless.sock","options":{"zones":["m.example.com"],"encryption_method":5,"encryption_key_file":"/run/credentials/niko-mdns.service/encryption.key"OPTS}}`
	with := func(cfg, opts string) string { return strings.Replace(cfg, "OPTS", opts, 1) }
	auth := `,"auth":"required","auth_keys_file":"/run/niko/dns-in/auth.keys"`
	for _, ok := range []string{
		with(dnstt, auth+`,"auth_hint":"optional"`), with(dnstt, auth+`,"auth_hint":"required"`), with(dnstt, auth+`,"auth_hint":"off"`),
		with(masterdns, auth+`,"auth_hint":"required"`), with(dnstt, auth),
	} {
		if errs := checkConfig(t, ok); len(errs) > 0 {
			t.Errorf("%v", errs)
		}
	}
	hy2 := `{"schema":1,"role":"backend","kind":"hy2-masq","socket":"/run/niko/h/packet.sock","front_uid":9100,
		"users_file":"/r/h/users.json","tls":{"certificate_file":"/r/h/chain.pem","key_file":"/run/niko/h/key.pem"},
		"options":{"auth_hint":"optional"}}`
	for _, c := range []struct{ content, path string }{
		{with(dnstt, auth+`,"auth_hint":"strict"`), "options.auth_hint"},
		{with(dnstt, `,"auth_hint":"optional"`), "options.auth_hint"},
		{with(masterdns, `,"auth":"off","auth_hint":"required"`), "options.auth_hint"},
		// optional auth would pass a v1 tag on as untagged
		{with(dnstt, `,"auth":"optional","auth_keys_file":"/run/niko/dns-in/auth.keys","auth_hint":"required"`), "options.auth_hint"},
		{hy2, "options"},
	} {
		errs := checkConfig(t, c.content)
		found := false
		for _, e := range errs {
			found = found || e.Path == c.path
		}
		if !found {
			t.Errorf("%s: no error at that path, got %v", c.path, errs)
		}
	}
}
