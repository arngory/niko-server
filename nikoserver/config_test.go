//go:build linux

package nikoserver

import (
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
	for want, content := range map[string]string{
		"stats_socket":              strings.Replace(dnstt, `"inner":`, `"stats_socket":"/run/niko/dns/stats.sock","inner":`, 1),
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
		"dns.listen[1]":             strings.Replace(front, `"[::]:53"`, `"localhost:53"`, 1),
		"options.encryption_method": strings.Replace(masterdns, `"encryption_method":5`, `"encryption_method":2`, 1),
		"inner":                     strings.Replace(dnstt, `"inner":"/run/niko/inner/vless.sock"`, `"inner":"relative.sock"`, 1),
		"kind":                      strings.Replace(dnstt, `"kind":"dnstt"`, `"kind":"naive"`, 1),
		"options.auth":              strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","auth":"strict"`, 1),
		"options.auth_keys_file":    strings.Replace(dnstt, `"zone":"t.example.com"`, `"zone":"t.example.com","auth":"required"`, 1),
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
