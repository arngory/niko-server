//go:build linux

package nikoserver

import (
	"strings"
	"testing"
)

// salamander-device-v1 (v0.19.3): a route of the devices' passwords, as
// raycontrol renders it, and its hy2-obfs backend with salamander_front;
// a route has one of sni and the two files, salamander_front no
// obfs_password_file and only on hy2-obfs.
func TestNekoServerConfigSalamanderDevices(t *testing.T) {
	front := `{"schema":1,"role":"front","backends":{
		"hy2-obfs":{"socket":"/run/niko/hy2-obfs/packet.sock","mode":"packet","uid":9115,"cid_label":6},
		"d":{"socket":"/run/niko/d-in/packet.sock","mode":"packet","uid":9104}},
		"dns":{"listen":["0.0.0.0:53"],"zones":[{"zone":"t.example.com","backend":"d"}],"stats_socket":"/run/niko/front/stats.sock"},
		"udp":{"listen":["0.0.0.0:443"],"cid_keys_file":"/r/front/quic-cid.keys",
			"routes":[{ROUTE"backend":"hy2-obfs"}]}}`
	keys := `"salamander_passwords_file":"/var/lib/raycontrol/rendered/front/hy2-obfs.salamander.keys",`
	route := func(r string) string { return strings.Replace(front, "ROUTE", r, 1) }
	if errs := checkConfig(t, route(keys)); len(errs) > 0 {
		t.Fatal(errs)
	}
	for name, c := range map[string]struct{ content, path string }{
		"its backend in an sni route too": {route(keys + `"backend":"hy2-obfs"},{"sni":["h.example.com"],`), "udp.routes[0].backend"},
		"its backend in a salamander_password_file route too": {
			route(keys + `"backend":"hy2-obfs"},{"salamander_password_file":"/r/front/o.salamander",`), "udp.routes[0].backend"},
		"the file and sni":   {route(keys + `"sni":["h.example.com"],`), "udp.routes[0]"},
		"both files":         {route(keys + `"salamander_password_file":"/r/front/o.salamander",`), "udp.routes[0]"},
		"neither":            {route(""), "udp.routes[0]"},
		"a relative file":    {route(`"salamander_passwords_file":"keys",`), "udp.routes[0].salamander_passwords_file"},
		"the stats socket's": {route(`"salamander_passwords_file":"/run/niko/front//stats.sock",`), "dns.stats_socket"},
	} {
		errs := checkConfig(t, c.content)
		if len(errs) != 1 || errs[0].Path != c.path {
			t.Errorf("%s: %v, want one error at %q", name, errs, c.path)
		}
	}
	// Two device routes of one backend: each says so.
	errs := checkConfig(t, route(keys+`"backend":"hy2-obfs"},{"salamander_passwords_file":"/r/front/other.keys",`))
	if len(errs) != 2 || errs[0].Path != "udp.routes[0].backend" || errs[1].Path != "udp.routes[1].backend" {
		t.Errorf("two device routes of one backend: %v", errs)
	}

	backend := `{"schema":1,"role":"backend","kind":"KIND","socket":"/run/niko/hy2-obfs/packet.sock","front_uid":9100,
		"users_file":"/r/h/users.json","tls":{"certificate_file":"/r/h/chain.pem","key_file":"/r/h/key.pem"},
		"options":{OPTIONS"up_mbps":0}}`
	hy2 := func(kind, options string) string {
		return strings.Replace(strings.Replace(backend, "KIND", kind, 1), "OPTIONS", options, 1)
	}
	if errs := checkConfig(t, hy2("hy2-obfs", `"salamander_front":true,`)); len(errs) > 0 {
		t.Fatal(errs)
	}
	if errs := checkConfig(t, hy2("hy2-obfs", `"obfs_password_file":"/r/h/obfs.pass",`)); len(errs) > 0 {
		t.Fatal(errs)
	}
	for name, c := range map[string]struct{ content, path string }{
		"salamander_front and a password": {hy2("hy2-obfs", `"salamander_front":true,"obfs_password_file":"/r/h/obfs.pass",`), "options.obfs_password_file"},
		"hy2-obfs with neither":           {hy2("hy2-obfs", ""), "options.obfs_password_file"},
		"salamander_front on hy2-masq":    {hy2("hy2-masq", `"salamander_front":true,`), "options.salamander_front"},
	} {
		errs := checkConfig(t, c.content)
		if len(errs) != 1 || errs[0].Path != c.path {
			t.Errorf("%s: %v, want one error at %q", name, errs, c.path)
		}
	}
}
