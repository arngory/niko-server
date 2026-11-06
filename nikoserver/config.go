//go:build linux

// Package nikoserver is niko-server, the data plane of a raycontrol node:
// a front (multiplexers) and one backend process per protocol, linked by unix
// sockets. Contracts: arngory/niko docs/server/CONFIG.md (schema 1) and
// docs/server/IPC.md (version 1). This release serves the DNS tunnels
// (dnstt, MasterDnsVPN), TCP 443 (tcpmux) and UDP 443 (udpmux).
package nikoserver

import (
	"encoding/json"
	"fmt"
	"github.com/arngory/niko-server/dnsttserver"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Schema = 1

// ConfigError is a problem in the config itself (check exits with 1).
type ConfigError struct {
	Path string `json:"path"`
	Err  string `json:"error"`
}

func (e ConfigError) Error() string { return e.Path + ": " + e.Err }

type configErrors []ConfigError

func (e *configErrors) add(path, format string, args ...any) {
	*e = append(*e, ConfigError{Path: path, Err: fmt.Sprintf(format, args...)})
}

type LogOptions struct {
	Level string `json:"level,omitempty"`
}

type BackendRef struct {
	Socket string `json:"socket"`
	Mode   string `json:"mode"`
	UID    int    `json:"uid"`
}

type DNSZone struct {
	Zone    string `json:"zone"`
	Backend string `json:"backend"`
	// Probe: the front answers dnsprobe-v1 in this zone (with
	// dns.probe_key_file). For dnstt zones: the answers are built as
	// dnstt's.
	Probe bool `json:"probe,omitempty"`
	// NS: the names the zone is delegated to. With them the front answers
	// SOA and NS at the zone's apex itself (dnstt zones: the answers are
	// built as dnstt's), the first being the SOA's primary.
	NS []string `json:"ns,omitempty"`
	// SealPad: the zone's dnstt answers are sealed (dnsseal-v1, required):
	// the front pads the TXT data of its probe answers as they are padded,
	// to a multiple of 64 within what the requester can carry.
	SealPad bool `json:"seal_pad,omitempty"`
}

type FrontDNS struct {
	Listen []string  `json:"listen"`
	Zones  []DNSZone `json:"zones"`
	// ProbeKeyFile: the key of dnsprobe-v1 (raycontrol
	// docs/spec/dnsprobe-v1.md), 32 bytes in hex. With it the front answers
	// a client's check of a resolver itself, before the zone's backend.
	ProbeKeyFile string `json:"probe_key_file,omitempty"`
}

// TCPRoute sends TLS connections with one of these server names, or
// offering one of these ALPN protocols, to a backend.
type TCPRoute struct {
	SNI     []string `json:"sni,omitempty"`
	ALPN    []string `json:"alpn,omitempty"`
	Backend string   `json:"backend"`
}

// FrontTCP is tcpmux (SPEC §3.1).
type FrontTCP struct {
	Listen       []string   `json:"listen"`
	SniffTimeout string     `json:"sniff_timeout,omitempty"`
	Routes       []TCPRoute `json:"routes"`
	Default      string     `json:"default,omitempty"`
	// Not served yet (check says so): raycontrol issues certificates with
	// DNS-01 or an HTTP-01 window, and clamping the window is a proposal.
	ACMEListen  []string `json:"acme_listen,omitempty"`
	WindowClamp int      `json:"window_clamp,omitempty"`
}

// UDPRoute sends QUIC flows whose ClientHello names one of these servers,
// or salamander flows that open with this password, to a backend.
type UDPRoute struct {
	SNI                    []string `json:"sni,omitempty"`
	SalamanderPasswordFile string   `json:"salamander_password_file,omitempty"`
	Backend                string   `json:"backend"`
}

// FrontUDP is udpmux (SPEC §3.2).
type FrontUDP struct {
	Listen []string   `json:"listen"`
	Idle   string     `json:"idle,omitempty"`
	Routes []UDPRoute `json:"routes"`
}

type FrontConfig struct {
	Schema   int                   `json:"schema"`
	Role     string                `json:"role"`
	Log      LogOptions            `json:"log"`
	DNS      *FrontDNS             `json:"dns,omitempty"`
	TCP      *FrontTCP             `json:"tcp,omitempty"`
	UDP      *FrontUDP             `json:"udp,omitempty"`
	Backends map[string]BackendRef `json:"backends"`
}

type BackendOptions struct {
	// dnstt
	Zone           string `json:"zone,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	// dnstt: dnsauth-v1 (raycontrol docs/spec/dnsauth-v1.md): off,
	// optional or required, and the devices' keys ("<id> <hex>" per line,
	// reread when the file changes).
	Auth         string `json:"auth,omitempty"`
	AuthKeysFile string `json:"auth_keys_file,omitempty"`
	// AuthScanHMACs bounds the HMACs a second spent on finding the key of
	// a query no session explains (dnsttserver.Auth.ScanHMACs); 0: the
	// default, 100000 or 20 full scans a second.
	AuthScanHMACs int `json:"auth_scan_hmacs,omitempty"`
	// dnstt: dnsseal-v1 (raycontrol docs/spec/dnsseal-v1.md): off,
	// optional or required, and the zone's keys (64 hex digits a line, the
	// current first).
	Seal        string `json:"seal,omitempty"`
	SealKeyFile string `json:"seal_key_file,omitempty"`
	// masterdns
	Zones             []string `json:"zones,omitempty"`
	EncryptionMethod  *int     `json:"encryption_method,omitempty"`
	EncryptionKeyFile string   `json:"encryption_key_file,omitempty"`
	// hy2-*: the per-connection ceilings of the server's Brutal (Mbit/s, 0:
	// the client's own rate, or BBR without one); hy2-obfs: salamander.
	UpMbps           int    `json:"up_mbps,omitempty"`
	DownMbps         int    `json:"down_mbps,omitempty"`
	ObfsPasswordFile string `json:"obfs_password_file,omitempty"`
	// yggdrasil: the node's key in private_key_file (hex: a 32-byte seed or
	// the 64-byte key of yggdrasil-go's config), the TCP ports of the node's
	// mesh address that lead to inner, and outgoing peers (public ones; none
	// by default: clients connect directly, raycontrol decision P-14).
	ExitPorts []int    `json:"exit_ports,omitempty"`
	Peers     []string `json:"peers,omitempty"`
	// hy2-*: a name that leads to an address on the node, TCP and UDP (the
	// channel probes of raycontrol, probe-v1); nothing else of the node is
	// reachable.
	Probe *ProbeRoute `json:"probe,omitempty"`
}

// ProbeRoute sends streams and datagrams for Name to Address.
type ProbeRoute struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// BackendTLS is a backend's certificate; curves default to X25519MLKEM768
// and nothing else is accepted.
type BackendTLS struct {
	CertificateFile string   `json:"certificate_file"`
	KeyFile         string   `json:"key_file"`
	Curves          []string `json:"curves,omitempty"`
}

type BackendConfig struct {
	Schema    int            `json:"schema"`
	Role      string         `json:"role"`
	Kind      string         `json:"kind"`
	Log       LogOptions     `json:"log"`
	Socket    string         `json:"socket"`
	FrontUID  int            `json:"front_uid"`
	UsersFile string         `json:"users_file,omitempty"`
	TLS       *BackendTLS    `json:"tls,omitempty"`
	Options   BackendOptions `json:"options"`
	Inner     string         `json:"inner,omitempty"`
	// StatsSocket (hy2-*): where the backend answers for the sessions of a
	// client address (raycontrol's channel probes). dnstt: where it gives
	// its counters (dnsttserver.StatsSnapshot, JSON) to whoever connects.
	StatsSocket string `json:"stats_socket,omitempty"`
}

var dnsName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// header reads schema and role first, so an unknown schema gives one clear error.
type header struct {
	Schema int    `json:"schema"`
	Role   string `json:"role"`
}

// Load reads a config file of either role. It returns a *FrontConfig or a
// *BackendConfig, config errors, or an environment error (unreadable file).
func Load(path string) (any, []ConfigError, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var h header
	if err = json.Unmarshal(raw, &h); err != nil {
		return nil, []ConfigError{{Path: "", Err: "not JSON: " + err.Error()}}, nil
	}
	if h.Schema != Schema {
		return nil, []ConfigError{{Path: "schema", Err: fmt.Sprintf("schema %d is not supported (this niko-server reads %d)", h.Schema, Schema)}}, nil
	}
	decoder := func(v any) error {
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		return d.Decode(v)
	}
	switch h.Role {
	case "front":
		var c FrontConfig
		if err = decoder(&c); err != nil {
			return nil, []ConfigError{{Path: "", Err: err.Error()}}, nil
		}
		return &c, c.validate(), nil
	case "backend":
		var c BackendConfig
		if err = decoder(&c); err != nil {
			return nil, []ConfigError{{Path: "", Err: err.Error()}}, nil
		}
		return &c, c.validate(), nil
	default:
		return nil, []ConfigError{{Path: "role", Err: fmt.Sprintf("role %q, want front or backend", h.Role)}}, nil
	}
}

func checkLog(e *configErrors, l LogOptions) {
	switch strings.ToLower(l.Level) {
	case "", "debug", "info", "warn", "error":
	default:
		e.add("log.level", "unknown level %q", l.Level)
	}
}

func checkSocket(e *configErrors, path, value string) {
	if !filepath.IsAbs(value) {
		e.add(path, "must be an absolute path")
	}
}

func (c *FrontConfig) validate() []ConfigError {
	var e configErrors
	checkLog(&e, c.Log)
	if len(c.Backends) == 0 {
		e.add("backends", "no backends")
	}
	for name, b := range c.Backends {
		path := "backends." + name
		checkSocket(&e, path+".socket", b.Socket)
		switch b.Mode {
		case "packet", "fd", "proxy-v2":
		default:
			e.add(path+".mode", "unknown mode %q", b.Mode)
		}
		if b.UID < 0 {
			e.add(path+".uid", "must be the backend's UID")
		}
	}
	if c.DNS == nil && c.TCP == nil && c.UDP == nil {
		e.add("", "nothing to serve: no dns, tcp or udp section")
		return e
	}
	if c.TCP != nil {
		c.TCP.validate(&e, c.Backends)
	}
	if c.UDP != nil {
		c.UDP.validate(&e, c.Backends)
	}
	if c.DNS == nil {
		return e
	}
	if len(c.DNS.Listen) == 0 {
		e.add("dns.listen", "no addresses")
	}
	for i, listen := range c.DNS.Listen {
		if _, err := netip.ParseAddrPort(listen); err != nil {
			e.add(fmt.Sprintf("dns.listen[%d]", i), "want IP:port, like 0.0.0.0:53 or [::]:53")
		}
	}
	if len(c.DNS.Zones) == 0 {
		e.add("dns.zones", "no zones")
	}
	if c.DNS.ProbeKeyFile != "" {
		checkSocket(&e, "dns.probe_key_file", c.DNS.ProbeKeyFile)
	}
	seen := map[string]bool{}
	for i, z := range c.DNS.Zones {
		path := fmt.Sprintf("dns.zones[%d]", i)
		zone := strings.ToLower(strings.TrimSuffix(z.Zone, "."))
		if !dnsName.MatchString(zone) {
			e.add(path+".zone", "not a DNS name: %q", z.Zone)
		}
		if seen[zone] {
			e.add(path+".zone", "duplicate zone %q", z.Zone)
		}
		seen[zone] = true
		b, ok := c.Backends[z.Backend]
		if !ok {
			e.add(path+".backend", "no backend %q in backends", z.Backend)
		} else if b.Mode != "packet" {
			e.add(path+".backend", "backend %q must have mode packet", z.Backend)
		}
		if z.Probe && c.DNS.ProbeKeyFile == "" {
			e.add(path+".probe", "needs dns.probe_key_file")
		}
		if z.SealPad && !z.Probe {
			e.add(path+".seal_pad", "pads probe answers: needs probe")
		}
		if len(z.NS) > 8 {
			e.add(path+".ns", "at most 8 names")
		}
		for j, ns := range z.NS {
			if n := strings.ToLower(strings.TrimSuffix(ns, ".")); !dnsName.MatchString(n) || len(n) > 253 {
				e.add(fmt.Sprintf("%s.ns[%d]", path, j), "not a DNS name: %q", ns)
			}
		}
	}
	return e
}

func (c *BackendConfig) validate() []ConfigError {
	var e configErrors
	checkLog(&e, c.Log)
	checkSocket(&e, "socket", c.Socket)
	if c.FrontUID < 0 {
		e.add("front_uid", "must be the front's UID")
	}
	switch c.Kind {
	case "dnstt":
		if !dnsName.MatchString(strings.TrimSuffix(c.Options.Zone, ".")) {
			e.add("options.zone", "not a DNS name: %q", c.Options.Zone)
		}
		checkSocket(&e, "options.private_key_file", c.Options.PrivateKeyFile)
		if mode, err := dnsttserver.ParseAuthMode(c.Options.Auth); err != nil {
			e.add("options.auth", "%v", err)
		} else if mode != dnsttserver.AuthOff {
			checkSocket(&e, "options.auth_keys_file", c.Options.AuthKeysFile)
		}
		if mode, err := dnsttserver.ParseSealMode(c.Options.Seal); err != nil {
			e.add("options.seal", "%v", err)
		} else if mode != dnsttserver.SealOff {
			checkSocket(&e, "options.seal_key_file", c.Options.SealKeyFile)
		}
	case "masterdns":
		if len(c.Options.Zones) == 0 {
			e.add("options.zones", "no zones")
		}
		for i, zone := range c.Options.Zones {
			if !dnsName.MatchString(strings.TrimSuffix(zone, ".")) {
				e.add(fmt.Sprintf("options.zones[%d]", i), "not a DNS name: %q", zone)
			}
		}
		// raycontrol decision R1-8: authenticated encryption only (3-5: AES-GCM)
		if c.Options.EncryptionMethod == nil || *c.Options.EncryptionMethod < 3 || *c.Options.EncryptionMethod > 5 {
			e.add("options.encryption_method", "must be 3, 4 or 5 (AES-GCM; 5 = AES-256-GCM)")
		}
		checkSocket(&e, "options.encryption_key_file", c.Options.EncryptionKeyFile)
	case "hy2-masq", "hy2-obfs":
		checkSocket(&e, "users_file", c.UsersFile)
		checkBackendTLS(&e, c.TLS, "a Hysteria2 backend needs its certificate")
		if c.Kind == "hy2-obfs" {
			checkSocket(&e, "options.obfs_password_file", c.Options.ObfsPasswordFile)
		} else if c.Options.ObfsPasswordFile != "" {
			e.add("options.obfs_password_file", "only hy2-obfs has salamander")
		}
		if c.Options.UpMbps < 0 || c.Options.DownMbps < 0 {
			e.add("options", "up_mbps and down_mbps cannot be negative")
		}
		if pr := c.Options.Probe; pr != nil {
			if !dnsName.MatchString(pr.Name) {
				e.add("options.probe.name", "not a DNS name: %q", pr.Name)
			}
			if ap, err := netip.ParseAddrPort(pr.Address); err != nil || !ap.Addr().IsLoopback() {
				e.add("options.probe.address", "want a loopback IP:port, like 127.0.0.1:34567")
			}
		}
	case "yggdrasil":
		checkSocket(&e, "users_file", c.UsersFile)
		checkBackendTLS(&e, c.TLS, "a Yggdrasil backend needs the certificate of its name")
		checkSocket(&e, "options.private_key_file", c.Options.PrivateKeyFile)
		if len(c.Options.ExitPorts) == 0 {
			e.add("options.exit_ports", "no exit ports: nothing would reach inner")
		}
		seen := map[int]bool{}
		for i, port := range c.Options.ExitPorts {
			if port < 1 || port > 65535 || seen[port] {
				e.add(fmt.Sprintf("options.exit_ports[%d]", i), "want a port 1-65535, once")
			}
			seen[port] = true
		}
		for i, peer := range c.Options.Peers {
			u, err := url.Parse(peer)
			switch {
			case err != nil || u.Host == "":
				e.add(fmt.Sprintf("options.peers[%d]", i), "want a peer URI like tls://host:port")
			case u.Scheme != "tls" && u.Scheme != "tcp" && u.Scheme != "quic" && u.Scheme != "ws" && u.Scheme != "wss":
				e.add(fmt.Sprintf("options.peers[%d]", i), "scheme %q: tls, tcp, quic, ws or wss", u.Scheme)
			}
		}
	case "":
		e.add("kind", "missing")
	default:
		e.add("kind", "kind %q is not served by this niko-server release (dnstt, masterdns, hy2-masq, hy2-obfs, yggdrasil)", c.Kind)
	}
	if c.StatsSocket != "" {
		if c.Kind != "hy2-masq" && c.Kind != "hy2-obfs" && c.Kind != "dnstt" {
			e.add("stats_socket", "only the Hysteria2 and dnstt backends have stats")
		} else {
			checkSocket(&e, "stats_socket", c.StatsSocket)
		}
	}
	if c.Options.Probe != nil && c.Kind != "hy2-masq" && c.Kind != "hy2-obfs" {
		e.add("options.probe", "only the Hysteria2 backends route a probe name")
	}
	if c.Kind != "yggdrasil" && (len(c.Options.ExitPorts) > 0 || len(c.Options.Peers) > 0) {
		e.add("options", "exit_ports and peers are Yggdrasil options")
	}
	if c.Options.AuthScanHMACs < 0 {
		e.add("options.auth_scan_hmacs", "not below 0")
	}
	if c.Kind != "dnstt" && (c.Options.Auth != "" || c.Options.AuthKeysFile != "" || c.Options.AuthScanHMACs != 0) {
		e.add("options", "auth, auth_keys_file and auth_scan_hmacs are dnstt options")
	}
	if c.Kind != "dnstt" && (c.Options.Seal != "" || c.Options.SealKeyFile != "") {
		e.add("options", "seal and seal_key_file are dnstt options")
	}
	if c.Kind == "dnstt" || c.Kind == "masterdns" || c.Kind == "yggdrasil" {
		if c.Inner == "" {
			e.add("inner", "the DNS tunnels and Yggdrasil lead to the inner stage: its socket is required")
		} else {
			checkSocket(&e, "inner", c.Inner)
		}
	}
	return e
}

func checkBackendTLS(e *configErrors, t *BackendTLS, missing string) {
	if t == nil {
		e.add("tls", "%s", missing)
		return
	}
	checkSocket(e, "tls.certificate_file", t.CertificateFile)
	checkSocket(e, "tls.key_file", t.KeyFile)
	for i, curve := range t.Curves {
		if curve != "X25519MLKEM768" {
			e.add(fmt.Sprintf("tls.curves[%d]", i), "only X25519MLKEM768 (post-quantum, no fallback)")
		}
	}
}

// zoneOf returns the zone that name falls into (by labels), or "".
func zoneOf(name string, zones []string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, zone := range zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return zone
		}
	}
	return ""
}

func (t *FrontTCP) validate(e *configErrors, backends map[string]BackendRef) {
	if len(t.Listen) == 0 {
		e.add("tcp.listen", "no addresses")
	}
	for i, listen := range t.Listen {
		if _, err := netip.ParseAddrPort(listen); err != nil {
			e.add(fmt.Sprintf("tcp.listen[%d]", i), "want IP:port, like 0.0.0.0:443 or [::]:443")
		}
	}
	if t.SniffTimeout != "" {
		if d, err := time.ParseDuration(t.SniffTimeout); err != nil || d <= 0 || d > 30*time.Second {
			e.add("tcp.sniff_timeout", "want a duration up to 30s, like 5s")
		}
	}
	if len(t.ACMEListen) > 0 {
		e.add("tcp.acme_listen", "the ACME window is not served by this release: raycontrol issues certificates with DNS-01 or HTTP-01")
	}
	if t.WindowClamp != 0 {
		e.add("tcp.window_clamp", "not served by this release")
	}
	streamBackend := func(path, name string) {
		b, ok := backends[name]
		switch {
		case !ok:
			e.add(path, "no backend %q in backends", name)
		case b.Mode != "fd" && b.Mode != "proxy-v2":
			e.add(path, "backend %q must have mode fd or proxy-v2", name)
		}
	}
	if len(t.Routes) == 0 && t.Default == "" {
		e.add("tcp.routes", "no routes and no default")
	}
	names := map[string]bool{}
	for i, r := range t.Routes {
		path := fmt.Sprintf("tcp.routes[%d]", i)
		if (len(r.SNI) == 0) == (len(r.ALPN) == 0) {
			e.add(path, "give either sni or alpn")
		}
		for j, name := range r.SNI {
			n := normalName(name)
			if !dnsName.MatchString(n) {
				e.add(fmt.Sprintf("%s.sni[%d]", path, j), "not a DNS name: %q", name)
			}
			if names[n] {
				e.add(fmt.Sprintf("%s.sni[%d]", path, j), "%q has a route already", name)
			}
			names[n] = true
		}
		for j, proto := range r.ALPN {
			if proto == "" || len(proto) > 255 {
				e.add(fmt.Sprintf("%s.alpn[%d]", path, j), "want a protocol name")
			}
		}
		streamBackend(path+".backend", r.Backend)
	}
	if t.Default != "" {
		streamBackend("tcp.default", t.Default)
	}
}

func (u *FrontUDP) validate(e *configErrors, backends map[string]BackendRef) {
	if len(u.Listen) == 0 {
		e.add("udp.listen", "no addresses")
	}
	for i, listen := range u.Listen {
		if _, err := netip.ParseAddrPort(listen); err != nil {
			e.add(fmt.Sprintf("udp.listen[%d]", i), "want IP:port, like 0.0.0.0:443 or [::]:443")
		}
	}
	if u.Idle != "" {
		if d, err := time.ParseDuration(u.Idle); err != nil || d < 5*time.Second || d > 10*time.Minute {
			e.add("udp.idle", "want a duration from 5s to 10m, like 60s")
		}
	}
	if len(u.Routes) == 0 {
		e.add("udp.routes", "no routes")
	}
	names := map[string]bool{}
	for i, r := range u.Routes {
		path := fmt.Sprintf("udp.routes[%d]", i)
		if (len(r.SNI) == 0) == (r.SalamanderPasswordFile == "") {
			e.add(path, "give either sni or salamander_password_file")
		}
		for j, name := range r.SNI {
			n := normalName(name)
			if !dnsName.MatchString(n) {
				e.add(fmt.Sprintf("%s.sni[%d]", path, j), "not a DNS name: %q", name)
			}
			if names[n] {
				e.add(fmt.Sprintf("%s.sni[%d]", path, j), "%q has a route already", name)
			}
			names[n] = true
		}
		if r.SalamanderPasswordFile != "" {
			checkSocket(e, path+".salamander_password_file", r.SalamanderPasswordFile)
		}
		b, ok := backends[r.Backend]
		switch {
		case !ok:
			e.add(path+".backend", "no backend %q in backends", r.Backend)
		case b.Mode != "packet":
			e.add(path+".backend", "backend %q must have mode packet", r.Backend)
		}
	}
}
