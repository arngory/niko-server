//go:build linux

// Package nikoserver is niko-server, the data plane of a raycontrol node:
// a front (multiplexers) and one backend process per protocol, linked by unix
// sockets. Contracts: arngory/niko docs/server/CONFIG.md (schema 1) and
// docs/server/IPC.md (version 1). This release serves the DNS tunnels
// (dnstt, MasterDnsVPN); TCP and UDP 443 come in later releases.
package nikoserver

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
}

type FrontDNS struct {
	Listen []string  `json:"listen"`
	Zones  []DNSZone `json:"zones"`
}

type FrontConfig struct {
	Schema   int                   `json:"schema"`
	Role     string                `json:"role"`
	Log      LogOptions            `json:"log"`
	DNS      *FrontDNS             `json:"dns,omitempty"`
	TCP      json.RawMessage       `json:"tcp,omitempty"`
	UDP      json.RawMessage       `json:"udp,omitempty"`
	Backends map[string]BackendRef `json:"backends"`
}

type BackendOptions struct {
	// dnstt
	Zone           string `json:"zone,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	// masterdns
	Zones             []string `json:"zones,omitempty"`
	EncryptionMethod  *int     `json:"encryption_method,omitempty"`
	EncryptionKeyFile string   `json:"encryption_key_file,omitempty"`
}

type BackendConfig struct {
	Schema    int            `json:"schema"`
	Role      string         `json:"role"`
	Kind      string         `json:"kind"`
	Log       LogOptions     `json:"log"`
	Socket    string         `json:"socket"`
	FrontUID  int            `json:"front_uid"`
	UsersFile string         `json:"users_file,omitempty"`
	Options   BackendOptions `json:"options"`
	Inner     string         `json:"inner,omitempty"`
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
	// R1: only the DNS front; TCP and UDP 443 come later (a route there would be silently dropped)
	if len(c.TCP) > 0 && string(c.TCP) != "null" {
		e.add("tcp", "TCP 443 is not served by this niko-server release; leave the section out")
	}
	if len(c.UDP) > 0 && string(c.UDP) != "null" {
		e.add("udp", "UDP 443 is not served by this niko-server release; leave the section out")
	}
	if len(c.Backends) == 0 {
		e.add("backends", "no backends")
	}
	for name, b := range c.Backends {
		path := "backends." + name
		checkSocket(&e, path+".socket", b.Socket)
		switch b.Mode {
		case "packet":
		case "fd", "proxy-v2":
			e.add(path+".mode", "mode %q is not served by this release (packet only)", b.Mode)
		default:
			e.add(path+".mode", "unknown mode %q", b.Mode)
		}
		if b.UID < 0 {
			e.add(path+".uid", "must be the backend's UID")
		}
	}
	if c.DNS == nil {
		e.add("dns", "nothing to serve: the dns section is missing")
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
	case "":
		e.add("kind", "missing")
	default:
		e.add("kind", "kind %q is not served by this niko-server release (dnstt, masterdns)", c.Kind)
	}
	if c.Kind == "dnstt" || c.Kind == "masterdns" {
		if c.Inner == "" {
			e.add("inner", "the DNS tunnels lead to the inner stage: its socket is required")
		} else {
			checkSocket(&e, "inner", c.Inner)
		}
	}
	return e
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
