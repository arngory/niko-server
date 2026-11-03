//go:build linux

package nikoserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Hysteria2 backends (SPEC §3.2): hy2-masq (the site's certificate, an empty
// 404 for anyone without a password) and hy2-obfs (salamander, a pinned
// self-signed certificate). The front passes their datagrams in mode
// packet; streams and datagrams of users go out to public addresses only.

// UsersFile is the users file of CONFIG.md; a backend reads its own kind.
type UsersFile struct {
	Users []struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
		Hy2     *struct {
			Password string `json:"password"`
		} `json:"hy2,omitempty"`
		Yggdrasil *struct {
			PublicKey string `json:"public_key"`
		} `json:"yggdrasil,omitempty"`
	} `json:"users"`
}

func readHy2Users(path string) ([]int, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f UsersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, err
	}
	var ids []int
	var passwords []string
	for i, u := range f.Users {
		if u.Enabled && u.Hy2 != nil && u.Hy2.Password != "" {
			ids = append(ids, i)
			passwords = append(passwords, u.Hy2.Password)
		}
	}
	return ids, passwords, nil
}

// runHysteria serves a Hysteria2 backend on the front's datagrams.
func runHysteria(ctx context.Context, c *BackendConfig, conn *packetConn, log *Logger, dial dialFunc) error {
	tlsConfig, err := sbtls.NewServer(ctx, nopLogger(), option.InboundTLSOptions{
		Enabled:          true,
		ALPN:             []string{"h3"},
		MinVersion:       "1.3",
		CertificatePath:  c.TLS.CertificateFile,
		KeyPath:          c.TLS.KeyFile,
		CurvePreferences: []option.CurvePreference{option.CurvePreference(tls.X25519MLKEM768)},
	})
	if err != nil {
		return envError("tls: %v", err)
	}
	if err := tlsConfig.Start(); err != nil {
		return envError("tls: %v", err)
	}
	defer tlsConfig.Close()
	var salamander string
	if c.Kind == "hy2-obfs" {
		b, err := os.ReadFile(c.Options.ObfsPasswordFile)
		if err != nil {
			return envError("salamander password: %v", err)
		}
		salamander = strings.TrimRight(string(b), "\r\n")
	}
	service, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:            ctx,
		Logger:             nopLogger(),
		SendBPS:            uint64(c.Options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(c.Options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamander,
		TLSConfig:          tlsConfig,
		UDPTimeout:         2 * time.Minute,
		Handler:            &outbound{dial: dial, log: log},
		MasqueradeHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNotFound)
		}),
	})
	if err != nil {
		return err
	}
	reload := func() error {
		ids, passwords, err := readHy2Users(c.UsersFile)
		if err != nil {
			return err
		}
		// UpdateUsers swaps the table without a lock: sessions see the old
		// or the new one, never one being written (to fix in a sing-quic
		// fork with an atomic swap).
		service.UpdateUsers(ids, passwords)
		log.Infof("%d users", len(ids))
		return nil
	}
	if err := reload(); err != nil {
		return envError("users: %v", err)
	}
	go watchUsers(ctx, c.UsersFile, reload, log)
	if err := service.Start(conn); err != nil {
		return err
	}
	<-ctx.Done()
	return service.Close()
}

// watchUsers reloads the users file on SIGHUP and when it changes.
func watchUsers(ctx context.Context, path string, reload func() error, log *Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	var last time.Time
	if st, err := os.Stat(path); err == nil {
		last = st.ModTime()
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		case <-tick.C:
			st, err := os.Stat(path)
			if err != nil || st.ModTime().Equal(last) {
				continue
			}
			last = st.ModTime()
		}
		if err := reload(); err != nil {
			log.Warnf("users: %v", err)
		}
	}
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// outbound takes the users' streams and datagrams out to public addresses.
type outbound struct {
	dial dialFunc
	log  *Logger
}

func (o *outbound) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	out, err := o.dial(dctx, "tcp", destination.String())
	cancel()
	if err != nil {
		o.log.Debugf("destination: %v", err)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	err = bufio.CopyConn(ctx, conn, out)
	if onClose != nil {
		onClose(err)
	}
}

func (o *outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := relayUDP(ctx, conn)
	if onClose != nil {
		onClose(err)
	}
}

// relayUDP carries a user's datagrams to and from public addresses.
func relayUDP(ctx context.Context, conn N.PacketConn) error {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		conn.Close()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		udp.Close()
		conn.Close()
	}()
	var resolved sync.Map // name -> netip.Addr
	go func() {
		defer cancel()
		b := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, from, err := udp.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			buffer := buf.As(b[:n])
			if err := conn.WritePacket(buffer, M.SocksaddrFromNetIP(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))); err != nil {
				return
			}
		}
	}()
	for {
		buffer := buf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		addr := destination.Addr
		if destination.IsFqdn() {
			if a, ok := resolved.Load(destination.Fqdn); ok {
				addr = a.(netip.Addr)
			} else if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn); err == nil && len(ips) > 0 {
				addr = ips[0].Unmap()
				resolved.Store(destination.Fqdn, addr)
			}
		}
		if addr.IsValid() && (Public(addr) || anyDestination()) {
			_, _ = udp.WriteToUDPAddrPort(buffer.Bytes(), netip.AddrPortFrom(addr.Unmap(), destination.Port))
		}
		buffer.Release()
	}
}

// PublicDialer reaches public unicast addresses only: not the node, not
// loopback, private, link-local, CGNAT or multicast ranges.
func PublicDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !Public(ap.Addr()) {
			return errors.New("destination not public")
		}
		return nil
	}}
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	localOnce sync.Once
	localSet  map[netip.Addr]bool
)

// Public reports a public unicast address that is not one of the node's own.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return false
	}
	localOnce.Do(func() {
		localSet = map[netip.Addr]bool{}
		addrs, _ := net.InterfaceAddrs()
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil {
				localSet[p.Addr().Unmap()] = true
			}
		}
	})
	return !localSet[a]
}

func nopLogger() log.ContextLogger { return log.NewNOPFactory().NewLogger("") }
