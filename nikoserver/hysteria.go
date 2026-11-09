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
	"sync/atomic"
	"syscall"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
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
			// LAN (v0.16.0): the key's group, its user's base name
			// (raycontrol lan-v1 §2.2); absent or "" none.
			LAN string `json:"lan,omitempty"`
		} `json:"yggdrasil,omitempty"`
	} `json:"users"`
}

// readHy2Users returns the names and passwords of the enabled Hysteria2
// users; the service knows each session's user by its name.
func readHy2Users(path string) ([]string, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f UsersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, err
	}
	var names, passwords []string
	for _, u := range f.Users {
		if u.Enabled && u.Hy2 != nil && u.Hy2.Password != "" {
			names = append(names, u.Name)
			passwords = append(passwords, u.Hy2.Password)
		}
	}
	return names, passwords, nil
}

// runHysteria serves a Hysteria2 backend on the front's datagrams.
// hysteriaIdle is the Hysteria2 listener's QUIC idle timeout.
const hysteriaIdle = 60 * time.Second

// hy2MaxStreams is how many streams (TCP requests) one QUIC connection may
// have open at once (raycontrol conn-limit-v1 §3.2); sing-quic's own is
// 2^60. A client opens a stream without waiting, and one past the
// connection's limit fails the whole connection ("too many open streams"):
// so this is above a user's limit of TCP at once (1024), which answers
// first, with its reason. With the limits off, it alone bounds a connection.
const hy2MaxStreams = 2048

func runHysteria(ctx context.Context, c *BackendConfig, conn *packetConn, log *Logger, dial dialFunc) error {
	return runHysteriaWith(ctx, c, conn, log, dial, newHyLimits())
}

// runHysteriaWith is runHysteria with the backend's limits given (tests:
// their numbers and clock).
func runHysteriaWith(ctx context.Context, c *BackendConfig, conn *packetConn, log *Logger, dial dialFunc, lim *hyLimits) error {
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
	// The switch of the per-user limits (conn_limit, conn_limit_file):
	// read now, and again at each look of the users file's watch.
	var connLimitProblem string // the file's last problem logged: once each
	connLimit := func() {
		on, problem := c.Options.connLimitOn()
		switch {
		case problem == nil:
			connLimitProblem = ""
		case problem.Error() != connLimitProblem:
			connLimitProblem = problem.Error()
			log.Warnf("conn_limit_file: %v; the limits stay on", problem)
		}
		if on == lim.off.Load() {
			lim.SetConnLimit(on)
			if on {
				log.Infof("per-user connection limits on")
			} else {
				log.Infof("per-user connection limits off")
			}
		}
	}
	connLimit()
	var live sessions
	users := newHy2Users()
	users.limits = lim
	if c.StatsSocket != "" {
		stop, err := live.serveStats(c.StatsSocket, users, log)
		if err != nil {
			return envError("stats socket: %v", err)
		}
		defer stop()
	}
	// The front sends with DF set (probeMTU): salamander's 8 bytes of salt
	// come on top of quic-go's first packets of 1280, so they start 8 bytes
	// smaller and leave the front at 1280 like every other QUIC on it. Path
	// MTU discovery then counts only what came through, the salt included.
	// 60 s idle rather than Hysteria's 30: quic-go pings at min(the
	// client's keepalive, idle/2), so a client asking for 25 s (Niko 1.28)
	// gets 25 s and not 15, which saves its battery. A dead connection
	// without keepalives is closed 30 s later than before.
	quicOptions := qtls.QUICOptions{IdleTimeout: hysteriaIdle, MaxConcurrentStreams: hy2MaxStreams}
	if salamander != "" {
		quicOptions.InitialPacketSize = 1280 - 8
	}
	service, err := hysteria2.NewService[*hy2User](hysteria2.ServiceOptions{
		QUICOptions:        quicOptions,
		ConnectionHook:     connectionHook(users, &live),
		Context:            ctx,
		Logger:             nopLogger(),
		SendBPS:            uint64(c.Options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(c.Options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamander,
		TLSConfig:          tlsConfig,
		UDPTimeout:         2 * time.Minute,
		Handler:            &outbound{dial: dial, log: log, probe: c.Options.Probe, lim: lim},
		MasqueradeHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNotFound)
		}),
	})
	if err != nil {
		return err
	}
	reload := func() error {
		names, passwords, err := readHy2Users(c.UsersFile)
		if err != nil {
			return err
		}
		// The vendored sing-quic swaps the table atomically; the connections
		// of a name gone or of a password changed close, as Yggdrasil's.
		if closed := users.set(names, passwords, service.UpdateUsers); closed > 0 {
			log.Infof("%d users, %d connections of removed users closed", len(names), closed)
		} else {
			log.Infof("%d users", len(names))
		}
		return nil
	}
	if err := reload(); err != nil {
		return envError("users: %v", err)
	}
	go watchUsers(ctx, c.UsersFile, reload, func() { users.check(); connLimit() }, log)
	if err := service.Start(conn); err != nil {
		return err
	}
	<-ctx.Done()
	return service.Close()
}

// watchUsers reloads the users file on SIGHUP and when it changes; check
// runs at each look, every 5 s and on SIGHUP, whether it changed or not.
func watchUsers(ctx context.Context, path string, reload func() error, check func(), log *Logger) {
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
			check()
		case <-tick.C:
			check()
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

// outbound takes the users' streams and datagrams out to public addresses,
// within each user's limits.
type outbound struct {
	// dial reaches one address (no names: those go through the limits'
	// cache), and refuses one that is not public.
	dial  dialFunc
	log   *Logger
	probe *ProbeRoute
	// lim are the backend's limits; made at first use when nil (tests).
	lim     *hyLimits
	limOnce sync.Once
}

func (o *outbound) limits() *hyLimits {
	o.limOnce.Do(func() {
		if o.lim == nil {
			o.lim = newHyLimits()
		}
	})
	return o.lim
}

// streamContext is ctx until the stream's own end as well: a QUIC stream's
// context ends when its client gives the stream up or the connection goes.
func streamContext(ctx context.Context, conn net.Conn) (context.Context, func()) {
	s, ok := common.Cast[interface{ Context() context.Context }](conn)
	if !ok {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.Context(), cancel)
	return ctx, func() { stop(); cancel() }
}

// isProbe reports whether a destination is the probe name.
func (o *outbound) isProbe(d M.Socksaddr) bool {
	return o.probe != nil && d.IsFqdn() && strings.EqualFold(strings.TrimSuffix(d.Fqdn, "."), o.probe.Name)
}

func (o *outbound) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, t := userFrom(ctx)
	defer t.open()()
	// The user's limits, before the dial (raycontrol conn-limit-v1 §3.2): a
	// place among the user's streams, kept until the stream ends; a token
	// for the attempt, waited for half a second at most and no longer than
	// the stream lasts; and no debt of failed dials. A refusal goes the
	// way a dial's failure does, and says "too many connections".
	wctx, stop := streamContext(ctx, conn)
	done, kind := o.limits().tcpStart(wctx, user)
	stop()
	if kind != "" {
		o.log.Debugf("too many connections")
		_ = N.CloseOnHandshakeFailure(conn, onClose, errTooMany)
		return
	}
	defer done()
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	out, err := o.dialUser(dctx, user, destination)
	cancel()
	if err != nil {
		// The client hears why (Hysteria2's TCP response), not a bare EOF;
		// the log hears neither where nor why: no destination in it.
		reason := dialReason(err)
		if reason == errTooMany.Error() {
			o.log.Debugf("too many connections")
		} else {
			o.log.Debugf("destination unreachable")
		}
		_ = N.CloseOnHandshakeFailure(conn, onClose, errors.New(reason))
		return
	}
	// The answer goes now, not with the destination's first bytes: a
	// client may wait for it before it sends (an honest connect), and with
	// a destination that speaks second both would wait for ever.
	if err := N.ReportConnHandshakeSuccess(conn, out); err != nil {
		out.Close()
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	// The user's bytes at the destination's side: read from it down,
	// written to it up. The copy unwraps the counters (the half-close and
	// the copy's fast paths stay) and adds each buffer once it is through.
	out = bufio.NewInt64CounterConn(out, []*atomic.Int64{&t.down}, []*atomic.Int64{&t.up})
	err = bufio.CopyConn(ctx, conn, out)
	if onClose != nil {
		onClose(err)
	}
}

// dialReason is what a client is told of a failed dial: the kind of
// failure, not the node's own details (its resolver, its addresses).
func dialReason(err error) string {
	var dns *net.DNSError
	switch {
	case errors.Is(err, errTooMany), errors.Is(err, errLookups):
		// A lookup or one more attempt past the user's limits (Niko
		// compares the text: it must not change).
		return errTooMany.Error()
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "no route to host"
	case errors.As(err, &dns) && dns.IsNotFound:
		return "no such host"
	case errors.As(err, &dns):
		return "lookup failed"
	case errors.Is(err, errNotPublic):
		return "destination not allowed"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	default:
		return "unreachable"
	}
}

var errNotPublic = errors.New("destination not public")

// PublicDialer reaches public unicast addresses only: not the node, not
// loopback, private, link-local, CGNAT or multicast ranges.
func PublicDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !Public(ap.Addr()) {
			return errNotPublic
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
