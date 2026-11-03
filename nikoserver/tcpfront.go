//go:build linux

package nikoserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// tcpFront is tcpmux (SPEC §3.1): TCP 443, the ClientHello's SNI (or ALPN)
// chooses the backend, the stream goes to it untouched. Not TLS, or no
// route and no default: closed without an answer.
type tcpFront struct {
	log     *Logger
	timeout time.Duration
	byName  map[string]string // server name -> backend
	byALPN  []alpnRoute
	def     string
	refs    map[string]BackendRef
	fdLinks map[string]*fdLink

	listeners []*net.TCPListener
	sniffing  chan struct{} // bounds connections still being read
	wg        sync.WaitGroup
}

type alpnRoute struct {
	protos  []string
	backend string
}

// maxSniffing bounds the connections whose ClientHello is still awaited.
const maxSniffing = 4096

func newTCPFront(c *FrontTCP, backends map[string]BackendRef, log *Logger) *tcpFront {
	f := &tcpFront{log: log, timeout: 5 * time.Second, byName: map[string]string{}, def: c.Default,
		refs: backends, fdLinks: map[string]*fdLink{}, sniffing: make(chan struct{}, maxSniffing)}
	if d, err := time.ParseDuration(c.SniffTimeout); err == nil && d > 0 {
		f.timeout = d
	}
	for _, r := range c.Routes {
		for _, name := range r.SNI {
			f.byName[normalName(name)] = r.Backend
		}
		if len(r.ALPN) > 0 {
			f.byALPN = append(f.byALPN, alpnRoute{protos: r.ALPN, backend: r.Backend})
		}
	}
	used := map[string]bool{c.Default: c.Default != ""}
	for _, r := range c.Routes {
		used[r.Backend] = true
	}
	for name := range used {
		if ref, ok := backends[name]; ok && ref.Mode == "fd" {
			f.fdLinks[name] = &fdLink{name: name, ref: ref, log: log}
		}
	}
	return f
}

func normalName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (f *tcpFront) listen(addrs []string) error {
	for _, listen := range addrs {
		addr := netip.MustParseAddrPort(listen)
		network := "tcp6"
		if addr.Addr().Is4() {
			network = "tcp4"
		}
		ln, err := net.ListenTCP(network, net.TCPAddrFromAddrPort(addr))
		if err != nil {
			f.close()
			return envError("listen %s: %v", listen, err)
		}
		f.listeners = append(f.listeners, ln)
	}
	return nil
}

func (f *tcpFront) close() {
	for _, ln := range f.listeners {
		ln.Close()
	}
}

// run serves until ctx ends; an accept error other than closing ends it.
func (f *tcpFront) run(ctx context.Context) error {
	for _, link := range f.fdLinks {
		go link.run(ctx)
	}
	errCh := make(chan error, len(f.listeners))
	for _, ln := range f.listeners {
		go func() { errCh <- f.serve(ln) }()
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	f.close()
	return err
}

func (f *tcpFront) serve(ln *net.TCPListener) error {
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// EMFILE and the like: back off instead of spinning
			f.log.Warnf("accept %s: %v", ln.Addr(), err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case f.sniffing <- struct{}{}:
		default:
			c.Close() // too many half-open handshakes
			continue
		}
		go f.handle(c)
	}
}

func (f *tcpFront) handle(c *net.TCPConn) {
	_ = c.SetReadDeadline(time.Now().Add(f.timeout))
	hello, prefetch, err := readClientHello(c)
	<-f.sniffing
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	backend := f.route(hello)
	ref, ok := f.refs[backend]
	if !ok {
		c.Close()
		return
	}
	src := addrPort(c.RemoteAddr())
	dst := addrPort(c.LocalAddr())
	switch ref.Mode {
	case "fd":
		err = f.fdLinks[backend].pass(c, tcpHandoff{route: backend, src: src, dst: dst, sni: hello.serverName, prefetch: prefetch})
		if err != nil {
			f.log.Debugf("backend %s: %v", backend, err)
		}
		c.Close() // the backend has its own copy now
	case "proxy-v2":
		f.proxy(c, ref, backend, src, dst, prefetch)
	default:
		c.Close()
	}
}

// route picks the backend for a ClientHello: its name, then ALPN, then the
// default.
func (f *tcpFront) route(h clientHello) string {
	if b, ok := f.byName[h.serverName]; ok && h.serverName != "" {
		return b
	}
	for _, r := range f.byALPN {
		for _, want := range r.protos {
			for _, got := range h.alpn {
				if got == want {
					return r.backend
				}
			}
		}
	}
	return f.def
}

// proxy streams the connection to a backend's unix socket after a PROXY v2
// header and the bytes already read (Xray, acceptProxyProtocol).
func (f *tcpFront) proxy(c *net.TCPConn, ref BackendRef, name string, src, dst netip.AddrPort, prefetch []byte) {
	defer c.Close()
	b, err := net.DialTimeout("unix", ref.Socket, 5*time.Second)
	if err != nil {
		f.log.Debugf("backend %s: %v", name, err)
		return
	}
	defer b.Close()
	uc := b.(*net.UnixConn)
	if uid, err := peerUID(uc); err != nil || uid != ref.UID {
		f.log.Warnf("%s is served by UID %d, want %d (%v)", ref.Socket, uid, ref.UID, err)
		return
	}
	if _, err := b.Write(append(proxyV2Header(src, dst), prefetch...)); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(uc, c)
		_ = uc.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, uc)
		_ = c.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
}
