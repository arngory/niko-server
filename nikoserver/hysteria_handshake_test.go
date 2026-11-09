//go:build linux

package nikoserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// handshakeConn records what a Hysteria2 stream would tell its client.
type handshakeConn struct {
	net.Conn
	ok   chan struct{}
	fail chan error
}

func (c *handshakeConn) HandshakeSuccess() error          { close(c.ok); return nil }
func (c *handshakeConn) HandshakeFailure(err error) error { c.fail <- err; return nil }

func newHandshakeConn(t *testing.T) *handshakeConn {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() { _, _ = io.Copy(io.Discard, b) }()
	return &handshakeConn{Conn: a, ok: make(chan struct{}), fail: make(chan error, 1)}
}

// The client hears at once that its stream is up, before the destination
// says anything (one that speaks second would wait for the client, which
// may wait for this), and why when it is not, without the node's details.
func TestHysteriaHandshake(t *testing.T) {
	quiet := NewLogger("error", io.Discard)
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close() // says nothing, never closes first
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	closed.Close()

	var d net.Dialer
	direct := &outbound{dial: d.DialContext, log: quiet}
	public := &outbound{dial: PublicDialer().DialContext, log: quiet}
	for name, c := range map[string]struct {
		o    *outbound
		to   string
		want string // "" for success
	}{
		"silent destination": {direct, silent.Addr().String(), ""},
		"refused":            {direct, refused, "connection refused"},
		"not public":         {public, silent.Addr().String(), "destination not allowed"},
		"no such host":       {direct, "nowhere.invalid:80", "no such host"},
	} {
		t.Run(name, func(t *testing.T) {
			hc := newHandshakeConn(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go c.o.NewConnectionEx(ctx, hc, M.Socksaddr{}, M.ParseSocksaddr(c.to), nil)
			select {
			case <-hc.ok:
				if c.want != "" {
					t.Fatalf("success, want %q", c.want)
				}
			case err := <-hc.fail:
				if err.Error() != c.want {
					t.Fatalf("failure %q, want %q", err, c.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the client heard nothing")
			}
		})
	}
}
