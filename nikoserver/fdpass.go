//go:build linux

package nikoserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// fdLink is the front's connection to a backend in mode "fd": one
// SOCK_SEQPACKET connection, kept up with backoff; each accepted TCP
// connection goes over it as its socket (SCM_RIGHTS) and a handoff message.
type fdLink struct {
	name string
	ref  BackendRef
	log  *Logger

	access sync.Mutex
	conn   *net.UnixConn
}

var errBackendAway = errors.New("backend not connected")

// pass hands the connection to the backend; the caller closes its copy.
func (l *fdLink) pass(tcp *net.TCPConn, h tcpHandoff) error {
	l.access.Lock()
	conn := l.conn
	l.access.Unlock()
	if conn == nil {
		return errBackendAway
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	msg := encodeHandoff(h)
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		_, _, sendErr = conn.WriteMsgUnix(msg, syscall.UnixRights(int(fd)), nil)
	})
	if err == nil {
		err = sendErr
	}
	if err != nil {
		conn.Close() // run reconnects
	}
	return err
}

func (l *fdLink) run(ctx context.Context) {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		conn, err := dialBackend(l.ref)
		if err != nil {
			l.log.Debugf("backend %s: %v (retry in %s)", l.name, err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 5*time.Second)
			continue
		}
		backoff = 100 * time.Millisecond
		l.log.Infof("backend %s connected", l.name)
		l.access.Lock()
		l.conn = conn
		l.access.Unlock()
		// The backend sends nothing: a read returns when it goes away.
		done := make(chan struct{})
		go func() {
			var b [1]byte
			_, _ = conn.Read(b[:])
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
		l.access.Lock()
		l.conn = nil
		l.access.Unlock()
		conn.Close()
		<-done
		l.log.Warnf("backend %s disconnected", l.name)
	}
}

// dialBackend connects to a backend's SOCK_SEQPACKET socket and checks that
// the expected UID serves it.
func dialBackend(ref BackendRef) (*net.UnixConn, error) {
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: ref.Socket, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	uid, err := peerUID(conn)
	if err != nil || uid != ref.UID {
		conn.Close()
		return nil, envError("%s is served by UID %d, want %d (%v)", ref.Socket, uid, ref.UID, err)
	}
	conn.SetWriteBuffer(4 << 20)
	return conn, nil
}

// FDListener is a backend's end of mode "fd": a net.Listener whose
// connections are the sockets the front passes, the bytes the front already
// read coming first.
type FDListener struct {
	listener *net.UnixListener
	frontUID int
	log      *Logger

	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

// ListenFD creates the backend's fd socket (mode 0660) and serves the
// front's connections to it.
func ListenFD(path string, frontUID int, log *Logger) (*FDListener, error) {
	listener, err := listenPacketSocket(path)
	if err != nil {
		return nil, err
	}
	l := &FDListener{listener: listener, frontUID: frontUID, log: log, conns: make(chan net.Conn), closed: make(chan struct{})}
	go l.acceptLoop()
	return l, nil
}

func (l *FDListener) acceptLoop() {
	for {
		conn, err := l.listener.AcceptUnix()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.log.Warnf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		uid, err := peerUID(conn)
		if err != nil || uid != l.frontUID {
			l.log.Warnf("refused a connection from UID %d (want the front, %d): %v", uid, l.frontUID, err)
			conn.Close()
			continue
		}
		conn.SetReadBuffer(4 << 20)
		go l.readLoop(conn)
	}
}

func (l *FDListener) readLoop(conn *net.UnixConn) {
	defer conn.Close()
	buffer := make([]byte, 4+2+255+2*addrSize+1+255+4+maxHelloBytes)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(buffer, oob)
		if err != nil || (n == 0 && oobn == 0) {
			return
		}
		fds := receivedFDs(oob[:oobn])
		h, err := decodeHandoff(buffer[:n])
		if err != nil || len(fds) != 1 {
			l.log.Warnf("bad handoff from the front (%d sockets): %v", len(fds), err)
			for _, fd := range fds {
				syscall.Close(fd)
			}
			continue
		}
		file := os.NewFile(uintptr(fds[0]), "front")
		c, err := net.FileConn(file)
		file.Close()
		if err != nil {
			l.log.Warnf("passed socket: %v", err)
			continue
		}
		passed := &prefetchConn{Conn: c, r: io.MultiReader(bytes.NewReader(append([]byte(nil), h.prefetch...)), c), remote: h.src, sni: h.sni}
		select {
		case l.conns <- passed:
		case <-l.closed:
			c.Close()
			return
		}
	}
}

func receivedFDs(oob []byte) []int {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for _, m := range msgs {
		if got, err := syscall.ParseUnixRights(&m); err == nil {
			fds = append(fds, got...)
		}
	}
	return fds
}

func (l *FDListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *FDListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.listener.Close()
	})
	return nil
}

func (l *FDListener) Addr() net.Addr { return l.listener.Addr() }

// prefetchConn reads the front's prefetch first; RemoteAddr is the client's.
type prefetchConn struct {
	net.Conn
	r      io.Reader
	remote netip.AddrPort
	sni    string
}

func (c *prefetchConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *prefetchConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }

// ServerName is the SNI the front routed by.
func (c *prefetchConn) ServerName() string { return c.sni }

// CloseWrite half-closes the passed TCP socket.
func (c *prefetchConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
