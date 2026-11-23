package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	GeckoPassword         string
	GeckoMinPacketSize    int
	GeckoMaxPacketSize    int
	TLSConfig             aTLS.ServerConfig
	QUICOptions           qtls.QUICOptions
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
	BBRProfile            string
	RealmOptions          *realm.Options
	// ConnectionHook, if set, learns of each authenticated connection: the
	// client's address, the user it authenticated as, its stats while it
	// lives, a way to close it, and when it ends (neko). The password is
	// checked once per connection, so UpdateUsers alone leaves a removed
	// user's connections open; closeConnection ends one with all its streams
	// and datagrams, at once or later, as often as wanted. The hook runs in
	// the auth request's handler after the password check, which may have
	// read the table UpdateUsers has just replaced: a caller closing the
	// connections of users it took out must refuse those here as well.
	ConnectionHook func(remote net.Addr, user any, stats func() ConnectionStats, closeConnection func(), done <-chan struct{})
	// ConnectionIDGenerator, if set, makes the server's connection IDs
	// (neko: IDs whose label the UDP front routes a client by when its
	// address changes); nil: quic-go's random ones.
	ConnectionIDGenerator quic.ConnectionIDGenerator
	// PathValidation (neko): the server sends to a client's new address
	// only once the client has answered a PATH_CHALLENGE there (quic-go's
	// path manager, RFC 9000 §9). Without it (upstream) the server moves
	// its whole send stream to any address one of the connection's packets
	// came from, at once: a client that spoofs a victim's source address
	// aims its download at the victim. Port hopping works either way; with
	// it a hop costs one round trip.
	PathValidation bool
	// StatelessResetKey (neko), if set, is the key of the server's
	// stateless resets, with an obfuscation too: a client whose connection
	// the server no longer has (closed while the client slept, or by a
	// restart) gets a reset at its next packet, and does not wait out its
	// idle timeout. Without it (upstream), resets with a key of the
	// process's own, and none under an obfuscation, where a reset would
	// answer anyone's probe; the caller sets it only where nothing but its
	// own clients' packets reaches the server (neko: the UDP front routes
	// by the labels of the server's connection IDs).
	StatelessResetKey *quic.StatelessResetKey
	// ObfsConnFilter (neko), if set, wraps the packet socket under the
	// obfuscation, where the QUIC packets are plain.
	ObfsConnFilter func(net.PacketConn) net.PacketConn
	// AuthCurve (neko), if set, is the key exchange a connection's TLS must
	// have taken for its password to be checked: on any other the auth
	// request gets the masquerade, as a wrong password does. The handshake
	// may then take groups the users' clients never offer (a site's), and
	// what the users send stays under this one.
	AuthCurve tls.CurveID
	// WrapCongestionControl (neko), if set, takes an authenticated
	// connection's congestion controller (Brutal, or BBR when the client
	// gives no rate) with the user, and gives the one the connection gets.
	WrapCongestionControl func(conn *quic.Conn, user any, cc congestion.CongestionControl) congestion.CongestionControl
	// StreamStart (neko), if set, is asked for each stream of an
	// authenticated connection before its TCP request is read: false resets
	// the stream at once; true with done, which the service calls once the
	// request is read (or failed), as the handler is called. RequestWait
	// (neko), if set, bounds the wait for the request.
	StreamStart func(user any) (done func(), ok bool)
	RequestWait time.Duration
	// PendingStreams (neko), if set, is how many streams of a connection,
	// authenticated or not, are read at once before they are known: until
	// their first frame type, and an HTTP request (the auth request, the
	// masquerade's) until its handler returns; the next ones wait to be
	// accepted. Each then waits RequestWait at most for its bytes, or is
	// reset. Without it (upstream) every stream gets a goroutine at once,
	// which waits as long as its client sends nothing.
	PendingStreams int
}

// errClosedByHook is how a connection ends when its ConnectionHook closes it
// (neko): a closed error, so that it is logged at debug level.
var errClosedByHook = E.Cause(net.ErrClosed, "closed by the server")

// ConnectionStats is what the server knows of a client connection (neko):
// QUIC's own numbers and, when the client gave its rate, the server's
// Brutal sender (its rate and the share of packets acknowledged).
type ConnectionStats struct {
	quic.ConnectionStats
	Brutal  bool
	RateBPS uint64  // bytes per second Brutal sends at
	AckRate float64 // Brutal's acknowledged share over the last seconds
}

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	geckoPassword         string
	geckoMinPacketSize    int
	geckoMaxPacketSize    int
	tlsConfig             aTLS.ServerConfig
	quicConfig            *quic.Config
	users                 atomic.Pointer[map[string]U] // swapped whole by UpdateUsers (neko: was a racy map write)
	connectionHook        func(remote net.Addr, user any, stats func() ConnectionStats, closeConnection func(), done <-chan struct{})
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	bbrProfile            congestion_meta2.Profile
	realmServer           *realm.Server
	connIDGenerator       quic.ConnectionIDGenerator
	statelessResetKey     *quic.StatelessResetKey
	obfsConnFilter        func(net.PacketConn) net.PacketConn
	authCurve             tls.CurveID
	wrapCongestionControl func(conn *quic.Conn, user any, cc congestion.CongestionControl) congestion.CongestionControl
	streamStart           func(user any) (done func(), ok bool)
	requestWait           time.Duration
	pendingStreams        int
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             1 << 60,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		DisablePathManager:             !options.PathValidation,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = geckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = geckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > geckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	var realmServer *realm.Server
	if options.RealmOptions != nil {
		var err error
		realmServer, err = realm.NewServer(*options.RealmOptions)
		if err != nil {
			return nil, E.Cause(err, "create realm server")
		}
	}
	service := &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		geckoPassword:         options.GeckoPassword,
		geckoMinPacketSize:    options.GeckoMinPacketSize,
		geckoMaxPacketSize:    options.GeckoMaxPacketSize,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		connectionHook:        options.ConnectionHook,
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		bbrProfile:            bbrProfile,
		realmServer:           realmServer,
		connIDGenerator:       options.ConnectionIDGenerator,
		statelessResetKey:     options.StatelessResetKey,
		obfsConnFilter:        options.ObfsConnFilter,
		authCurve:             options.AuthCurve,
		wrapCongestionControl: options.WrapCongestionControl,
		streamStart:           options.StreamStart,
		requestWait:           options.RequestWait,
		pendingStreams:        options.PendingStreams,
	}
	service.users.Store(&map[string]U{})
	return service, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	s.users.Store(&userMap)
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.realmServer != nil {
		return s.startWithRealm(conn)
	}
	if s.geckoPassword != "" {
		conn = NewGeckoConn(conn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	obfsEnabled := s.geckoPassword != "" || s.salamanderPassword != ""
	if obfsEnabled && s.obfsConnFilter != nil {
		conn = s.obfsConnFilter(conn)
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	listener, err := qtls.ListenWithOptions(conn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		DisableVersionNegotiationPackets: obfsEnabled,
		StatelessReset:                   !obfsEnabled,
		StatelessResetKey:                s.statelessResetKey,
		ConnectionIDGenerator:            s.connIDGenerator,
	})
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) startWithRealm(conn net.PacketConn) error {
	punchConn, err := s.realmServer.Start(s.ctx, conn)
	if err != nil {
		return E.Cause(err, "start realm server")
	}
	var quicConn net.PacketConn = punchConn
	if s.geckoPassword != "" {
		quicConn = NewGeckoConn(quicConn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		quicConn = NewSalamanderConn(quicConn, []byte(s.salamanderPassword))
	}
	err = qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return E.Errors(err, s.realmServer.Close())
	}
	obfsEnabled := s.geckoPassword != "" || s.salamanderPassword != ""
	listener, err := qtls.ListenWithOptions(quicConn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		DisableVersionNegotiationPackets: obfsEnabled,
		StatelessReset:                   !obfsEnabled,
		ConnectionIDGenerator:            s.connIDGenerator,
	})
	if err != nil {
		return E.Errors(err, s.realmServer.Close())
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	var realmErr error
	if s.realmServer != nil {
		realmErr = s.realmServer.Close()
	}
	return E.Errors(realmErr, common.Close(s.quicListener))
}

func (s *Service[U]) Reset() {
	if s.realmServer != nil {
		s.realmServer.Reset()
	}
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	if s.pendingStreams > 0 {
		_ = session.serveStreams(&httpServer)
	} else {
		_ = httpServer.ServeQUICConn(connection)
	}
	_ = connection.CloseWithError(0, "")
}

// serveStreams is http3.Server.ServeQUICConn with the streams read before
// they are known bounded (neko, PendingStreams): pendingStreams at once,
// each for requestWait at most. Graceful shutdown is not needed here: the
// service closes its connections whole.
func (s *serverSession[U]) serveStreams(srv *http3.Server) error {
	conn := s.quicConn
	hconn, err := srv.NewRawServerConn(conn)
	if err != nil {
		return err
	}
	go func() {
		for {
			str, err := conn.AcceptUniStream(conn.Context())
			if err != nil {
				return
			}
			go hconn.HandleUnidirectionalStream(str)
		}
	}()
	places := make(chan struct{}, s.pendingStreams)
	for {
		str, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return err
		}
		select {
		case places <- struct{}{}:
		case <-conn.Context().Done():
			return conn.Context().Err()
		}
		go func() {
			defer func() { <-places }()
			if s.requestWait > 0 {
				_ = str.SetReadDeadline(time.Now().Add(s.requestWait))
			}
			frameType, err := quicvarint.Peek(str)
			if err != nil {
				str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
				str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
				return
			}
			handled, err := s.dispatchStream(http3.FrameType(frameType), str, nil)
			if err != nil {
				str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
				str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
				return
			}
			if !handled {
				// An HTTP request: its header and its handler within the
				// same wait (the auth request has no body, the masquerade
				// reads none).
				hconn.HandleRequestStream(str)
			}
		}()
	}
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	// auth is the user the connection authenticated as, nil before (neko:
	// a bool and a U written by the auth request's handler and read by the
	// stream's goroutines without a lock, so a stream could see the bool
	// and not the user).
	auth       atomic.Pointer[U]
	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*udpPacketConn
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		authenticated := func() {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.receiveBPS == 0 && s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
		}
		if _, ok := s.user(); ok {
			authenticated()
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := (*s.users.Load())[request.Auth]
		if loaded && s.authCurve != 0 && s.quicConn.ConnectionState().TLS.CurveID != s.authCurve {
			// Not the key exchange the users' traffic must have (neko):
			// a stranger's, whatever the password.
			loaded = false
		}
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		// One auth request of a connection's makes it its user's (neko): of
		// two at once, the second is answered as authenticated already, and
		// the connection's controller, hook and datagram loop are set once.
		// Before, both went on, and the hook admitted the connection twice.
		// A request the server answers with the masquerade is no auth: it
		// leaves the connection unauthenticated (neko), before the swap.
		if s.receiveBPS > 0 && s.ignoreClientBandwidth && request.Rx == 0 {
			s.logger.Debug("process connection from ", r.RemoteAddr, ": BBR disabled by server")
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		if !s.auth.CompareAndSwap(nil, &user) {
			authenticated()
			return
		}
		var rxAuto bool
		var brutal *hyCC.BrutalSender
		if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			brutal = hyCC.NewBrutalSender(rx, s.quicConn.InitialPacketSize(), s.brutalDebug, s.logger)
			s.setCongestionControl(user, brutal)
		} else {
			s.setCongestionControl(user, congestion_meta2.NewBbrSenderWithProfile(
				s.quicConn.InitialPacketSize(),
				s.bbrProfile,
			))
			rxAuto = true
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     rxAuto,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.connectionHook != nil {
			conn := s.quicConn
			s.connectionHook(conn.RemoteAddr(), user, func() ConnectionStats {
				st := ConnectionStats{ConnectionStats: conn.ConnectionStats()}
				if brutal != nil {
					st.Brutal, st.RateBPS, st.AckRate = true, brutal.BPS(), brutal.AckRate()
				}
				return st
			}, func() { s.closeWithError(errClosedByHook) }, conn.Context().Done())
		}
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

// user is whom the connection authenticated as, if it did.
func (s *serverSession[U]) user() (U, bool) {
	if p := s.auth.Load(); p != nil {
		return *p, true
	}
	var none U
	return none, false
}

// setCongestionControl gives the connection cc, through the caller's wrap
// if it has one (neko).
func (s *serverSession[U]) setCongestionControl(user U, cc congestion.CongestionControl) {
	if s.wrapCongestionControl != nil {
		cc = s.wrapCongestionControl(s.quicConn, user, cc)
	}
	s.quicConn.SetCongestionControl(cc)
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	user, authenticated := s.user()
	if !authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	// The caller's admission of a stream before its request (neko): one
	// refused is reset, as a stream past the connection's limit would be.
	var started func()
	if s.streamStart != nil {
		done, ok := s.streamStart(user)
		if !ok {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return true, nil
		}
		started = done
	}
	if s.requestWait > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(s.requestWait))
	}
	_, err = quicvarint.Read(quicvarint.NewReader(stream))
	if err != nil {
		if started != nil {
			started()
		}
		s.logger.Error(E.Cause(err, "seek frame type"))
		return true, nil
	}
	go func() {
		hErr := s.handleStream(stream, user, started)
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream *quic.Stream, user U, started func()) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if started != nil {
		started()
	}
	if s.requestWait > 0 {
		_ = stream.SetReadDeadline(time.Time{})
	}
	if err != nil {
		return E.New("read TCP request")
	}
	destination := M.ParseSocksaddr(destinationString).Unwrap()
	if len(destination.Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, user), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint32]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrInvalid
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

// CloseWrite ends this side of the stream and keeps reading the client's
// (neko, from the client's fork arngory/sing-box 26325f0): bufio.CopyConn
// passes the target's half-close on to a connection that has CloseWrite and
// closes the others whole, so a target that finished first cancelled the
// client's upload still under way. The response goes out first if it has
// not.
func (c *serverConn) CloseWrite() error {
	if err := c.HandshakeSuccess(); err != nil {
		return err
	}
	return qtls.WrapError(c.Stream.Close())
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
