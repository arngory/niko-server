package hysteria2

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := s.handleMessage(message)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(data []byte) error {
	message := allocMessage()
	err := decodeUDPMessage(message, data)
	if err != nil {
		message.releaseMessage()
		return E.Cause(err, "decode UDP message")
	}
	s.handleUDPMessage(message)
	return nil
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage) {
	sessionID := message.sessionID
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = s.newUDPConn(sessionID)
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnectionEx(newCtx, newConn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), M.ParseSocksaddr(message.destination).Unwrap(), nil)
	}
	udpConn.inputPacket(message)
}

// newUDPConn makes the conn of a session and stores it under its number.
// When it ends it takes out only itself (neko): its ctx ends before its
// onDestroy runs, and a datagram of the same number in between makes and
// stores a new conn, which upstream's onDestroy then deleted; the next
// datagram made a third, and the second ran on unseen until its idle time.
func (s *serverSession[U]) newUDPConn(sessionID uint32) *udpPacketConn {
	var udpConn *udpPacketConn
	udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, func() {
		s.udpAccess.Lock()
		if s.udpConnMap[sessionID] == udpConn {
			delete(s.udpConnMap, sessionID)
		}
		s.udpAccess.Unlock()
	})
	udpConn.sessionID = sessionID
	s.udpAccess.Lock()
	s.udpConnMap[sessionID] = udpConn
	s.udpAccess.Unlock()
	return udpConn
}
