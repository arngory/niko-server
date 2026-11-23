package hysteria2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

var udpMessagePool = sync.Pool{
	New: func() interface{} {
		return new(udpMessage)
	},
}

func allocMessage() *udpMessage {
	message := udpMessagePool.Get().(*udpMessage)
	message.referenced = true
	return message
}

func releaseMessages(messages []*udpMessage) {
	for _, message := range messages {
		if message != nil {
			message.releaseMessage()
		}
	}
}

type udpMessage struct {
	sessionID     uint32
	packetID      uint16
	fragmentID    uint8
	fragmentTotal uint8
	destination   string
	data          *buf.Buffer
	referenced    bool
	held          int // neko: the received datagram's bytes this message keeps (decodeUDPMessage)
}

// footprint is what a client's message keeps of the server's memory
// (neko): the datagram it was decoded from, whose payload it slices, or
// its own buffer, its destination, and the message itself; the bounds of a
// session count it, not the payload alone, which a datagram of a long
// destination and no data makes nothing.
func (m *udpMessage) footprint() int {
	n := m.held
	if n == 0 && m.data != nil {
		n = m.data.RawCap()
	}
	return n + len(m.destination) + udpMessageOverhead
}

func (m *udpMessage) release() {
	if !m.referenced {
		return
	}
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *udpMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		protocol.WriteVString(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 8 + int(quicvarint.Len(uint64(len(m.destination)))) + len(m.destination)
}

func fragUDPMessage(message *udpMessage, maxPacketSize int) []*udpMessage {
	udpMTU := maxPacketSize - message.headerSize()
	if message.data.Len() <= udpMTU {
		return []*udpMessage{message}
	}
	var fragments []*udpMessage
	originPacket := message.data.Bytes()
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := allocMessage()
		*fragment = *message
		if remaining > udpMTU {
			fragment.data = buf.As(originPacket[:udpMTU])
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = buf.As(originPacket)
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	fragmentTotal := uint16(len(fragments))
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(fragmentTotal)
		/*if index > 0 {
			fragment.destination = ""
			// not work in hysteria
		}*/
	}
	return fragments
}

type udpPacketConn struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	sessionID       uint32
	quicConn        *quic.Conn
	data            chan *udpMessage
	udpMTU          int
	packetId        atomic.Uint32
	closeOnce       sync.Once
	defragger       *udpDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	queued          atomic.Int64 // bytes in data (neko)
}

// The bounds of a session's datagrams from the client (neko). Before, a
// session queued 64 messages whatever their size, a reassembled one up to
// 64 KiB, while its reader waited (a lookup takes seconds), and kept the
// fragments of up to 65536 packets for 10 s, none ever completed: a user's
// 256 sessions held what the client sent of them, unbounded. Now a session
// queues udpQueueBytes, keeps the fragments of udpDefragPackets packets
// (Hysteria's own keeps one), and a packet whose fragments keep more than
// udpMaxPacketBytes is dropped; their number is the client's (up to 255),
// which a long destination's header or a smaller MTU raises. Each counts
// at its footprint, the datagram and the destination it keeps; and a
// destination longer than udpMaxDestination is no message (an IPv6
// literal's zone could be a kilobyte).
const (
	udpQueueBytes      = 128 << 10
	udpDefragPackets   = 2
	udpMaxPacketBytes  = 96 << 10 // 65535 of payload and the fragments' own: 78 of 300 bytes of destination
	udpMaxDestination  = 300      // a name of 255 and a port; an IPv6 address with a zone (Linux: 15)
	udpMessageOverhead = 96       // the message, its buffer's header, the strings' headers
)

// took counts a message out of the queue.
func (c *udpPacketConn) took(p *udpMessage) { c.queued.Add(-int64(p.footprint())) }

func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, onDestroy func()) *udpPacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &udpPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		quicConn:     quicConn,
		data:         make(chan *udpMessage, 64),
		udpMTU:       1200 - 3,
		defragger:    newUDPDefragger(),
		onDestroy:    onDestroy,
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		c.took(p)
		_, err = buffer.ReadOnceFrom(p.data)
		destination = M.ParseSocksaddr(p.destination).Unwrap()
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		c.took(pkt)
		n = copy(p, pkt.data.Bytes())
		destination := M.ParseSocksaddr(pkt.destination).Unwrap()
		if destination.IsDomain() {
			addr = destination
		} else {
			addr = destination.UDPAddr()
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > protocol.MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: protocol.MaxUDPSize}
	}
	if !destination.IsIP() && len(destination.Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination.String(),
		data:          buffer,
	}
	defer message.releaseMessage()
	var err error
	if c.udpMTU > message.headerSize() && buffer.Len() > c.udpMTU-message.headerSize() {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) || int(tooLargeErr.MaxDatagramPayloadSize-3) <= message.headerSize() {
		return err
	}
	return c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > protocol.MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: protocol.MaxUDPSize}
	}
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsIP() && len(destination.Fqdn) > 255 {
		return 0, E.New("fqdn too long")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   addr.String(),
		data:          buf.As(p),
	}
	defer message.releaseMessage()
	if c.udpMTU > message.headerSize() && len(p) > c.udpMTU-message.headerSize() {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return len(p), nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) || int(tooLargeErr.MaxDatagramPayloadSize-3) <= message.headerSize() {
		return
	}
	err = c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
	if err == nil {
		return len(p), nil
	}
	return
}

func (c *udpPacketConn) inputPacket(message *udpMessage) {
	if message.fragmentTotal > 1 {
		if message = c.defragger.feed(message); message == nil {
			return
		}
	}
	// Within udpQueueBytes (neko); a full queue or past them, dropped.
	n := int64(message.footprint())
	if c.queued.Add(n) > udpQueueBytes {
		c.queued.Add(-n)
		message.releaseMessage()
		return
	}
	select {
	case c.data <- message:
	default:
		c.queued.Add(-n)
		message.releaseMessage()
	}
}

func (c *udpPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	buffer := message.pack()
	defer buffer.Release()
	return c.quicConn.SendDatagram(buffer.Bytes())
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
}

// SessionID is the session's number, as its client chose it (neko): a
// handler that refuses a session, which the client then repeats with every
// datagram, tells the repeats of one session by it.
func (c *udpPacketConn) SessionID() uint32 {
	return c.sessionID
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) ReaderMTU() int {
	return protocol.MaxUDPSize
}

func (c *udpPacketConn) WriterMTU() int {
	return protocol.MaxUDPSize
}

type udpDefragger struct {
	packetMap *cache.LruCache[uint16, *packetItem]
}

func newUDPDefragger() *udpDefragger {
	return &udpDefragger{
		packetMap: cache.New(
			cache.WithAge[uint16, *packetItem](10),
			cache.WithSize[uint16, *packetItem](udpDefragPackets), // neko
			cache.WithUpdateAgeOnGet[uint16, *packetItem](),
			cache.WithEvict[uint16, *packetItem](func(key uint16, value *packetItem) {
				releaseMessages(value.messages)
			}),
		),
	}
}

type packetItem struct {
	access   sync.Mutex
	messages []*udpMessage
	count    uint8
	bytes    int // of the fragments kept (neko)
}

func (d *udpDefragger) feed(m *udpMessage) *udpMessage {
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		m.releaseMessage()
		return nil
	}
	item, _ := d.packetMap.LoadOrStore(m.packetID, newPacketItem)
	item.access.Lock()
	defer item.access.Unlock()
	if int(m.fragmentTotal) != len(item.messages) {
		releaseMessages(item.messages)
		item.messages = make([]*udpMessage, m.fragmentTotal)
		item.count = 1
		item.messages[m.fragmentID] = m
		item.bytes = m.footprint()
		return nil
	}
	if item.messages[m.fragmentID] != nil {
		m.releaseMessage()
		return nil
	}
	if item.bytes += m.footprint(); item.bytes > udpMaxPacketBytes { // neko
		m.releaseMessage()
		releaseMessages(item.messages)
		item.messages, item.count, item.bytes = nil, 0, 0
		return nil
	}
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	newMessage := allocMessage()
	newMessage.sessionID = m.sessionID
	newMessage.packetID = m.packetID
	newMessage.destination = item.messages[0].destination
	var finalLength int
	for _, message := range item.messages {
		finalLength += message.data.Len()
	}
	if finalLength > 0 {
		newMessage.data = buf.NewSize(finalLength)
		for _, message := range item.messages {
			newMessage.data.Write(message.data.Bytes())
			message.releaseMessage()
		}
		item.messages = nil
		return newMessage
	} else {
		newMessage.releaseMessage()
		for _, message := range item.messages {
			message.releaseMessage()
		}
	}
	item.messages = nil
	return nil
}

func newPacketItem() *packetItem {
	return new(packetItem)
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	message.destination, err = protocol.ReadVString(reader)
	if err != nil {
		return err
	}
	if len(message.destination) > 255 && len(M.ParseSocksaddr(message.destination).Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	if len(message.destination) > udpMaxDestination { // neko
		return E.New("destination too long")
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	message.held = cap(data)
	return nil
}
