// dnstt-server is the server end of a DNS tunnel.
//
// Usage:
//
//	dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	dnstt-server -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN UPSTREAMADDR
//
// Example:
//
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	dnstt-server -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	dnstt-server -gen-key
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
// Package dnsttserver is dnstt-server v1.20260501.0 (www.bamsoftware.com/git/dnstt.git,
// public domain, CC0) as a library for niko-server: the DNS socket and the upstream
// dialer come from the caller instead of flags. Changes are marked "neko".
package dnsttserver

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	maxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second
)

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream Dialer, conv uint32) error {
	// neko: the caller dials the upstream (niko-server: the inner stage's unix socket)
	upstreamConn, err := upstream(upstreamDialTimeout)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := halfCloser{upstreamConn}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream Dialer) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptStream temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream Dialer, sizes *clientSizes) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptKCP temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		m := sessionMTU(mtu, sizes, conn.RemoteAddr())
		if m < mtu {
			log.Printf("session %08x: MTU %d for a requester payload size under %d", conn.GetConv(), m, maxUDPPayload)
		}
		if rc := conn.SetMtu(m); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a TXT record.
func responseFor(query *dns.Message, domain dns.Name, auth *Auth) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	if question.Type != dns.RRTypeTXT {
		// (neko) Only TXT carries data, but another type gets NOERROR
		// with no answer (NODATA), not NXDOMAIN: a resolver minimising
		// QNAMEs (RFC 9156) asks for the names above the tunnel's with A
		// or NS, and one that takes NXDOMAIN as "nothing below"
		// (RFC 8020) then gave up on the whole query.
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error: (neko) no data at this name, as for any query
		// the tunnel does not take (recvLoop).
		return resp, nil
	}
	payload = payload[:n]

	// dnsauth-v1 (neko): the tag before anything that is dnstt's own, so a
	// query without a valid one learns nothing, not even the FORMERR below
	// for a small payload size: the zone answers as an empty one.
	if payload, ok = auth.Check(payload); !ok {
		return resp, nil
	}

	// (neko) A requester payload size under maxUDPPayload is no FORMERR
	// any more: resolvers that advertise 512 or 1220 broke the tunnel. The
	// session of such a client gets a smaller KCP MTU instead (sessionMTU),
	// and its answers are sized for the requester (sendLoop): slower, not
	// dead.
	return resp, payload
}

// carriesData reports whether a NOERROR response may carry downstream data:
// an answer to one TXT question (neko: other types get NODATA).
func carriesData(resp *dns.Message) bool {
	return len(resp.Question) == 1 && resp.Question[0].Type == dns.RRTypeTXT
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
	// Size is the requester's UDP payload size, 512 to maxUDPPayload
	// (neko): the answer stays within it.
	Size int
	// NoData: the query carried no ClientID, the answer no record.
	NoData bool
	// Key is the query's payload (neko): a retry's is the same, however
	// its name was cased or split into labels (answerMemo).
	Key string
}

// answerMemo keeps the data of recent answers by query payload (neko). A
// resolver that hears nothing in time asks again, the same query of the
// client's, and takes whichever answer comes first; the other is dropped.
// Answered with new data, the retry lost what it carried, and KCP had to
// send it again. Now it gets the first answer's data, and so does any
// copy of the query, however its name is cased or split: it takes nothing
// of the client's next data. The payload carries the client's random
// padding, so the client never repeats one. Two generations of
// memoGeneration bound it: an answer is kept 5 to 10 seconds, fewer under
// a flood. Only sendLoop uses it, from one goroutine.
type answerMemo struct {
	cur, prev map[string]memoEntry
	swapped   time.Time
}

type memoEntry struct {
	data []byte // TXT RDATA
	raw  int    // payload bytes in it
}

const (
	memoGeneration = 5 * time.Second
	memoMax        = 4096 // answers in a generation
)

// age turns the generations over by the clock: what is older than two
// generations is gone even when no answer came meanwhile.
func (m *answerMemo) age(now time.Time) {
	switch since := now.Sub(m.swapped); {
	case m.cur == nil || since > 2*memoGeneration:
		m.prev, m.cur, m.swapped = nil, make(map[string]memoEntry), now
	case since > memoGeneration || len(m.cur) >= memoMax:
		m.prev, m.cur, m.swapped = m.cur, make(map[string]memoEntry), now
	}
}

// answer fills rec's answer from the memo, if its query was answered
// lately. Data that would not fit this requester (a retry through a
// smaller resolver) is not sent: the answer goes out empty.
func (m *answerMemo) answer(rec *record) bool {
	if rec.Key == "" {
		return false
	}
	m.age(time.Now())
	e, ok := m.cur[rec.Key]
	if !ok {
		e, ok = m.prev[rec.Key]
	}
	if !ok {
		return false
	}
	data := e.data
	if e.raw > encodedPayload(rec.Size) {
		data = dns.EncodeRDataTXT(nil)
	}
	q := rec.Resp.Question[0]
	rec.Resp.Answer = []dns.RR{{Name: q.Name, Type: q.Type, Class: q.Class, TTL: responseTTL, Data: data}}
	return true
}

func (m *answerMemo) remember(rec *record, raw int) {
	if rec.Key == "" {
		return
	}
	m.age(time.Now())
	m.cur[rec.Key] = memoEntry{data: rec.Resp.Answer[0].Data, raw: raw}
}

// requesterSize is a query's EDNS(0) UDP payload size within 512 and
// maxUDPPayload (neko): RFC 6891 §6.1.1, "values lower than 512 MUST be
// treated as equal to 512"; no OPT, 512.
func requesterSize(query *dns.Message) int {
	size := 512
	for _, rr := range query.Additional {
		if rr.Type == dns.RRTypeOPT {
			size = int(rr.Class)
			break
		}
	}
	return min(max(size, 512), maxUDPPayload)
}

// encodedPayloads[size-512] is computeMaxEncodedPayload(size) for the
// requester sizes from 512 to maxUDPPayload, worked out once (neko).
var (
	encodedPayloadsOnce sync.Once
	encodedPayloads     []int
)

// encodedPayload is the most TXT data an answer to a requester of this
// size may carry, for a query with the longest name.
func encodedPayload(size int) int {
	encodedPayloadsOnce.Do(func() {
		encodedPayloads = make([]int, maxUDPPayload-512+1)
		for s := range encodedPayloads {
			encodedPayloads[s] = computeMaxEncodedPayload(s + 512)
		}
	})
	return encodedPayloads[min(max(size, 512), maxUDPPayload)-512]
}

// clientSizes remembers the smallest requester size each client's queries
// came with (neko): a session's KCP MTU is set from it when KCP accepts
// it, so its packets fit the answers of the resolvers it goes through. The
// MTU of a live session is never changed: KCP panics on segments queued at
// the old size. A smaller requester later gets the packets that fit, the
// others wait (sendLoop). Two generations bound the map: a client not heard
// from for a generation or two is forgotten, never refused.
type clientSizes struct {
	mu        sync.Mutex
	cur, prev map[turbotunnel.ClientID]int
}

// clientSizesMax is the clients of a generation.
const clientSizesMax = 16384

func (c *clientSizes) note(id turbotunnel.ClientID, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		c.cur = map[turbotunnel.ClientID]int{}
	}
	old, ok := c.cur[id]
	if !ok {
		if old, ok = c.prev[id]; !ok && len(c.cur) >= clientSizesMax {
			c.prev, c.cur = c.cur, map[turbotunnel.ClientID]int{}
		}
	}
	if ok && old < size {
		size = old
	}
	c.cur[id] = size
}

func (c *clientSizes) get(id turbotunnel.ClientID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.cur[id]; ok {
		return s
	}
	if s, ok := c.prev[id]; ok {
		return s
	}
	return maxUDPPayload
}

// sessionMTU is the KCP MTU of a client's session: the most a packet may
// be to fit the answers to its smallest requester.
func sessionMTU(mtu int, sizes *clientSizes, addr net.Addr) int {
	id, ok := addr.(turbotunnel.ClientID)
	if !ok || sizes == nil {
		return mtu
	}
	return min(mtu, encodedPayload(sizes.get(id))-2)
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, auth *Auth, sizes *clientSizes) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		resp, payload := responseFor(&query, domain, auth)
		size := requesterSize(&query)
		key := string(payload)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			// Before KCP sees the packets: a new session takes its
			// MTU from it.
			sizes.note(clientID, size)
			// Discard padding and pull out the packets contained in
			// the payload.
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// Feed the incoming packet to KCP.
				ttConn.QueueIncoming(p, clientID)
			}
		}
		// (neko) Without a ClientID (another type, bad base32, no valid
		// dnsauth tag, too short) the answer is NOERROR with no record:
		// the same for every name and type the tunnel does not take, so a
		// scanner learns nothing, and a resolver minimising QNAMEs goes on.
		noData := n != len(clientID)
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID, size, noData, key}:
			default:
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record) error {
	var nextRec *record
	var memo answerMemo
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && carriesData(rec.Resp) && !rec.NoData && memo.answer(rec) {
			// (neko) A query asked before (a resolver's retry): the
			// same data as the first answer, which the resolver may
			// already have taken.
		} else if rec.Resp.Rcode() == dns.RcodeNoError && carriesData(rec.Resp) && !rec.NoData {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			// Any changes to how responses are built need to happen
			// also in computeMaxEncodedPayload.
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer
			// (neko) Within the requester's size, not the global one.
			limit := encodedPayload(rec.Size)
			// We loop and bundle as many packets from OutgoingQueue
			// into the response as will fit. Any packet that would
			// overflow the capacity of the DNS response, we stash
			// to be bundled into a future response.
			timer := time.NewTimer(maxResponseDelay)
			timerExpired := false
			// (neko) Once a stashed packet does not fit this
			// requester at all, it stays stashed and the answer
			// takes what fits from the queue: ACKs and the
			// session's newer, smaller packets go on.
			skipStash := false
			for {
				var p []byte
				unstash := ttConn.Unstash(rec.ClientID)
				if skipStash {
					unstash = nil // a nil channel is never ready
				}
				outgoing := ttConn.OutgoingQueue(rec.ClientID)
				// Prioritize taking a packet first from the
				// stash, then from the outgoing queue, then
				// finally check for the expiration of the timer
				// or for a receive on ch (indicating a new
				// query that we must respond to).
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
							timerExpired = true
						case nextRec = <-ch:
						}
					}
				}
				// We wait for the first packet in a bundle
				// only. The second and later packets must be
				// immediately available or they will be omitted
				// from this bundle.
				if !timerExpired && !timer.Stop() {
					<-timer.C
				}
				timer.Reset(0)
				timerExpired = false

				if len(p) == 0 {
					// timer expired or receive on ch, we
					// are done with this response.
					break
				}

				if 2+len(p) > limit {
					// Stash this packet to send in the next
					// response. (neko) The first packet too,
					// instead of being truncated and lost.
					if !ttConn.Stash(p, rec.ClientID) && skipStash && 2+len(p) <= encodedPayload(rec.Size) {
						// The stash holds a packet no answer to
						// this requester can carry, and this one
						// fits the next: it goes first, the other
						// is dropped, and KCP sends it again.
						select {
						case <-ttConn.Unstash(rec.ClientID):
						default:
						}
						ttConn.Stash(p, rec.ClientID)
					}
					if payload.Len() > 0 {
						break // this answer is full
					}
					// Larger than any answer to this requester
					// (a session that began through a larger
					// resolver): it waits for a larger one,
					// the rest goes on.
					skipStash = true
					continue
				}
				limit -= 2 + len(p)
				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}
				binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			if !timerExpired && !timer.Stop() {
				<-timer.C
			}

			rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
			memo.remember(rec, payload.Len())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if size := min(max(rec.Size, 512), maxUDPPayload); len(buf) > size {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), size)
			buf = buf[:size]
			buf[2] |= 0x02 // TC = 1
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			// net.ErrClosed means we'll never be able to send on
			// dnsConn, so terminate the loop. Treat all other
			// errors as temporary and simply log them.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("WriteTo error: %v", err)
			continue
		}
	}
	return nil
}

// computeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keep the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int) int {
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.RRTypeTXT,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, dns.Name([][]byte{}), nil)
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

// Dialer opens a connection to the upstream for one client stream.
type Dialer func(timeout time.Duration) (net.Conn, error)

// halfCloser shuts one direction where the connection allows it (TCP, unix), or closes it.
type halfCloser struct{ net.Conn }

func (c halfCloser) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c halfCloser) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Conn.Close()
}

// ReadKey reads a key file as dnstt-server -gen-key writes it (64 hex digits).
func ReadKey(filename string) ([]byte, error) { return readKeyFromFile(filename) }

// Run serves the tunnel for domain on dnsConn until one of its loops stops; the
// caller should then exit, as dnstt-server does since v1.20260501.0.
func Run(privkey []byte, domain string, dnsConn net.PacketConn, upstream Dialer) error {
	return RunAuth(privkey, domain, dnsConn, upstream, nil)
}

// RunAuth is Run with dnsauth-v1 (neko): auth checks the tags of queries;
// nil takes queries without them.
func RunAuth(privkey []byte, domain string, dnsConn net.PacketConn, upstream Dialer, auth *Auth) error {
	name, err := dns.ParseName(domain)
	if err != nil {
		return fmt.Errorf("invalid domain %+q: %v", domain, err)
	}
	return run(privkey, name, upstream, dnsConn, auth)
}

func run(privkey []byte, domain dns.Name, upstream Dialer, dnsConn net.PacketConn, auth *Auth) error {
	defer dnsConn.Close()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	maxEncodedPayload := computeMaxEncodedPayload(maxUDPPayload)
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// The smallest requester size of each client (neko).
	sizes := &clientSizes{}

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()

	// We will run acceptSessions, sendLoop, and recvLoop concurrently. The
	// first one to finish closes the done channel.
	doneChan := make(chan struct{})
	var doneOnce sync.Once
	done := func() { doneOnce.Do(func() { close(doneChan) }) }

	go func() {
		defer done()
		err := acceptSessions(ln, privkey, mtu, upstream, sizes)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	// recvLoop is the only sender on ch and closes it when it returns
	// (neko): run may return first, and closing ch then raced a send.
	ch := make(chan *record, 100)

	// We could run multiple copies of sendLoop; that would allow more time
	// for each response to collect downstream data before being evicted by
	// another response that needs to be sent.
	go func() {
		defer done()
		err := sendLoop(dnsConn, ttConn, ch)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	go func() {
		defer done()
		err := recvLoop(domain, dnsConn, ttConn, ch, auth, sizes)
		close(ch)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()

	// Wait for any of acceptSessions, sendLoop, or recvLoop to return. In
	// normal operation, we don't expect any of these to return.
	<-doneChan

	return nil
}

// GenerateKeypair returns a new server key pair as hex (neko).
func GenerateKeypair() (private, public string, err error) {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return "", "", err
	}
	return noise.EncodeKey(privkey), noise.EncodeKey(noise.PubkeyFromPrivkey(privkey)), nil
}

// MaxTXTData is the most TXT data dnstt puts in an answer to a requester
// of this EDNS size (512 for none): the DNS front's probe answers keep
// within it, as the tunnel's own do (neko).
func MaxTXTData(size int) int { return encodedPayload(size) }
