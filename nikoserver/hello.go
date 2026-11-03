package nikoserver

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// The TLS front reads the ClientHello and nothing else: SNI and ALPN choose
// the backend, the bytes read go to it untouched (SPEC §3.1).

// maxHelloBytes bounds what the front reads before it decides: a ClientHello
// split over several records still fits.
const maxHelloBytes = 64 << 10

var errNotTLS = errors.New("not a TLS ClientHello")

// clientHello is what the front needs from a ClientHello.
type clientHello struct {
	serverName string   // lower case, "" if none
	alpn       []string // in the client's order
}

// readClientHello reads TLS records until they hold a whole ClientHello and
// returns it with every byte read.
func readClientHello(r io.Reader) (clientHello, []byte, error) {
	var raw, handshake []byte
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return clientHello{}, raw, err
		}
		raw = append(raw, header[:]...)
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if header[0] != 0x16 || header[1] != 3 || length == 0 || length > 16384+2048 {
			return clientHello{}, raw, errNotTLS
		}
		if len(raw)+length > maxHelloBytes {
			return clientHello{}, raw, errNotTLS
		}
		start := len(raw)
		raw = append(raw, make([]byte, length)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return clientHello{}, raw, err
		}
		handshake = append(handshake, raw[start:]...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 { // client_hello
			return clientHello{}, raw, errNotTLS
		}
		size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if size > maxHelloBytes {
			return clientHello{}, raw, errNotTLS
		}
		if len(handshake) >= 4+size {
			hello, err := parseClientHello(handshake[4 : 4+size])
			return hello, raw, err
		}
	}
}

// parseClientHello reads server_name and ALPN from a ClientHello body.
func parseClientHello(b []byte) (clientHello, error) {
	var hello clientHello
	s := helloReader(b)
	// legacy_version, random
	if !s.skip(2 + 32) {
		return hello, errNotTLS
	}
	for _, lengthSize := range []int{1, 2, 1} { // session id, cipher suites, compression
		if _, ok := s.vector(lengthSize); !ok {
			return hello, errNotTLS
		}
	}
	if len(s) == 0 {
		return hello, nil // no extensions
	}
	extensions, ok := s.vector(2)
	if !ok {
		return hello, errNotTLS
	}
	for len(extensions) > 0 {
		var typ uint16
		if typ, ok = extensions.uint16(); !ok {
			return hello, errNotTLS
		}
		var data helloReader
		if data, ok = extensions.vector(2); !ok {
			return hello, errNotTLS
		}
		switch typ {
		case 0: // server_name
			list, ok := data.vector(2)
			for ok && len(list) > 0 {
				var nameType []byte
				var name helloReader
				if nameType, ok = list.bytes(1); !ok {
					break
				}
				if name, ok = list.vector(2); ok && nameType[0] == 0 {
					hello.serverName = strings.ToLower(strings.TrimSuffix(string(name), "."))
				}
			}
			if !ok {
				return hello, errNotTLS
			}
		case 16: // application_layer_protocol_negotiation
			list, ok := data.vector(2)
			for ok && len(list) > 0 {
				var proto helloReader
				if proto, ok = list.vector(1); ok {
					hello.alpn = append(hello.alpn, string(proto))
				}
			}
			if !ok {
				return hello, errNotTLS
			}
		}
	}
	return hello, nil
}

type helloReader []byte

func (s *helloReader) skip(n int) bool {
	if len(*s) < n {
		return false
	}
	*s = (*s)[n:]
	return true
}

func (s *helloReader) bytes(n int) ([]byte, bool) {
	if len(*s) < n {
		return nil, false
	}
	b := (*s)[:n]
	*s = (*s)[n:]
	return b, true
}

func (s *helloReader) uint16() (uint16, bool) {
	b, ok := s.bytes(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

// vector reads a length-prefixed field.
func (s *helloReader) vector(lengthSize int) (helloReader, bool) {
	b, ok := s.bytes(lengthSize)
	if !ok {
		return nil, false
	}
	n := 0
	for _, x := range b {
		n = n<<8 | int(x)
	}
	v, ok := s.bytes(n)
	return helloReader(v), ok
}
