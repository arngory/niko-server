//go:build linux

package nikoserver

import (
	"encoding/binary"
)

// queryName returns the first question's name of a DNS query, lower case
// (ASCII, RFC 4343) and without the final dot, or ok=false for anything
// that is not a well-formed query (responses, no question, compression, a
// name longer than 253 characters or with a dot inside a label). One copy:
// it runs for every query the front reads.
func queryName(msg []byte) (name string, questionEnd int, ok bool) {
	if len(msg) < 12 || msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, false
	}
	var buf [maxNameText]byte
	n := 0
	i := 12
	for {
		if i >= len(msg) {
			return "", 0, false
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(msg) {
			return "", 0, false
		}
		if n > 0 {
			if n == len(buf) {
				return "", 0, false
			}
			buf[n] = '.'
			n++
		}
		if n+l > len(buf) {
			return "", 0, false
		}
		for _, c := range msg[i : i+l] {
			switch {
			case c == '.':
				// The name would read as other labels than it has.
				return "", 0, false
			case 'A' <= c && c <= 'Z':
				c += 'a' - 'A'
			}
			buf[n] = c
			n++
		}
		i += l
	}
	// type and class
	if i+4 > len(msg) {
		return "", 0, false
	}
	return string(buf[:n]), i + 4, true
}

// maxNameText is the longest name as text: 255 octets on the wire.
const maxNameText = 253

// refused answers a query with REFUSED: same ID, opcode and RD, the question echoed.
func refused(query []byte, questionEnd int) []byte {
	answer := make([]byte, questionEnd)
	copy(answer, query[:questionEnd])
	answer[2] = 0x80 | query[2]&0x79 // QR, opcode, RD
	answer[3] = 5                    // REFUSED
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint16(answer[6:8], 0)
	binary.BigEndian.PutUint16(answer[8:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 0)
	return answer
}
