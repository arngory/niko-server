//go:build linux

package nikoserver

import (
	"encoding/binary"
	"strings"
)

// queryName returns the first question's name of a DNS query, or ok=false for
// anything that is not a well-formed query (responses, no question, compression).
func queryName(msg []byte) (name string, questionEnd int, ok bool) {
	if len(msg) < 12 || msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, false
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return "", 0, false
		}
		n := int(msg[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[i:i+n]))
		i += n
	}
	// type and class
	if i+4 > len(msg) {
		return "", 0, false
	}
	return strings.ToLower(strings.Join(labels, ".")), i + 4, true
}

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
