package nikoserver

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"github.com/arngory/niko-server/dnsttserver"
)

// serveDNSTTStats gives the dnstt backend's counters on a unix socket: to
// each connection a dnsttserver.StatsSnapshot as one JSON line, then the
// close; nothing is read. The socket's directory keeps it to the service's
// group (raycontrol's rayd), as the Hysteria2 backends' stats socket.
func serveDNSTTStats(path string, stats *dnsttserver.Stats, auth *dnsttserver.Auth, seal *dnsttserver.Seal, log *Logger) (func(), error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(c).Encode(stats.Snapshot(auth, seal))
			c.Close()
		}
	}()
	log.Infof("stats on %s", path)
	return func() { ln.Close() }, nil
}
