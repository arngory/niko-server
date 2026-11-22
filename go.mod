module github.com/arngory/niko-server

go 1.26.0

toolchain go1.27.4

require (
	github.com/Arceliar/ironwood v0.0.0-20261023231900-0712eccbb962
	github.com/quic-go/quic-go v0.64.1
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
	github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf
	github.com/sagernet/sing-box v1.14.4
	github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4
	github.com/xtaci/kcp-go/v5 v5.6.8
	github.com/xtaci/smux v1.5.24
	github.com/yggdrasil-network/yggdrasil-go v0.5.14
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	masterdnsvpn-go v0.0.0
	www.bamsoftware.com/git/dnstt.git v1.20260501.0
)

require (
	github.com/Arceliar/phony v0.0.0-20220903101357-530938a4b13d // indirect
	github.com/bits-and-blooms/bitset v1.26.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.7.1 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/gologme/log v1.3.0 // indirect
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/andybalholm/brotli v1.2.8 // indirect
	github.com/caddyserver/certmagic v0.25.3-0.20260421143802-60d9d8b415d6 // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/database64128/tfo-go/v2 v2.3.2 // indirect
	github.com/florianl/go-nfqueue/v2 v2.1.0 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.20.4 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libdns/acmedns v0.5.0 // indirect
	github.com/libdns/alidns v1.0.6 // indirect
	github.com/libdns/cloudflare v0.2.2 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/mholt/acmez/v3 v3.1.6 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/fswatch v0.1.2 // indirect
	github.com/sagernet/netlink v0.0.0-20260814022025-64455d367bbf // indirect
	github.com/sagernet/nftables v0.3.0-mod.4 // indirect
	github.com/sagernet/sing-tun v0.9.7-0.20261023115432-040db71fcd33 // indirect
	github.com/sagernet/sing-usbip v0.0.0-20260817040617-28bd42667eca // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
)

replace github.com/sagernet/sing-box => github.com/arngory/sing-box v1.14.5-0.20261102040805-34eaa8c9c5a9

replace masterdnsvpn-go => github.com/arngory/sing-box/third_party/masterdnsvpn v0.0.0-20261106212949-f0eadfa3e71c

replace github.com/yggdrasil-network/yggdrasil-go => github.com/arngory/yggdrasil-go v0.5.16-0.20261122081220-4f11eeb903b2

// ironwood from the fork (de48fd0 on upstream's 0712ecc): a repeated session
// init gets its first ack again, while nothing came over the session, so the
// first contact of a device no longer hangs a minute when that ack was lost
// (found and fixed by the client, arngory/niko); a window of 8128 nonces
// (upstream's Arceliar/ironwood#53, as WireGuard's) takes a packet reordered
// on the way, which a strict high-water mark dropped; and a traffic packet
// too short for the sender's next key is dropped: with long varints it passed
// the size check, and any peer of a session crashed the process with one
// (arngory/ironwood#1); at a ratchet step the new receive key keeps the strict
// mark it had as the next key, and the minute of packets before the step no
// longer opens again (arngory/ironwood#2); a peer's init keeps the replay
// state of the keys that stay receive keys, and a re-init no longer opens
// again what the peer sent before it, as upstream did (arngory/ironwood#3).
// The wire is the same. Since v0.19.0, ironwood's hybrid post-quantum
// sessions, off unless options.pq turns them on; off, what the node sends of
// its own is as above (its replies to PQ packets are core.PQSessions').
// From the forks' main lines now: ironwood main 15d2d67 (arngory/ironwood#5,
// on e8dbf9c, the tree of cf9739c that v0.19.0 pinned: of two ends, the one
// with the higher key starts the PQ upgrade itself when the other, an answer
// only node, does not; a lost answer to our PQInfo is asked again; the
// classic session takes the peer's traffic for 3 s after the switch, so a
// window of data in flight is not lost), yggdrasil-go niko 4f11eeb
// (arngory/yggdrasil-go#4, core.PQSessions).
replace github.com/Arceliar/ironwood => github.com/arngory/ironwood v0.0.0-20261122120922-15d2d6776ffd

replace github.com/sagernet/sing-quic => ./third_party/sing-quic

replace www.bamsoftware.com/git/dnstt.git => ./third_party/dnstt
