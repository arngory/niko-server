# niko-server

English | [Русский](README.ru.md)

Data plane of a [raycontrol](https://github.com/arngory/raycontrol) node. Its front takes the clients' traffic on
UDP 53, TCP 443 and UDP 443 and hands each connection to a protocol backend (DNS tunnels, Hysteria2, Yggdrasil, or a
socket of raycontrol's own services); the backends pass the streams on to the node's inner stage. raycontrol writes
its configs and runs it; nothing here is meant to be set up by hand.

Releases: [GitHub](https://github.com/arngory/niko-server/releases) (pre-releases): `niko-server-linux-{amd64,arm64}` and
`SHA256SUMS`, pinned by tag and hash in raycontrol's `deploy/versions.env`.

## Build and test

Go as in `go.mod`:

```sh
go test -race ./...
CGO_ENABLED=0 go build -trimpath ./cmd/niko-server
```

CI (`.github/workflows/ci.yml`) also brings a node up (front, backends, Xray as the inner stage) and carries the
client core of Niko through every tunnel.

## More

- [docs/README.md](docs/README.md): specification, configs, IPC, release notes.
- [CONTRIBUTING.md](CONTRIBUTING.md): branches, checks and releases.

License: GPL-3.0-or-later, see [LICENSE](LICENSE); inside: dnstt (CC0), MasterDnsVPN (MIT), sing (GPL-3.0).
