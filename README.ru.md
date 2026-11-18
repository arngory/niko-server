# niko-server

[English](README.md) | Русский

Data plane ноды [raycontrol](https://github.com/arngory/raycontrol). Фронт принимает трафик клиентов на UDP 53,
TCP 443 и UDP 443 и отдаёт каждое соединение бэкенду протокола (DNS-туннели, Hysteria2, Yggdrasil или сокет сервиса
raycontrol), а бэкенды передают потоки во внутреннюю ступень ноды. Конфиги пишет и запускает его raycontrol: вручную
здесь ничего не настраивается.

Выпуски: [GitHub](https://github.com/arngory/niko-server/releases) (pre-release): `niko-server-linux-{amd64,arm64}` и
`SHA256SUMS`; raycontrol закрепляет тег и хеши в `deploy/versions.env`.

## Сборка и тесты

Go — как в `go.mod`:

```sh
go test -race ./...
CGO_ENABLED=0 go build -trimpath ./cmd/niko-server
```

CI (`.github/workflows/ci.yml`) ещё и поднимает ноду (фронт, бэкенды, Xray как внутренняя ступень) и проводит
клиентское ядро Niko через каждый туннель.

## Ещё

- [docs/README.md](docs/README.md): спецификация, конфиги, IPC, заметки выпусков.
- [CONTRIBUTING.md](CONTRIBUTING.md): ветки, проверки и выпуски.

Лицензия: GPL-3.0-or-later, см. [LICENSE](LICENSE); внутри: dnstt (CC0), MasterDnsVPN (MIT), sing (GPL-3.0).
