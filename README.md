# niko-server

Data plane ноды под управлением [raycontrol](https://github.com/arngory/raycontrol): фронт принимает трафик
клиентов [Niko](https://github.com/arngory/niko) и раздаёт его бэкендам протоколов, а те отдают поток во внутреннюю
ступень `inner` (Xray, VLESS с ML-KEM-768). Конфиги пишет raycontrol, он же ведёт SPA, nftables и ротацию ключей.

## Состояние

| Что | Состояние |
|---|---|
| Фронт: DNS (UDP 53, маршрут по зоне) | готово (v0.1) |
| Бэкенды `dnstt`, `masterdns` (AES-256-GCM, метод 5) | готово (v0.1) |
| `check` (коды 0/1/2, `--json`), `keygen dnstt`, `version` | готово |
| Фронт TCP 443 (tcpmux) и UDP 443 (udpmux), бэкенд `site` | не начато — [`docs/SPEC.md`](docs/SPEC.md) §3.1–§3.2 |
| Бэкенды naive-quic, DoH3 (нужен udpmux), Yggdrasil | не начато |
| Нагрузочный тест (SPEC §6.6) | не выполнен |

Пока фронта 443 нет, REALITY, Hysteria2, DoH и naive работают на Xray и `rayd` (raycontrol, решения R3).

## Документы

| Документ | Зачем |
|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | что строить: процессы, мультиплексоры, бэкенды, этапы |
| [`docs/CONFIG.md`](docs/CONFIG.md) | схема конфигов (schema 1) |
| [`docs/IPC.md`](docs/IPC.md) | протокол фронт ↔ бэкенд (версия 1) |
| raycontrol [`docs/08-decisions.md`](https://github.com/arngory/raycontrol/blob/claude/clever-feynman-w0e2v1/docs/08-decisions.md) | решения; главнее этого репозитория |
| raycontrol [`docs/handoff/`](https://github.com/arngory/raycontrol/tree/claude/clever-feynman-w0e2v1/docs/handoff) | заметки raycontrol для Niko, в т.ч. просьбы к niko-server (`niko-r4-note.md` §6) |
| niko [`docs/server/RAYCONTROL.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/RAYCONTROL.md) | ответы Niko для raycontrol (история R1–R4) |

## Код

| Путь | Что |
|---|---|
| `cmd/niko-server` | команды `front`, `backend`, `check`, `keygen dnstt`, `version` |
| `nikoserver/` | конфиги, IPC (`SOCK_SEQPACKET`, `SO_PEERCRED` в обе стороны), фронт, бэкенды |
| `dnsttserver/` | сервер dnstt как библиотека (из dnstt-server, CC0) |
| `masterdnsvpn-go/embed` | сервер MasterDnsVPN как библиотека: модуль `third_party/masterdnsvpn` форка [`arngory/sing-box`](https://github.com/arngory/sing-box), закреплён в `go.mod` |

Тесты используют клиент dnstt из ядра Niko (`github.com/sagernet/sing-box` → `arngory/sing-box`, тот же коммит).

## Сборка и проверка

```sh
go test -race ./...
CGO_ENABLED=0 go build -trimpath ./cmd/niko-server
```

CI (`.github/workflows/ci.yml`) поднимает ноду: фронт, оба бэкенда, `inner` на Xray, — и проводит через оба туннеля
клиентское ядро Niko до `generate_204`; чужое имя получает `REFUSED`. Версии ядра и Xray — в `.github/interop.env`.

## Релиз

`release.yml`: тег `vX.Y.Z` (пуш тега или workflow_dispatch с входом `tag`) → CI → `niko-server-linux-amd64`,
`niko-server-linux-arm64`, `SHA256SUMS`. Заметки — `docs/release-notes/<тег>.md`. raycontrol закрепляет тег и хэши
в `deploy/versions.env` и проверяет их в `scripts/niko-server.sh`.

Релизы до переезда (`niko-server-v0.1.1`) — в [`arngory/niko`](https://github.com/arngory/niko/releases/tag/niko-server-v0.1.1).

## Кто ведёт

Сессия raycontrol (сервер). Сессия Niko отвечает за клиент и ядро клиента; вопросы между ними — заметками.

## Лицензия

GPL-3.0-or-later ([`LICENSE`](LICENSE)). Внутри: dnstt (CC0), MasterDnsVPN (MIT), sing (GPL-3.0).
