# Документация niko-server

| Документ | О чём |
|---|---|
| [SPEC.md](SPEC.md) | что это и как устроено: процессы, фронт (tcpmux, udpmux, DNS), бэкенды, безопасность, нагрузка |
| [CONFIG.md](CONFIG.md) | схема конфигов (schema 1): их пишет raycontrol |
| [IPC.md](IPC.md) | протокол фронт ↔ бэкенд (версия 1) |
| [release-notes/](release-notes/) | заметки выпусков, начиная с v0.18.3 |

Снаружи:
- решения, общие с raycontrol, — raycontrol [`docs/decisions.md`](https://github.com/arngory/raycontrol/blob/main/docs/decisions.md);
  при расхождении они главнее этого репозитория;
- контракт с клиентом — спецификации raycontrol [`docs/spec/`](https://github.com/arngory/raycontrol/tree/main/docs/spec);
- кто закрепляет niko-server и как он выходит — [CONTRIBUTING.md](../CONTRIBUTING.md).

Код:

| Путь | Что |
|---|---|
| `cmd/niko-server` | команды `front`, `backend`, `check`, `keygen dnstt`, `version` |
| `nikoserver/` | конфиги, IPC (`SOCK_SEQPACKET`, `SO_PEERCRED` в обе стороны), фронт, бэкенды |
| `dnsttserver/` | сервер dnstt как библиотека (из dnstt-server, CC0) |
| `masterdnsvpn-go/embed` | сервер MasterDnsVPN как библиотека: `third_party/masterdnsvpn` форка `arngory/sing-box`, закреплён в `go.mod` |
| `third_party/` | вендоренные зависимости с правками (sing-quic и другие), правки помечены `neko` |

Что уже сделано по версиям — в заметках выпусков и в SPEC (этапы).
