# Конфиги niko-server (схема 1, черновик)

Черновик для согласования с raycontrol, замораживается на R1. После заморозки любое несовместимое изменение
поднимает `schema`. niko-server отказывается запускаться с незнакомой `schema` (`check` пишет почему).
JSON Schema появится в `arngory/sing-box`, `cmd/niko-server/schema/` вместе с кодом.

Общие правила:
- формат — JSON;
- секреты только путями к файлам (`*_file`): `/run/credentials/<юнит>.service/<имя>` из `LoadCredential=` (имя юнита полное, с `.service`, например `/run/credentials/niko-dns.service/noise.key`);
- длительности — строки Go (`"60s"`, `"10m"`);
- `SIGHUP` перечитывает файлы пользователей и ключей (`users_file`, `*_key_file`); остальные поля — только при перезапуске.
  У DNS-туннелей пользователей нет: их бэкенды на `SIGHUP` только пишут в лог, новый ключ — перезапуск.
- имена — по имени сервиса в raycontrol, не по виду: сервис `dns` вида `dnstt` → бэкенд `dns`,
  сокет `/run/niko/dns/packet.sock`, юнит `niko-dns.service`; вид — поле `kind`.
- UID: фронт 9100, бэкенды и Xray 9110–9179 (raycontrol R1-6).

## Проверка (`niko-server check -c FILE [--json]`)

- Коды выхода: `0` — конфиг верен, `1` — ошибка конфига, `2` — ошибка окружения (файл не читается).
- `--json` печатает массив `[{"path": "dns.zones[0].backend", "error": "…"}]`, пустой — если всё верно.
- `check` не открывает файлы секретов (`LoadCredential=` есть только внутри юнита): пути проверяются на форму,
  содержимое — при запуске (ошибка — код 2).

## Фронт

```json
{
  "schema": 1,
  "role": "front",
  "log": {"level": "warn"},
  "tcp": {
    "listen": ["0.0.0.0:443", "[::]:443"],
    "sniff_timeout": "5s",
    "acme_listen": ["0.0.0.0:9443", "[::]:9443"],
    "routes": [
      {"sni": ["k3f.example.com"], "backend": "xray-reality"},
      {"sni": ["p8w.example.com"], "backend": "naive"},
      {"sni": ["q2m.example.com"], "backend": "yggdrasil"},
      {"alpn": ["acme-tls/1"], "backend": "acme"}
    ],
    "default": "xray-reality"
  },
  "udp": {
    "listen": ["0.0.0.0:443", "[::]:443"],
    "idle": "60s",
    "routes": [
      {"sni": ["h7d.example.com"], "backend": "hy2-masq"},
      {"sni": ["p8w.example.com"], "backend": "naive-quic"},
      {"salamander_password_file": "/run/credentials/niko-front.service/salamander", "backend": "hy2-obfs"}
    ]
  },
  "dns": {
    "listen": ["0.0.0.0:53", "[::]:53"],
    "zones": [
      {"zone": "t5x.example.com", "backend": "dnstt"},
      {"zone": "v9c.example.com", "backend": "masterdns"}
    ]
  },
  "backends": {
    "xray-reality": {"socket": "/run/niko/xray-reality/reality.sock", "mode": "proxy-v2", "uid": 9110},
    "naive":        {"socket": "/run/niko/naive/fd.sock",          "mode": "fd",       "uid": 9111},
    "yggdrasil":    {"socket": "/run/niko/yggdrasil/fd.sock",      "mode": "fd",       "uid": 9112},
    "acme":         {"socket": "/run/niko/acme/fd.sock",           "mode": "fd",       "uid": 9113},
    "hy2-masq":     {"socket": "/run/niko/hy2-masq/packet.sock",   "mode": "packet",   "uid": 9114},
    "hy2-obfs":     {"socket": "/run/niko/hy2-obfs/packet.sock",   "mode": "packet",   "uid": 9115},
    "naive-quic":   {"socket": "/run/niko/naive/packet.sock",      "mode": "packet",   "uid": 9111},
    "dnstt":        {"socket": "/run/niko/dnstt/packet.sock",      "mode": "packet",   "uid": 9116},
    "masterdns":    {"socket": "/run/niko/masterdns/packet.sock",  "mode": "packet",   "uid": 9117}
  }
}
```

- `mode`: `fd` — передача сокета (`SCM_RIGHTS`), `proxy-v2` — поток с заголовком PROXY v2 (Xray), `packet` — датаграммы
  с заголовком адреса. Формат и права — [`IPC.md`](IPC.md). `uid` — ожидаемый `SO_PEERCRED` бэкенда.
- Маршрут без бэкенда в `backends` — ошибка `check`.
- Секции `tcp`, `udp`, `dns` необязательны: нет маршрутов — нет секции, фронт этот порт не слушает. Сейчас
  (niko-server v0.1, R1) фронт обслуживает только `dns`; секции `tcp` и `udp` `check` отклоняет, пока они не реализованы.
- `tcp.window_clamp` (байты, R2, предложение raycontrol): окно TCP в SYN-ACK на 443, чтобы клиент резал ClientHello.
- `acme_listen` — порт окна ACME. В окне выпуска сертификата nftables перенаправляет на него TCP 443 от адресов
  без SPA. На этом порту фронт пропускает только ClientHello с ALPN `acme-tls/1` (в бэкенд `acme`). Остальное
  закрывает без ответа, маршруты по SNI здесь не действуют. Вне окна на порт ничего не попадает: снаружи он закрыт.
  Если сокет `acme` недоступен, соединения тоже закрываются.

## Бэкенд

```json
{
  "schema": 1,
  "role": "backend",
  "kind": "hy2-masq",
  "log": {"level": "warn"},
  "socket": "/run/niko/hy2-masq/packet.sock",
  "front_uid": 9100,
  "users_file": "/run/credentials/niko-hy2-masq.service/users.json",
  "tls": {
    "certificate_file": "/run/credentials/niko-hy2-masq.service/cert.pem",
    "key_file": "/run/credentials/niko-hy2-masq.service/key.pem",
    "curves": ["X25519MLKEM768"]
  },
  "options": {"masquerade": {"type": "proxy", "url": "https://www.example.org/", "rewrite_host": true}},
  "inner": "/run/niko/inner/vless.sock"
}
```

- `front_uid` — единственный UID, которому бэкенд отвечает (`SO_PEERCRED`).
- `tls.curves` по умолчанию `["X25519MLKEM768"]`. Другие значения `check` отвергает для `hy2-*`, `naive`, `doh`,
  `yggdrasil`.
- `inner` — потоковый unix-сокет `inner` (Xray, VLESS с `decryption`). Обязателен для `dnstt`, `masterdns`, `yggdrasil`.

`options` по видам:

| `kind` | `options` |
|---|---|
| `hy2-masq` | `masquerade` (как в sing-box hysteria2), `up_mbps`/`down_mbps` (необязательно) |
| `hy2-obfs` | `obfs_password_file` (тот же пароль salamander, что у фронта) |
| `naive` | `site` — сокет бэкенда `site` для запросов без авторизации |
| `doh` | `path_token_file`, `upstream` (DNS-серверы sing-box) |
| `dnstt` | `zone`, `private_key_file` (hex закрытого ключа X25519, 64 символа и перевод строки, как `dnstt-server -gen-key`) |
| `masterdns` | `zones`, `encryption_method` (только AEAD: 3–5; raycontrol — `5`, AES-256-GCM), `encryption_key_file` (ключ текстом: 32 символа для метода 5) |
| `yggdrasil` | `private_key_file`, `allowed_public_keys_file`, `public_peers` (bool, по умолчанию `false`), `exit_ports` |
| `site` | `root` (каталог сгенерированного сайта), `tls` как выше (сертификат `<r>` для self-steal) |

## Файл пользователей (`users_file`)

raycontrol пишет отдельный файл для каждого бэкенда, только с учётными данными его `kind` (минимум прав).
Бэкенд не должен рассчитывать на поля других видов.

Один формат для всех видов. Неизвестные поля игнорируются. Пользователь без учётных данных для этого `kind`
пропускается.

```json
{
  "users": [
    {"name": "u-17", "enabled": true,
     "hy2": {"password": "…"},
     "naive": {"username": "…", "password": "…"},
     "yggdrasil": {"public_key": "<64 hex>"}}
  ]
}
```

Пары «текущие + следующие» для ротации: raycontrol кладёт в файл обе записи, например с именами
`u-17` и `u-17@next`. Бэкенд принимает обе до следующего `SIGHUP`.
