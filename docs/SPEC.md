# niko-server: спецификация

niko-server — data plane и «наше ядро»: обслуживает протоколы клиента Niko. Управляет им raycontrol (control plane):
хранит пользователей и ключи, генерирует конфиги niko-server и Xray, ведёт nftables и SPA, ротирует ключи,
отдаёт подписку и API. Решения raycontrol главнее этого документа: при расхождении действует
[`docs/08-decisions.md`](https://github.com/arngory/raycontrol/blob/claude/clever-feynman-w0e2v1/docs/08-decisions.md).

Ответы на вопросы raycontrol и черновики контрактов: [`RAYCONTROL.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/RAYCONTROL.md), [`CONFIG.md`](CONFIG.md), [`IPC.md`](IPC.md).

## 0. Исходные данные

| Что | Где |
|---|---|
| Приложение (клиент) | `arngory/niko`, ветка `claude/intelligent-allen-0oa8na` |
| Ядро и niko-server (форк sing-box 1.14.4) | `arngory/sing-box`, та же ветка, `cmd/niko-server`; коммит клиента — `COMMIT_SING_BOX` в `buildScript/lib/core/get_source_env.sh` |
| raycontrol (control plane) | `arngory/raycontrol`, ветка `claude/clever-feynman-w0e2v1` |
| SPA v2 | [`docs/spec/spa-v2.md`](https://github.com/arngory/raycontrol/blob/claude/clever-feynman-w0e2v1/docs/spec/spa-v2.md) в raycontrol (заморожен) |
| Xray (REALITY, `inner`) | `arngory/xray-core`, закреплён в `.github/xray-interop.env` (v26.10.31) |
| Проверка клиента против Xray | `.github/workflows/xray-interop.yml` в `arngory/niko` |
| Проверка Yggdrasil на публичных пирах | `.github/workflows/ygg-probe.yml` в `arngory/niko` |

Что уже есть в форке sing-box:
- входящие `vless` (REALITY через `sagernet/reality`), `hysteria2`, `naive` (h2 и QUIC), `trojan`, `shadowsocks`, `tuic`, `anytls`, `socks`, `mixed`;
- endpoint `yggdrasil` (`protocol/yggdrasil`) с `listen`, `peers`, `allowed_public_keys`;
- клиенты dnstt (`transport/dnstt`) и MasterDnsVPN (`third_party/masterdnsvpn`), клиент VLESS encryption (серверной части нет, см. §3.9);
- сниферы TLS и QUIC (`common/sniff`): по первому пакету достают SNI и ALPN.

Правила работы (в обоих репозиториях):
- всё собирается из наших форков, сторонних бинарников нет;
- версии закреплены (коммит или тег), обновление — отдельным коммитом;
- release notes по одной строке на правку: сначала английские строки, потом те же на русском;
- после каждого законченного блока — релиз.

## 1. Цель

Нода обслуживает все протоколы клиента на одном IP. Работают отдельные процессы:

| Процесс | Что делает | Права |
|---|---|---|
| `niko-server front` | мультиплексоры TCP 443, UDP 443, UDP 53; знает только таблицу маршрутов, пароль salamander и сокеты бэкендов, ключей пользователей не знает | только `CAP_NET_BIND_SERVICE` |
| `niko-server backend` (по одному на протокол) | `hy2-masq`, `hy2-obfs`, `naive`, `doh`, `dnstt`, `masterdns`, `yggdrasil`, `inner`, `site` | без capabilities, только свой unix-сокет |
| Xray | REALITY (и `inner`, пока в форке нет сервера VLESS encryption) | без capabilities, unix-сокет |
| `rayspa` (raycontrol) | приём SPA v2 через NFLOG, ведение nftables | `CAP_NET_ADMIN` |

У каждого процесса свой системный пользователь с фиксированным UID (правила nftables по `skuid`).

**Периметр.** Все порты закрыты (nftables, policy `drop`). Доступ — только после SPA v2 и только к портам из scope
устройства, на TTL. Для всех открыты лишь:

| Порт | Кому | Что |
|---|---|---|
| UDP 53 | всем | dnstt и MasterDnsVPN в своих делегированных зонах, остальное — `REFUSED` |
| TCP 443 | всем, только на время выпуска сертификата | только ACME (TLS-ALPN-01): nftables перенаправляет адреса без SPA на отдельный порт фронта, там проходит лишь ALPN `acme-tls/1` (§3.1) |
| TCP 443, UDP 443 | после SPA v2 | всё остальное (§2) |
| UDP, порт слота SPA | всем | `rayspa`, порт ротируется по слотам |

TCP 80 и TCP/UDP 853 не открываются. Port-knocking не используется. Неавторизованный адрес получает drop,
а не приманку.

## 2. Архитектура

```
                        nftables: drop, кроме UDP 53, порта SPA и окна ACME; allow-наборы от rayspa
TCP 443 ──► front/tcpmux ─┬─ SNI <r>.example.com ──► unix + PROXY v2 ──► Xray REALITY
                          ├─ SNI <n>.example.com ──► SCM_RIGHTS ──► backend naive / doh
                          ├─ SNI <y>.example.com ──► SCM_RIGHTS ──► backend yggdrasil (tls-линк)
                          ├─ (адрес без SPA, окно ACME) ──► acme_listen: только ALPN acme-tls/1 ──► ACME
                          └─ остальное           ──► как <r> (REALITY уведёт в приманку site)
UDP 443 ──► front/udpmux ─┬─ QUIC, SNI <h>.example.com ──► backend hy2-masq
                          ├─ QUIC, SNI <n>.example.com ──► backend naive (QUIC) / doh (HTTP/3)
                          ├─ salamander             ──► backend hy2-obfs
                          └─ остальное              ──► drop
UDP 53  ──► front/dnsmux ─┬─ *.<t>.example.com ──► backend dnstt     ──► inner
                          ├─ *.<v>.example.com ──► backend masterdns ──► inner
                          └─ остальное         ──► REFUSED
```

Связь фронта с бэкендами — unix-сокеты, формат — в [`IPC.md`](IPC.md):
- **TCP:** фронт передаёт принятый сокет бэкенду через `SCM_RIGHTS` вместе с метаданными (адрес клиента, уже
  прочитанные байты, маршрут). Xray получает поток через свой unix-сокет с заголовком PROXY v2.
- **UDP:** фронт пересылает датаграммы бэкенду по соединению `SOCK_SEQPACKET` с заголовком «адрес клиента»; бэкенд
  видит виртуальный `net.PacketConn`. Ответы идут обратно по тому же соединению через фронт.
- Сокет каждого процесса лежит в его каталоге `/run/niko/<имя>/`. Доступ есть только у тех, кто входит в его группу.
  Обе стороны сверяют `SO_PEERCRED`. Правила — в [`IPC.md`](IPC.md).

### 2.1. Почему REALITY отдаётся Xray

- Xray — эталон REALITY: `mldsa65Seed`, `minClientVer`, правильная работа с гибридным X25519MLKEM768.
  `sagernet/reality` в sing-box отстаёт.
- Xray слушает unix-сокет с `acceptProxyProtocol`. Фронт пишет туда заголовок PROXY v2, затем уже прочитанные
  байты ClientHello, затем остальной поток.

### 2.2. Домены

- Поддомены (`<r>`, `<n>`, `<h>`, `<y>`, зоны туннелей `<t>`, `<v>`) выбираются случайно при установке и ротируются
  через raycontrol. В тексте ниже они обозначены угловыми скобками.
- DNS: wildcard `*.example.com A <IP>` и NS-делегирование зон туннелей. Записи ведутся вручную, `check` их проверяет.
- Сертификаты: если у DNS-провайдера есть API — wildcard через DNS-01; иначе поддомены через короткое окно ACME
  и редкая ротация SNI (много выпущенных поддоменов в журналах CT — сам по себе отпечаток).
- REALITY в режиме self-steal: `target` — бэкенд `site` (генерируемый правдоподобный сайт с настоящим сертификатом
  `<r>.example.com`, TLS 1.3 + h2).
- Вариант «домена нет» (REALITY с чужим `target`) не поддерживается: раньше он запрещал naive и DoH на том же IP,
  а случайные поддомены его заменяют.

## 3. Компоненты

### 3.1. tcpmux (TCP 443)

- Читает первый TLS-рекорд (до 16 КБ, таймаут 5 с), достаёт SNI и ALPN (`common/sniff`).
- Таблица маршрутов SNI → бэкенд — из конфига фронта. Без SNI и с неизвестным SNI — маршрут `default` (REALITY).
- Не TLS: закрыть соединение без ответа.
- **Окно ACME (TLS-ALPN-01).** nftables не видит ALPN, поэтому открывать 443 целиком нельзя: сканер, следящий за
  журналами CT, в это время дошёл бы до naive, Yggdrasil и REALITY без SPA. На время окна `rayspa` добавляет правило
  `tcp dport 443` от адресов вне allow-наборов → `redirect to :<acme_listen>`. На этом порту фронт пропускает только
  ClientHello с ALPN `acme-tls/1` (в бэкенд `acme`), остальное закрывает без ответа. Адреса с SPA идут на обычный
  443, как всегда. Если у DNS-провайдера есть API, предпочтителен DNS-01: окно не нужно вовсе.
- Неавторизованных адресов до фронта не пропускает nftables. Приманка остаётся для тех, кто прошёл SPA:
  за одним адресом CGNAT может быть и проверяющий, поэтому сервисы должны выдерживать активное зондирование сами.

### 3.2. udpmux (UDP 443)

Один сокет, разбор по потокам (адрес:порт клиента). Классификация по первому пакету потока, запоминается до 60 с
бездействия:

1. **QUIC long header с известной версией.** Расшифровать Initial на initial-ключах (QUIC-сниффер sing-box),
   достать SNI, выбрать бэкенд.
2. **Salamander.** 8 байт соли + (нагрузка XOR поток `BLAKE2b-256(пароль ‖ соль)`). Снять обфускацию паролем
   из конфига фронта; если внутри QUIC long header с известной версией — поток `hy2-obfs`.
3. Иначе — drop. **Поток по такому пакету не запоминается**: закрепляется только первый пакет, прошедший классификацию. Клиент может слать перед настоящими пакетами фейки (случайные или QUIC Initial с чужим SNI), и они не должны закреплять поток за drop ([`../research/anti-dpi.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/research/anti-dpi.md) §3).

SPA в udpmux нет: SPA v2 принимает `rayspa` на отдельном ротируемом порту (§3.5).

Hysteria2 принимает готовый `net.PacketConn` (виртуальный, от IPC) без патча: `hysteria2.Service.Start(conn)` из
sing-quic. Бэкенды `hy2-masq` и `hy2-obfs` — niko-server на sing-quic.

Два конфига Hysteria2 — два бэкенда:
- `hy2-masq`: TLS с сертификатом `<h>.example.com` и `masquerade`;
- `hy2-obfs`: `obfs.type = salamander`, самоподписанный сертификат; клиент пинит его публичный ключ
  («Настройки соединения → Пиннинг сертификата», не `pinSHA256`).

**Постквант:** у обоих TLS `CurvePreferences = [X25519MLKEM768]`, без отката на классические группы.

### 3.3. dnsmux (UDP 53)

- Выбор бэкенда по суффиксу QNAME (без учёта регистра, по меткам): `<t>.example.com` → `dnstt`,
  `<v>.example.com` → `masterdns`. Остальное — `REFUSED`, открытым резолвером нода не становится.
- Отправитель запроса — рекурсивный резолвер, а не клиент: SPA к порту 53 не применяется. Аутентификация —
  ключ туннеля (Noise у dnstt, общий ключ у MasterDnsVPN).
- Оба туннеля не открывают соединений к произвольным адресам: каждый поток идёт в бэкенд `inner` (§3.9).
  Клиент поднимает VLESS с ML-KEM-768 к `inner` внутри туннеля.

**dnstt** (`arngory/dnstt`, от `master` = v1.20260501.0):
1. Вынести серверную часть в библиотеку: `server.Run(ctx, Options{Domain, PrivKey, PacketConn, Upstream func() (net.Conn, error)})`.
2. `PacketConn` — виртуальный от IPC, `Upstream` — соединение с `inner` через unix-сокет.

**MasterDnsVPN** (`arngory/MasterDnsVPN`, `main`):
1. Добавить серверу `SetPacketConnFactory` (для клиента такой патч уже есть: `SetListenerFactory`).
2. Режим `PROTOCOL_TYPE = "TCP"` с фиксированным upstream = `inner`. Режим `SOCKS5` на ноде не используется.
3. `DATA_ENCRYPTION_METHOD` = **5** (AES-256-GCM). Нода разрешает только AEAD (raycontrol R1-8): метод 2 у MasterDnsVPN — ChaCha20 без аутентификации. Ключ — файл с 32 символами через `LoadCredential=`; niko-server его только читает и никогда не генерирует.

**DNS-записи:**
```
*.example.com.   A   <IP>
<t>.example.com. NS  <ns>.example.com.
<v>.example.com. NS  <ns>.example.com.
```

### 3.4. Yggdrasil

Сделано в v0.4.0 (`nikoserver/yggdrasil.go`).

- **Подключение — только прямое (P-14).** Клиент указывает пир `tls://<адрес ноды>:443?sni=<y>.example.com&key=<ключ узла>`.
  tcpmux отдаёт поток по SNI бэкенду `yggdrasil` в режиме `fd`.
  - yggdrasil-go передаёт `sni` из URI в TLS: `tlsSNI` в `link_tls.go`.
  - Клиент Niko отправляет ClientHello Chrome через uTLS (`tls_fingerprint`).
- **TLS в бэкенде.** TLS 1.3, только `X25519MLKEM768`, сертификат имени `<y>` из `tls`. ALPN — `h2` и `http/1.1`,
  как у веб-сервера.
- **Проверка ключа.** Бэкенд читает рукопожатие линка (`meta`: TLV и подпись ed25519 над BLAKE2b ключа). Ключ должен
  быть в `users_file` (`yggdrasil.public_key`), подпись должна сходиться. Всё, что начинается не с `meta`, получает
  ответ сайта: пустой `404` по h2 или HTTP/1.1, смотря что выбрал TLS.
- **Перечитывание пользователей.** Файл перечитывается по `SIGHUP` и при изменении, без перезапуска. Линки удалённых
  ключей закрываются сразу.
- **Передача линка ядру.** Ядро yggdrasil-go (форк из `arngory/sing-box/third_party`) слушает unix-сокет в каталоге
  0700, который виден только процессу бэкенда.
  - Каждый линк приходит в ядро со своего адреса: ядро различает входящие линки по адресу собеседника.
  - Своего `AllowedPublicKeys` у ядра нет: проверку ключей ведёт бэкенд.
- **Выход.** На адресе узла в mesh работает стек gVisor. TCP на `exit_ports` уходит в `inner`, на другие порты —
  RST; UDP отбрасывается. Соединения выхода держат keepalive: клиент, пропавший из mesh, сброса не шлёт.
- **Изоляция клиентов (v0.15.0, raycontrol `docs/spec/lan-v1.md` §2).** Ядро пересылало бы кадры ironwood между
  любыми двумя своими пирами. Бэкенд копирует линк не байтами, а по кадрам (`yggframe.go`), после `meta` в каждую
  сторону. В кадрах traffic, pathNotify, pathBroken и pathLookup он читает ключи источника и назначения, как их читает
  ironwood.
  - От клиента K проходит только источник K и назначение — ключ узла N; к клиенту — источник N и назначение K. У
    pathBroken роли меняются: он идёт обратно к источнику трафика. Правило идёт через группу ключа G(x), пока у
    всех пустую: с LAN пройдёт и своя группа.
  - pathLookup (6) рассылается всем, кто может ответить (iw `bloomfilter.go:301-329`). От K проходит любой его
    lookup (источник K). К K — только lookup узла (источник N) того, на что K ответил бы сам: назначение K или ключ
    из его адреса (iw `pathfinder.go:62-64`). Иначе клиент, объявивший в bloom все ключи, получал бы lookup других
    клиентов к узлу и lookup узла к каждому из них — с полными ключами.
  - Остальное молча отбрасывается, счётчик `dropped_frames` в `stats_socket`. В журнал о кадрах — ничего.
  - **Кадры клиента к узлу узел берёт сам.** У traffic и pathNotify клиента с назначением N и у pathBroken с
    источником N (он идёт назад к N) фильтр переписывает водяной знак на месте нулём той же длины (n−1 байт `0x80`,
    затем `0x00`). `_lookup` узла не находит следующего шага, пока расстояние не меньше знака (iw
    `router.go:701-711`), и узел обрабатывает кадр сам (`router.go:603-616`, `pathfinder.go:95-103`, `238-247`) — как
    кадр с верным путём: знак не подписан и дальше не читается. Путём клиент ничего не направляет: ни трафик к
    порту другого клиента (отброс, ответ, знание, занят ли порт), ни ответ по выбранному им `from`.
  - **За отброшенный кадр отвечает фильтр.** Пир ironwood, пославший кадр (кроме keepalive), рвёт линк, если за
    3 с ничего не пришло в ответ, а получивший кадр должен keepalive через 1 с, и любой его кадр этот долг гасит
    (iw `peers.go:127-181`). Без ответа отброшенный lookup убивал линк простаивающего клиента, а уход корня дерева
    (устаревшие пути узла ведут к другому клиенту) — линки и связь на секунды. Поэтому на линке, где кадр
    отброшен:
    - кадр клиента: клиенту — keepalive `01 01`, ответ, какой дал бы узел; узлу, если он ждёт ответа (долг мог
      погасить отброшенный кадр), — keepalive;
    - traffic к клиенту от узла или к узлу: ядру — pathBroken, какой послал бы ironwood клиента (iw
      `pathfinder.go:228-236`): путь — `from` трафика как есть, водяной знак `^uint64(0)`, источник и назначение
      трафика; он чинит устаревший путь узла. Клиенту, если он ждёт ответа, — keepalive;
    - остальное к клиенту: клиенту — «пинг», pathBroken от N к K с пустым путём и водяным знаком 0 (68 байт). Его
      ironwood никуда его не передаёт и отбрасывает (источник не его ключ), но должен за него keepalive узлу. Ядру за
      клиента не отвечают: линк, чей клиент пропал молча (TCP без сброса), остаётся без ответа, и ядро рвёт его за
      3 с, сколько бы клиента ни искали.
    - Тот, кто перебирает порты, ничего о них не узнаёт: его кадры к узлу узел берёт сам, отброса нет.
    - Один ответ на кадр и только на этом линке; ожидают не больше одного keepalive и одного пинга на сторону.
      Запись — целыми кадрами под одним замком на сторону; ожидающие кадры — не больше 16 КиБ на сторону, пишет их
      своя горутина, отбрасывающий не ждёт.
  - **Packet Too Big — только своему.** ipv6rwc ядра отвечал на пакет больше MTU сообщением ICMPv6 Packet Too Big
    с 512 байтами пакета на адрес источника, ещё не сверив его с ключом отправителя: клиент, подставивший адрес
    другого, слал ему свои байты через узел. В форке (`5afe92f`) адрес сверяется раньше.
  - Кадр, который ядро не приняло бы (длина больше 131070 байт, пустой, разбор не сходится), закрывает линк.
  - Остальные типы (keepalive, дерево, bloom) проходят как есть.
  - Ядро не отвечает на удалённые getSelf, getPeers, getTree (`DebugPrivacy` форка): иначе getPeers отдавал бы ключи
    всех подключённых устройств.
  - **Известные утечки, оставлены сознательно** (переписывать bloom и дерево — риск для маршрутизации):
    - bloom узла к клиенту содержит ключи (их /64) всех остальных пиров на дереве (iw `bloomfilter.go:216-234`,
      ygg `src/core/core.go:96-98`): клиент проверит, на узле ли адрес, который он уже знает, но не перечислит.
      Ключи устройств выводит сервер, чужим они неизвестны;
    - дерево: пир получает анонсы цепочки предков узла и своей (iw `router.go:332-389`). Корень — наименьший ключ;
      без публичных пиров это обычно клиент, и его ключ получают все клиенты. Это один случайный ключ без имени,
      трафик к нему всё равно отбрасывается;
    - bloom как канал между двумя *сговорившимися* клиентами: биты, что A ставит в свой bloom, узел сливает в bloom
      для B (iw `bloomfilter.go:216-234`) — до 8192 бит на обновление. Через узел у них и так есть интернет:
      нового это им не даёт;
    - память: пока большой кадр приходит по частям, линк держит буфер самого большого кадра (131 080 байт) на
      сторону.
- **Публичные пиры.** Включаются списком `peers`; по умолчанию его нет.
- **Постквант.** См. [`RAYCONTROL.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/RAYCONTROL.md),
  вопрос 5.
  - Линк — TLS с `X25519MLKEM768`, при прямом подключении он и есть весь путь.
  - Сквозное шифрование Yggdrasil классическое, поэтому полезный трафик идёт в `inner` (VLESS с ML-KEM-768).

### 3.5. SPA

SPA v2 — [`spa-v2.md`](https://github.com/arngory/raycontrol/blob/claude/clever-feynman-w0e2v1/docs/spec/spa-v2.md):
ключи устройств по эпохам, порт по слотам, scope и время внутри пакета XChaCha20-Poly1305. Пакеты принимает
`rayspa` через NFLOG и добавляет адрес в allow-наборы портов из scope. niko-server в SPA не участвует.

Клиент Niko отправляет SPA v2 (`libcore/knock/spa2.go`, векторы raycontrol проверяются побайтно), по UDP, а при неудаче — TCP-носителем (`spa-v2.md` §10, с v1.12.1).
Niko SPA v1 (`libcore/knock/spa.go`, шаг `ПОРТ/spa:КЛЮЧ`) остаётся в клиенте только для сторонних серверов.

### 3.6. REALITY в Xray

```json
{"inbounds":[{"listen":"/run/niko/xray-reality/reality.sock,0660","protocol":"vless",
  "settings":{"clients":[{"id":"<uuid>","flow":"xtls-rprx-vision"}],"decryption":"none"},
  "streamSettings":{"network":"raw","security":"reality",
    "sockopt":{"acceptProxyProtocol":true},
    "realitySettings":{"target":"/run/niko/site/tls.sock","xver":0,"serverNames":["<r>.example.com"],
      "privateKey":"<xray x25519>","shortIds":["<8 hex>"],
      "mldsa65Seed":"<xray mldsa65: Seed>"}}}],
 "outbounds":[{"protocol":"freedom"}]}
```

- **`mldsa65Seed` обязателен.** Клиент проверяет подпись по ключу из профиля (`pqv=` в ссылке); совместимость
  проверяет `xray-interop.yml`.
- Ключи REALITY, shortId и SNI ротирует raycontrol (пользователи — через gRPC API Xray без перезапуска).
- **`minClientVer`** не задавать (по умолчанию 26.3.27) или ровно `"26.3.27"`: Niko сообщает эту версию.
- **Постквант:** гибридный ключ X25519MLKEM768 (обязателен в Xray с 26.9.8). Клиент — отпечаток `chrome`.

### 3.7. NaiveProxy

- Бэкенд `naive` (inbound из форка, h2 и QUIC), сертификат `<n>.example.com`.
- Запросы без авторизации и не CONNECT получают сайт, без `407`.
- **Постквант:** `CurvePreferences = [X25519MLKEM768]` без отката. Клиент naive (Chromium) предлагает его по умолчанию.
- В клиенте Niko naive работает через плагин (форк `arngory/naiveproxy`); совместимость — в CI.

### 3.8. DoH

- Бэкенд `doh`: `https://<n>.example.com/dns-query/<token>` (h2 и HTTP/3), резолвер — DNS-роутер sing-box.
- **Постквант:** только `X25519MLKEM768`.
- DoT/DoQ (853) не поддерживаются.

### 3.9. Внутренняя ступень `inner`

- VLESS-сервер с `decryption` ML-KEM-768 (`mlkem768x25519plus`), пользователи — от raycontrol.
- Принимает потоки от `dnstt`, `masterdns`, `yggdrasil`, olcRTC и OpenFlux (unix-сокет), выпускает в интернет.
- Серверной части VLESS encryption в форке sing-box нет, поэтому `inner` работает на Xray, пока сервер не перенесён
  в форк (см. [`RAYCONTROL.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/RAYCONTROL.md), вопрос 1). Клиент Niko против Xray с `decryption` уже проверяется в CI.

### 3.10. olcRTC и OpenFlux

- Форки: `arngory/olcrtc` (движок Ghostlane), `arngory/OpenFlux`. На ноде — отдельные процессы под управлением
  raycontrol, входящих портов нет.
- Режим фиксированного upstream: каждый поток идёт в `inner`, произвольных соединений сервер не открывает.
- OpenFlux: шифрование обязательно, выход L4, без root.
- Аккаунты платформ: режим `node` (выделенные аккаунты на ноде) или `client` (пользователь входит в клиенте).

## 4. Конфиги и команды

- Конфиги фронта, бэкендов и Xray генерирует raycontrol по схеме из [`CONFIG.md`](CONFIG.md) (версия схемы — поле
  `schema` в каждом конфиге). Источник правды — база raycontrol.
- Секреты (ключи, пароли, сертификаты) — пути к файлам из `LoadCredential=`, не строки в конфиге.
- `SIGHUP`: перечитать пользователей и ключи без разрыва соединений; соединения снятых пользователей закрываются
  (Yggdrasil, с v0.15.0 Hysteria2). Смена портов и доменов — перезапуск.

Команды niko-server:
- `niko-server front -c <файл>`, `niko-server backend -c <файл>`;
- `niko-server check -c <файл>` — проверка без запуска; ненулевой код и понятная ошибка. raycontrol вызывает её
  перед каждым применением.

`init`, `export` и подписка — в raycontrol (`rayctl`), формат ссылок задаёт raycontrol (решение P-10).

Деплой (ставит raycontrol): systemd-юнит на каждый процесс, отдельные пользователи, фиксированные UID, секреты через
systemd credentials (TPM при наличии), systemd-resolved stub выключен (UDP 53).

## 5. Форки

| Репозиторий | Зачем | Статус |
|---|---|---|
| `arngory/sing-box` | ядро клиента и niko-server | есть |
| `arngory/xray-core` | REALITY, `inner`, эталон для тестов | есть |
| `arngory/dnstt` | серверная библиотека (§3.3) | есть: зеркало апстрима, работа от `master` (v1.20260501.0) |
| `arngory/MasterDnsVPN` | сервер с внешним PacketConn | есть, `main` (сервер в `cmd/server`, `internal/`) |
| sing-quic | сервер Hysteria2 | вендорен в `third_party/sing-quic` (`replace` в `go.mod`, с версии v0.6.0). Правки помечены `neko`: хук соединений с пользователем, статистикой QUIC и Brutal и (v0.15.0) способом закрыть соединение, атомарная доля подтверждённых у Brutal, атомарная замена таблицы пользователей (раньше запись без блокировки гонялась с чтением), salamander без побайтового цикла и без обрезки полного пакета до 1444 байт (v0.7.1) |
| `arngory/yggdrasil-go` | патч `LinkDialer` (исходящие линки через дозвонщик встраивающей программы); `DebugPrivacy` (без ответов на удалённые getSelf, getPeers, getTree); ipv6rwc: Packet Too Big только на адрес, сверенный с ключом отправителя | есть: 0.5.15 с патчем в `develop` ([#1](https://github.com/arngory/yggdrasil-go/pull/1)); `DebugPrivacy` — `9ba3c0a`, Packet Too Big только своему (ipv6rwc) — `5afe92f`, оба в `claude/clever-feynman-w0e2v1`. niko-server берёт ядро отсюда (`replace` в `go.mod`, `5afe92f` с v0.15.0); клиенту — перейти с `sing-box/third_party/yggdrasil-go` на этот форк |
| `arngory/naiveproxy` | клиент naive для тестов и плагин Android | есть, Chromium 154.0.8037.49; в `apk/` — сборка плагина (свой ключ подписи) |
| `arngory/olcrtc`, `arngory/OpenFlux` | белые списки (§3.10) | по raycontrol |
| apernet/hysteria | официальный клиент для тестов | форк не нужен, тег собирается в CI |

## 6. Проверки (критерии готовности)

Каждый пункт — job в CI (GitHub Actions).

1. **Клиент Niko ↔ нода** для каждого протокола после SPA v2: REALITY с ML-DSA-65, Hysteria2 masq и obfs, naive h2
   и QUIC, DoH, dnstt и MasterDnsVPN с `inner`, Yggdrasil через `<y>`. Ожидается `204` от `generate_204`.
2. **Периметр:** без SPA все порты, кроме UDP 53 и порта слота, молчат (drop); повтор и пакет старше 30 с не дают доступа.
3. **Зондирование после SPA:** чужой SNI получает приманку; naive без авторизации — сайт; UDP-мусор на 443 — без ответа;
   DNS-запрос к чужому имени — `REFUSED`.
4. **Постквант:** клиент без `X25519MLKEM768` не подключается к Hysteria2, naive и DoH.
5. **Совместимость:** официальный клиент hysteria (salamander), Xray-клиент (REALITY), naive (форк), dnstt-client.
6. **Нагрузка:** 200 одновременных потоков через каждый мультиплексор, с разделёнными процессами. Без утечек
   горутин и роста памяти за 10 минут. Если копия UDP через фронт — узкое место: `SO_REUSEPORT` + eBPF.

## 7. Порядок работы (синхронно с этапами raycontrol)

| Этап | niko-server | Клиент Niko |
|---|---|---|
| R0 | — | сделано: SPA v2 по векторам, импорт `rcdev1:` (v1.11.0) |
| R1 | сделано (`niko-server-v0.1.1`): dnstt и MasterDnsVPN как библиотеки, фронт и бэкенды, IPC 1, схема конфигов 1, dnsmux, `inner` на Xray | сделано: подписка subscription-v1 (v1.13.0–v1.13.2), SPA v2 по TCP (v1.12.1) |
| R2 | tcpmux (v0.2), Xray на unix-сокете; `site`, naive и DoH — в `rayd` raycontrol (R2-12, R2-14, R3-2) | — (PQ-проверка REALITY уже есть) |
| R3 | udpmux без SPA (v0.3), Hysteria2 ×2 на sing-quic (v0.3); naive-quic и DoH3 — в `rayd` | регистрация через API |
| R4 | Yggdrasil через tcpmux (v0.4), ключи пользователей перечитываются по `SIGHUP` и при изменении файла | переключение учётных данных с перекрытием |
| R5 | `inner` для olcRTC и OpenFlux | olcRTC, OpenFlux, вторая ступень к `inner` |

После каждого этапа — релиз.

## 8. Что доделать в клиенте

- ~~Импорт `rcdev1:`~~ — сделано в v1.11.0: вставка из буфера (буфер после импорта очищается) и QR. Нода хранится
  в настройках, `device_key` — обёрнутым ключом Android Keystore (AES-256-GCM, неэкспортируемый), в бэкап не
  попадает. В ядро ключ передаётся по ссылке (`spa_v2.device_key_ref`), в JSON конфига его нет. Профили с адресом
  ноды автоматически получают SPA v2 со scope «все разрешённые». Ноды видны и удаляются в «Настройки → Ноды raycontrol».
- ~~Предупреждение о неверных часах~~ — сделано в v1.13.0 по полю `time` подписки; при молчании ноды — подсказка проверить время (v1.13.1).
- ~~Подписка с ротацией~~ — сделано в v1.13.0–v1.13.2: «текущие + следующие», автообновление к `next.from` и до `expires`.
- Ротация UDP-портов сервисов — ждёт `services[].port_key` от raycontrol.
- Вторая ступень: исходящий VLESS с ML-KEM-768 к `inner` через detour (dnstt, MasterDnsVPN, olcRTC, OpenFlux).
- Пир Yggdrasil с `?sni=` (§3.4).
- Для нод raycontrol — только TLS с `X25519MLKEM768`, без отката.
