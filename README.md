# ⚡ node-accelerator

[![ci](https://github.com/jestivald/node-accelerator/actions/workflows/ci.yml/badge.svg)](https://github.com/jestivald/node-accelerator/actions/workflows/ci.yml)

Оптимизация, диагностика и защита VPN-ноды (Remnawave / Xray / VLESS-Reality, xHTTP, Hysteria2/TUIC).
Три модуля, все идемпотентны, всё откатывается одной командой.

> **Поддержка:** Debian 11/12/13, Ubuntu 20.04–26.04. Тестируется на нодах с `network_mode: host`.

---

## Что внутри

### ⚡ Оптимизатор (`scripts/optimize.sh`)
Снимает потолок по юзерам и выжимает скорость:

- **XanMod-ядро (BBRv3)** — авто-выбор сборки по psABI-уровню CPU (`x64v3/v2/v1`),
  авто-skip на контейнерах (OpenVZ/LXC делят ядро хоста) и не-x86_64.
- **sysctl (tier-aware)**: BBR + `fq`, буферы/`somaxconn`/conntrack **масштабируются от RAM**
  (TIER 1–4: мелкая VPS не уходит в OOM, крупная получает полный размер), syncookies,
  anti-spoof (`rp_filter=2`), `netdev_budget` под высокий PPS, пассивный `tcp_ecn=2`.
- **RPS/RFS** — раскидывает обработку пакетов по всем ядрам. На virtio/single-queue VPS
  иначе весь RX-softirq висит на cpu0 — это и есть реальный потолок PPS. На 1 vCPU и когда
  RX-очередей не меньше, чем ядер (аппаратный RSS), RPS не включается; XPS (раскладку
  TX-очередей задаёт драйвер) — только с `NA_XPS=1`.
- **Сверка sysctl**: после применения значения наших файлов сверяются с ядром; если ключ
  перебивает чужой файл, сортирующийся позже (`99-…` после `99-node-accelerator.conf`),
  optimize называет его, а не печатает «применено».
- **Порты ноды вне эфемерного диапазона**: LISTEN-порты xray/rw-core/rw-node (включая
  `127.0.0.1:10085`) внутри `ip_local_port_range` пишутся в `ip_local_reserved_ports` —
  резерв оператора сохраняется. xray ещё не запущен — ре-ран optimize после старта ноды.
- **Ядро XanMod — с проверками**: при включённом UEFI Secure Boot и при свободном месте в
  `/boot` < 200 МБ ядро не ставится (остальной тюнинг продолжается); после установки —
  проверка initrd и драйвера текущего NIC в новом ядре до слов «нужна перезагрузка».
- **zram-swap** на мелких нодах (tier 1/2), иначе `/swapfile`; **MSS clamp к PMTU** (opt-in, для
  routed/WireGuard); **`tcp_min_snd_mss`-пол** от MSS-коллапса на туннелях.
- **nofile/nproc → 1 048 576**, journald-cap, THP=never, governor=performance, NIC tune, irqbalance.
  Drop-in journald — `10-na-size.conf`: операторский `99-*.conf` главнее; журнал в RAM
  (volatile) переводится в `Storage=persistent`, если `Storage=` никто не задал явно.
- **Откат без ребута**: при первом прогоне снимаются исходные значения sysctl, маски
  RPS/XPS и режим THP; `rollback optimize` возвращает их сразу.
- **Ротация логов ноды + часовой таймер.** journald-cap держит только журнал systemd, а `access.log`
  от nginx и ядра ноды растёт в /var/log без предела — на боевой ноде это сотни МБ в сутки, и диск
  уходит в 100% за недели (тихо: контейнеры перестают писать логи, `acme.sh` не может обновить
  сертификат). Штатной ротации мало: `maxsize` проверяется только в момент запуска logrotate, а тот
  суточный, поэтому файл проскакивает лимит между прогонами — наблюдалось превышение заявленного
  капа в девять раз. Ставится сам пакет `logrotate` (на минимальных образах его нет, и станса лежит
  мёртвым грузом), станса на пути ноды и `na-logrotate.timer` с часовым прогоном. Маску, которую уже
  держит чужая станса, тулкит отдаёт ей (спор решает сам `logrotate`), **сам проверяет в ней
  `maxsize`/`size`** и пишет факт уступки в состояние — `na-diagnose` показывает, кто ротирует и есть ли
  кап, вместо зелёного «таймер активен».

### 🛡 Защита (`scripts/protect.sh`)
`nftables`-движок в **своей** таблице `inet na_filter` (не `flush ruleset` — сосуществует с CrowdSec и Docker):

- **Режим файрвола `FW_MODE`** — `strict` (дефолт): блокируются все порты, кроме явно
  разрешённых (Remnawave node — порты известны заранее); `open`: не перечисленные порты
  **не** блокируются (**3x-ui** — inbound-порты создаются из панели динамически), при этом
  им достаются те же per-IP флуд-лимиты, что и перечисленным (conn-limit / SYN-rate /
  UDP-rate: drop сверх лимита, не бан), остальная защита — как в strict; `skip`: nftables
  не трогается вообще (только CrowdSec) + печатается инструкция, как закрыть порты вручную.
  Интерактивный прогон спрашивает; найден 3x-ui — предлагается `open`.
- **AntiScan** — SYN на несервисный порт → автобан. С **ban-once** (дефолт): 1-й быстрый
  скан → `suspect` (наблюдение), 2-й в окне → бан. Снимает ложные баны CGNAT-операторов.
  (В `FW_MODE=open` не ставится: «закрытых» портов нет — банил бы легитимные inbound'ы.)
  В журнал `[na portscan]` пишется **только переход адреса** в suspect/бан, а не каждый стук в
  закрытый порт (до v4.2 интернет-шум давал 70–99% строк журнала); объёмы — в счётчиках `c_*`.
- **flag-drop** — XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST и прочие скан-пакеты.
- **anti-spoofing** — bogon/RFC1918/CGNAT источники на WAN (v4 **и** v6 bogon).
- **SYN-flood / UDP-flood** — **per-IP** rate-limit (масштабируется по числу клиентов, а не глобальный потолок).
  Состояние лимитов — в наборах с `timeout` (запись живёт, пока адрес активен), правило «превысил → drop»:
  переполненный спуф-флудом набор отключает лимит для новых адресов, а не отрезает их.
- **connect-flood SSH** — >6 новых/мин с IP → `suspect`; бан — только если перебор
  **продолжается** (втрое больший burst в окне suspect), а не за ретрансмит одного SYN.
  Переполненный набор SSH не открывает дверь: новые адреса идут под общий потолок 30/мин.
- **per-IP connlimit** (`ct count`) — кап одновременных коннектов с одного адреса.
- **node-agent порт** — **автодетект с ноды** (`NODE_PORT=auto`, дефолт: слушатель `rw-node`
  → контейнеры `remnawave/node` с **host-сетью** (образ по `.Config.Image`, работает и с
  закреплением по digest; bridge-контейнер второго тенанта не в счёт) → `.env` compose; не
  нашлось — правила на оба известных дефолта `2222,3000`; бокс без агента — `NODE_PORT=none`);
  whitelist-only при заданном `WHITELIST` (контрол-порт не светится в мир).
  Явный `NODE_PORT`, расходящийся с фактом, открывает **оба** порта + громкий warn — панель
  не теряет ноду молча при миграции агента `2222→3000`. При whitelist-only established-пиры
  порта (= панель) пускаются отдельным сетом `na_nodeport_wl_*` — анти-самоотстрел, если IP
  панели забыли в `WHITELIST` (`NODE_PORT_AUTOWL`); пожарный допуск без ре-рана:
  `nft add element inet na_filter na_nodeport_wl_v4 '{ <IP панели> }'`.
- **conntrack phantom-eviction** *(opt-in)* — защита от **distributed connect-and-hold**
  по живым сокетам (`conntrack ≫ ss`), CGNAT-safe, observe-режим по умолчанию.
- **SYNPROXY** *(opt-in, done-right)* — `notrack` только host-local (`fib daddr type local`,
  не ломает Docker/транзит), правило до `ct state invalid drop` + `nf_conntrack_tcp_loose=0`
  (иначе третий ACK рукопожатия не доходил до synproxy), verify ядра/модуля, fail-loud при
  недоступности. Autoban, блок-листы и per-IP SYN-rate решаются **до** synproxy (после него
  соединение уже established); `CONN_LIMIT` на этих портах не действует, а `tcp_loose=0` — на
  весь хост (сессии, пережившие сброс conntrack, рвутся). На VPN-relay обычно избыточен (syncookies + per-IP ct-лимиты уже дают
  анти-спуф) — **default off**. Опубликованные Docker-порты в `TCP_PORTS` с ним не сочетать.
- **Опубликованные Docker-порты** (`-p`, bridge, DNAT) — трафик к ним идёт через hook forward,
  мимо цепочки input. С v4.2 (`DNAT_GUARD=1`) новые DNAT-соединения проходят те же проверки
  источника: whitelist → пропуск, autoban/блок-листы/bogon → drop. Лимиты и список портов
  контейнеров не трогаются — у них свои потребители.
- **Анти-амплификация** (`UDP_AMP_DROP=1`) — новые UDP на сервисные порты с исходных портов
  отражателей (DNS, NTP, SSDP, memcached, CLDAP) режутся до per-IP лимитов.
- **статич-блоклисты** *(opt-in)* — Spamhaus DROP + FireHOL L1 (+ Tor), bogon-фильтр, таймер.
- **Remnawave fleet auto-sync** *(opt-in)* — ноды флота сами держат IP друг друга в whitelist (с панели).
- **ICMP rate-limit** (пинг жив, флуд режется).
- **CrowdSec + `crowdsec-firewall-bouncer-nftables`** — поведенческий IPS + community-блоклист.
  С v4.2 блок-листы по умолчанию действуют **только на SSH** (`CROWDSEC_SCOPE=ssh`: bouncer в
  `set-only`, правило ставит тулкит, whitelist исключён): community-лист на всех портах отрезал
  мобильных абонентов за CGNAT, а CrowdSec на ноде и так разбирает только журнал sshd.
  `CROWDSEC_SCOPE=all` — прежнее поведение, на всех портах. Переключение: bouncer
  останавливается, грузятся правила, bouncer стартует и проверяется; не поднялся в `set-only` —
  откат на `all` с предупреждением (CrowdSec не останется без правил).
  Ставится из **пиннингованного APT-репо**: ключ проверяется по полному отпечатку и в
  keyring кладётся **ровно он** (а не всё, что приехало в ответе). Suite берётся канонический
  `any/any` — он же работает на Debian 13 (trixie), где у CrowdSec **нет** своего suite, а
  родной пакет дистрибутива устарел; дальше фоллбэки на `<os>/<codename>` и `bookworm`/`noble`.
  Не поднялся вообще — CrowdSec просто не ставится: `CROWDSEC_STRICT=1` с v4.0 стоит по умолчанию,
  потому что фоллбэк на `curl|bash`-установщик форсируется атакующим (достаточно сделать репозиторий
  недоступным). Вернуть прежнее поведение — `CROWDSEC_STRICT=0`. `CROWDSEC_PROBE=1` — проверить резолв репо/пакетов на этой ОС без установки.
- Полный **IPv6-паритет**, **rate-limit на логи**, **авто-whitelist твоего SSH-IP** + **сейфти-таймер** от самоблокировки.
- **Анти-локаут по SSH-порту**: порт берётся из `sshd -T` и socket-юнита (Ubuntu 24.04+
  слушает `ssh.socket`, где `Port` из `sshd_config` игнорируется), а порт **текущей
  SSH-сессии** добавляется в правила всегда — ошибка детекта не может отрезать твой доступ.
  Сработавший сейфти-таймер снимает и таблицу, **и автозагрузку правил** — локаут не
  возвращается после ребута.
- **Персист конфига** — ре-ран без ENV не сбрасывает поднятые под ноду ручки. Пустой ENV
  значит «как в conf»; явно очистить список — словом `none` (`WHITELIST=none`, `UDP_PORTS=none`).
- **`na-fw`** — whitelist и разбан одной командой во всех слоях сразу (живой сет, `na_filter.nft`,
  `protect.conf`, CrowdSec, правило `CROWDSEC_SCOPE`): `na-fw allow add|del|list <ip|cidr>`,
  `na-fw unban <ip>`. Файл проверяется `nft -c` до любых изменений; префиксы шире `/8` (v6 —
  `/16`) отвергаются.
- **Локальные правила** — `/etc/node-accelerator/na_filter.d/table/*.nft` (наборы, свои цепочки) и
  `…/input/*.nft` (правила в input сразу после whitelist) вклеиваются в каждую генерацию и
  проверяются общим `nft -c`; ручная правка самого `na_filter.nft` ре-раном стирается.
- **Баны переживают ре-ран** — записи autoban/suspect с оставшимся сроком переносятся в новую таблицу.

### 🩺 Диагностика (`scripts/diagnose.sh`)
Read-only отчёт: ядро/BBR, sysctl, лимиты, conntrack, NIC/RPS, swap/THP/governor, firewall, CrowdSec, порты, RTT — с итогом ✔/▲/✘ и рекомендациями. Плюс сенсоры **стека ноды**: контейнер `remnanode` (статус/рестарты/`SPAWN_ERROR` за час — ловит коллизию node-address в панели), **рассинхрон порта node-агента с файрволом** (агент слушает `:3000`, а strict-правила держат `:2222` → «нода недоступна» для панели; в отчёте — с командой пожарного фикса, в `--json` — `node_port_detected`/`node_port_fw`), **сроки TLS-сертификатов** (LE/acme.sh/`/opt/*/certs`; серты, снятые с renew в acme.sh, не считаются; свои пути — `NA_CERT_PATHS="глоб1 глоб2"`; истекающий серт, который никто не обслуживает, — ▲ «брошенный», а не ✘; исключить — `NA_CERT_IGNORE`), **whitelist в трёх местах** (живой сет vs `na_filter.nft` vs `protect.conf`: адрес, который переживёт ребут, но не ре-ран `protect`, называется по имени), **датчик `CONN_LIMIT` по тому же срезу, что и правило** (только входящие на сервисные порты, без loopback/whitelist — раньше на ноде с внутренним nginx он горел всегда), **PSI** (различает «не собран», «выключен в сборке ядра» и «работает»), **ретеншен journald в часах**, **замороженные дефолты в сохранённом конфиге**, **свежесть fleet-sync/blocklist**, IPv6 default-route, UDP `RcvbufErrors` (QUIC/Hysteria2), **заполненность наборов-лимитеров** (и есть ли у них timeout), **ожидание перезагрузки по факту загрузки** (`reboot_needed` сверяется с `boot_id`, а не верит вечному маркеру).

С v4.2 накопительные счётчики (UDP `RcvbufErrors` v4+v6, softnet drop/`time_squeeze`, `ListenOverflows`, steal) оцениваются **по приросту с прошлого запуска**, а не «с загрузки»: каждый запуск оставляет снимок `/var/lib/node-accelerator/diag-counters.last` (единственное, что diagnose пишет; окно ≥30 с, после ребута — заново). CPU steal — окно 3 с плюс среднее с загрузки, PSI тревожит по `avg60`. Порты для сенсоров берутся из **живых правил** (`protect.conf` и маркер — запасные источники), расхождение правил с `protect.conf` называется вместе с тем, что изменит ре-ран. Новые сенсоры: **CrowdSec по источникам решений** (локальные vs CAPI/списки, область действия блок-листов, откуда читаются логи), **whitelist в четырёх слоях** (живой сет, `na_filter.nft`, `protect.conf`, эффективный allowlist CrowdSec из всех `s02-enrich/*.yaml`; дрейф в обе стороны), **порты, опубликованные через DNAT** (Docker `-p`, ручные relay) мимо `na_filter`, **публичные слушатели вне разрешённых портов** и разрешённые порты без слушателя, **MemAvailable/своп/balloon**, `nftables.service` с `flush ruleset`, ручная правка `na_filter.nft` (хэш из маркера), именованные счётчики дропов, порт xray в эфемерном диапазоне без резерва, доступное обновление XanMod, `/run/reboot-required` от стоковых ядер (info, а не ▲), json-логи контейнеров без `max-size`, OOM за сутки по всем загрузкам. Серты ищутся и в хранилище **Caddy** (docker volume и пакетный), и по `ssl_certificate` из конфигов nginx; **просроченный серт — ✘**, а не «не найден». Убраны ложные ▲: «ядро не XanMod» при `ENABLE_XANMOD=0`, уступка ротации стансе с капом, буферы ниже 32M на маленьком RAM-tier, «RPS выключен» при RX-очередей ≥ ядер, глубина volatile-журнала и журнала ≈ аптайму; лог анти-скана оценивается долей журнала за сутки. Новые поля `--json` — только в хвосте объекта: `udp_rcvbuf_errors_delta`, `softnet_drops_delta`, `time_squeeze_delta`, `listen_overflows_delta`, `delta_window_s` (−1 — окна ещё нет), `cpu_steal_boot_pct`, `crowdsec_decisions_local`, `crowdsec_decisions_capi`, `crowdsec_scope`, `whitelist_drift_crowdsec`, `dnat_ports`, `dnat_guard`, `xanmod_update`, `cert_found`, `portscan_log_lines_24h`, `portscan_log_share_pct`, `cert_stale_count`, `cert_stale_file`. Полный `--json` на ноде с большим журналом занимает десятки секунд; для частого опроса — **`--json --fast`** (`NA_DIAG_FAST=1`): без проходов по журналу, `cscli -a` и `apt-cache`, неизмеренное — −1/пусто.

После установки доступна как команда **`na-diagnose`** (`--json` для мониторинга/панели — теперь с `na_version`, `hostname`, `uptime_s`, `load1`, `mem_used_pct`, WAN rx/tx-байтами; `--retrans [--window N]` — разбор причин TCP-retransmits).

### 🔥 Форензика атак (`scripts/na-report.sh`)
Read-only: кто/откуда/чем/когда — из журнала ядра, nft-сетов и CrowdSec. **`na-report`** (человекочитаемо) или **`na-report --json`**: `drops_by_reason`, `timeline`, `top_ips` с вердиктом, `top_asn` (ASN/гео — best-effort через Team Cymru whois). Флаги: `--hours N`, `--top N`, `--ip <addr>`. Журнал читается по всем загрузкам (`-b all`), а не с момента ребута; в шапке — фактическая глубина журнала (`journal_span_h`), чтобы «событий мало» не путать с «журнал вытеснен». `drops_by_reason.crowdsec` — активные локальные решения CrowdSec, `crowdsec_decisions_all` — вместе с CAPI/списками; `ban_rate_5m` (исторически — число событий за 5 мин) сохранён, честные имена — `events_5m` и `unique_src_5m`; `asn_enrichment` = `ok|partial|unavailable`.

---

## Установка

```bash
# меню
sudo bash install.sh

# по модулям
sudo bash install.sh optimize     # ⚡ XanMod+BBRv3 + тюнинг
sudo bash install.sh protect      # 🛡 nftables + CrowdSec
sudo bash install.sh diagnose     # 🩺 read-only
sudo bash install.sh all          # всё подряд

# неинтерактивно (Remnawave node: strict — блок всех портов, кроме перечисленных;
# порт node-агента детектится с ноды сам, NODE_PORT= нужен только чтобы закрепить вручную)
sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
     WHITELIST="1.2.3.4,2001:db8::1" REMNAWAVE_NONINTERACTIVE=1 \
     bash scripts/protect.sh

# 3x-ui (inbound-порты создаются динамически — защита без блокировки прочих портов)
sudo FW_MODE=open REMNAWAVE_NONINTERACTIVE=1 bash scripts/protect.sh
```

```bash
# curl|bash:
curl -fsSL https://raw.githubusercontent.com/jestivald/node-accelerator/main/install.sh | sudo bash -s all

# прод-режим: пиньте тег через NA_REF — компрометация ветки main тогда не утечёт
# сразу на весь флот (скрипты тянутся из того же тега):
export NA_REF=v4.2
curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all

# максимум: + проверка minisign-подписей модулей (подписи лежат в дереве с v3.6):
export NA_REF=v4.2 NA_REQUIRE_SIG=1 \
       NA_MINISIGN_PUBKEY="RWQrJghT9nkdBC3ntiEXF29zrS8o429WhObHKq6I7CKoftVDhQBrBscu"
curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all
```

> После установки **XanMod нужна перезагрузка** (`reboot`), чтобы BBRv3 заработал. Проверка: `uname -r` содержит `xanmod`.

---

## Параметры `protect.sh` (ENV)

| Переменная | По умолч. | Что |
|---|---|---|
| `FW_MODE` | `strict` | `strict` — блок всех портов, кроме разрешённых (Remnawave node); `open` — прочие порты не блокируются, но получают per-IP флуд-лимиты как перечисленные (3x-ui: динамические inbound'ы; анти-скан автобан и node-port правила не ставятся); `skip` — nftables не трогать (только CrowdSec) + инструкция по ручной блокировке. Интерактивно спрашивается; найден 3x-ui — предлагается `open` |
| `SSH_PORT` | авто-детект | порт(ы) SSH через запятую. Детект (все порты): активный `ssh.socket`/`sshd.socket` (свойство `Listen`) → `sshd -T` (учитывает `sshd_config.d/*`) → `ss` → `sshd_config`. Порт текущей SSH-сессии добавляется к правилам автоматически + warn (сессия ищется и у предков процесса — `sudo` вычищает `SSH_CONNECTION`). В `protect.conf` сохраняется только заданный оператором порт; автодетект каждый прогон делается заново |
| `TCP_PORTS` / `UDP_PORTS` | `443,2087` | сервисные порты; `none` — ни одного (сохраняется словом `none`) |
| `NODE_PORT` | `auto` | порт(ы) node-agent через запятую. `auto` — детект с ноды (слушатель `rw-node` → контейнеры `remnawave/node` с host-сетью → `.env`; агент молчит → прошлый детект, иначе оба дефолта `2222,3000`). Явный порт ≠ факту → правила на оба + warn. `none` — правил node-порта нет (панель, CDN-origin) |
| `WHITELIST` | _пусто_ | IP/CIDR (v4+v6) панели/мониторинга — никогда не банятся (`none` — очистить; менять на ходу — `na-fw allow`). Это **полный обход** защиты (accept раньше автобана/CrowdSec/лимитов), а не «доверенный список»: префиксы шире `/29` (v6 — `/64`) вызывают предупреждение; дубли и `/32` нормализуются перед записью в правила |
| `SYN_RATE`/`SYN_BURST` | `200`/`400` | **per-IP** новых TCP-конн./сек на порт |
| `UDP_RATE`/`UDP_BURST` | `200`/`400` | **per-IP** UDP пакетов/сек |
| `UDP_BULK_PORTS` | _пусто_ | порты объёмного UDP-туннеля (Hysteria2/TUIC). Общий `UDP_RATE` — это потолок около 2 Мбит/с: он душит туннель, клиент ретранслитит и видит огромную задержку. Порт должен быть и в `UDP_PORTS` |
| `UDP_BULK_RATE`/`UDP_BULK_BURST` | `50000`/`100000` | per-IP потолок для этих портов |
| `CONN_LIMIT` | `2048` | макс. одновременных конн. с одного IP (с запасом под CGNAT) |
| `ICMP_RATE`/`ICMP_BURST` | `10`/`20` | **per-IP** ICMP echo/сек (раньше был глобальный потолок) |
| `SSH_RATE`/`SSH_BURST` | `6`/`5` | новых SSH/мин до бана |
| `SSH_BAN_TIME`/`PORTSCAN_BAN_TIME` | `24h`/`1h` | сроки бана |
| `ENABLE_PORTSCAN_BAN` | `1` | автобан за скан закрытых портов |
| `PORTSCAN_RATE`/`PORTSCAN_BURST` | `15`/`30` | порог скана (SYN на закрытые порты/мин, per-IP) до бана — ниже порога просто дроп, без бана |
| `PORTSCAN_LOG_RATE`/`PORTSCAN_LOG_BURST` | `60`/`30` | потолок строк `[na portscan]` в минуту на каждое лог-правило (v4/v6 × suspect/бан; с v4.2 строка пишется только при переходе адреса в suspect/бан) (до v4.1 — `5/second` ≈ 432 000 строк/сутки: на публичной ноде журнал в 300M жил меньше суток и форензика старше вчера была невозможна). Бан работает по счётчикам, не по логу; `0` — лог анти-скана не ставить. `protect` считает теоретический суточный потолок против капа journald и предупреждает, если он больше капа |
| `ENABLE_CROWDSEC` | `1` | ставить CrowdSec + bouncer |
| `CROWDSEC_SCOPE` | `ssh` | где действуют блок-листы CrowdSec: `ssh` — только SSH-порт(ы), whitelist исключён (bouncer в `set-only`, правило — `na-crowdsec-scope.service`); `all` — на всех портах (как до v4.2) |
| `DNAT_GUARD` | `1` | проверки источника (whitelist/autoban/блок-листы/bogon) для новых соединений к опубликованным Docker-портам (forward) |
| `UDP_AMP_DROP` | `1` | drop новых UDP на `UDP_PORTS` с исходных портов отражателей (17, 19, 53, 123, 389, 1900, 11211) |
| `CROWDSEC_STRICT` | `1` | только пиннингованный APT-репо; не поднялся → CrowdSec пропускается. `0` возвращает `curl\|bash`-фоллбэк, который атакующий может форсировать, сделав репозиторий недоступным |
| `ENABLE_SYNPROXY` | `0` | nft synproxy на сервисные порты (advanced). На VPN-relay избыточен — syncookies + per-IP ct-лимиты уже дают анти-спуф; включать под подтверждённый спуф-SYN-флуд |
| `CROWDSEC_ENROLL_KEY` | _пусто_ | enroll в CrowdSec Console |
| `SAFETY_DELAY` | `300` | сек до авто-сброса правил, если не подтвердить SSH (минимум 30). Сброс снимает и таблицу, и автозагрузку (`na-firewall.service`) — иначе локаут вернулся бы ребутом |
| `FLEET_SYNC_INTERVAL` | `5min` | интервал fleet-sync (персистится; `na-diagnose` считает свежесть по нему, а не по дефолту) |
| `NA_NO_LOCK` | `0` | `1` — не брать flock (по умолчанию параллельный второй прогон отказывается стартовать) |
| `NA_ADOPT_NEW_DEFAULTS` | `0` | `1` — принять новые дефолты тулкита разом там, где сохранённый конфиг пиннит старый (см. [Сохранённый конфиг и смена дефолтов](#сохранённый-конфиг-и-смена-дефолтов)). Работает и для `optimize` |
| `DRY_RUN` | `0` | `1` — только сгенерировать + `nft -c`, не применять |
| `ENABLE_BANONCE` | `1` | двухступенчатый автобан (suspect→confirmed), анти-CGNAT-FP |
| `SUSPECT_TIME` | `30m` | окно наблюдения за «подозреваемым» (ban-once) |
| `NODE_PORT_WHITELIST_ONLY` | `auto` | `auto` (whitelist-only если задан `WHITELIST`) / `0` / `1` |
| `NODE_PORT_AUTOWL` | `auto` | при whitelist-only пускать текущих established-пиров node-порта (= панель) сетом `na_nodeport_wl_*` — анти-самоотстрел. `auto` — вкл, когда wl-only вывелся из `WHITELIST` (явный `NODE_PORT_WHITELIST_ONLY=1` — только warn) / `1` форс / `0` выкл. Пиры персистятся (`NODE_PORT_PEERS`) |
| `ENABLE_BLOCKLISTS` | `0` | статич-блоклисты Spamhaus DROP + FireHOL L1 |
| `BLOCK_TOR` | `0` | добавить Tor exit-nodes в блоклист |
| `BLOCKLIST_REFRESH` | `12h` | интервал обновления блоклистов |
| `REMNAWAVE_URL` / `REMNAWAVE_TOKEN` | _пусто_ | панель для fleet auto-sync (токен → `fleet.env` 0600) |
| `REMNAWAVE_NODES_URL` | _пусто_ | fleet-sync **без токена на ноде**: URL статического списка нод (JSON вида `/api/nodes` или plain-text «адрес на строку») |
| `CADDY_AUTH_API_TOKEN` | _пусто_ | Caddy Security / Tiny Auth перед панелью → `X-Api-Key` на запросы fleet-sync. Алиас: `REMNAWAVE_CADDY_TOKEN` |
| `FLEET_SYNC` | `auto` | `auto` (вкл при URL+TOKEN) / `1` / `0` |
| `ENABLE_CTGUARD` | `0` | conntrack phantom-eviction (анти connect-and-hold) |
| `NA_CTG_ENFORCE` | `0` | `0` — observe (только лог), `1` — эвиктить фантомы |
| `NA_CTG_PHANTOM_MIN` / `NA_CTG_LIVE_FLOOR` | `4000` / `2` | порог conntrack-холдера / порог живых сокетов. `LIVE_FLOOR` подбирают по observe-режиму: у обычных клиентов бывает 1–2 живых сокета при заметном conntrack |
| `NA_CTG_BANTIME` / `NA_CTG_INTERVAL` / `NA_CTG_COARSE_MULT` | `15m` / `20s` / `3` | срок эвикта / период проверки / во сколько раз conntrack должен превышать число живых сокетов, чтобы вообще запускать разбор |

`optimize.sh`: `ENABLE_XANMOD=1`, `XANMOD_FLAVOR=lts|main|edge|rt`, `XANMOD_PKG=...`, `REMNAWAVE_SWAP_SIZE=2G`, `TCP_ECN_MODE=2` (0/1/2), `DISABLE_TFO=0`, `CT_EST_TIMEOUT=7440` (conntrack established-timeout, сек; ↑ напр. до `14400` для idle-туннелей/мостов без частого keepalive), `QDISC=fq|fq_codel|cake` (cake — против bufferbloat на слабых аплинках; сравнивай A/B), `ENABLE_MSS_CLAMP=0` (для routed/WireGuard-нод), `SETUP_NO_ZRAM=0`, `ENABLE_LOGROTATE=1` + `NA_LOG_PATHS`/`NA_LOG_MAXSIZE=200M`/`NA_LOG_ROTATE=4`/`NA_LOG_INTERVAL=hourly` (ротация файловых логов ноды, см. ниже), `ENABLE_PSI=0` (`1` — дописать `psi=1` в `GRUB_CMDLINE_LINUX_DEFAULT`: XanMod и стоковые ядра Debian собраны с `CONFIG_PSI_DEFAULT_DISABLED=y`, без этого `/proc/pressure` нет и сенсор давления в `na-diagnose` слеп; учёт PSI не бесплатен для планировщика, поэтому opt-in; ребут), `NA_JOURNAL_MAX_USE=300M` (кап journald), `NA_REMNANODE_ENV=/opt/remnanode/.env` (откуда брать порт агента), `NA_NODE_CONTAINER=remnanode` (имя контейнера node-агента для сенсора `na-diagnose`), `NA_CERT_PATHS` (доп. сертификаты для сенсора срока), `NA_CERT_IGNORE` (глобы брошенных сертов, которые сенсор не смотрит), `NA_IPV6_FORWARD` (пусто — авто: v6-форвардинг остаётся, если нода уже маршрутизирует IPv6; `1`/`0` — явно). Буферы/conntrack/somaxconn — **tier-aware** (масштаб от RAM).
`XANMOD_PROBE=1` — проверить, что репозиторий+ключ+сборка ядра резолвятся на этой ОС, **без установки** (для CI и быстрой проверки совместимости).

---

## Проверка и эксплуатация

```bash
na-fw-status                 # баны, suspect, счётчики отброшенного, blocklist, fleet, ctguard, CrowdSec
na-fw allow add 203.0.113.7  # whitelist во всех слоях сразу (del / list — так же)
na-fw unban 198.51.100.9     # снять autoban/suspect и решения CrowdSec
na-fw-top-talkers            # топ источников по сервисным портам
na-diagnose                  # 🩺 health-отчёт (read-only)
na-diagnose --json           # JSON для флот-мониторинга (Zabbix/Prometheus/панель); частый опрос — --json --fast
na-diagnose --retrans        # 🔬 разбор ПРИЧИН TCP-retransmits (TX/RX, тип, хвост, CC, дропы)
na-report                    # 🔥 форензика атак за 24ч (кто/откуда/чем/когда)
na-report --json             # JSON форензики; --hours N, --top N
na-report --ip 1.2.3.4       # глубокий вердикт по IP (rDNS, nft-сеты, conntrack, таймлайн)
na-report --port 443         # топ дроп-источников по порту + кто слушает
nft list table inet na_filter
cscli decisions list
journalctl -t na-fleet-sync -t na-blocklist -t na-ctguard   # логи модулей
```

### Fleet auto-sync (ноды флота → whitelist)

Чтобы каждая нода сама держала IP всех остальных нод в whitelist (новую добавил в панель —
остальные подхватят сами; fail-safe last-known-good):

```bash
sudo REMNAWAVE_URL="https://panel.example.com" REMNAWAVE_TOKEN="ey..." \
     CADDY_AUTH_API_TOKEN="your-caddy-api-key" \
     REMNAWAVE_NONINTERACTIVE=1 bash scripts/protect.sh
# токен из панели: Remnawave → Settings → API Tokens. Хранится в /etc/node-accelerator/fleet.env (0600).
# CADDY_AUTH_API_TOKEN — если панель за Caddy Security / Tiny Auth (заголовок X-Api-Key).
```

> ⚠️ **Blast-radius токена.** API-токен Remnawave — полноправный; лежащий на каждой ноде
> `fleet.env`, при компрометации одной ноды отдаёт доступ к панели. Заведите под fleet-sync
> **отдельный** токен (легко отозвать), а лучше — режим **без токена на ноде**:
>
> ```bash
> # панель кроном публикует список нод (JSON /api/nodes или «адрес на строку»)
> # за basic-auth / IP-allowlist, ноды тянут его без всяких токенов:
> sudo REMNAWAVE_NODES_URL="https://user:pass@panel.example.com/fleet/nodes.json" \
>      REMNAWAVE_NONINTERACTIVE=1 bash scripts/protect.sh
> ```
>
> Свежесть синка видна в `na-diagnose` (`fleet_sync_age_s` в `--json`): протухший
> токен/сменившийся API больше не прячутся за fail-safe last-known-good.

### Защита от distributed connect-and-hold (ctguard)

```bash
# раскат observe → enforce: сначала смотрим кандидатов (только лог), потом включаем эвикт
sudo ENABLE_CTGUARD=1 REMNAWAVE_NONINTERACTIVE=1 bash scripts/protect.sh   # observe (NA_CTG_ENFORCE=0)
journalctl -t na-ctguard         # кандидаты = только атакеры (live≤2)? тогда:
sudo ENABLE_CTGUARD=1 NA_CTG_ENFORCE=1 REMNAWAVE_NONINTERACTIVE=1 bash scripts/protect.sh
```

> **Нода за реверс-прокси / балансировщиком / CDN?** Тогда весь трафик приходит с
> небольшого набора upstream-адресов, и per-IP лимиты (`CONN_LIMIT`/`SYN_RATE`) начнут их
> резать. Посмотри кандидатов через `na-fw-top-talkers` и занеси upstream-диапазоны в
> `WHITELIST=` — whitelist стоит выше всех лимитов.

## Сохранённый конфиг и смена дефолтов

Эффективные параметры каждого прогона сохраняются в `/etc/node-accelerator/{protect,optimize}.conf`
идиомой `: "${KEY:=value}"` — ре-ран без ENV не сбрасывает то, что оператор задал под ноду
(`WHITELIST`, `CONN_LIMIT`, `NODE_PORT`…). Пустой ENV тоже значит «как в conf» (обёртка с
незаданной переменной не должна молча стереть whitelist); явное «пусто» — слово `none`. Обратная сторона: файл так же пиннит и **дефолты той
версии, при которой ноду настраивали**, и встроенный дефолт новой версии не может выиграть у
записанного никогда. Ужесточение по безопасности (например, `CROWDSEC_STRICT` `0→1` в v4.0) на уже
настроенных нодах молча не применялось.

С v4.1 тулкит различает «оператор задал» и «записан тогдашний дефолт»: ключи, пришедшие из ENV,
помечаются в файле маркером `# explicit: KEY`; ключ без маркера, пиннящий старый дефолт, — заморозка,
о которой `protect`/`optimize` печатают `[!] conf: KEY=old записан старой версией, а дефолт с vX = new…`,
а `na-diagnose` — отдельный ▲ (в `--json` — `conf_stale_defaults`). Принять новые дефолты разом:
`NA_ADOPT_NEW_DEFAULTS=1` при ре-ране; оставить старое осознанно: задать `KEY=old` в ENV один раз —
маркер `explicit` переживёт последующие ре-раны.

---

## Откат

```bash
sudo bash install.sh rollback all        # protect + optimize
sudo bash install.sh rollback protect    # снять firewall (CrowdSec остаётся; NA_PURGE_CROWDSEC=1 чтобы удалить)
sudo bash install.sh rollback optimize   # снять тюнинг (XanMod остаётся; NA_REMOVE_XANMOD=1 + загрузка со стока чтобы удалить)
```

`rollback optimize` убирает и то, что раньше оставалось жить: строки `pam_limits` в
`common-session*` и `/swapfile` вместе с записью в `/etc/fstab` — **swap снимается только
если его создали мы** (метка `swapfile.created`) и только если он не занят.

Бэкапы оригиналов — в `/var/backups/node-accelerator/<timestamp>/`.

---

## Почему так (отличия от старого toolkit)

- **Порядок правил исправлен.** В старом `protect.sh` глобальный `syn … accept 1000/s` стоял выше
  пер-портовых правил и `accept` затенял весь port-allow-list, SSH-бан и portscan-детект. Здесь
  SYN-rate **per-IP** внутри каждого сервисного порта, несервисные SYN падают в автобан.
- **Лимиты per-IP, а не глобальные** — один атакующий ограничен, а агрегат масштабируется по числу клиентов.
- **Не `flush ruleset`.** Управляем только `inet na_filter` — CrowdSec-bouncer (`ip crowdsec`, priority −10)
  и Docker-NAT остаются нетронутыми (старый flush ломал Docker-сеть).
- **IPv6-паритет** — autoban/whitelist/scan-детект **и v6-bogon anti-spoof** (раньше v6-сканеры/брут не банились вообще).
- **Логи под rate-limit** — флуд сканов больше не забивает journald/диск, а `na-diagnose` отдельно
  показывает крупные файлы в /var/log, json-логи контейнеров и то, активен ли часовой таймер ротации
  (в `--json`: `disk_pct`, `inode_pct`, `log_max_bytes`, `docker_log_max_bytes`, `logrotate_timer`).
- **autoban с `size`-капом** — спуф-флудом чистого SYN нельзя раздуть set в памяти ядра.
- **Лимитеры с `timeout`, а не вечные `meter`** — до v4.1.3 каждый адрес, хоть раз пришедший на порт,
  оставался в наборе до ребута; на 65 535 записях новые клиенты молча отсекались. Теперь записи истекают,
  а `na-diagnose` показывает заполненность (`dynset_fill_max_pct`, `dynset_no_timeout` в `--json`).
- **Файл автозагрузки меняется последним** — ruleset сначала проходит `nft -c` и `nft -f`, и только потом
  становится `na_filter.nft`; отвергнутый лежит рядом как `na_filter.nft.rejected`.
- **CGNAT-дружелюбность** — portscan-бан срабатывает по порогу скорости скана (а не по одному SYN, который за CGNAT банил весь оператор); ICMP-лимит per-IP, а не глобальный; `CONN_LIMIT` с большим запасом. Датчик `макс конн/IP vs CONN_LIMIT` в 🩺 диагностике показывает, душит ли лимит на самом деле.
- **conntrack-ёмкость от RAM** — мелкая VPS под флудом не упирается в OOM ядра.
- **Ключ XanMod по полному отпечатку** + keyserver-фоллбэк при CF-403 (Hetzner/GCP) + поддержка Ubuntu 22.04 (jammy→bookworm).
- **CI** — `shellcheck` + smoke-матрица (Debian/Ubuntu): генерация nftables и резолв XanMod проверяются на каждый PR;
  поведение лимитеров — на настоящем nft в netns (`tests/nft-behavior.sh`), запрет `| grep -q` под `pipefail` — линтером.

---

MIT. Гарантий нет — это инфраструктурные скрипты, читай перед запуском на проде.
