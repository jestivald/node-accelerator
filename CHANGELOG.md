# Changelog

## v3.6 — 2026-07-01

Наблюдаемость стека ноды + supply-chain-хардинг. Все новые сенсоры **read-only**;
поведение защиты/тюнинга по умолчанию **не меняется**. Впервые репозиторий получает
**теги/релизы** (v2.0…v3.6) и **подписи модулей** — `NA_REF=<тег>` из README теперь
рабочий, а не пример.

### 🔐 protect.sh — CrowdSec из пиннингованного APT-репозитория
- Вместо `curl https://install.crowdsec.net | bash` — их **packagecloud APT-репо** с
  проверкой **полного отпечатка** ключа (`6A89E3C2303A901A889971D3376ED5326E93CD0C`;
  64-битный keyid подделать дёшево — как уже сделано для XanMod). Suite нет для этой ОС
  → фоллбэк на `noble`/`bookworm`; репо совсем не поднялся → официальный установщик как
  **last-resort** (громко, `warn`). `CROWDSEC_PROBE=1` — проверить резолв репо/ключа/
  пакетов без установки (CI/ops).

### 🩺 diagnose.sh — сенсоры стека ноды (в отчёте и `--json`)
- **remnanode**: статус контейнера, `RestartCount`, число `SPAWN_ERROR` за час
  (ловит коллизию node-address в панели: два node-record на один IP → xray не стартует).
- **TLS-сертификаты**: ближайший к истечению (Let's Encrypt/acme.sh/`NA_CERT_PATHS`),
  warn <14 дн, fail <7 дн.
- **Свежесть fleet-sync / blocklist**: `na-fleet-sync`/`na-blocklist-update` штампуют
  время УСПЕШНОГО обновления; diagnose ругается, если fleet-sync не проходил > 3× интервала
  (протухший токен панели / сменившийся API больше не молчат за fail-safe last-known-good).
- **IPv6 default-route** (пропажа тихо ломает v6-клиентов) и **UDP RcvbufErrors**
  (переполнение приёмного буфера QUIC/Hysteria2/TUIC).
- `--json` дополнен для флот-панели: `na_version`, `hostname`, `uptime_s`, `load1`,
  `mem_used_pct`, `wan_iface`/`wan_rx_bytes`/`wan_tx_bytes`, `ipv6_default`,
  `udp_rcvbuf_errors`, `remnanode_status`/`_restarts`/`_spawn_errors_1h`,
  `fleet_sync_age_s`, `blocklist_age_s`, `cert_min_days` (трафик/нагрузка без второго SSH).
- **Фикс:** датчик whitelist считал только v4 — на нодах с чисто-v6 whitelist давал ложное
  «whitelist пуст». Теперь v4+v6.

### 🌐 optimize.sh
- **`QDISC=fq|fq_codel|cake`** (opt-in) — cake как альтернатива `fq` на bufferbloat-аплинках
  дешёвых VPS (BBR пейсит внутренне). Дефолт `fq` не меняется; персистится.
- **LRO off** в NIC-тюнинге (GRO оставляем): LRO ломает форвардинг-путь на bare-metal.
- XanMod-репо теперь по **https** (был http).

### 🛡 fleet-sync без API-токена на ноде (`REMNAWAVE_NODES_URL`)
- Альтернатива Bearer-токену панели на каждой ноде (blast-radius): статический источник
  адресов — JSON вида `/api/nodes` **или** plain-text «адрес на строку». Панель публикует
  его кроном за basic-auth/allowlist, ноды тянут без токена. `REMNAWAVE_URL`+`TOKEN`
  по-прежнему поддерживаются.

### 🧰 lib/common.sh
- **`NA_VERSION`** — единый источник версии; пишется в installed-маркеры и во все `--json`
  (флот-панель видит version-drift по нодам).
- **Авто-ремонт dpkg** в `apt_install`: при сбое — `dpkg --configure -a` + `apt-get -f install`
  + ретрай (прерванный прошлый прогон/битый dpkg — частый кейс на чужих нодах).

### 📦 Релизы, подписи, CI
- **Теги+GitHub Releases** для всей истории (v2.0…v3.6). `NA_REF=v3.6` в примерах — рабочий.
- **Подписи модулей** (`.minisig`) в дереве; `NA_REQUIRE_SIG=1` + `NA_MINISIGN_PUBKEY`
  теперь реально применимы (публичный ключ — в README). `RELEASING.md` — чеклист релиза.
- CI: матрица +`ubuntu:26.04`; `CROWDSEC_PROBE`; проверка, что `na-report --proxyware --json`
  — одна строка; `na_version` присутствует в `--json`.
- Дрейф доков: шапка `protect.sh` показывала старые дефолты (`SYN_RATE=100`/`CONN_LIMIT=600`)
  — поправлено на актуальные (200/2048).

## v3.5 — 2026-06-27

Мелкий тюнинг-апдейт: одна новая ручка + уточнение по SYNPROXY. Поведение по умолчанию НЕ меняется.

### ⚙️ optimize.sh — `CT_EST_TIMEOUT` (новая ENV-ручка)
- `nf_conntrack_tcp_timeout_established` вынесен из хардкода в ENV `CT_EST_TIMEOUT` (секунды,
  дефолт `7440` — поведение прежнее). Валидируется (целое 120…432000, иначе дефолт) и
  **персистится** в `optimize.conf` (ре-ран без ENV не сбрасывает значение).
- Зачем: idle-туннели/мосты без частого keepalive можно поднять (напр. `14400`=4ч), не патча
  скрипт; ноды под флуд-профилем — оставить дефолт (агрессивнее реклеймит брошенные /
  connect-and-hold established, не раздувая conntrack-таблицу).

### 📝 SYNPROXY — уточнение (код не меняется)
- Зафиксирован вывод: на VPN-relay SYNPROXY **избыточен** — анти-спуф уже дают
  `tcp_syncookies=1` + per-IP ct-лимиты, а издержки (`be_liberal`, поломка TFO на защищённых
  портах, per-packet overhead) не оправданы; против connect-and-hold / PPS-флуда он не
  помогает. Остаётся **opt-in, default off**; включать только под подтверждённый спуфнутый
  SYN-флуд. (Комментарий в `protect.sh` + строка в README.)

## v3.4 — 2026-06-24

Self-audit на residential-proxy / proxyware-SDK (read-only) — доказательная база для ответа на abuse-тикеты хостеров.

### 🕵 na-report — новый режим `--proxyware`
- проверка сигнатур известного proxyware (IPIDEA/PacketSDK/Honeygain/EarnApp/Peer2Profit/…) в процессах, systemd-юнитах, cron, файлах и docker-образах;
- поиск **установленных** соединений к C2-инфраструктуре proxyware (резолв доменов → match по ESTABLISHED peer-адресам);
- список внешне-доступных listener'ов (контекст для оператора);
- вердикт `clean|suspect`; `--proxyware --json` — один объект для панели/флота.
- Сигнатуры — только конкретные имена продуктов (generic «proxy» не матчим, чтобы не ловить сам xray/VLESS).

## v3.3.1 — 2026-06-16

### 🐞 Фикс
- `na-report --json`: `crowdsec_count` мог выдать `0\n0` (битый JSON) на нодах, где cscli
  установлен, но 0 решений — `grep -c … || echo 0` двоил вывод при нуле совпадений (grep
  печатает `0` и выходит с кодом 1). Теперь ровно одно целое. CI: добавлена проверка, что
  `na-report --json` — ровно одна строка.

## v3.3 — 2026-06-15

Расширение read-only наблюдаемости (поведение защиты/тюнинга НЕ меняется) + фикс деплоя.

### 🩺 diagnose.sh — новые health-проверки
- conntrack-дропы `insert_failed`/`drop`/`early_drop` (если есть conntrack-tools) — память vs хеш vs переполнение;
- **PSI** (`/proc/pressure` cpu/mem/io) — стол ядра под нагрузкой;
- NIC drops/errors (`ip -s link`);
- диск + **inode-исчерпание** (`df` / `df -i`); инциденты ядра (OOM/lockup/hung за 24ч) и упавшие systemd-юниты.

### 🔥 na-report — обогащение
- `--ip <addr>`: rDNS + паттерн сканера, точное членство во ВСЕХ наших nft-сетах (`nft get element`), активные conntrack-сессии, per-IP таймлайн по часам;
- `--port <N>`: топ дроп-источников по порту + кто слушает;
- в отчёте: SSH brute (топ юзернеймов/source-IP) и топ CrowdSec-сценариев.

### 🐞 Фикс
- `install.sh` (curl|bash) теперь докачивает `na-report.sh` → `install.sh persist` ставит и `na-report` (не только `na-diagnose`).

Концепция диагностик/форензики вдохновлена наработками коллеги-оператора (по его просьбе — без имени).

## v3.2 — 2026-06-15

Диагностика **причин** TCP-retransmits (read-only, поведение не меняется).

### 🔬 `na-diagnose --retrans [--window N]`
Докапывается до причины retrans, а не только до факта. За одно окно семплинга
(по умолч. 20с): retrans-rate, TX/RX-перекос (download vs upload), разбивка по
**типу** (Timeouts/LostRetransmit/SackRecovery/SlowStart/BacklogDrop), хвост сокетов
с retrans + распределение, реальный congestion-control **на проводе** (bbr vs cubic),
дропы TX-тракта (qdisc/softirq/NIC ring), accept-queue, TCP-фичи (sack/dsack/frto/
recovery/`min_snd_mss`/`mtu_probing`) — и **вердикт** (MSS-коллапс / qdisc-overflow /
путь). Концепция вдохновлена наработками коллеги-оператора (по его просьбе — без имени).

## v3.1 — 2026-06-15

Наблюдаемость: нода теперь отдаёт стабильный машинный интерфейс для внешнего
мониторинга/панели. Поведение защиты/тюнинга не меняется. Концепция форензик-слоя
вдохновлена наработками коллеги-оператора (по его просьбе — без имени).

### 🩺 Постоянная CLI (na-diagnose / na-report)
- **`na-diagnose`** — после `optimize`/`protect`/`all` на ноде остаётся read-only
  команда (обёртка в `/usr/local/sbin`, скрипты в `/usr/local/lib/node-accelerator`).
  Раньше при `curl|bash` модули жили в temp и постоянной команды диагностики не
  оставалось — панелям/Zabbix/SSH-поллингу нужен стабильный `na-diagnose --json`.
  Новый сабкоманд `install.sh persist` — (пере)создать CLI без полного прогона.
  `DRY_RUN=1` ничего не пишет; `rollback` снимает CLI, когда не осталось модулей.

### 🔥 na-report — форензика атак (read-only)
- **`na-report` / `na-report --json`** — кто/откуда/чем/когда, из данных, которые уже
  есть на ноде: журнал ядра (`[na portscan|synflood|ssh-flood|badflags]`), nft-сеты
  (`autoban`/`suspect`/`blocklist`), решения CrowdSec. Выдаёт: `events_total`,
  `ban_rate_5m`, `drops_by_reason`, `timeline[12]` (последний час), `top_ips`
  (с вердиктом attacker/suspect + confidence) и `top_asn`. ASN/гео — best-effort через
  Team Cymru whois (нет `whois`/сети → поле пустое, остальное работает). `--hours N`,
  `--top N`, `--ip <addr>` (вердикт по одному IP).

### ✅ CI
- smoke-матрица теперь прогоняет `install.sh persist` (na-diagnose создаётся и отдаёт
  JSON), проверяет `DRY_RUN` без эффектов и снятие CLI на `rollback`.

## v3.0 — 2026-06-13

Крупный релиз: персист-конфиг, fleet auto-sync, новый класс DDoS-защиты
(phantom-eviction), статич-блоклисты, ban-once, tier-aware тюнинг, `--json`-
диагностика. Все новые тяжёлые модули **opt-in** и **ничего не меняют у текущих
пользователей**, пока их явно не включат; багфиксы/footgun-фиксы применяются всегда.
Часть концепций DDoS-защиты вдохновлена наработками коллеги-оператора (по его просьбе —
без имени).

### 🔧 Footgun-фиксы (применяются всегда)
- **Персист конфига ноды.** Эффективные значения сохраняются в `/etc/node-accelerator/
  {protect,optimize}.conf` (идиома `: "${KEY:=value}"`) и подхватываются на ре-ране.
  Раньше повторный `protect.sh` БЕЗ ENV молча сбрасывал поднятые под ноду ручки
  (`CONN_LIMIT`/`WHITELIST`/…) к дефолтам — на нодах за CDN/мостом это рвало бы upstream.
  Прецеденс: **ENV > сохранённый конфиг > встроенный дефолт**.
- **node-agent порт больше не светится в мир.** При заданном `WHITELIST` контрол-порт
  (`NODE_PORT`) становится whitelist-only (раньше был открыт всем под лимитом 30/с).
  Управляется `NODE_PORT_WHITELIST_ONLY=auto|0|1`.

### 🛡 protect.sh — новые слои защиты
- **conntrack phantom-eviction (`ENABLE_CTGUARD=1`).** Ловит **distributed
  connect-and-hold** — класс атаки, который статичные rate-limit'ы не видят (сотни IP
  открывают тысячи TCP, проходят handshake и бросают; conntrack пухнет, xray
  захлёбывается, per-IP счётчики молчат). Детект по **живым сокетам**: `conntrack ≫ ss`.
  CGNAT-safe (эвикт только концентрированный холдер с `conntrack ≥ NA_CTG_PHANTOM_MIN`
  и `live ≤ NA_CTG_LIVE_FLOOR`; whitelist/fleet щадятся). Дешёвый коарс-гейт перед
  дорогим `conntrack -L`. **observe по умолчанию** (`NA_CTG_ENFORCE=0` — только лог).
  Изолированная таблица `inet na_ctguard` (priority −5).
- **Remnawave fleet auto-sync (`REMNAWAVE_URL`+`REMNAWAVE_TOKEN`).** Таймер тянет
  `GET /api/nodes` по Bearer и держит IP всех нод флота в nft-сете `na_fleet_*`
  (accept сразу после whitelist). Новую ноду добавил в панель → остальные подхватят сами.
  Fail-safe **last-known-good** (панель легла → whitelist нод не трогаем). Токен — в
  `/etc/node-accelerator/fleet.env` (root:root 0600), **не** в protect.conf.
- **Статич-блоклисты (`ENABLE_BLOCKLISTS=1`).** Spamhaus DROP (json v4+v6) + FireHOL L1
  (+ Tor по `BLOCK_TOR=1`) + `custom-blocklist.txt` оператора. Bogon-фильтр фидов,
  отдельная nft-транзакция, last-known-good. Обновление таймером (`BLOCKLIST_REFRESH`).
- **ban-once (`ENABLE_BANONCE=1`, дефолт).** Двухступенчатый автобан: 1-е нарушение →
  `suspect` (наблюдение, без полного бана), 2-е в окне `SUSPECT_TIME` → `confirmed` (бан).
  Режет ложные баны целых CGNAT-операторов из-за одного шального скана/перебора.
- **SYNPROXY done-right.** `notrack` теперь ТОЛЬКО для host-local (`fib daddr type
  local`) — больше не ломает conntrack/NAT транзита (Docker-контейнер панели → нода).
  Проверка ядра ≥5.14 + `nf_synproxy`, mss из MTU аплинка, **fail-loud** (маркер
  `.synproxy-degraded` + видно в diagnose/na-fw-status), модуль грузится на boot.

### ⚡ optimize.sh
- **Tier-aware sysctl по RAM** (TIER 1–4): потолки сокетов (`rmem/wmem_max`,
  `tcp_rmem/wmem`) масштабируются от RAM — мелкая VPS не уходит в OOM от 64MB×сокеты,
  крупная получает полный размер. `netdev_budget` поднят под высокий PPS.
- **`tcp_ecn` 1 → 2 (пассивный)** по умолчанию — безопаснее на исходящих через битые
  middlebox (настраивается `TCP_ECN_MODE`). **TFO выключаемо** (`DISABLE_TFO=1`).
  `overcommit` на tier1 → heuristic (0) вместо агрессивного 1.
- **zram-swap на tier 1/2** (компрессированный swap в RAM, lz4) вместо дискового
  `/swapfile`; fallback на swapfile. `SETUP_NO_ZRAM=1` форсит swapfile.
- **MSS clamp к PMTU (`ENABLE_MSS_CLAMP=1`, opt-in)** — против PMTU-блэкхолов на туннелях
  (WireGuard/routed). Своя таблица `inet na_mss`. Дополняет `tcp_min_snd_mss`-пол из v2.4.

### 🩺 diagnose.sh
- **`diagnose.sh --json`** — один машинно-читаемый объект для флот-мониторинга
  (Zabbix/Prometheus/SSH-поллинг): ядро, steal, ретрансмиты, conntrack%, MSS, firewall,
  autoban/suspect/blocklist/fleet, ctguard, synproxy, safety, reboot_needed.
- **Сенсор MSS-коллапса** — считает живые сокеты с обрезанным MSS (<256) + проверяет
  `tcp_min_snd_mss`/`mtu_probing`. Ловит ровно прод-инцидент, что чинит v2.4.
- Сенсоры новых компонентов (blocklist/fleet/ctguard/synproxy-degraded) в отчёте и
  `na-fw-status`.

### install.sh
- **Опц. проверка подписи модулей** в curl|bash-режиме (`NA_REQUIRE_SIG=1` +
  `NA_MINISIGN_PUBKEY` или `NA_SIG_FINGERPRINT`) — supply-chain hardening поверх `NA_REF`.
- `diagnose --json` пробрасывается через `install.sh diagnose --json`.

### ↩️ rollback.sh / CI
- Откат снимает все новые компоненты (fleet-sync/blocklists/ctguard/mss-clamp/zram,
  таблицы `na_ctguard`/`na_mss`, конфиги, токен) — `custom-blocklist.txt` оператора сохраняется.
- CI: добавлен DRY_RUN с включёнными blocklists/fleet/whitelist-only (full-feature
  `nft -c`) + smoke `diagnose --json`.

## v2.4 — 2026-06-12

Фикс MSS-коллапса под потерями на оптимизаторе.

### ⚡ Оптимизатор (`optimize.sh`)
- **Пол `tcp_min_snd_mss=512`**: при `tcp_mtu_probing=1` ядро на лоссовой линии
  принимает серию RTO за PMTU-чёрную-дыру и ужимает send-MSS до дефолтного пола
  48Б (сегмент ~97% оверхед → throughput коллапсирует без восстановления). 512
  оставляет probing рабочим для настоящих чёрных дыр, но не убивает goodput.

## v2.3 — 2026-06-12

Security-хардинг входной валидации (по итогам аудита). Тулкит параметризуется
неинтерактивно (панель/оркестратор), поэтому непровалидированный ENV — не «root сам
себе», а реальный вектор. Бэкдоров/эксфильтрации/скрытых кредов аудит не выявил.

### 🛡 protect.sh
- **Валидация числовых и duration-ENV**: `SYN_RATE`/`SYN_BURST`/`CONN_LIMIT`/`ICMP_*`/
  `PORTSCAN_*`/`SAFETY_DELAY` (целое) и `SSH_BAN_TIME`/`PORTSCAN_BAN_TIME` (`N[s|m|h|d]`).
  Раньше уходили в nft-ruleset без проверки. **`SAFETY_DELAY`** к тому же шёл в `sh -c`
  (единственный shell-eval-сток) — теперь валидируется и передаётся позиционным аргументом.
- **WHITELIST IPv6** строго валидируется (hex+`:`+опц.`/prefix`), как и IPv4. Раньше
  v6-ветка принимала любую строку с `:` и дословно уходила в nft `elements = { … }` (инъекция).
- **Стейт сейфти-таймера** перенесён из предсказуемого `/tmp` в root-only `$STATE_DIR`
  (симлинк/TOCTOU), с проверкой `! -L` перед чтением pid.
- CrowdSec-установщик: `curl -s` → `-fsSL` (fail-closed на HTTP-ошибке/редиректе).

### install.sh
- **`NA_REF` валидируется** (`^[A-Za-z0-9._/-]+$`, без `..`) — раньше шёл в URL модулей и
  допускал path-traversal/увод на чужой репозиторий.

### 🩺 diagnose.sh / ↩️ rollback.sh
- Подхватывают новый путь стейта сейфти + чистят legacy `/tmp` от старых версий.

## v2.2 — 2026-06-12

CGNAT-дружелюбность защиты (issue #2: «спонтанно пропадает пинг до ноды в некоторых
регионах»). За CGNAT мобильных операторов много абонентов делят один egress-IP, и
дефолты резали целые операторские пулы.

### 🛡 protect.sh
- **portscan-автобан по порогу скорости**, а не по одному SYN. Раньше один шальной коннект
  на закрытый порт банил весь IP (= весь оператор за CGNAT) на `PORTSCAN_BAN_TIME`. Теперь
  бан только если IP бьёт по закрытым портам быстрее `PORTSCAN_RATE` (по умолч. 15/мин);
  одиночные SYN под порогом просто дропаются. **Главный фикс симптома из issue #2.**
- **ICMP-лимит PER-IP** (`ICMP_RATE`/`ICMP_BURST`, meter) вместо глобального 10/с — нода с
  сотнями пингующих клиентов больше не упирается в общий потолок («пропадает пинг»).
- **`CONN_LIMIT` 600 → 2048** и **`SYN_RATE`/`SYN_BURST` 100/200 → 200/400** — запас под
  агрегированный CGNAT-трафик. (Эмпирика по флоту: реальные юзеры — десятки конн., но
  страховка от операторских пулов и от роста; всё по-прежнему настраивается через ENV.)

### 🩺 diagnose.sh
- Датчик **«макс конн. с одного IP vs CONN_LIMIT»** — видно, душит ли per-IP лимит на самом
  деле (предупреждение при ≥80% потолка), чтобы решать по факту, а не по слухам.

## v2.1 — 2026-06-12

Усиление установки XanMod и защиты + CI. Вобрала валидную часть внешнего PR
(Ubuntu 22.04, keyserver-фоллбэк, прогресс-бар) с фиксом его багов.

### ⚡ Оптимизатор (`optimize.sh`)
- **Ubuntu 22.04/20.04 (jammy/focal)**: XanMod выпилил эти suite из репо — теперь
  подменяем на совместимый Debian `bookworm` (LTS-ветка) + форсим lts-сборку.
- **Keyserver-фоллбэк ключа**: при CF-403 на `dl.xanmod.org` (типично для Hetzner/GCP)
  ключ берётся с `keyserver.ubuntu.com`. В обоих случаях **сверяется полный отпечаток**
  `D38D7D1DA1349567ADED882D86F7D09EE734E623` (64-битного keyid недостаточно).
- **Таймауты curl** (`--connect-timeout 5 --max-time 20`) против зависаний в firewall-сетях.
- **Прогресс-бар** установки ядра по `APT::Status-Fd` (с гарантированным возвратом курсора).
- **conntrack-ёмкость масштабируется от RAM** (`max`/`buckets` в отдельном drop-in) —
  мелкая VPS под флудом не упирается в OOM ядра.
- Фиксы: точечная чистка только мёртвых suite (не сносит рабочий list → не замораживает
  обновления ядра); восстановлена деградация сборок v3→v2→v1; убран небезопасный
  фоллбэк psABI через `curl|awk` под root. Репо обновляется и для уже стоящего ядра.
- `XANMOD_PROBE=1` — проверка «репо+ключ+сборка резолвятся» без установки (для CI/ops).

### 🛡 Защита (`protect.sh`)
- **size-кап на `autoban`-сеты** (65536) — спуф-флуд чистого SYN больше не раздувает
  набор в памяти ядра.
- **IPv6 bogon anti-spoof** на WAN (осознанно без `fe80::/10`/multicast, чтобы не убить NDP/RA).
- **`na-fw-top-talkers`** — топ источников по сервисным портам (кандидаты в `WHITELIST=`,
  если нода за реверс-прокси/балансировщиком/CDN).

### 🩺 Диагностика (`diagnose.sh`)
- **CPU steal** (скрытый потолок VPS), **доля TCP-ретрансмитов** и **число живых
  BBR-сокетов** (реальность поверх sysctl), детект **взведённого сейфти-таймера**
  (иначе firewall молча самоудаляется).

### CI
- `.github/workflows/ci.yml`: `shellcheck` + smoke-матрица (Debian bookworm/trixie,
  Ubuntu 22.04/24.04) — `bash -n`, генерация nftables (`DRY_RUN`), `diagnose`,
  резолв XanMod (`XANMOD_PROBE`).

### Прочее
- `NA_REF` — пиннинг ветки/тега для `curl|bash` (supply-chain: компрометация `main`
  не утекает сразу на весь флот).

## v2.0 — 2026-06-06

Первый релиз **node-accelerator**. Заменяет `remnawave-node-toolkit` v1, исправляя
её баги и расширяя функциональность.

### ⚡ Оптимизатор (`optimize.sh`)
- **XanMod-ядро (BBRv3)** — авто-выбор сборки по psABI-уровню CPU, авто-skip на
  контейнерах (OpenVZ/LXC) и не-x86_64.
- **RPS/RFS/XPS** — раскидывает обработку пакетов по ядрам (критично на virtio-VPS).
- BBR + `fq`, буферы до 64 МБ, conntrack 2M, syncookies, anti-spoof `rp_filter=2`.
- nofile/nproc → 1M, swap, journald-cap, THP off, governor=performance, NIC tune.

### 🛡 Защита (`protect.sh`)
- **Исправлен баг порядка правил** v1: глобальный `syn accept` затенял весь
  port-allow-list, SSH-бан и portscan-детект. Теперь SYN-rate **per-IP**.
- **per-IP лимиты** (а не глобальные) — масштабируются по числу клиентов.
- **Полный IPv6-паритет** (в v1 v6-сканеры/брут не банились вообще).
- **Не `flush ruleset`** — своя таблица `inet na_filter`, сосуществует с
  CrowdSec-bouncer и Docker (v1 ломала Docker-сеть).
- AntiScan, flag-drop (XMAS/NULL/SYN+FIN/…), anti-spoof, SYN+UDP-flood, ssh-flood,
  `ct count` connlimit, rate-limit на логи.
- **CrowdSec + nftables firewall-bouncer** — поведенческий IPS + community-блоклист.

### 🩺 Диагностика (`diagnose.sh`)
- Read-only отчёт: ядро/BBR, sysctl, conntrack, NIC/RPS, firewall, CrowdSec, RTT.
