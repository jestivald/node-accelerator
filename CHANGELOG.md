# Changelog

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
