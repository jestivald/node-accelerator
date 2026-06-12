# Changelog

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
- **Пол `tcp_min_snd_mss=512`**: при `tcp_mtu_probing=1` ядро на лоссовой линии
  принимает серию RTO за PMTU-чёрную-дыру и ужимает send-MSS до дефолтного пола
  48Б (сегмент ~97% оверхед → throughput коллапсирует без восстановления). 512
  оставляет probing рабочим для настоящих чёрных дыр, но не убивает goodput.
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
