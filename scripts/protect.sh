#!/usr/bin/env bash
#
# protect.sh — 🛡 Защита ноды.
#   • nftables (своя таблица inet na_filter, БЕЗ flush ruleset — сосуществует с
#     CrowdSec-bouncer и Docker-NAT):
#       AntiScan (portscan→autoban), flag-drop (XMAS/NULL/SYN+FIN/SYN+RST/FIN+RST/…),
#       anti-spoofing (bogon на WAN), SYN-flood + UDP-flood (per-IP rate-limit),
#       connect-flood SSH (per-IP→бан), per-IP connlimit (ct count), ICMP rate-limit.
#   • CrowdSec + crowdsec-firewall-bouncer-nftables — поведенческий IPS и community-блоклист.
#   • Авто-whitelist IP, с которого ты сейчас по SSH + сейфти-таймер от самоблокировки.
#
# Откат: scripts/rollback.sh protect
#
# ENV (всё опционально):
#   SSH_PORT, TCP_PORTS=443,2087, UDP_PORTS=443,2087, NODE_PORT=2222
#   WHITELIST="1.2.3.4,5.6.7.0/24"     IP/CIDR панели/мониторинга (v4 и v6)
#   SYN_RATE=200  SYN_BURST=400        per-IP лимит новых TCP-конн./сек на сервисный порт
#   UDP_RATE=200  UDP_BURST=400        per-IP лимит UDP пакетов/сек
#   CONN_LIMIT=2048                    макс. одновременных конн. с одного IP (ct count)
#   SSH_RATE=6    SSH_BURST=5          per-IP новых SSH/мин до бана
#   SSH_BAN_TIME=24h  PORTSCAN_BAN_TIME=1h
#   ENABLE_PORTSCAN_BAN=1  ENABLE_CROWDSEC=1  ENABLE_SYNPROXY=0
#   CROWDSEC_ENROLL_KEY=...            enroll в CrowdSec Console (опц.)
#   SAFETY_DELAY=300  DRY_RUN=0  REMNAWAVE_NONINTERACTIVE=1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
detect_os
BACKUP="$(backup_dir)"

# Подхватываем сохранённый конфиг ноды (если есть): ре-ран без ENV не сбрасывает
# поднятые под эту ноду ручки на дефолты. ENV по-прежнему всё переопределяет.
load_conf "$CONF_DIR/protect.conf"

# ─── Параметры ───────────────────────────────────────────────────────────────
SSH_PORT="${SSH_PORT:-$(detect_ssh_port)}"
TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS:-443,2087}"
NODE_PORT="${NODE_PORT:-2222}"
WHITELIST="${WHITELIST:-}"
SYN_RATE="${SYN_RATE:-200}";  SYN_BURST="${SYN_BURST:-400}"
UDP_RATE="${UDP_RATE:-200}";  UDP_BURST="${UDP_BURST:-400}"
# CONN_LIMIT — потолок ОДНОВРЕМЕННЫХ конн. с одного IP. За CGNAT (мобильные операторы,
# частый кейс в RU/IR) один egress-IP агрегирует много абонентов → держим с большим
# запасом, чтобы не рубить целые операторские пулы. Реальный VLESS-юзер — десятки конн.
CONN_LIMIT="${CONN_LIMIT:-2048}"
ICMP_RATE="${ICMP_RATE:-10}"; ICMP_BURST="${ICMP_BURST:-20}"   # PER-IP (не глобально)
SSH_RATE="${SSH_RATE:-6}";    SSH_BURST="${SSH_BURST:-5}"
SSH_BAN_TIME="${SSH_BAN_TIME:-24h}"
PORTSCAN_BAN_TIME="${PORTSCAN_BAN_TIME:-1h}"
# Порог автобана за скан: банить IP только если он бьёт по закрытым портам БЫСТРЕЕ
# порога (реальный сканер). Одиночные шальные SYN из CGNAT-пула не банят весь оператор.
PORTSCAN_RATE="${PORTSCAN_RATE:-15}"; PORTSCAN_BURST="${PORTSCAN_BURST:-30}"  # /minute, per-IP
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-1}"
ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
ENABLE_SYNPROXY="${ENABLE_SYNPROXY:-0}"
SAFETY_DELAY="${SAFETY_DELAY:-300}"
DRY_RUN="${DRY_RUN:-0}"
WAN="$(default_iface || true)"

# ── v3.0: ban-once, защита node-port, блоклисты, fleet-sync, ctguard ──────────
# ban-once: первое нарушение → suspect (наблюдение, без drop), второе в окне →
# confirmed (drop). Режет ложные баны за CGNAT. 1=вкл (дефолт), 0=сразу банить.
ENABLE_BANONCE="${ENABLE_BANONCE:-1}"
SUSPECT_TIME="${SUSPECT_TIME:-30m}"        # окно наблюдения за «подозреваемым»
# node-agent порт: открыт миру (мягкий лимит) или только whitelist. 'auto' =
# whitelist-only, если оператор задал WHITELIST (значит, знает свой доверенный набор);
# если WHITELIST пуст — оставляем мягкий лимит, чтобы не отрезать неизвестную панель.
NODE_PORT_WHITELIST_ONLY="${NODE_PORT_WHITELIST_ONLY:-auto}"
# Статич-блоклисты (Spamhaus DROP + FireHOL L1 [+ Tor]) — opt-in, обновляются таймером.
ENABLE_BLOCKLISTS="${ENABLE_BLOCKLISTS:-0}"
BLOCK_TOR="${BLOCK_TOR:-0}"
BLOCKLIST_REFRESH="${BLOCKLIST_REFRESH:-12h}"
# Remnawave fleet auto-sync: ноды флота сами держат IP друг друга в whitelist.
# 'auto' = вкл при заданных REMNAWAVE_URL+TOKEN (или REMNAWAVE_NODES_URL); 1=форс; 0=выкл.
# REMNAWAVE_NODES_URL — альтернатива БЕЗ токена панели на ноде: статический JSON того же
# вида, что /api/nodes (панель публикует кроном, доступ ограничить basic-auth/allowlist),
# либо plain-text: адрес/hostname на строку, # — комментарий. Снимает blast-radius
# полноценного API-токена, лежащего на каждой ноде.
REMNAWAVE_URL="${REMNAWAVE_URL:-}"
REMNAWAVE_TOKEN="${REMNAWAVE_TOKEN:-}"
REMNAWAVE_NODES_URL="${REMNAWAVE_NODES_URL:-}"
FLEET_SYNC="${FLEET_SYNC:-auto}"
FLEET_SYNC_INTERVAL="${FLEET_SYNC_INTERVAL:-5min}"
# conntrack phantom-eviction (защита от distributed connect-and-hold) — opt-in,
# по умолчанию observe-режим (только лог, без эвикта), включать осознанно.
ENABLE_CTGUARD="${ENABLE_CTGUARD:-0}"
NA_CTG_ENFORCE="${NA_CTG_ENFORCE:-0}"
NA_CTG_PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"  # conntrack-порог «холдера» (выше CGNAT-churn)
NA_CTG_LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"       # ≤ столько живых сокетов = фантом
NA_CTG_COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"     # дамп conntrack только если ct ≥ ss×N
NA_CTG_BANTIME="${NA_CTG_BANTIME:-15m}"
NA_CTG_INTERVAL="${NA_CTG_INTERVAL:-20s}"

if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" && "$DRY_RUN" != "1" && "${CROWDSEC_PROBE:-0}" != "1" ]]; then
    title "Параметры защиты"
    read -rp "SSH порт                         [$SSH_PORT]: "  _v && SSH_PORT="${_v:-$SSH_PORT}"
    read -rp "TCP порты сервиса (через ,)       [$TCP_PORTS]: " _v && TCP_PORTS="${_v:-$TCP_PORTS}"
    read -rp "UDP порты сервиса (через ,)       [$UDP_PORTS]: " _v && UDP_PORTS="${_v:-$UDP_PORTS}"
    read -rp "Порт node-agent                  [$NODE_PORT]: " _v && NODE_PORT="${_v:-$NODE_PORT}"
    read -rp "Whitelist IP/CIDR (панель, твои)  [пусто]: "     _v && WHITELIST="${_v:-$WHITELIST}"
fi

# ─── Валидация ───────────────────────────────────────────────────────────────
_is_port()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }
validate_port_list() {
    local v="$1" name="$2" p
    [[ -z "$v" ]] && return 0
    [[ "$v" =~ ^[0-9,]+$ ]] || { err "$name: '$v' — только цифры и запятые"; return 1; }
    for p in ${v//,/ }; do _is_port "$p" || { err "$name: '$p' вне 1..65535"; return 1; }; done
}
_is_port "$SSH_PORT"  || { err "SSH_PORT '$SSH_PORT' невалиден"; exit 1; }
_is_port "$NODE_PORT" || { err "NODE_PORT '$NODE_PORT' невалиден"; exit 1; }
validate_port_list "$TCP_PORTS" TCP_PORTS || exit 1
validate_port_list "$UDP_PORTS" UDP_PORTS || exit 1

# Числовые/duration параметры тоже валидируем: они разворачиваются в nft-ruleset и
# (SAFETY_DELAY) в sh-таймер. Тулкит параметризуется неинтерактивно из панели/оркестратора,
# поэтому непровалидированный ENV здесь — не «root сам себе», а реальный вектор.
_is_uint()     { [[ "$1" =~ ^[0-9]+$ ]]; }
_is_duration() { [[ "$1" =~ ^[0-9]+(s|m|h|d)?$ ]]; }
# systemd-time (OnUnitActiveSec): один числовой терм с опц. словом-единицей. Уходит
# в .timer-юнит → валидируем, чтобы непровалидированный ENV не дописал директив.
_is_systime()  { [[ "$1" =~ ^[0-9]+(s|sec|m|min|h|hr|d|day)?$ ]]; }
for _k in SYN_RATE SYN_BURST UDP_RATE UDP_BURST CONN_LIMIT ICMP_RATE ICMP_BURST \
          SSH_RATE SSH_BURST PORTSCAN_RATE PORTSCAN_BURST SAFETY_DELAY \
          NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR NA_CTG_COARSE_MULT; do
    _is_uint "${!_k}" || { err "$_k='${!_k}' — ожидается целое число"; exit 1; }
done
for _k in SSH_BAN_TIME PORTSCAN_BAN_TIME SUSPECT_TIME NA_CTG_BANTIME; do
    _is_duration "${!_k}" || { err "$_k='${!_k}' — ожидается число с опц. суффиксом s|m|h|d"; exit 1; }
done
for _k in BLOCKLIST_REFRESH FLEET_SYNC_INTERVAL NA_CTG_INTERVAL; do
    _is_systime "${!_k}" || { err "$_k='${!_k}' — ожидается systemd-интервал (напр. 12h, 5min)"; exit 1; }
done
# enum-флаги 0/1 (+auto где уместно)
for _k in ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC ENABLE_SYNPROXY ENABLE_BANONCE \
          ENABLE_BLOCKLISTS BLOCK_TOR ENABLE_CTGUARD NA_CTG_ENFORCE; do
    [[ "${!_k}" =~ ^[01]$ ]] || { err "$_k='${!_k}' — ожидается 0 или 1"; exit 1; }
done
[[ "$NODE_PORT_WHITELIST_ONLY" =~ ^(auto|0|1)$ ]] || { err "NODE_PORT_WHITELIST_ONLY должно быть auto|0|1"; exit 1; }
[[ "$FLEET_SYNC" =~ ^(auto|0|1)$ ]] || { err "FLEET_SYNC должно быть auto|0|1"; exit 1; }
if [[ -n "$REMNAWAVE_URL" && ! "$REMNAWAVE_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_URL='$REMNAWAVE_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
if [[ -n "$REMNAWAVE_NODES_URL" && ! "$REMNAWAVE_NODES_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_NODES_URL='$REMNAWAVE_NODES_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
unset _k

# Резолв NODE_PORT_WHITELIST_ONLY=auto: whitelist-only только если оператор задал
# WHITELIST (знает доверенный набор). Пустой WHITELIST → мягкий лимит (не отрезаем панель).
if [[ "$NODE_PORT_WHITELIST_ONLY" == "auto" ]]; then
    [[ -n "$WHITELIST" ]] && NODE_PORT_WHITELIST_ONLY=1 || NODE_PORT_WHITELIST_ONLY=0
fi

# whitelist → v4/v6
WL4=""; WL6=""
add_wl() {
    local x
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then
            # строго hex+двоеточия (+опц. /prefix) — иначе значение уходит дословно в
            # nft-heredoc 'elements = { ... }' и может дописать произвольные правила
            [[ "$x" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] || { err "WHITELIST: '$x' не валидный IPv6/CIDR"; return 1; }
            WL6+="${WL6:+, }$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then WL4+="${WL4:+, }$x"
        else err "WHITELIST: '$x' не IPv4/IPv6/CIDR"; return 1; fi
    done
}
add_wl "$WHITELIST" || exit 1
ADMIN_IP="$(ssh_client_ip || true)"
if [[ -n "$ADMIN_IP" ]]; then
    add_wl "$ADMIN_IP" || true
    info "Авто-whitelist твоего SSH-IP: $ADMIN_IP (защита от самоблокировки)"
fi

# ─── Зависимости ─────────────────────────────────────────────────────────────
title "Зависимости"
apt_install nftables curl ca-certificates iproute2 gnupg
ok "ok"

# ─── CrowdSec: пиннингованный APT-репозиторий (supply-chain) ─────────────────
# Вместо curl|bash с install.crowdsec.net — их packagecloud-репо с проверкой ПОЛНОГО
# отпечатка ключа (64-битный keyid подделать дёшево). Suite нет для этой ОС (свежие
# релизы Ubuntu/Debian) → фоллбэк на noble/bookworm; совсем не поднялся → официальный
# установщик как last-resort (громко, warn).
CROWDSEC_FP="6A89E3C2303A901A889971D3376ED5326E93CD0C"
setup_crowdsec_repo() {
    local keyring=/etc/apt/keyrings/crowdsec-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/crowdsec.list
    local os="$OS_ID" codename fb
    codename="$(os_codename)"; [[ -n "$codename" ]] || codename=bookworm
    mkdir -p /etc/apt/keyrings
    if ! curl -fsSL --connect-timeout 5 --max-time 20 https://packagecloud.io/crowdsec/crowdsec/gpgkey \
            | gpg --yes --dearmor -o "$keyring" 2>/dev/null; then
        warn "ключ CrowdSec (packagecloud) недоступен"; rm -f "$keyring"; return 1
    fi
    if ! gpg --show-keys --with-colons "$keyring" 2>/dev/null \
            | awk -F: '/^fpr:/{print $10}' | grep -qx "$CROWDSEC_FP"; then
        warn "отпечаток ключа CrowdSec не совпал с $CROWDSEC_FP — отказываюсь использовать"
        rm -f "$keyring"; return 1
    fi
    chmod 0644 "$keyring"
    # ВАЖНО: обновляем ТОЛЬКО свой list. Глобальный `apt-get update` вернул бы rc≠0 из-за
    # ЛЮБОГО постороннего битого источника на боксе (протухший сторонний репо — типовой
    # съёмный VPS), и пиннинг ложно самоотключился бы на живом packagecloud. Скоуп через
    # Dir::Etc даёт вердикт именно о нашем репо.
    local -a UPDSC=(-o "Dir::Etc::sourcelist=$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)
    echo "deb [signed-by=$keyring] https://packagecloud.io/crowdsec/crowdsec/$os $codename main" > "$list"
    if ! apt-get update -qq "${UPDSC[@]}" 2>/dev/null; then
        fb=bookworm; [[ "$os" == "ubuntu" ]] && fb=noble
        if [[ "$codename" != "$fb" ]]; then
            warn "suite '$codename' в репо CrowdSec не поднялся — пробую '$fb'"
            echo "deb [signed-by=$keyring] https://packagecloud.io/crowdsec/crowdsec/$os $fb main" > "$list"
            if ! apt-get update -qq "${UPDSC[@]}" 2>/dev/null; then
                rm -f "$list"; apt-get update -qq 2>/dev/null || true; return 1
            fi
        else
            rm -f "$list"; apt-get update -qq 2>/dev/null || true; return 1
        fi
    fi
    # общий кэш подтянуть (наш list валиден); чужие битые источники тут не фатальны
    apt-get update -qq 2>/dev/null || true
    return 0
}

# PROBE: репозиторий+ключ+пакеты CrowdSec резолвятся на этой ОС, БЕЗ установки.
# Для CI-матрицы и ops-проверки совместимости (аналог XANMOD_PROBE в optimize.sh).
if [[ "${CROWDSEC_PROBE:-0}" == "1" ]]; then
    setup_crowdsec_repo || { err "CROWDSEC_PROBE: репозиторий не поднялся"; exit 1; }
    apt-cache show crowdsec >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: пакет crowdsec резолвится" \
        || { err "CROWDSEC_PROBE: пакет crowdsec не резолвится"; exit 1; }
    apt-cache show crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: bouncer резолвится" \
        || warn "CROWDSEC_PROBE: crowdsec-firewall-bouncer-nftables не резолвится в этом suite"
    exit 0
fi

# ─── Сейфти-таймер: если потеряем SSH — снести нашу таблицу через N сек ───────
arm_safety() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    title "Подстраховка от блокировки"
    warn "Если SSH отвалится — таблица na_filter удалится через ${SAFETY_DELAY}s (доступ вернётся)."
    if command -v systemd-run >/dev/null 2>&1; then
        systemctl stop na-fw-safety.timer 2>/dev/null || true
        systemd-run --quiet --unit=na-fw-safety --on-active="${SAFETY_DELAY}s" \
            /usr/sbin/nft delete table inet na_filter >/dev/null 2>&1 \
            && { ok "safety: systemd-таймер na-fw-safety на ${SAFETY_DELAY}s"; return 0; }
    fi
    # fallback (нет systemd-run): nohup-таймер. Стейт в $STATE_DIR (root-only), НЕ в общей
    # /tmp — убирает симлинк/TOCTOU через предсказуемый путь. SAFETY_DELAY и pid передаём
    # позиционными аргументами в sh -c (без интерполяции в строку оболочки).
    mkdir -p "$STATE_DIR"
    local pidf="$STATE_DIR/na-fw-safety.pid" logf="$STATE_DIR/na-fw-safety.log"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; }
    nohup sh -c 'sleep "$1"; /usr/sbin/nft delete table inet na_filter 2>/dev/null; rm -f "$2"' \
        _ "$SAFETY_DELAY" "$pidf" >"$logf" 2>&1 &
    echo $! > "$pidf"
    ok "safety: nohup pid $(cat "$pidf")"
}
disarm_safety() {
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    local pidf="$STATE_DIR/na-fw-safety.pid"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; rm -f "$pidf"; }
    rm -f /tmp/na-fw-safety.pid /tmp/na-fw-safety.log 2>/dev/null || true   # legacy-стейт старых версий
}

# ─── Сборка per-port правил ──────────────────────────────────────────────────
TCP_RULES=""
for p in ${TCP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    TCP_RULES+="
        # порт ${p}: per-IP лимит одновременных коннектов (анти-exhaustion)
        tcp dport ${p} ct state new meter cc4_${p} { ip saddr ct count over ${CONN_LIMIT} } drop
        tcp dport ${p} ct state new meter cc6_${p} { ip6 saddr ct count over ${CONN_LIMIT} } drop
        # порт ${p}: per-IP SYN-rate (масштабируется по числу клиентов, не глобальный потолок)
        tcp dport ${p} ct state new meter syn4_${p} { ip saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new meter syn6_${p} { ip6 saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new limit rate 5/second log prefix \"[na synflood] \" level info
        tcp dport ${p} ct state new drop"
done

UDP_RULES=""
for p in ${UDP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    UDP_RULES+="
        # порт ${p}/udp: per-IP rate (QUIC/Hysteria2/TUIC) — анти-UDP-flood
        udp dport ${p} meter udp4_${p} { ip saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        udp dport ${p} meter udp6_${p} { ip6 saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        udp dport ${p} drop"
done

# anti-spoofing (только на WAN-интерфейсе)
ANTISPOOF=""
if [[ -n "$WAN" ]]; then
    ANTISPOOF="        # anti-spoofing: приватные/bogon источники на WAN = спуф
        udp sport 67 udp dport 68 accept
        iifname \"${WAN}\" ip saddr @bogon_v4 drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 drop"
fi

# node-agent порт: whitelist-only (drop мир) или мягкий per-IP лимит для неизвестных.
if [[ "$NODE_PORT_WHITELIST_ONLY" == "1" ]]; then
    NODE_RULES="        # node-agent: ТОЛЬКО whitelist (принят выше) — остальным drop (контрол-порт не светим)
        tcp dport ${NODE_PORT} ct state new drop"
    info "node-agent порт ${NODE_PORT}: whitelist-only (WHITELIST задан)"
else
    NODE_RULES="        # node-agent: whitelist (выше) + мягкий per-IP лимит для неизвестных
        tcp dport ${NODE_PORT} ct state new meter na4 { ip saddr limit rate 30/second burst 60 packets } accept
        tcp dport ${NODE_PORT} ct state new meter na6 { ip6 saddr limit rate 30/second burst 60 packets } accept
        tcp dport ${NODE_PORT} ct state new drop"
fi

# portscan → autoban (включается флагом). При ENABLE_BANONCE=1 — двухступенчато:
# 1-й быстрый скан → suspect (наблюдение, БЕЗ полного бана: скан-пакеты и так дропает
# финальный catch-all, но легит-трафик IP не режется), повторный в окне SUSPECT_TIME →
# confirmed-бан. Снимает ложные баны целых CGNAT-операторов из-за одного шального скана.
PORTSCAN=""
if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
    _ps_log4="meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new limit rate 5/second log prefix \"[na portscan] \" level info"
    if [[ "$ENABLE_BANONCE" == "1" ]]; then
        PORTSCAN="        # ANTI-SCAN (ban-once): 1-й быстрый скан → suspect, 2-й в окне ${SUSPECT_TIME} → бан.
        $_ps_log4
        # уже suspect и снова бьёт быстрее порога → confirmed-бан
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new ip saddr @suspect_v4 meter psc4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} } drop
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new ip6 saddr @suspect_v6 meter psc6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} } drop
        # ещё не suspect и бьёт быстрее порога → пометить suspect (без бана; скан дропнет catch-all)
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} }
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} }"
    else
        PORTSCAN="        # ANTI-SCAN: бьёт по закрытым портам быстрее ${PORTSCAN_RATE}/min → бан ${PORTSCAN_BAN_TIME}.
        $_ps_log4
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} } drop
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} } drop"
    fi
fi

# ─── SYNPROXY (опционально, done-right) ──────────────────────────────────────
# ⚠️ На VPN-relay (профиль connect-and-hold / PPS-флуд) SYNPROXY обычно ИЗБЫТОЧЕН:
# его единственный реальный плюс — анти-спуф SYN — уже закрыт tcp_syncookies=1 +
# per-IP ct-лимитами (CONN_LIMIT/SYN_RATE), а издержки (обязательный be_liberal=1,
# per-packet overhead, поломка TFO на защищённых портах) не оправданы. Против самого
# распространённого вектора (connect-and-hold / реальный PPS) он не помогает вовсе.
# Поэтому default OFF; включать ТОЛЬКО под подтверждённый спуфнутый SYN-флуд. Оставлен
# opt-in для не-relay сценариев (голый L4-фронт без syncookies-достаточности).
#
# notrack ТОЛЬКО для трафика к самому хосту (fib daddr type local): иначе правило в
# prerouting цепляет conntrack/NAT ТРАНЗИТА (Docker-контейнер панели → удалённая нода)
# и ломает его. Требует ядро ≥5.14 + модуль nf_synproxy. Запрошен, но недоступен →
# fail-loud (маркер degraded + warn), БЕЗ тихой деградации; synproxy-правила не ставятся.
SYNPROXY_PRE=""; SYNPROXY_IN=""; SP_MODPROBE=""; SYNPROXY_OK=0
rm -f "$STATE_DIR/.synproxy-degraded" 2>/dev/null || true
if [[ "$ENABLE_SYNPROXY" == "1" ]]; then
    _kmaj="$(uname -r | cut -d. -f1)"; _kmin="$(uname -r | cut -d. -f2)"
    [[ "$_kmaj" =~ ^[0-9]+$ ]] || _kmaj=0; [[ "$_kmin" =~ ^[0-9]+$ ]] || _kmin=0
    if { [[ "$_kmaj" -gt 5 ]] || { [[ "$_kmaj" -eq 5 ]] && [[ "$_kmin" -ge 14 ]]; }; } && modprobe nf_synproxy 2>/dev/null; then
        SYNPROXY_OK=1
        SP_SET="$TCP_PORTS"
        # mss из MTU аплинка (−40Б IPv4+TCP), wscale 7 (дефолт Linux); клампим в 536..1460.
        _mtu="$(cat /sys/class/net/"$WAN"/mtu 2>/dev/null || echo 1500)"; [[ "$_mtu" =~ ^[0-9]+$ ]] || _mtu=1500
        SP_MSS=$(( _mtu - 40 )); { [[ "$SP_MSS" -gt 1460 ]] || [[ "$SP_MSS" -lt 536 ]]; } && SP_MSS=1460
        SP_MODPROBE="ExecStartPre=/bin/sh -c 'modprobe nf_synproxy 2>/dev/null || true'"
        SYNPROXY_PRE="    chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        fib daddr type local tcp dport { ${SP_SET} } tcp flags syn notrack
    }"
        SYNPROXY_IN="        tcp dport { ${SP_SET} } ct state invalid,untracked synproxy mss ${SP_MSS} wscale 7 timestamp sack-perm"
        ok "SYNPROXY: ядро $(uname -r) ок, mss ${SP_MSS} wscale 7 (notrack только host-local)"
    else
        warn "SYNPROXY запрошен, но недоступен (нужно ядро ≥5.14 + модуль nf_synproxy). Защита БЕЗ synproxy."
        mkdir -p "$STATE_DIR"; echo "kernel=$(uname -r) reason=no_nf_synproxy at=$(date -Is)" > "$STATE_DIR/.synproxy-degraded"
    fi
fi

# ── Условные сеты/правила v3.0 (ban-once / blocklists / fleet) ────────────────
# suspect-сеты для ban-once (timeout + size-cap как у autoban).
SUSPECT_SETS=""
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    SUSPECT_SETS="    set suspect_v4 { type ipv4_addr; flags timeout; size 65536; }
    set suspect_v6 { type ipv6_addr; flags timeout; size 65536; }"
fi

# blocklist-сеты (наполняет na-blocklist-update таймером) + drop-правило.
BLOCKLIST_SETS=""; BLOCKLIST_DROP=""
if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
    BLOCKLIST_SETS="    set blocklist_v4 { type ipv4_addr; flags interval; auto-merge; }
    set blocklist_v6 { type ipv6_addr; flags interval; auto-merge; }"
    BLOCKLIST_DROP="        # статич-блоклисты (Spamhaus DROP / FireHOL L1 [/ Tor]) — обновляет na-blocklist-update
        ip  saddr @blocklist_v4 drop
        ip6 saddr @blocklist_v6 drop"
fi

# fleet-сеты (наполняет na-fleet-sync с панели Remnawave) + accept сразу после whitelist.
FLEET_ON=0
case "$FLEET_SYNC" in
    1) FLEET_ON=1;;
    auto) { [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]] || [[ -n "$REMNAWAVE_NODES_URL" ]]; } && FLEET_ON=1 \
          || { [[ -f "$CONF_DIR/fleet.env" ]] && FLEET_ON=1; };;
esac
FLEET_SETS=""; FLEET_ACCEPT=""
if [[ "$FLEET_ON" == "1" ]]; then
    FLEET_SETS="    set na_fleet_v4 { type ipv4_addr; flags interval; auto-merge; }
    set na_fleet_v6 { type ipv6_addr; flags interval; auto-merge; }"
    FLEET_ACCEPT="        # ноды флота (авто-синк с панели) — свои серверы, обходят все лимиты
        ip  saddr @na_fleet_v4 accept
        ip6 saddr @na_fleet_v6 accept"
fi

# SSH connect-flood: с ban-once (suspect→confirmed) или прямой бан.
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    SSH_RULES="        # SSH connect-flood (ban-once): перебор → 1-й раз suspect+drop, 2-й в окне → бан ${SSH_BAN_TIME}
        tcp dport ${SSH_PORT} ct state new meter ssh4 { ip saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new meter ssh6 { ip6 saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        tcp dport ${SSH_PORT} ct state new ip saddr @suspect_v4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport ${SSH_PORT} ct state new ip6 saddr @suspect_v6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv4 add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} } drop
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv6 add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} } drop"
else
    SSH_RULES="        # SSH connect-flood: >${SSH_RATE}/мин новых с одного IP → бан ${SSH_BAN_TIME}
        tcp dport ${SSH_PORT} ct state new meter ssh4 { ip saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new meter ssh6 { ip6 saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } drop"
fi

WL4_LINE=""; [[ -n "$WL4" ]] && WL4_LINE="elements = { $WL4 }"
WL6_LINE=""; [[ -n "$WL6" ]] && WL6_LINE="elements = { $WL6 }"

# ─── Генерация nft-файла ─────────────────────────────────────────────────────
NFT_FILE="$CONF_DIR/na_filter.nft"
[[ "$DRY_RUN" == "1" ]] && NFT_FILE="$(mktemp /tmp/na_filter.XXXXXX.nft)"
mkdir -p "$CONF_DIR"
title "Генерация nftables → $NFT_FILE"

cat > "$NFT_FILE" <<NFT
#!/usr/sbin/nft -f
# node-accelerator / protect.sh @ $(date -Is)
# Управляем ТОЛЬКО своей таблицей — НЕ flush ruleset (живём рядом с CrowdSec/Docker).

table inet na_filter {}
delete table inet na_filter

table inet na_filter {

    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; $WL4_LINE }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; $WL6_LINE }

    # size — потолок записей: portscan-бан ловит чистый SYN (тривиально спуфится),
    # без лимита спуф-флуд раздул бы set в памяти ядра. При переполнении новые баны
    # просто не добавляются (старые живут по timeout).
    set autoban_v4 { type ipv4_addr; flags timeout; size 65536; }
    set autoban_v6 { type ipv6_addr; flags timeout; size 65536; }
$SUSPECT_SETS
$BLOCKLIST_SETS
$FLEET_SETS

    # bogon/martian источники (RFC1918, CGNAT, loopback, link-local, TEST-NET, multicast)
    set bogon_v4 {
        type ipv4_addr; flags interval; auto-merge
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
            192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
            224.0.0.0/3
        }
    }

    # bogon-источники IPv6, которые НЕ могут легитимно прийти как saddr на WAN.
    # СОЗНАТЕЛЬНО без fe80::/10 (NDP/RA — link-local source) и без ff00::/8 (multicast):
    # их дроп убил бы соседство/автоконфиг IPv6. Только однозначно поддельные диапазоны.
    set bogon_v6 {
        type ipv6_addr; flags interval; auto-merge
        elements = {
            ::1/128, ::/128, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7
        }
    }

    # битые TCP-флаги / скан-пакеты → лог(rl) + drop
    chain scan_drop {
        limit rate 5/second log prefix "[na badflags] " level info
        counter drop
    }

$SYNPROXY_PRE

    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # whitelist — всегда сверху (в т.ч. твой текущий SSH-IP)
        ip  saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept
$FLEET_ACCEPT

        # уже забаненные
        ip  saddr @autoban_v4 drop
        ip6 saddr @autoban_v6 drop
$BLOCKLIST_DROP

$ANTISPOOF

        # flag-drop: NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST и прочие невалидные комбинации
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0                       jump scan_drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) jump scan_drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg)                         jump scan_drop
        tcp flags & (syn|fin) == (syn|fin)                                 jump scan_drop
        tcp flags & (syn|rst) == (syn|rst)                                 jump scan_drop
        tcp flags & (fin|rst) == (fin|rst)                                 jump scan_drop
        tcp flags & (fin|ack) == fin                                       jump scan_drop
        tcp flags & (psh|ack) == psh                                       jump scan_drop
        tcp flags & (ack|urg) == urg                                       jump scan_drop

        # ICMP: пинг работает, флуд режется. Лимит PER-IP (meter), НЕ глобальный — иначе
        # нода с сотнями пингующих клиентов упирается в общий потолок и пинг «пропадает».
        ip protocol icmp icmp type echo-request meter icmp4 { ip saddr limit rate ${ICMP_RATE}/second burst ${ICMP_BURST} packets } accept
        ip protocol icmp icmp type echo-request drop
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type echo-request meter icmp6 { ip6 saddr limit rate ${ICMP_RATE}/second burst ${ICMP_BURST} packets } accept
        icmpv6 type echo-request drop
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, time-exceeded, parameter-problem, destination-unreachable, mld-listener-query, mld-listener-report, mld-listener-done } accept

$SYNPROXY_IN

$SSH_RULES

        # сервисные TCP-порты (per-IP лимиты)
$TCP_RULES

        # сервисные UDP-порты (per-IP лимиты)
$UDP_RULES

$NODE_RULES

$PORTSCAN

        counter drop
    }

    chain forward { type filter hook forward priority filter; policy accept; }
    chain output  { type filter hook output  priority filter; policy accept; }
}
NFT

# ─── Проверка синтаксиса ДО применения ───────────────────────────────────────
if ! nft -c -f "$NFT_FILE"; then
    err "Сгенерированный ruleset не прошёл nft -c. Файл: $NFT_FILE (ничего не применено)."
    exit 1
fi
ok "nft -c: синтаксис валиден"

if [[ "$DRY_RUN" == "1" ]]; then
    ok "DRY-RUN: файл сгенерирован и проверен. Применение пропущено."
    info "Посмотреть: cat $NFT_FILE"
    exit 0
fi

# ─── Применяем (с сейфти-таймером) ───────────────────────────────────────────
arm_safety
nft -f "$NFT_FILE"
ok "nftables na_filter применён"

# boot-persist через свой сервис (не трогаем /etc/nftables.conf и чужие таблицы)
cat > /etc/systemd/system/na-firewall.service <<EOF
[Unit]
Description=node-accelerator nftables (na_filter)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
$SP_MODPROBE
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecReload=/usr/sbin/nft -f $NFT_FILE

[Install]
WantedBy=multi-user.target
EOF
# nf_synproxy грузим на boot (на стоковых ядрах модульный; на XanMod встроен — no-op).
if [[ "$SYNPROXY_OK" == "1" ]]; then
    echo "nf_synproxy" > /etc/modules-load.d/na-synproxy.conf
else
    rm -f /etc/modules-load.d/na-synproxy.conf 2>/dev/null || true
fi
systemctl daemon-reload
systemctl enable na-firewall.service >/dev/null 2>&1 || true
systemctl enable nftables >/dev/null 2>&1 || true
ok "na-firewall.service включён (правила переживут reboot)"

# ─── CrowdSec + firewall-bouncer ─────────────────────────────────────────────
if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    title "CrowdSec + nftables firewall-bouncer"
    if ! command -v cscli >/dev/null 2>&1; then
        info "Подключаю APT-репозиторий CrowdSec (пиннингованный ключ $CROWDSEC_FP)…"
        if setup_crowdsec_repo; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        else
            # last-resort: официальный установщик. -fsSL (а не -s): при HTTP-ошибке/
            # редиректе curl падает, а не отдаёт HTML в bash.
            warn "пиннингованный репо не поднялся — fallback на официальный установщик (curl|bash)"
            curl -fsSL https://install.crowdsec.net | bash >/dev/null 2>&1 || warn "install.crowdsec.net недоступен"
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        fi
    fi
    if command -v cscli >/dev/null 2>&1; then
        systemctl enable --now crowdsec >/dev/null 2>&1 || true
        sleep 2
        cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 || true

        # whitelist админа/панели в самом CrowdSec — чтобы IPS их не банил.
        # Ключи ip:/cidr: пишем ТОЛЬКО при наличии записей (пустые ключи валят парсер).
        mkdir -p /etc/crowdsec/parsers/s02-enrich
        IP_ITEMS=""; CIDR_ITEMS=""
        for x in ${WHITELIST//,/ } ${ADMIN_IP:-}; do
            [[ -z "$x" ]] && continue
            if [[ "$x" == */* ]]; then CIDR_ITEMS+="    - \"$x\""$'\n'; else IP_ITEMS+="    - \"$x\""$'\n'; fi
        done
        if [[ -n "$IP_ITEMS$CIDR_ITEMS" ]]; then
            {
                echo "name: node-accelerator/whitelist"
                echo "description: never ban admin/panel"
                echo "whitelist:"
                echo "  reason: node-accelerator trusted"
                [[ -n "$IP_ITEMS"   ]] && { echo "  ip:";   printf "%s" "$IP_ITEMS"; }
                [[ -n "$CIDR_ITEMS" ]] && { echo "  cidr:"; printf "%s" "$CIDR_ITEMS"; }
            } > /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        else
            rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        fi

        # источник логов sshd через journald (на системах без /var/log/auth.log)
        mkdir -p /etc/crowdsec/acquis.d
        cat > /etc/crowdsec/acquis.d/na-sshd.yaml <<'ACQ'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
ACQ
        systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1 || true

        # firewall-bouncer (nftables-режим): своя таблица crowdsec/crowdsec6, priority -10
        if ! dpkg -s crowdsec-firewall-bouncer-nftables >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
                || warn "bouncer не установился"
        fi
        systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true

        # опциональный enroll в Console
        if [[ -n "${CROWDSEC_ENROLL_KEY:-}" ]]; then
            cscli console enroll "$CROWDSEC_ENROLL_KEY" >/dev/null 2>&1 \
                && { systemctl reload crowdsec >/dev/null 2>&1 || true; ok "enroll в CrowdSec Console отправлен"; } \
                || warn "enroll не прошёл (проверь ключ)"
        fi

        if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
            ok "CrowdSec + bouncer активны (community-блоклист + поведенческий бан)"
        else
            warn "CrowdSec/bouncer установлены, но сервис не active — проверь: cscli metrics"
        fi
    fi
else
    info "ENABLE_CROWDSEC=0 — CrowdSec пропущен"
fi

# ═══ v3.0 МОДУЛИ: fleet-sync · blocklists · ctguard ═══════════════════════════
# Зависимости только под включённые модули (jq — fleet/blocklists, conntrack — ctguard).
_dep_list=()
[[ "$FLEET_ON" == "1" || "$ENABLE_BLOCKLISTS" == "1" ]] && _dep_list+=(jq)
[[ "$ENABLE_CTGUARD" == "1" ]] && _dep_list+=(conntrack)
if [[ "${#_dep_list[@]}" -gt 0 ]]; then
    apt_install "${_dep_list[@]}" || warn "не доустановил зависимости: ${_dep_list[*]}"
fi

# ── Fleet auto-sync: ноды флота из Remnawave-панели → nft-сет na_fleet_* ──────
if [[ "$FLEET_ON" == "1" ]]; then
    title "Fleet auto-sync (ноды флота → whitelist)"
    if [[ -n "$REMNAWAVE_NODES_URL" ]] || [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]]; then
        umask 077; mkdir -p "$CONF_DIR"
        {
            [[ -z "$REMNAWAVE_URL"       ]] || printf 'REMNAWAVE_URL=%s\n' "$REMNAWAVE_URL"
            [[ -z "$REMNAWAVE_TOKEN"     ]] || printf 'REMNAWAVE_TOKEN=%s\n' "$REMNAWAVE_TOKEN"
            [[ -z "$REMNAWAVE_NODES_URL" ]] || printf 'REMNAWAVE_NODES_URL=%s\n' "$REMNAWAVE_NODES_URL"
        } > "$CONF_DIR/fleet.env"
        chmod 0600 "$CONF_DIR/fleet.env"; chown root:root "$CONF_DIR/fleet.env" 2>/dev/null || true
        if [[ -n "$REMNAWAVE_NODES_URL" ]]; then
            ok "источник нод сохранён в $CONF_DIR/fleet.env (NODES_URL — без API-токена на ноде)"
        else
            ok "токен панели сохранён в $CONF_DIR/fleet.env (root:root 0600, НЕ в protect.conf)"
        fi
    elif [[ -f "$CONF_DIR/fleet.env" ]]; then
        info "использую сохранённый $CONF_DIR/fleet.env"
    fi
    cat > /usr/local/sbin/na-fleet-sync <<'FSYNC'
#!/usr/bin/env bash
# na-fleet-sync — держит адреса нод флота в nft-сете na_fleet_v4/v6 (accept сразу
# после whitelist). Источник (из /etc/node-accelerator/fleet.env):
#   1) REMNAWAVE_NODES_URL — статический список БЕЗ токена панели на ноде: JSON того же
#      вида, что /api/nodes, ИЛИ plain-text «адрес на строку» (# — комментарий).
#   2) REMNAWAVE_URL + REMNAWAVE_TOKEN — GET /api/nodes по Bearer. Токен уходит ТОЛЬКО
#      на заданный оператором URL.
# Fail-safe: источник недоступен / кривой ответ / 0 валидных IP → текущий whitelist нод
# НЕ трогаем (last-known-good). Применение отдельной nft-транзакцией: битые данные не
# ломают na_filter. Успех отмечается в /var/lib/node-accelerator/fleet-sync.last —
# na-diagnose показывает возраст последнего синка (протухший токен виден, а не молчит).
set -u
TAG=na-fleet-sync
ENVF=/etc/node-accelerator/fleet.env
STAMP=/var/lib/node-accelerator/fleet-sync.last
[ -r "$ENVF" ] || { logger -t "$TAG" "нет $ENVF — выкл"; exit 0; }
# shellcheck disable=SC1090
. "$ENVF"
URL="${REMNAWAVE_URL:-}"; TOKEN="${REMNAWAVE_TOKEN:-}"; NURL="${REMNAWAVE_NODES_URL:-}"
{ [ -n "$NURL" ] || { [ -n "$URL" ] && [ -n "$TOKEN" ]; }; } || { logger -t "$TAG" "источник не задан — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет na_fleet нет (protect без fleet) — выкл"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
if [ -n "$NURL" ]; then
    SRC="$NURL"
    HTTP="$(curl -fsSL --max-redirs 3 --max-time 15 -o "$TMP/r" -w '%{http_code}' "$NURL" 2>/dev/null || true)"
else
    command -v jq >/dev/null 2>&1 || { logger -t "$TAG" "нет jq (нужен для /api/nodes)"; exit 1; }
    URL="${URL%/}"; SRC="$URL/api/nodes"
    HTTP="$(curl -fsS --max-time 15 -o "$TMP/r" -w '%{http_code}' \
            -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" \
            "$SRC" 2>/dev/null || true)"
fi
[ "$HTTP" = "200" ] && [ -s "$TMP/r" ] || { logger -t "$TAG" "источник недоступен (HTTP=$HTTP) — last-known-good"; exit 0; }
: > "$TMP/addr"
if command -v jq >/dev/null 2>&1; then
    jq -r '.. | objects | .address? // empty' "$TMP/r" 2>/dev/null | awk 'NF' >> "$TMP/addr" || true
fi
if [ ! -s "$TMP/addr" ] && [ -n "$NURL" ]; then
    # plain-text режим NODES_URL: адрес/hostname на строку (валидация/резолв ниже).
    # s/\r$//: CRLF-файлы (Windows/панель/CDN) иначе оставляют \r в токене → 0 валидных
    # адресов навсегда. head -n 200: кэп на случай, если по URL прилетела HTML-страница
    # логина — не делать сотни getent-резолвов мусора каждый тик.
    sed -E 's/\r$//; s/#.*$//' "$TMP/r" | awk 'NF{print $1}' | head -n 200 >> "$TMP/addr"
fi
sort -u -o "$TMP/addr" "$TMP/addr"
[ -s "$TMP/addr" ] || { logger -t "$TAG" "в ответе нет адресов — last-known-good"; exit 0; }
: > "$TMP/v4"; : > "$TMP/v6"
while IFS= read -r a; do
    [ -n "$a" ] || continue
    if printf '%s' "$a" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$a" >> "$TMP/v4"; continue; fi
    if printf '%s' "$a" | grep -qE '^[0-9a-fA-F:]+$' && printf '%s' "$a" | grep -q ':'; then echo "$a" >> "$TMP/v6"; continue; fi
    getent ahostsv4 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v4"
    getent ahostsv6 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v6"
done < "$TMP/addr"
V4="$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMP/v4" 2>/dev/null | sort -u | paste -sd, -)"
V6="$(grep -E '^[0-9a-fA-F:]+$' "$TMP/v6" 2>/dev/null | grep ':' | sort -u | paste -sd, -)"
[ -n "$V4" ] || [ -n "$V6" ] || { logger -t "$TAG" "0 валидных IP — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter na_fleet_v4"
    [ -n "$V4" ] && echo "add element inet na_filter na_fleet_v4 { $V4 }"
    echo "flush set inet na_filter na_fleet_v6"
    [ -n "$V6" ] && echo "add element inet na_filter na_fleet_v6 { $V6 }"
} > "$TMP/upd.nft"
n4=$(printf '%s' "$V4" | tr ',' '\n' | grep -c . || true)
n6=$(printf '%s' "$V6" | tr ',' '\n' | grep -c . || true)
if nft -f "$TMP/upd.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > "$STAMP"
    logger -t "$TAG" "whitelist нод обновлён: ${n4} v4 + ${n6} v6 (из $SRC)"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good сохранён"
fi
FSYNC
    chmod +x /usr/local/sbin/na-fleet-sync
    cat > /etc/systemd/system/na-fleet-sync.service <<'EOF'
[Unit]
Description=node-accelerator fleet whitelist sync (Remnawave /api/nodes)
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-fleet-sync
EOF
    cat > /etc/systemd/system/na-fleet-sync.timer <<EOF
[Unit]
Description=node-accelerator fleet sync timer
[Timer]
OnBootSec=60s
OnUnitActiveSec=$FLEET_SYNC_INTERVAL
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-fleet-sync.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-fleet-sync >/dev/null 2>&1 || true
    ok "fleet-sync включён (интервал $FLEET_SYNC_INTERVAL). Лог: journalctl -t na-fleet-sync"
fi

# ── Статич-блоклисты: Spamhaus DROP + FireHOL L1 [+ Tor] → nft-сет blocklist_* ─
if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
    title "Статич-блоклисты (Spamhaus DROP / FireHOL L1$([[ "$BLOCK_TOR" == "1" ]] && echo ' / Tor'))"
    cat > /usr/local/sbin/na-blocklist-update <<'BLUP'
#!/usr/bin/env bash
# na-blocklist-update — обновляет nft-сеты blocklist_v4/v6 из публичных threat-фидов.
# Источники: Spamhaus DROP (json v4+v6), FireHOL Level 1 (v4), опц. Tor exit-list.
# Плюс /etc/node-accelerator/custom-blocklist.txt (локальные дополнения оператора).
# Bogon/private-фильтр, валидация, отдельная nft-транзакция (битый фид не ломает
# na_filter), last-known-good при недоступности фидов.
set -u
TAG=na-blocklist
BLOCK_TOR_FLAG="${1:-0}"
CUSTOM=/etc/node-accelerator/custom-blocklist.txt
nft list set inet na_filter blocklist_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет blocklist нет — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null; }
: > "$TMP/v4.raw"; : > "$TMP/v6.raw"
# Spamhaus DROP (json). jq может не быть — тогда фид пропускается.
if command -v jq >/dev/null 2>&1; then
    fetch https://www.spamhaus.org/drop/drop_v4.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v4.raw"
    fetch https://www.spamhaus.org/drop/drop_v6.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v6.raw"
fi
# FireHOL Level 1 (v4, high-confidence)
fetch https://iplists.firehol.org/files/firehol_level1.netset | grep -vE '^#' >> "$TMP/v4.raw"
# Tor exit nodes (опц.)
[ "$BLOCK_TOR_FLAG" = "1" ] && fetch https://check.torproject.org/torbulkexitlist >> "$TMP/v4.raw"
# локальные дополнения оператора (v4 и v6 вперемешку)
[ -r "$CUSTOM" ] && grep -vE '^\s*#|^\s*$' "$CUSTOM" >> "$TMP/v4.raw" && grep ':' "$CUSTOM" 2>/dev/null >> "$TMP/v6.raw"
# v4: только валидные IP/CIDR, без приватных/CGNAT/loopback/0.0.0.0
grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP/v4.raw" 2>/dev/null \
  | grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' \
  | sort -u > "$TMP/v4.clean"
# v6: из jq-чистых .cidr (+ кастомные), базовая sanity
grep -hE '^[0-9a-fA-F:/]+$' "$TMP/v6.raw" 2>/dev/null | grep ':' | sort -u > "$TMP/v6.clean"
N4="$(grep -c . "$TMP/v4.clean" 2>/dev/null || echo 0)"
N6="$(grep -c . "$TMP/v6.clean" 2>/dev/null || echo 0)"
[ "$N4" -gt 0 ] || { logger -t "$TAG" "0 v4-записей (фиды недоступны?) — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter blocklist_v4"
    echo "add element inet na_filter blocklist_v4 { $(paste -sd, "$TMP/v4.clean") }"
    if [ "$N6" -gt 0 ]; then
        echo "flush set inet na_filter blocklist_v6"
        echo "add element inet na_filter blocklist_v6 { $(paste -sd, "$TMP/v6.clean") }"
    fi
} > "$TMP/bl.nft"
if nft -f "$TMP/bl.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > /var/lib/node-accelerator/blocklist.last
    logger -t "$TAG" "blocklist обновлён: ${N4} v4 + ${N6} v6"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good"
fi
BLUP
    chmod +x /usr/local/sbin/na-blocklist-update
    cat > /etc/systemd/system/na-blocklist.service <<EOF
[Unit]
Description=node-accelerator threat blocklist update
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-blocklist-update $BLOCK_TOR
EOF
    cat > /etc/systemd/system/na-blocklist.timer <<EOF
[Unit]
Description=node-accelerator blocklist refresh timer
[Timer]
OnBootSec=120s
OnUnitActiveSec=$BLOCKLIST_REFRESH
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-blocklist.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-blocklist-update "$BLOCK_TOR" >/dev/null 2>&1 || true
    ok "блоклисты включены (обновление $BLOCKLIST_REFRESH). Лог: journalctl -t na-blocklist"
fi

# ── conntrack phantom-eviction (защита от distributed connect-and-hold) ───────
if [[ "$ENABLE_CTGUARD" == "1" ]]; then
    title "conntrack-guard (phantom-eviction)$([[ "$NA_CTG_ENFORCE" == "1" ]] && echo ' [ENFORCE]' || echo ' [observe]')"
    cat > "$CONF_DIR/ctguard.conf" <<EOF
# node-accelerator ctguard — детект distributed connect-and-hold по «живым» сокетам.
# Источник-фантом: conntrack ≫ живых сокетов (ss) → соединения брошены. CGNAT-safe:
# эвикт только концентрированный холдер с conntrack ≥ PHANTOM_MIN и live ≤ LIVE_FLOOR.
NA_CTG_ENFORCE=$NA_CTG_ENFORCE
NA_CTG_PHANTOM_MIN=${NA_CTG_PHANTOM_MIN:-4000}
NA_CTG_LIVE_FLOOR=${NA_CTG_LIVE_FLOOR:-2}
NA_CTG_BANTIME=${NA_CTG_BANTIME:-15m}
NA_CTG_COARSE_MULT=${NA_CTG_COARSE_MULT:-3}
EOF
    chmod 0640 "$CONF_DIR/ctguard.conf"
    cat > /usr/local/sbin/na-ctguard <<'CTG'
#!/usr/bin/env bash
# na-ctguard — liveness-aware защита от distributed connect-and-hold флуда. Класс атаки,
# который статичные rate-limit'ы не ловят: сотни IP открывают тысячи TCP, проходят
# handshake и БРОСАЮТ их — conntrack пухнет, приложение (xray) захлёбывается, но per-IP
# счётчики молчат (пик атаки пересекается с легит-CGNAT-потолком). Признак фантома:
# conntrack ≫ живых сокетов (ss). Дёшево: дорогой `conntrack -L` только если коарс-гейт
# (conntrack ≫ ss) сработал. CGNAT-safe: пропускаем источники с живыми сокетами,
# малым conntrack или в whitelist. observe-режим (NA_CTG_ENFORCE=0) — только лог.
set -u
TAG=na-ctguard
CONF=/etc/node-accelerator/ctguard.conf
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"
ENFORCE="${NA_CTG_ENFORCE:-0}"
PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"
LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"
BANTIME="${NA_CTG_BANTIME:-15m}"
COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"
command -v conntrack >/dev/null 2>&1 || { logger -t "$TAG" "нет conntrack-tools"; exit 0; }

# своя изолированная таблица (priority -5 → раньше na_filter); rollback = удалить таблицу
nft list table inet na_ctguard >/dev/null 2>&1 || nft -f - <<'NFTG'
table inet na_ctguard {
    set phantom_v4 { type ipv4_addr; flags timeout; size 131072; }
    set phantom_v6 { type ipv6_addr; flags timeout; size 131072; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip  saddr @phantom_v4 drop
        ip6 saddr @phantom_v6 drop
    }
}
NFTG

CT_TOTAL="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
SS_TOTAL="$(ss -tnH state established 2>/dev/null | wc -l)"
# коарс-гейт: дорогой дамп только если conntrack заметно больше живых сокетов И велик
[ "$CT_TOTAL" -ge "$PHANTOM_MIN" ] || exit 0
[ "$CT_TOTAL" -ge $((SS_TOTAL * COARSE_MULT)) ] || exit 0

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# живые established по src-IP клиента
ss -tnH state established 2>/dev/null | awk '{print $NF}' \
  | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort | uniq -c > "$TMP/live"
# conntrack по ПЕРВОМУ src= (это клиентский IP) — только tcp
conntrack -L -p tcp 2>/dev/null \
  | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}' \
  | sort | uniq -c | sort -rn > "$TMP/ct"

is_white() {  # в whitelist na_filter или в fleet-сете?
    local ip="$1" s4 s6
    if printf '%s' "$ip" | grep -q ':'; then s4=whitelist_v6; s6=na_fleet_v6; else s4=whitelist_v4; s6=na_fleet_v4; fi
    nft get element inet na_filter "$s4" "{ $ip }" >/dev/null 2>&1 && return 0
    nft get element inet na_filter "$s6" "{ $ip }" >/dev/null 2>&1 && return 0
    return 1
}
cand=0; eict=0
while read -r cnt ip; do
    [ -n "${ip:-}" ] || continue
    [ "$cnt" -ge "$PHANTOM_MIN" ] || break   # отсортировано по убыванию → дальше только меньше
    is_white "$ip" && continue
    live="$(awk -v ip="$ip" '$2==ip{print $1; f=1} END{if(!f)print 0}' "$TMP/live")"
    [ "${live:-0}" -le "$LIVE_FLOOR" ] || continue   # есть живые сокеты → легит/shared-front, щадим
    cand=$((cand+1))
    if [ "$ENFORCE" = "1" ]; then
        if printf '%s' "$ip" | grep -q ':'; then setn=phantom_v6; else setn=phantom_v4; fi
        nft add element inet na_ctguard "$setn" "{ $ip timeout $BANTIME }" 2>/dev/null \
            && conntrack -D -s "$ip" >/dev/null 2>&1 && eict=$((eict+1))
        logger -t "$TAG" "evict $ip ct=$cnt live=$live (bantime $BANTIME)"
    else
        logger -t "$TAG" "[observe] phantom-кандидат $ip ct=$cnt live=$live (NA_CTG_ENFORCE=0 — без эвикта)"
    fi
done < "$TMP/ct"
[ "$cand" -gt 0 ] && logger -t "$TAG" "тик: ct_total=$CT_TOTAL ss=$SS_TOTAL кандидатов=$cand эвиктов=$eict enforce=$ENFORCE"
exit 0
CTG
    chmod +x /usr/local/sbin/na-ctguard
    cat > /etc/systemd/system/na-ctguard.service <<'EOF'
[Unit]
Description=node-accelerator conntrack phantom-eviction
After=na-firewall.service
[Service]
Type=oneshot
# не отбираем CPU у xray под атакой
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/na-ctguard
EOF
    cat > /etc/systemd/system/na-ctguard.timer <<EOF
[Unit]
Description=node-accelerator ctguard timer
[Timer]
OnBootSec=90s
OnUnitActiveSec=${NA_CTG_INTERVAL:-20s}
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-ctguard.timer >/dev/null 2>&1 || true
    if [[ "$NA_CTG_ENFORCE" == "1" ]]; then
        ok "ctguard ENFORCE: фантом-холдеры эвиктятся. Лог: journalctl -t na-ctguard"
    else
        warn "ctguard в OBSERVE (только лог). Убедись по journalctl -t na-ctguard, что кандидаты = только атакеры (live≤$NA_CTG_LIVE_FLOOR), затем NA_CTG_ENFORCE=1 + ре-ран protect."
    fi
fi

# ─── fw-status хелпер ────────────────────────────────────────────────────────
cat > /usr/local/sbin/na-fw-status <<'STAT'
#!/usr/bin/env bash
echo "── nft table inet na_filter ──"
nft list table inet na_filter 2>/dev/null | grep -E 'policy|counter|elements' | head -40
echo
echo "── autoban (живые баны) ──"
echo "v4: $(nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ timeout' | wc -l)   v6: $(nft list set inet na_filter autoban_v6 2>/dev/null | grep -c timeout)"
nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ (timeout|expires)[^,]*' | head -15
if nft list set inet na_filter suspect_v4 >/dev/null 2>&1; then
    echo "suspect (наблюдение, ban-once) v4: $(nft list set inet na_filter suspect_v4 2>/dev/null | grep -c timeout)   v6: $(nft list set inet na_filter suspect_v6 2>/dev/null | grep -c timeout)"
fi
echo
if nft list set inet na_filter blocklist_v4 >/dev/null 2>&1; then
    echo "── threat-блоклисты ──"
    echo "v4: $(nft list set inet na_filter blocklist_v4 2>/dev/null | grep -coE '[0-9.]+')   v6: $(nft list set inet na_filter blocklist_v6 2>/dev/null | grep -c ':')   (обновляет na-blocklist-update)"
    echo
fi
if nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1; then
    echo "── fleet-sync (ноды флота → whitelist) ──"
    echo "v4: $(nft list set inet na_filter na_fleet_v4 2>/dev/null | grep -coE '[0-9.]+')   v6: $(nft list set inet na_filter na_fleet_v6 2>/dev/null | grep -c ':')   (последний синк: $(journalctl -t na-fleet-sync -n1 --no-pager -o cat 2>/dev/null | head -c 80))"
    echo
fi
if nft list table inet na_ctguard >/dev/null 2>&1; then
    echo "── ctguard (phantom-eviction) ──"
    enf="$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)"
    echo "режим: $([ "${enf:-0}" = 1 ] && echo ENFORCE || echo observe)   фантомов в блоке v4: $(nft list set inet na_ctguard phantom_v4 2>/dev/null | grep -c timeout)   v6: $(nft list set inet na_ctguard phantom_v6 2>/dev/null | grep -c timeout)"
    journalctl -t na-ctguard -n3 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    echo
fi
if [ -f /var/lib/node-accelerator/.synproxy-degraded ]; then
    echo "⚠ SYNPROXY DEGRADED: $(cat /var/lib/node-accelerator/.synproxy-degraded)"
    echo
fi
if command -v cscli >/dev/null 2>&1; then
    echo "── CrowdSec ──"
    cscli decisions list 2>/dev/null | head -20
    echo
    cscli metrics 2>/dev/null | sed -n '1,25p'
fi
STAT
chmod +x /usr/local/sbin/na-fw-status

# ─── top-talkers хелпер ──────────────────────────────────────────────────────
# Если нода за реверс-прокси/балансировщиком/CDN — трафик идёт с горстки upstream-IP,
# и per-IP лимиты их режут. Хелпер показывает топ источников → кандидаты в WHITELIST=.
cat > /usr/local/sbin/na-fw-top-talkers <<'TT'
#!/usr/bin/env bash
# Топ удалённых IP по числу установленных TCP-соединений на сервисных портах.
# Если нода за реверс-прокси/балансировщиком/CDN — легитимный трафик приходит с
# небольшого набора upstream-адресов; их стоит занести в WHITELIST=, чтобы per-IP
# лимиты (CONN_LIMIT/SYN_RATE) их не резали. Хелпер показывает кандидатов.
#   na-fw-top-talkers [порт[,порт...]] [N]   (по умолчанию порты из protect, N=25)
set -u
DEF=443
if [ -r /var/lib/node-accelerator/protect.installed ]; then
    DEF="$(awk -F= '/^tcp_ports=/{print $2}' /var/lib/node-accelerator/protect.installed)"
fi
PORTS="${1:-${DEF:-443}}"
N="${2:-25}"
filt=""
for p in ${PORTS//,/ }; do
    [ -n "$p" ] || continue
    filt="${filt:+$filt or }sport = :$p"
done
[ -n "$filt" ] || { echo "нет портов для анализа"; exit 1; }
echo "── Топ-$N удалённых IP по established TCP на портах: $PORTS ──"
ss -Hnt state established "( $filt )" 2>/dev/null \
    | awk '{print $5}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' \
    | sort | uniq -c | sort -rn | head -n "$N"
TT
chmod +x /usr/local/sbin/na-fw-top-talkers

# ─── Маркер ──────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/protect.installed" <<EOF
installed_at=$(date -Is)
na_version=$NA_VERSION
backup=$BACKUP
ssh_port=$SSH_PORT
tcp_ports=$TCP_PORTS
udp_ports=$UDP_PORTS
node_port=$NODE_PORT
crowdsec=$ENABLE_CROWDSEC
nft_file=$NFT_FILE
EOF

# Персист эффективного конфига → ре-ран без ENV сохранит эти значения (ENV всё ещё
# переопределяет). WHITELIST хранит только заданный оператором список (без транзитного
# авто-IP текущей SSH-сессии — тот добавляется в WL4/WL6 отдельно).
# REMNAWAVE_URL/TOKEN сюда НЕ пишем — токен живёт в fleet.env (0600), fleet-режим
# восстанавливается по наличию fleet.env.
save_conf "$CONF_DIR/protect.conf" \
    SSH_PORT TCP_PORTS UDP_PORTS NODE_PORT WHITELIST \
    SYN_RATE SYN_BURST UDP_RATE UDP_BURST CONN_LIMIT \
    ICMP_RATE ICMP_BURST SSH_RATE SSH_BURST SSH_BAN_TIME \
    PORTSCAN_BAN_TIME PORTSCAN_RATE PORTSCAN_BURST \
    ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC ENABLE_SYNPROXY \
    ENABLE_BLOCKLISTS BLOCK_TOR BLOCKLIST_REFRESH ENABLE_BANONCE SUSPECT_TIME \
    NODE_PORT_WHITELIST_ONLY SAFETY_DELAY \
    ENABLE_CTGUARD NA_CTG_ENFORCE NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR \
    NA_CTG_COARSE_MULT NA_CTG_BANTIME NA_CTG_INTERVAL

# ─── Подтверждение работы ────────────────────────────────────────────────────
title "Подтверждение (защита от самоблокировки)"
echo "  Открой НОВОЕ окно и проверь: ssh root@<этот сервер>"
echo "  (твой текущий IP $ADMIN_IP уже в whitelist, но лучше убедиться.)"
echo
if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
    read -r -p "Соединение работает? [y/N]: " c
    if [[ "$c" =~ ^[yYдД] ]]; then
        disarm_safety; ok "Сейфти-таймер снят. Защита активна."
    else
        warn "Сейфти оставлен: через ${SAFETY_DELAY}s na_filter удалится сам."
        warn "Если всё ок — сними: systemctl stop na-fw-safety.timer  (или kill из /tmp/na-fw-safety.pid)"
    fi
else
    warn "Неинтерактивно: сейфти-таймер на ${SAFETY_DELAY}s АКТИВЕН."
    warn "Подтверди доступ и сними: systemctl stop na-fw-safety.timer"
fi
echo
ok "Готово. Статус: na-fw-status | топ источников (для WHITELIST за CDN/LB): na-fw-top-talkers"
